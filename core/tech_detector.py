"""
技术指纹检测器 - 从资产的 HTTP 响应中检测使用的技术栈

本模块通过匹配预定义的技术指纹签名，从资产的 HTTP 响应头、
HTML 内容、Cookie 等信息中识别目标使用的技术栈及版本。

支持两种检测方式：
1. 从 FOFA 返回的资产信息中检测（无需访问目标）
2. 通过实际 HTTP 请求检测（需要访问目标 URL）
"""
import json
import re
import os
import logging
from typing import List, Dict, Tuple, Optional, Any

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger(__name__)


class Technology:
    """检测到的技术

    存储检测到的技术信息，包括名称、版本、分类、厂商和供应链归属。
    """

    def __init__(self, name: str, version: str = "", category: str = "",
                 vendor: str = "", supply_chain: str = ""):
        """初始化技术对象

        Args:
            name: 技术名称，如 "Apache HTTP Server"
            version: 检测到的版本号，如 "2.4.49"
            category: 技术分类，如 "web_server"、"web_framework"
            vendor: 厂商名称，如 "Apache Software Foundation"
            supply_chain: 供应链名称，如 "Apache"
        """
        self.name = name
        self.version = version
        self.category = category
        self.vendor = vendor
        self.supply_chain = supply_chain

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典，便于序列化"""
        return {
            "name": self.name,
            "version": self.version,
            "category": self.category,
            "vendor": self.vendor,
            "supply_chain": self.supply_chain,
        }

    def __repr__(self):
        if self.version:
            return f"Technology(name={self.name!r}, version={self.version!r}, category={self.category!r})"
        return f"Technology(name={self.name!r}, category={self.category!r})"

    def __eq__(self, other):
        if not isinstance(other, Technology):
            return NotImplemented
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)


class TechDetector:
    """技术指纹检测器

    加载技术签名数据库，对资产信息进行指纹匹配，
    识别目标使用的技术栈。

    使用示例::

        detector = TechDetector()
        # 从 FOFA 资产信息检测
        technologies = detector.detect_from_fofa(asset)
        for tech in technologies:
            print(f"{tech.name} {tech.version} ({tech.category})")
    """

    def __init__(self, signatures_path: Optional[str] = None):
        """初始化技术检测器

        Args:
            signatures_path: 签名数据库路径，为空时自动定位默认路径
        """
        self.signatures: List[Dict] = self._load_signatures(signatures_path)
        logger.info("已加载 %d 条技术指纹签名", len(self.signatures))

    def _get_default_data_path(self) -> str:
        """获取默认的数据目录路径

        自动定位项目结构中的 data 目录：
        - 优先查找与本文件同级目录下的 ../data/
        - 兼容从不同工作目录运行的情况

        Returns:
            data 目录的绝对路径
        """
        # 本文件位于 core/ 目录下，数据文件位于 ../data/
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(current_dir, "..", "data")
        return os.path.abspath(data_dir)

    def _load_signatures(self, signatures_path: Optional[str] = None) -> List[Dict]:
        """加载技术签名数据库

        从 JSON 文件加载技术指纹签名。

        Args:
            signatures_path: 签名文件路径，为空时使用默认路径

        Returns:
            签名列表，每个签名是一个字典
        """
        if signatures_path is None:
            signatures_path = os.path.join(
                self._get_default_data_path(), "tech_signatures.json"
            )

        logger.debug("加载技术签名文件: %s", signatures_path)

        if not os.path.exists(signatures_path):
            logger.error("技术签名文件不存在: %s", signatures_path)
            return []

        try:
            with open(signatures_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # 兼容两种结构：直接是列表，或者包含 signatures 字段的字典
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("signatures", [])
            logger.warning("技术签名文件格式异常，返回空列表")
            return []
        except json.JSONDecodeError as e:
            logger.error("技术签名文件 JSON 解析失败: %s", e)
            return []
        except IOError as e:
            logger.error("读取技术签名文件失败: %s", e)
            return []

    def _match_patterns(self, text: str, patterns: List[str]) -> Tuple[bool, str]:
        """匹配正则模式，返回是否匹配和提取的版本号

        遍历模式列表，使用正则表达式匹配文本。
        如果模式中包含捕获组，则提取第一个捕获组作为版本号。

        Args:
            text: 待匹配的文本
            patterns: 正则表达式模式列表

        Returns:
            元组 (是否匹配, 版本号)
            - 匹配成功且模式含捕获组: (True, 捕获到的版本号)
            - 匹配成功但模式无捕获组: (True, "")
            - 未匹配: (False, "")
        """
        if not text or not patterns:
            return False, ""

        for pattern in patterns:
            if not pattern:
                continue
            try:
                # 使用 re.IGNORECASE 忽略大小写，re.DOTALL 使 . 匹配换行
                match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                if match:
                    # 如果模式中有捕获组，提取版本号
                    version = ""
                    if match.groups():
                        version = match.group(1) or ""
                    return True, version
            except re.error as e:
                logger.warning("正则表达式编译失败: %s, pattern=%s", e, pattern)
                continue

        return False, ""

    def _detect_with_signature(self, signature: Dict,
                               header_text: str = "",
                               body_text: str = "",
                               cookie_text: str = "") -> Optional[Technology]:
        """使用单个签名进行检测

        将签名中的 header_patterns、body_patterns、cookie_patterns
        分别与对应的文本进行匹配，任一匹配成功即判定为检测到该技术。

        Args:
            signature: 技术签名字典
            header_text: HTTP 响应头文本
            body_text: HTML 正文文本
            cookie_text: Cookie 文本

        Returns:
            检测到则返回 Technology 对象，否则返回 None
        """
        header_patterns = signature.get("header_patterns", [])
        body_patterns = signature.get("body_patterns", [])
        cookie_patterns = signature.get("cookie_patterns", [])

        detected_version = ""

        # 检测 HTTP 响应头
        if header_text and header_patterns:
            matched, version = self._match_patterns(header_text, header_patterns)
            if matched:
                if version:
                    detected_version = version
                logger.debug("签名 [%s] 通过 header 匹配成功, version=%s",
                             signature.get("name"), version)
                return self._build_technology(signature, detected_version)

        # 检测 HTML 正文
        if body_text and body_patterns:
            matched, version = self._match_patterns(body_text, body_patterns)
            if matched:
                if version:
                    detected_version = version
                logger.debug("签名 [%s] 通过 body 匹配成功, version=%s",
                             signature.get("name"), version)
                return self._build_technology(signature, detected_version)

        # 检测 Cookie
        if cookie_text and cookie_patterns:
            matched, version = self._match_patterns(cookie_text, cookie_patterns)
            if matched:
                if version:
                    detected_version = version
                logger.debug("签名 [%s] 通过 cookie 匹配成功, version=%s",
                             signature.get("name"), version)
                return self._build_technology(signature, detected_version)

        return None

    def _build_technology(self, signature: Dict, version: str = "") -> Technology:
        """根据签名和版本号构建 Technology 对象

        Args:
            signature: 技术签名字典
            version: 检测到的版本号

        Returns:
            Technology 对象
        """
        return Technology(
            name=signature.get("name", ""),
            version=version,
            category=signature.get("category", ""),
            vendor=signature.get("vendor", ""),
            supply_chain=signature.get("supply_chain", ""),
        )

    def detect_from_fofa(self, asset) -> List[Technology]:
        """从 FOFA 返回的资产信息中检测技术

        利用 FOFA 资产中的 server、header、banner、title 字段
        进行技术指纹匹配，无需实际访问目标。

        Args:
            asset: FOFA 资产对象（需包含 server、header、banner、title 等属性）
                   支持 fofa_client.Asset 对象或具有相同属性的任意对象

        Returns:
            检测到的技术列表
        """
        if asset is None:
            return []

        # 安全地获取各字段，兼容不同类型的资产对象
        server = self._safe_get_attr(asset, "server", "")
        header = self._safe_get_attr(asset, "header", "")
        banner = self._safe_get_attr(asset, "banner", "")
        title = self._safe_get_attr(asset, "title", "")
        protocol = self._safe_get_attr(asset, "protocol", "")

        # 将可用于 header 匹配的文本合并（server、header、banner）
        header_text = "\n".join(filter(None, [server, header, banner, protocol]))
        # title 作为 body 文本的一部分进行匹配
        body_text = title or ""
        # FOFA 资产通常不单独返回 cookie，这里用 header 中的 Set-Cookie 行
        cookie_text = self._extract_cookies_from_header(header)

        return self._detect_all(header_text, body_text, cookie_text)

    def detect_from_http(self, url: str, timeout: int = 10,
                         verify_ssl: bool = False,
                         headers: Optional[Dict[str, str]] = None) -> List[Technology]:
        """通过 HTTP 请求检测技术

        主动访问目标 URL，分析 HTTP 响应头和 HTML 正文进行技术检测。

        Args:
            url: 目标 URL
            timeout: 请求超时时间（秒），默认 10
            verify_ssl: 是否验证 SSL 证书，默认 False
            headers: 自定义请求头

        Returns:
            检测到的技术列表

        Raises:
            ImportError: 当 requests 库未安装时
            RuntimeError: 当请求失败时
        """
        if requests is None:
            raise ImportError("detect_from_http 需要 requests 库，请先安装: pip install requests")

        if not url:
            return []

        # 默认请求头
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }
        if headers:
            default_headers.update(headers)

        logger.info("通过 HTTP 请求检测技术: %s", url)

        try:
            response = requests.get(
                url,
                headers=default_headers,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True,
            )
        except requests.exceptions.SSLError as e:
            logger.warning("SSL 错误，尝试不验证证书重试: %s", e)
            try:
                response = requests.get(
                    url, headers=default_headers, timeout=timeout,
                    verify=False, allow_redirects=True,
                )
            except requests.RequestException as retry_err:
                logger.error("HTTP 请求失败: %s", retry_err)
                return []
        except requests.RequestException as e:
            logger.error("HTTP 请求失败: %s", e)
            return []

        # 构造 header 文本
        header_text = self._response_headers_to_text(response)
        # 构造 body 文本
        try:
            body_text = response.text
        except Exception:
            body_text = ""
        # 提取 cookie 文本
        cookie_text = self._extract_cookies_from_response(response)

        return self._detect_all(header_text, body_text, cookie_text)

    def _detect_all(self, header_text: str, body_text: str,
                    cookie_text: str) -> List[Technology]:
        """对所有签名执行检测

        Args:
            header_text: HTTP 响应头文本
            body_text: HTML 正文文本
            cookie_text: Cookie 文本

        Returns:
            检测到的技术列表（已去重）
        """
        technologies: List[Technology] = []
        seen_names = set()

        for signature in self.signatures:
            tech = self._detect_with_signature(
                signature, header_text, body_text, cookie_text
            )
            if tech and tech.name not in seen_names:
                technologies.append(tech)
                seen_names.add(tech.name)

        logger.info("技术检测完成，共检测到 %d 项技术", len(technologies))
        return technologies

    def _safe_get_attr(self, obj, attr: str, default: str = "") -> str:
        """安全获取对象属性，兼容字典和对象

        Args:
            obj: 目标对象（可以是字典或普通对象）
            attr: 属性名/键名
            default: 默认值

        Returns:
            属性值（字符串）或默认值
        """
        if obj is None:
            return default
        if isinstance(obj, dict):
            value = obj.get(attr, default)
        else:
            value = getattr(obj, attr, default)
        # 确保返回字符串
        if value is None:
            return default
        return str(value) if value else default

    def _response_headers_to_text(self, response) -> str:
        """将 requests 响应头转换为可匹配的文本

        将响应头格式化为 "Key: Value" 的形式，
        模拟原始 HTTP 响应头，便于正则匹配。

        Args:
            response: requests 响应对象

        Returns:
            格式化后的响应头文本
        """
        lines = []
        for key, value in response.headers.items():
            lines.append(f"{key}: {value}")
        return "\n".join(lines)

    def _extract_cookies_from_header(self, header_text: str) -> str:
        """从 header 文本中提取 Cookie 信息

        Args:
            header_text: HTTP 响应头文本

        Returns:
            Cookie 相关的文本
        """
        if not header_text:
            return ""
        cookie_lines = []
        for line in header_text.split("\n"):
            line_lower = line.lower()
            if "set-cookie" in line_lower or "cookie" in line_lower:
                cookie_lines.append(line)
        return "\n".join(cookie_lines)

    def _extract_cookies_from_response(self, response) -> str:
        """从 requests 响应对象中提取 Cookie 文本

        Args:
            response: requests 响应对象

        Returns:
            Cookie 文本
        """
        cookie_lines = []
        # 从响应头中提取 Set-Cookie
        for key, value in response.headers.items():
            if key.lower() == "set-cookie":
                cookie_lines.append(f"Set-Cookie: {value}")
        # 从 cookies 对象中提取
        if hasattr(response, "cookies") and response.cookies:
            for cookie in response.cookies:
                cookie_lines.append(f"Set-Cookie: {cookie.name}={cookie.value}")
        return "\n".join(cookie_lines)

    def get_signature_categories(self) -> List[str]:
        """获取所有签名涵盖的技术分类

        Returns:
            去重后的分类列表
        """
        categories = set()
        for sig in self.signatures:
            cat = sig.get("category", "")
            if cat:
                categories.add(cat)
        return sorted(categories)

    def reload(self, signatures_path: Optional[str] = None):
        """重新加载签名数据库

        Args:
            signatures_path: 签名文件路径，为空时使用默认路径
        """
        self.signatures = self._load_signatures(signatures_path)
        logger.info("重新加载签名数据库完成，共 %d 条", len(self.signatures))


if __name__ == "__main__":
    # 模块直接运行时的演示
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    print("=" * 60)
    print("技术指纹检测器测试")
    print("=" * 60)

    detector = TechDetector()
    print(f"\n已加载 {len(detector.signatures)} 条签名")
    print(f"技术分类: {detector.get_signature_categories()}")

    # 模拟 FOFA 资产进行检测演示
    class MockAsset:
        def __init__(self):
            self.host = "example.com"
            self.ip = "1.2.3.4"
            self.port = 8080
            self.title = "Apache Tomcat/8.5.50 - 管理后台"
            self.server = "Apache-Coyote/1.1"
            self.header = (
                "Server: Apache-Coyote/1.1\n"
                "Set-Cookie: JSESSIONID=abc123; Path=/\n"
                "X-Powered-By: JSP/2.3"
            )
            self.banner = "Apache Tomcat/8.5.50"
            self.protocol = "http"
            self.country = "China"
            self.city = "Beijing"
            self.domain = "example.com"
            self.url = "http://example.com:8080"
            self.icp = ""

    print("\n--- 模拟 FOFA 资产检测 ---")
    mock_asset = MockAsset()
    technologies = detector.detect_from_fofa(mock_asset)
    for tech in technologies:
        version_str = f" v{tech.version}" if tech.version else ""
        print(f"  {tech.name}{version_str} [{tech.category}] - {tech.vendor}")

    print("\n--- 模拟 HTTP 响应头检测 ---")
    # 模拟 header 文本检测
    test_header = "Server: nginx/1.18.0\nX-Powered-By: PHP/7.4.3"
    test_body = '<script src="/jquery-3.5.1.min.js"></script><meta name="generator" content="WordPress 5.6">'
    test_cookie = "Set-Cookie: PHPSESSID=xyz789; wordpress_logged_in=test"
    technologies = detector._detect_all(test_header, test_body, test_cookie)
    for tech in technologies:
        version_str = f" v{tech.version}" if tech.version else ""
        print(f"  {tech.name}{version_str} [{tech.category}] - {tech.vendor}")
    print("=" * 60)
