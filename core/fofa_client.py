"""
FOFA API 客户端 - 通过 FOFA 搜索语法获取网络资产

本模块封装了 FOFA (网络空间资产搜索引擎) 的 API 调用，
支持资产搜索、连接测试、结果分页等功能。
"""
import base64
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from urllib.parse import urlsplit

import requests

# 配置日志记录器
logger = logging.getLogger(__name__)


@dataclass
class Asset:
    """网络资产数据模型

    用于存储从 FOFA 返回的单个网络资产信息，
    包含主机、IP、端口、标题、服务器等关键字段。
    """
    host: str = ""
    ip: str = ""
    port: int = 0
    title: str = ""
    server: str = ""
    header: str = ""
    banner: str = ""
    protocol: str = "http"
    country: str = ""
    city: str = ""
    domain: str = ""
    url: str = ""
    icp: str = ""

    def __post_init__(self):
        """初始化后处理：自动构造 URL（当 url 为空且 host 存在时）"""
        raw_host = (self.host or "").strip()
        if raw_host.startswith(("http://", "https://")):
            parsed = urlsplit(raw_host)
            self.protocol = parsed.scheme
            self.host = parsed.hostname or ""
            if not self.port and parsed.port:
                self.port = parsed.port
            if not self.url:
                self.url = raw_host.rstrip("/")
        elif not self.url and raw_host:
            default_port = 443 if self.protocol == "https" else 80
            port_suffix = f":{self.port}" if self.port and self.port != default_port else ""
            self.url = f"{self.protocol or 'http'}://{raw_host}{port_suffix}"

    def to_dict(self) -> Dict[str, Any]:
        """将资产对象转换为字典，便于序列化"""
        return {
            "host": self.host,
            "ip": self.ip,
            "port": self.port,
            "title": self.title,
            "server": self.server,
            "header": self.header,
            "banner": self.banner,
            "protocol": self.protocol,
            "country": self.country,
            "city": self.city,
            "domain": self.domain,
            "url": self.url,
            "icp": self.icp,
        }


class FofaError(Exception):
    """FOFA API 调用异常基类"""


class FofaAuthError(FofaError):
    """FOFA 认证失败异常（邮箱或 Key 无效）"""


class FofaApiError(FofaError):
    """FOFA API 业务异常（返回 error 为 true）"""


class FofaClient:
    """FOFA API 客户端

    通过 FOFA 的搜索语法查询网络空间资产，
    支持分页、超时控制、自动重试等特性。

    使用示例::

        client = FofaClient(email="your_email", key="your_key")
        if client.test_connection():
            assets = client.search('title="管理后台"', size=100)
            for asset in assets:
                print(asset.host, asset.port, asset.title)
    """

    # FOFA 搜索接口
    BASE_URL = "https://fofa.info/api/v1/search/all"
    # FOFA 用户信息接口（用于测试连接）
    INFO_URL = "https://fofa.info/api/v1/info/my"
    # 默认请求超时时间（秒）
    DEFAULT_TIMEOUT = 30
    # 每页最大结果数
    MAX_SIZE = 10000
    # 默认每页结果数
    DEFAULT_SIZE = 100

    def __init__(self, key: str = "", email: str = "",
                 timeout: int = DEFAULT_TIMEOUT,
                 max_retries: int = 3):
        """初始化 FOFA 客户端

        Args:
            key: FOFA API Key（主要认证方式）
            email: FOFA 注册邮箱（可选，部分旧接口可能需要）
            timeout: 请求超时时间（秒），默认 30
            max_retries: 最大重试次数，默认 3
        """
        self.key = key.strip()
        self.email = email.strip() if email else ""
        self.timeout = timeout
        self.max_retries = max_retries
        # 使用会话复用 TCP 连接，提升性能
        self.session = requests.Session()
        # 设置默认请求头
        self.session.headers.update({
            "User-Agent": "SupplyChainSecurityAnalyzer/1.0",
            "Accept": "application/json",
        })

    def _encode_query(self, query: str) -> str:
        """将 FOFA 查询语句进行 base64 编码

        FOFA API 要求查询语句以 base64 编码传输。

        Args:
            query: FOFA 搜索语法，例如 title="管理后台"

        Returns:
            base64 编码后的查询字符串
        """
        if not query:
            raise ValueError("查询语句不能为空")
        # 注意：FOFA 要求使用 UTF-8 编码后进行 base64
        return base64.b64encode(query.encode("utf-8")).decode("utf-8")

    def _build_params(self, query: str, size: int, page: int,
                      fields: str = "") -> Dict[str, Any]:
        """构造 API 请求参数

        Args:
            query: FOFA 搜索语法
            size: 每页结果数
            page: 页码
            fields: 指定返回字段（逗号分隔），为空时使用默认字段

        Returns:
            请求参数字典
        """
        # 限制 size 在合理范围内
        size = max(1, min(size, self.MAX_SIZE))
        page = max(1, page)

        params = {
            "key": self.key,
            "qbase64": self._encode_query(query),
            "size": size,
            "page": page,
        }
        # 如果指定了返回字段，则添加 fields 参数
        if fields:
            params["fields"] = fields
        return params

    def _parse_result_row(self, row: List[str]) -> Asset:
        """将 FOFA 返回的单行结果解析为 Asset 对象

        FOFA 默认返回字段顺序：
        host, ip, port, title, server, banner, header, protocol, country, city, domain, icp

        Args:
            row: FOFA 返回的单行数据列表

        Returns:
            Asset 对象
        """
        asset = Asset()
        # 安全地按索引取值，避免因字段缺失导致索引越界
        if len(row) > 0:
            asset.host = str(row[0]) if row[0] else ""
        if len(row) > 1:
            asset.ip = str(row[1]) if row[1] else ""
        if len(row) > 2:
            try:
                asset.port = int(row[2]) if row[2] else 0
            except (ValueError, TypeError):
                asset.port = 0
        if len(row) > 3:
            asset.title = str(row[3]) if row[3] else ""
        if len(row) > 4:
            asset.server = str(row[4]) if row[4] else ""
        if len(row) > 5:
            asset.banner = str(row[5]) if row[5] else ""
        if len(row) > 6:
            asset.header = str(row[6]) if row[6] else ""
        if len(row) > 7:
            asset.protocol = str(row[7]) if row[7] else "http"
        if len(row) > 8:
            asset.country = str(row[8]) if row[8] else ""
        if len(row) > 9:
            asset.city = str(row[9]) if row[9] else ""
        if len(row) > 10:
            asset.domain = str(row[10]) if row[10] else ""
        if len(row) > 11:
            asset.icp = str(row[11]) if row[11] else ""
        # FOFA fields are assigned after dataclass initialization, normalize again.
        asset.__post_init__()
        return asset

    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """处理 HTTP 响应，返回解析后的 JSON 数据

        Args:
            response: requests 响应对象

        Returns:
            解析后的 JSON 字典

        Raises:
            FofaApiError: 当 API 返回错误时
            FofaError: 当响应解析失败时
        """
        # 检查 HTTP 状态码
        if response.status_code != 200:
            raise FofaApiError(
                f"FOFA API 返回非 200 状态码: {response.status_code}, "
                f"响应内容: {response.text[:500]}"
            )

        try:
            data = response.json()
        except ValueError as e:
            raise FofaError(f"FOFA 响应 JSON 解析失败: {e}, 原始内容: {response.text[:500]}") from e

        # 检查 API 业务错误标记
        if isinstance(data, dict) and data.get("error", False):
            error_msg = data.get("errmsg", "未知错误")
            # 认证类错误的特殊处理
            if "401" in str(error_msg) or "Unauthorized" in str(error_msg) or "email" in str(error_msg).lower():
                raise FofaAuthError(f"FOFA 认证失败: {error_msg}")
            raise FofaApiError(f"FOFA API 返回错误: {error_msg}")

        return data

    def _request_with_retry(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """带重试机制的请求发送

        Args:
            url: 请求 URL
            params: 请求参数

        Returns:
            解析后的 JSON 数据
        """
        last_exception = None
        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug("FOFA API 请求 (第 %d 次): url=%s, params keys=%s",
                             attempt, url, list(params.keys()))
                response = self.session.get(
                    url, params=params, timeout=self.timeout
                )
                return self._handle_response(response)
            except (requests.ConnectionError, requests.Timeout) as e:
                # 网络错误进行重试
                last_exception = e
                logger.warning("FOFA API 请求网络错误 (第 %d 次): %s", attempt, e)
            except FofaApiError as e:
                # API 错误（包括认证错误）不进行重试，直接抛出
                raise
            except FofaError as e:
                # 其他 FOFA 错误不重试
                raise

        # 所有重试均失败
        raise FofaError(
            f"FOFA API 请求在 {self.max_retries} 次重试后仍失败: {last_exception}"
        ) from last_exception

    def search(self, query: str, size: int = DEFAULT_SIZE,
               page: int = 1, fields: str = "") -> List[Asset]:
        """搜索网络资产

        通过 FOFA 搜索语法查询网络空间资产。

        Args:
            query: FOFA 搜索语法，例如 title="管理后台" 或 port="8080"
            size: 每页结果数，默认 100，最大 10000
            page: 页码，从 1 开始，默认 1
            fields: 指定返回字段（逗号分隔），为空时使用 FOFA 默认字段

        Returns:
            资产列表 (List[Asset])

        Raises:
            ValueError: 当查询语句为空或邮箱/Key 未配置时
            FofaAuthError: 当认证失败时
            FofaApiError: 当 API 返回错误时
            FofaError: 当请求失败时

        示例::

            client = FofaClient(email="xxx", key="xxx")
            # 搜索标题包含"管理后台"的资产
            assets = client.search('title="管理后台"', size=100)
            # 搜索使用 Apache 且开放 8080 端口的资产
            assets = client.search('server="Apache" && port="8080"', size=50, page=2)
        """
        # 参数校验
        if not query or not query.strip():
            raise ValueError("FOFA 查询语句不能为空")
        if not self.key:
            raise ValueError("FOFA Key 必须配置后才能搜索")

        logger.info("FOFA 搜索: query=%r, size=%d, page=%d", query, size, page)

        # 构造请求参数
        params = self._build_params(query, size, page, fields)

        # 发送请求
        data = self._request_with_retry(self.BASE_URL, params)

        # 解析结果
        results = data.get("results", [])
        assets: List[Asset] = []
        for row in results:
            try:
                asset = self._parse_result_row(row)
                assets.append(asset)
            except Exception as e:
                # 单条记录解析失败不影响整体结果
                logger.warning("解析 FOFA 结果行失败，跳过: %s, 原始数据: %s", e, row)
                continue

        logger.info("FOFA 搜索完成: 共获取 %d 条资产", len(assets))
        return assets

    def search_all(self, query: str, max_results: int = 1000,
                   fields: str = "") -> List[Asset]:
        """分页获取所有搜索结果

        自动分页拉取，直到达到最大结果数或无更多数据。

        Args:
            query: FOFA 搜索语法
            max_results: 最大获取结果数，默认 1000
            fields: 指定返回字段

        Returns:
            资产列表
        """
        if not self.key:
            raise ValueError("FOFA Key 必须配置后才能搜索")

        all_assets: List[Asset] = []
        page = 1
        # 每页固定拉取 100 条，减少请求次数
        page_size = 100

        while len(all_assets) < max_results:
            remaining = max_results - len(all_assets)
            current_size = min(page_size, remaining)
            try:
                assets = self.search(query, size=current_size, page=page, fields=fields)
            except FofaError as e:
                logger.error("分页拉取第 %d 页失败: %s", page, e)
                break

            if not assets:
                # 没有更多结果
                logger.info("第 %d 页无更多结果，停止拉取", page)
                break

            all_assets.extend(assets)
            logger.info("已拉取 %d 条资产 (第 %d 页)", len(all_assets), page)

            # 如果本页结果数少于请求的 size，说明已是最后一页
            if len(assets) < current_size:
                break

            page += 1

        logger.info("分页拉取完成: 共获取 %d 条资产", len(all_assets))
        return all_assets

    def test_connection(self) -> bool:
        """测试 FOFA API 连接是否正常

        通过调用 FOFA 的用户信息接口验证 Key 是否有效。

        Returns:
            连接且认证成功返回 True，否则返回 False
        """
        if not self.key:
            logger.warning("FOFA Key 未配置，无法测试连接")
            return False

        try:
            params = {"key": self.key}
            data = self._request_with_retry(self.INFO_URL, params)
            # 如果能正常返回且无 error，说明连接正常
            if data and not data.get("error", False):
                remaining_points = data.get("remaining_free_point",
                                            data.get("vip_level", "未知"))
                logger.info("FOFA 连接测试成功，剩余点数/等级: %s", remaining_points)
                return True
            return False
        except FofaError as e:
            logger.error("FOFA 连接测试失败: %s", e)
            return False
        except Exception as e:
            logger.error("FOFA 连接测试发生未知异常: %s", e)
            return False

    def close(self):
        """关闭客户端会话，释放连接池资源"""
        if self.session:
            self.session.close()
            logger.debug("FOFA 客户端会话已关闭")

    def __enter__(self):
        """支持 with 语句上下文管理"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出上下文时自动关闭会话"""
        self.close()


if __name__ == "__main__":
    # 模块直接运行时的简易测试
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    # 以下为使用示例（需配置真实 email 和 key）
    print("=" * 60)
    print("FOFA API 客户端测试")
    print("=" * 60)
    print("提示: 请通过设置 email 和 key 参数来测试真实 API 调用")
    print()
    print("使用示例:")
    print('  client = FofaClient(email="your_email", key="your_key")')
    print('  if client.test_connection():')
    print('      assets = client.search(\'title="管理后台"\', size=10)')
    print('      for a in assets:')
    print('          print(f"{a.host}:{a.port} - {a.title}")')
    print("=" * 60)

    # 演示 Asset 对象的构造
    demo_asset = Asset(
        host="example.com",
        ip="93.184.216.34",
        port=443,
        title="Example Domain",
        server="nginx",
        protocol="https",
    )
    print("\n演示 Asset 对象:")
    print(f"  URL: {demo_asset.url}")
    print(f"  Host: {demo_asset.host}")
    print(f"  IP: {demo_asset.ip}")
    print(f"  Port: {demo_asset.port}")
    print(f"  Protocol: {demo_asset.protocol}")
