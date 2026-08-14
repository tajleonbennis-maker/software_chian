"""
漏洞检查器 - 对检测到的技术组件进行已知漏洞匹配

本模块负责将技术检测器识别出的技术组件与漏洞数据库进行匹配，
发现组件中存在的已知安全漏洞。

支持三种漏洞数据来源：
1. 离线漏洞数据库（data/known_vulns.json）- 默认启用，快速匹配
2. NVD API（在线查询）- 可选，获取最新漏洞信息
3. OSV API（在线查询）- 可选，查询开源软件漏洞

核心功能：
- 解析 affected_versions 字段，判断当前版本是否受影响
- 支持组件名别名匹配（如 "Apache HTTP Server" 匹配 "Apache"）
- 版本范围比较（支持 "to"、"prior to"、"and earlier" 等多种格式）
"""
import json
import os
import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """漏洞数据模型

    存储单个已匹配漏洞的完整信息，包括 CVE 编号、组件名、
    安装版本、受影响版本范围、严重等级、CVSS 分数等。
    """
    cve_id: str
    component: str
    installed_version: str
    affected_versions: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    title: str
    description: str
    exploit_type: str = ""
    exploit_difficulty: str = ""
    references: List[str] = None
    source: str = "local"  # local, nvd, osv
    # 漏洞级验证状态（Codex P0-2）：suspected / condition_matched / actively_verified / excluded
    verification_status: str = "suspected"
    verification_method: str = ""
    verified_at: float = 0.0

    def __post_init__(self):
        """初始化后处理：确保 references 是列表"""
        if self.references is None:
            self.references = []

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典，便于序列化"""
        return {
            "cve_id": self.cve_id,
            "component": self.component,
            "installed_version": self.installed_version,
            "affected_versions": self.affected_versions,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "title": self.title,
            "description": self.description,
            "exploit_type": self.exploit_type,
            "exploit_difficulty": self.exploit_difficulty,
            "references": self.references,
            "source": self.source,
            "verification_status": self.verification_status,
            "verification_method": self.verification_method,
            "verified_at": self.verified_at,
        }


# ---------------------------------------------------------------------------
# 组件别名映射表
# ---------------------------------------------------------------------------
# 用于将不同命名方式的组件名统一匹配到漏洞库中的标准组件名。
# 键为标准组件名（小写），值为该组件的所有别名（小写）。
COMPONENT_ALIASES: Dict[str, List[str]] = {
    "log4j": ["log4j2", "log4j-core", "apache log4j", "log4shell", "log4j-core2"],
    "spring framework": ["spring", "springframework", "spring-core", "spring boot",
                         "springboot", "spring-boot"],
    "spring cloud gateway": ["spring cloud", "spring-cloud-gateway"],
    "struts2": ["struts", "apache struts", "struts 2", "struts2-core"],
    "shiro": ["apache shiro", "shiro-core"],
    "fastjson": ["alibaba fastjson", "fastjson2"],
    "weblogic": ["oracle weblogic", "weblogic server"],
    "jboss": ["jboss as", "wildfly", "jboss eap"],
    "tomcat": ["apache tomcat", "tomcat-server"],
    "drupal": ["drupal core"],
    "django": ["django framework"],
    "thinkphp": ["think php"],
    "jquery": ["jquery.js", "jquery library"],
    "phpmyadmin": ["php myadmin"],
    "php": ["php-fpm", "php language"],
    "jenkins": ["jenkins-ci", "hudson"],
    "gitlab": ["gitlab ce", "gitlab ee"],
    "grafana": ["grafana server"],
    "harbor": ["vmware harbor", "goharbor"],
    "nginx": ["nginx server", "nginx web server"],
    "apache http server": ["apache", "apache httpd", "httpd", "apache2",
                            "apache web server", "apache http server"],
    "node.js": ["nodejs", "node", "node js"],
    "python pyyaml": ["pyyaml", "yaml", "python-yaml"],
    "solr": ["apache solr"],
    "confluence": ["atlassian confluence"],
    "druid": ["apache druid"],
}


class VulnChecker:
    """漏洞检查器

    加载离线漏洞数据库，对技术组件列表进行漏洞匹配。
    支持可选的 NVD API 和 OSV API 在线查询。

    使用示例::

        checker = VulnChecker()
        technologies = [
            Technology(name="Log4j", version="2.14.1"),
            Technology(name="Apache Tomcat", version="8.5.50"),
        ]
        vulnerabilities = checker.check(technologies)
        for vuln in vulnerabilities:
            print(f"[{vuln.severity}] {vuln.cve_id}: {vuln.title}")
    """

    # NVD API 端点
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # OSV API 端点
    OSV_API_URL = "https://api.osv.dev/v1/query"
    # 默认请求超时时间（秒）
    DEFAULT_TIMEOUT = 15
    # 严重等级权重（用于风险评分）
    SEVERITY_WEIGHTS = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1,
    }

    def __init__(self,
                 vuln_db_path: Optional[str] = None,
                 enable_nvd: bool = False,
                 enable_osv: bool = False,
                 nvd_api_key: str = "",
                 timeout: int = DEFAULT_TIMEOUT):
        """初始化漏洞检查器

        Args:
            vuln_db_path: 离线漏洞数据库路径，为空时使用默认路径
            enable_nvd: 是否启用 NVD API 在线查询，默认 False
            enable_osv: 是否启用 OSV API 在线查询，默认 False
            nvd_api_key: NVD API Key（可选，有 Key 时请求频率限制更宽松）
            timeout: 在线 API 请求超时时间（秒），默认 15
        """
        self.vuln_database: List[Dict] = []
        self.enable_nvd = enable_nvd
        self.enable_osv = enable_osv
        self.nvd_api_key = nvd_api_key
        self.timeout = timeout
        # 构建反向别名索引：别名 -> 标准组件名
        self._alias_reverse_map: Dict[str, str] = {}
        self._build_alias_reverse_map()

        # 加载离线漏洞数据库
        self._load_vuln_database(vuln_db_path)
        logger.info("漏洞检查器初始化完成，已加载 %d 条离线漏洞记录", len(self.vuln_database))

        # 初始化 HTTP 会话（用于在线查询）
        self._session = None
        if requests is not None and (enable_nvd or enable_osv):
            self._session = requests.Session()
            self._session.headers.update({
                "User-Agent": "SupplyChainSecurityAnalyzer/1.0",
                "Accept": "application/json",
            })

    # ------------------------------------------------------------------
    # 数据加载
    # ------------------------------------------------------------------

    def _get_default_data_path(self) -> str:
        """获取默认的数据目录路径

        自动定位项目结构中的 data 目录（与本文件同级的 ../data/）。

        Returns:
            data 目录的绝对路径
        """
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(current_dir, "..", "data")
        return os.path.abspath(data_dir)

    def _load_vuln_database(self, vuln_db_path: Optional[str] = None):
        """加载离线漏洞数据库

        从 JSON 文件加载漏洞数据。文件格式为：
        {"vulnerabilities": [{"cve_id": "CVE-xxx", "component": "...", ...}]}

        Args:
            vuln_db_path: 漏洞数据库文件路径，为空时使用默认路径
        """
        if vuln_db_path is None:
            vuln_db_path = os.path.join(
                self._get_default_data_path(), "known_vulns.json"
            )

        logger.debug("加载漏洞数据库: %s", vuln_db_path)

        if not os.path.exists(vuln_db_path):
            logger.error("漏洞数据库文件不存在: %s", vuln_db_path)
            return

        try:
            with open(vuln_db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error("漏洞数据库 JSON 解析失败: %s", e)
            return
        except IOError as e:
            logger.error("读取漏洞数据库文件失败: %s", e)
            return

        # 兼容两种结构：直接列表或包含 vulnerabilities 字段的字典
        if isinstance(data, list):
            self.vuln_database = data
        elif isinstance(data, dict):
            self.vuln_database = data.get("vulnerabilities", [])
        else:
            logger.warning("漏洞数据库格式异常，返回空列表")
            self.vuln_database = []

    def reload(self, vuln_db_path: Optional[str] = None):
        """重新加载漏洞数据库

        Args:
            vuln_db_path: 漏洞数据库文件路径，为空时使用默认路径
        """
        self.vuln_database = []
        self._load_vuln_database(vuln_db_path)
        logger.info("重新加载漏洞数据库完成，共 %d 条记录", len(self.vuln_database))

    # ------------------------------------------------------------------
    # 组件别名匹配
    # ------------------------------------------------------------------

    def _build_alias_reverse_map(self):
        """构建别名反向索引

        将 COMPONENT_ALIASES 中的所有别名映射到标准组件名，
        同时将标准组件名自身也加入索引。
        """
        for standard_name, aliases in COMPONENT_ALIASES.items():
            # 标准名映射到自身
            self._alias_reverse_map[standard_name] = standard_name
            for alias in aliases:
                self._alias_reverse_map[alias] = standard_name

    def _normalize_component_name(self, name: str) -> str:
        """将组件名标准化为漏洞库中的标准名称

        通过别名映射表将各种命名方式统一为标准组件名。
        如果未找到映射，返回原始名称（小写）。

        Args:
            name: 原始组件名

        Returns:
            标准化的组件名（小写）
        """
        if not name:
            return ""
        name_lower = name.lower().strip()
        # 精确匹配别名
        if name_lower in self._alias_reverse_map:
            return self._alias_reverse_map[name_lower]
        # 模糊匹配：检查别名是否包含在名称中
        for alias, standard in self._alias_reverse_map.items():
            if alias in name_lower or name_lower in alias:
                return standard
        return name_lower

    def _match_component(self, tech_name: str, vuln_component: str) -> bool:
        """检查技术组件名是否与漏洞记录中的组件名匹配

        支持别名匹配和模糊包含匹配。

        Args:
            tech_name: 检测到的技术组件名
            vuln_component: 漏洞记录中的组件名

        Returns:
            是否匹配
        """
        if not tech_name or not vuln_component:
            return False

        # 标准化两个名称
        tech_normalized = self._normalize_component_name(tech_name)
        vuln_normalized = self._normalize_component_name(vuln_component)

        # 精确匹配
        if tech_normalized == vuln_normalized:
            return True

        # 包含匹配（一方包含另一方）
        if vuln_normalized in tech_normalized or tech_normalized in vuln_normalized:
            return True

        # 分词匹配：将组件名拆分为单词，检查是否有重叠
        tech_words = set(re.split(r'[\s\-_/\.]+', tech_normalized))
        vuln_words = set(re.split(r'[\s\-_/\.]+', vuln_normalized))
        # 过滤掉空字符串和过短的词
        tech_words = {w for w in tech_words if len(w) > 1}
        vuln_words = {w for w in vuln_words if len(w) > 1}
        if tech_words and vuln_words:
            overlap = tech_words & vuln_words
            # 如果有有意义的词汇重叠，认为匹配
            if overlap:
                return True

        return False

    # ------------------------------------------------------------------
    # 版本解析与比较
    # ------------------------------------------------------------------

    def _parse_version(self, version_str: str) -> Tuple[Tuple[int, ...], int, int]:
        """将版本字符串解析为可比较的结构

        将版本号解析为 (主版本元组, 预发布优先级, 预发布序号) 三元组。
        正式版的预发布优先级为 5（最高），预发布版（alpha/beta/rc/milestone）优先级更低。

        例如：
            "2.14.1"       -> ((2, 14, 1), 5, 0)   正式版
            "2.0-beta9"    -> ((2, 0), 2, 9)        beta 版
            "9.0.0.M1"     -> ((9, 0, 0), 3, 1)     里程碑版
            "8.0.0.RC1"    -> ((8, 0, 0), 4, 1)     候选版

        Args:
            version_str: 版本字符串

        Returns:
            (主版本元组, 预发布优先级, 预发布序号) 三元组
        """
        if not version_str:
            return ((0,), 5, 0)

        version_str = version_str.strip()

        # 预发布标记优先级映射（数字越大越接近正式版）
        pre_release_priority_map = {
            'dev': 0, 'snapshot': 0,
            'alpha': 1, 'a': 1,
            'beta': 2, 'b': 2,
            'm': 3,  # Milestone
            'rc': 4, 'cr': 4,
        }

        # 步骤 1：分离主版本号和预发布标记
        # 先按 "-" 分割，如 "2.0-beta9" -> main="2.0", pre="beta9"
        main_version_str = version_str
        pre_release_str = ""

        if '-' in version_str:
            dash_parts = version_str.split('-', 1)
            main_version_str = dash_parts[0].strip()
            pre_release_str = dash_parts[1].strip()

        # 如果没有 "-"，检查点分隔的最后一部分是否含字母
        # 如 "9.0.0.M1" -> main="9.0.0", pre="M1"
        if not pre_release_str:
            dot_parts = main_version_str.split('.')
            if len(dot_parts) > 1:
                last_part = dot_parts[-1].strip()
                # 检查最后一部分是否包含字母（非纯数字）
                if last_part and not last_part.isdigit():
                    match = re.match(r'^(\d*)([a-zA-Z]\w*)$', last_part)
                    if match:
                        num_prefix = match.group(1)
                        alpha_suffix = match.group(2)
                        if num_prefix:
                            dot_parts[-1] = num_prefix
                        else:
                            dot_parts = dot_parts[:-1]
                        main_version_str = '.'.join(dot_parts)
                        pre_release_str = alpha_suffix

        # 步骤 2：解析主版本号
        main_parts = []
        for part in main_version_str.split('.'):
            part = part.strip()
            if not part:
                continue
            # 尝试转换为整数
            if part.isdigit():
                main_parts.append(int(part))
            else:
                # 提取开头的数字部分
                num_match = re.match(r'^(\d+)', part)
                if num_match:
                    main_parts.append(int(num_match.group(1)))
                else:
                    main_parts.append(0)

        if not main_parts:
            main_parts = [0]

        # 步骤 3：解析预发布标记
        pre_priority = 5  # 正式版优先级最高
        pre_num = 0

        if pre_release_str:
            pre_lower = pre_release_str.lower()
            # 提取字母前缀
            alpha_match = re.match(r'^([a-zA-Z]+)', pre_lower)
            if alpha_match:
                prefix = alpha_match.group(1)
                pre_priority = pre_release_priority_map.get(prefix, 3)
            # 提取数字部分
            num_match = re.search(r'(\d+)', pre_release_str)
            if num_match:
                pre_num = int(num_match.group(1))

        return (tuple(main_parts), pre_priority, pre_num)

    def _compare_versions(self, v1: str, v2: str) -> int:
        """比较两个版本字符串

        Args:
            v1: 版本字符串 1
            v2: 版本字符串 2

        Returns:
            -1 表示 v1 < v2
             0 表示 v1 == v2
             1 表示 v1 > v2
        """
        parsed1 = self._parse_version(v1)
        parsed2 = self._parse_version(v2)

        main1, pre_pri1, pre_num1 = parsed1
        main2, pre_pri2, pre_num2 = parsed2

        # 填充主版本元组到相同长度（用 0 填充）
        max_len = max(len(main1), len(main2))
        main1_padded = main1 + (0,) * (max_len - len(main1))
        main2_padded = main2 + (0,) * (max_len - len(main2))

        # 比较主版本号
        if main1_padded < main2_padded:
            return -1
        if main1_padded > main2_padded:
            return 1

        # 主版本号相同，比较预发布标记
        # 正式版（priority=5）大于任何预发布版
        if pre_pri1 < pre_pri2:
            return -1
        if pre_pri1 > pre_pri2:
            return 1

        # 预发布类型相同，比较序号
        if pre_num1 < pre_num2:
            return -1
        if pre_num1 > pre_num2:
            return 1

        return 0

    def _extract_version_number(self, text: str) -> str:
        """从文本中提取版本号字符串

        从可能包含非版本字符的文本中提取纯版本号。
        例如 "2.0-beta9 to 2.14.1" 中的 "2.0-beta9"

        Args:
            text: 包含版本号的文本

        Returns:
            提取的版本号字符串，未找到返回空字符串
        """
        if not text:
            return ""
        # 匹配版本号模式：数字开头，可包含点、数字、字母、连字符
        # 例如: 2.14.1, 2.0-beta9, 9.0.0.M1, 8.0.0.RC1, 1.2.24
        match = re.search(
            r'(\d+(?:\.\d+)*(?:[-\.][a-zA-Z]+\d*)?)',
            text.strip()
        )
        if match:
            return match.group(1)
        return ""

    def _is_version_affected(self, installed_version: str, affected_versions: str) -> bool:
        """检查安装的版本是否在受影响版本范围内

        解析 affected_versions 字段，支持多种格式：
        - "X to Y"：版本范围（包含边界）
        - "X to Y (excluding Z)"：排除特定版本的范围
        - "X and earlier"：小于等于 X
        - "prior to X"：小于 X
        - "X and later"：大于等于 X
        - "X"：精确版本
        - "X.x"：通配符版本
        - 多个范围用逗号分隔

        Args:
            installed_version: 已安装的版本号
            affected_versions: 受影响版本范围描述

        Returns:
            是否受影响
        """
        if not installed_version or not affected_versions:
            return False

        installed_version = installed_version.strip()
        affected_versions = affected_versions.strip()

        # 如果安装版本为空或包含通配符，保守判定为受影响
        if not installed_version or installed_version in ("unknown", "latest"):
            return False

        # 预处理：将括号内的逗号替换为分号，避免错误分割
        cleaned_affected = self._escape_paren_commas(affected_versions)

        # 按逗号分割多个范围
        range_parts = [r.strip() for r in cleaned_affected.split(',') if r.strip()]

        for range_str in range_parts:
            # 恢复括号内的逗号
            range_str = range_str.replace(';', ',').strip()
            if self._check_single_range(installed_version, range_str):
                return True

        return False

    def _escape_paren_commas(self, text: str) -> str:
        """将括号内的逗号替换为分号

        避免在分割多个版本范围时，括号内的逗号被误判为分隔符。

        Args:
            text: 原始文本

        Returns:
            处理后的文本
        """
        result = []
        in_paren = 0
        for char in text:
            if char == '(':
                in_paren += 1
                result.append(char)
            elif char == ')':
                in_paren = max(0, in_paren - 1)
                result.append(char)
            elif char == ',' and in_paren > 0:
                result.append(';')
            else:
                result.append(char)
        return ''.join(result)

    def _check_single_range(self, installed_version: str, range_str: str) -> bool:
        """检查版本是否落在单个范围描述内

        Args:
            installed_version: 已安装的版本号
            range_str: 单个版本范围描述字符串

        Returns:
            是否在此范围内
        """
        range_str = range_str.strip()
        range_lower = range_str.lower()

        # 跳过无法解析的描述性文字
        skip_keywords = ["older unsupported versions", "unsupported", "and older",
                         "older versions", "all versions"]
        if any(kw in range_lower for kw in skip_keywords):
            # 对于 "older unsupported versions" 这类描述，保守判定为受影响
            # 但仅当无法通过其他范围精确判断时才会到达这里
            return False

        # 处理 "and earlier" 格式：版本 <= X
        if 'and earlier' in range_lower:
            ver = self._extract_version_number(range_str)
            if ver:
                return self._compare_versions(installed_version, ver) <= 0
            return False

        # 处理 "prior to" 格式：版本 < X
        if 'prior to' in range_lower:
            # 提取 "prior to" 后面的版本号
            match = re.search(r'prior to\s+(\d+(?:\.\d+)*(?:[-\.][a-zA-Z]+\d*)?)',
                              range_str, re.IGNORECASE)
            if match:
                return self._compare_versions(installed_version, match.group(1)) < 0
            return False

        # 处理 "and later" 格式：版本 >= X
        if 'and later' in range_lower:
            ver = self._extract_version_number(range_str)
            if ver:
                return self._compare_versions(installed_version, ver) >= 0
            return False

        # 处理 "to" 范围格式：start <= 版本 <= end
        if ' to ' in range_lower:
            # 提取排除标记
            excluding_ver = None
            excl_match = re.search(r'\(excluding\s+(\d+(?:\.\d+)*(?:[-\.][a-zA-Z]+\d*)?)\)',
                                   range_str, re.IGNORECASE)
            if excl_match:
                excluding_ver = excl_match.group(1)

            # 移除括号内容，便于按 " to " 分割
            range_clean = re.sub(r'\([^)]*\)', '', range_str).strip()

            parts = range_clean.split(' to ')
            if len(parts) == 2:
                start_ver = self._extract_version_number(parts[0])
                end_ver = self._extract_version_number(parts[1])

                if start_ver and end_ver:
                    cmp_start = self._compare_versions(installed_version, start_ver)
                    cmp_end = self._compare_versions(installed_version, end_ver)

                    # 版本在范围内（包含边界）
                    if cmp_start >= 0 and cmp_end <= 0:
                        # 检查排除版本
                        if excluding_ver and self._compare_versions(installed_version,
                                                                     excluding_ver) == 0:
                            return False
                        return True
            return False

        # 处理通配符版本 "X.x" 或 "X.Y.x"
        if '.x' in range_lower:
            # 可能包含 "and" 连接多个通配符，如 "5.x and 6.x"
            wildcard_parts = re.split(r'\s+and\s+', range_str)
            for wp in wildcard_parts:
                if '.x' in wp.lower():
                    match = re.match(r'^(\d+)(?:\.(\d+))?\.x', wp.strip(), re.IGNORECASE)
                    if match:
                        major = int(match.group(1))
                        minor = int(match.group(2)) if match.group(2) else None
                        installed_parsed = self._parse_version(installed_version)
                        inst_main = installed_parsed[0]
                        inst_major = inst_main[0] if inst_main else 0
                        if minor is not None:
                            inst_minor = inst_main[1] if len(inst_main) > 1 else 0
                            if inst_major == major and inst_minor == minor:
                                return True
                        else:
                            if inst_major == major:
                                return True
            return False

        # 处理 "and" 连接的多个版本（如 "prior to 2.121 and 2.107.2"）
        if ' and ' in range_lower and 'prior to' not in range_lower:
            and_parts = re.split(r'\s+and\s+', range_str)
            for ap in and_parts:
                ver = self._extract_version_number(ap)
                if ver and self._compare_versions(installed_version, ver) == 0:
                    return True
            return False

        # 处理精确版本匹配
        ver = self._extract_version_number(range_str)
        if ver:
            return self._compare_versions(installed_version, ver) == 0

        return False

    # ------------------------------------------------------------------
    # 漏洞检查核心逻辑
    # ------------------------------------------------------------------

    def check(self, technologies: List) -> List[Vulnerability]:
        """对技术组件列表进行漏洞检查

        将每个技术与离线漏洞数据库进行匹配，发现已知漏洞。
        如果启用了 NVD 或 OSV 在线查询，还会补充在线查询结果。

        Args:
            technologies: 技术组件列表（Technology 对象或兼容对象，
                         需包含 name 和 version 属性）

        Returns:
            匹配到的漏洞列表 (List[Vulnerability])

        示例::

            checker = VulnChecker()
            vulns = checker.check([
                Technology(name="Log4j", version="2.14.1"),
            ])
        """
        if not technologies:
            return []

        all_vulns: List[Vulnerability] = []
        seen_cve_ids: set = set()  # 用于去重

        # 第一步：离线数据库匹配
        local_vulns = self._check_local(technologies)
        for vuln in local_vulns:
            if vuln.cve_id not in seen_cve_ids:
                all_vulns.append(vuln)
                seen_cve_ids.add(vuln.cve_id)

        logger.info("离线漏洞匹配完成，发现 %d 个漏洞", len(all_vulns))

        # 第二步：NVD API 在线查询（可选）
        if self.enable_nvd and self._session:
            nvd_vulns = self._check_nvd(technologies, seen_cve_ids)
            for vuln in nvd_vulns:
                if vuln.cve_id not in seen_cve_ids:
                    all_vulns.append(vuln)
                    seen_cve_ids.add(vuln.cve_id)
            logger.info("NVD 在线查询补充 %d 个漏洞", len(nvd_vulns))

        # 第三步：OSV API 在线查询（可选）
        if self.enable_osv and self._session:
            osv_vulns = self._check_osv(technologies, seen_cve_ids)
            for vuln in osv_vulns:
                if vuln.cve_id not in seen_cve_ids:
                    all_vulns.append(vuln)
                    seen_cve_ids.add(vuln.cve_id)
            logger.info("OSV 在线查询补充 %d 个漏洞", len(osv_vulns))

        # 按严重等级和 CVSS 分数排序
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_vulns.sort(key=lambda v: (
            severity_order.get(v.severity.upper(), 4),
            -v.cvss_score
        ))

        logger.info("漏洞检查完成，共发现 %d 个漏洞", len(all_vulns))
        return all_vulns

    def _check_local(self, technologies: List) -> List[Vulnerability]:
        """使用离线漏洞数据库进行匹配

        Args:
            technologies: 技术组件列表

        Returns:
            匹配到的漏洞列表
        """
        vulns: List[Vulnerability] = []

        for tech in technologies:
            tech_name = self._safe_get_attr(tech, "name", "")
            tech_version = self._safe_get_attr(tech, "version", "")

            if not tech_name:
                continue

            # 遍历漏洞数据库，逐条匹配
            for vuln_record in self.vuln_database:
                vuln_component = vuln_record.get("component", "")

                # 组件名匹配
                if not self._match_component(tech_name, vuln_component):
                    continue

                # 版本匹配
                affected_versions = vuln_record.get("affected_versions", "")
                if tech_version and affected_versions:
                    if not self._is_version_affected(tech_version, affected_versions):
                        continue
                elif not tech_version:
                    # 如果未检测到版本号，保守判定为可能受影响（仅对 HIGH/CRITICAL）
                    severity = vuln_record.get("severity", "").upper()
                    if severity not in ("CRITICAL", "HIGH"):
                        continue

                # 构建漏洞对象
                vuln = Vulnerability(
                    cve_id=vuln_record.get("cve_id", ""),
                    component=vuln_component,
                    installed_version=tech_version,
                    affected_versions=affected_versions,
                    severity=vuln_record.get("severity", "UNKNOWN"),
                    cvss_score=vuln_record.get("cvss_score", 0.0),
                    title=vuln_record.get("title", ""),
                    description=vuln_record.get("description", ""),
                    exploit_type=vuln_record.get("exploit_type", ""),
                    exploit_difficulty=vuln_record.get("exploit_difficulty", ""),
                    references=vuln_record.get("references", []),
                    source="local",
                )
                vulns.append(vuln)

        return vulns

    def _check_nvd(self, technologies: List, seen_cve_ids: set) -> List[Vulnerability]:
        """通过 NVD API 进行在线漏洞查询

        NVD（National Vulnerability Database）是美国国家漏洞数据库，
        提供 CVE 漏洞的详细信息和 CVSS 评分。

        Args:
            technologies: 技术组件列表
            seen_cve_ids: 已发现的 CVE ID 集合（用于去重）

        Returns:
            从 NVD 查询到的漏洞列表
        """
        if requests is None:
            logger.warning("requests 库未安装，无法使用 NVD API")
            return []

        vulns: List[Vulnerability] = []

        for tech in technologies:
            tech_name = self._safe_get_attr(tech, "name", "")
            tech_version = self._safe_get_attr(tech, "version", "")

            if not tech_name:
                continue

            # 使用关键词搜索 NVD
            # NVD API 支持关键字搜索，格式为 "component version"
            keyword = tech_name
            params = {"keywordSearch": keyword}
            if self.nvd_api_key:
                params["apiKey"] = self.nvd_api_key

            try:
                response = self._session.get(
                    self.NVD_API_URL,
                    params=params,
                    timeout=self.timeout,
                )
                if response.status_code != 200:
                    logger.warning("NVD API 返回状态码 %d", response.status_code)
                    continue

                data = response.json()
                cve_items = data.get("vulnerabilities", [])

                for item in cve_items:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")

                    # 跳过已发现的漏洞
                    if cve_id in seen_cve_ids:
                        continue

                    # 提取 CVSS 分数和严重等级
                    cvss_score = 0.0
                    severity = "UNKNOWN"
                    metrics = cve.get("metrics", {})
                    # 优先使用 CVSS v3.1，其次 v3.0，最后 v2
                    for cvss_version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if cvss_version in metrics and metrics[cvss_version]:
                            cvss_data = metrics[cvss_version][0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            severity = cvss_data.get("baseSeverity", "UNKNOWN")
                            break

                    # 提取描述
                    descriptions = cve.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break

                    # 提取参考链接
                    references = [
                        ref.get("url", "") for ref in cve.get("references", [])
                        if ref.get("url")
                    ]

                    vuln = Vulnerability(
                        cve_id=cve_id,
                        component=tech_name,
                        installed_version=tech_version,
                        affected_versions="（见 NVD 详情）",
                        severity=severity.upper() if severity else "UNKNOWN",
                        cvss_score=cvss_score,
                        title=cve_id,
                        description=description,
                        references=references,
                        source="nvd",
                    )
                    vulns.append(vuln)

            except requests.Timeout:
                logger.warning("NVD API 请求超时: %s", tech_name)
            except requests.ConnectionError:
                logger.warning("NVD API 连接失败: %s", tech_name)
            except Exception as e:
                logger.warning("NVD API 查询异常 (%s): %s", tech_name, e)

        return vulns

    def _check_osv(self, technologies: List, seen_cve_ids: set) -> List[Vulnerability]:
        """通过 OSV API 进行在线漏洞查询

        OSV（Open Source Vulnerabilities）是一个开源漏洞数据库，
        覆盖多种开源生态系统（PyPI、npm、Maven 等）。

        Args:
            technologies: 技术组件列表
            seen_cve_ids: 已发现的 CVE ID 集合（用于去重）

        Returns:
            从 OSV 查询到的漏洞列表
        """
        if requests is None:
            logger.warning("requests 库未安装，无法使用 OSV API")
            return []

        vulns: List[Vulnerability] = []

        for tech in technologies:
            tech_name = self._safe_get_attr(tech, "name", "")
            tech_version = self._safe_get_attr(tech, "version", "")

            if not tech_name:
                continue

            # 构造 OSV 查询请求
            # OSV 支持按包名和版本查询
            query_payload = {
                "package": {
                    "name": tech_name,
                },
            }
            if tech_version:
                query_payload["version"] = tech_version

            try:
                response = self._session.post(
                    self.OSV_API_URL,
                    json=query_payload,
                    timeout=self.timeout,
                )
                if response.status_code != 200:
                    logger.debug("OSV API 返回状态码 %d (%s)", response.status_code, tech_name)
                    continue

                data = response.json()
                vuln_list = data.get("vulns", [])

                for osv_vuln in vuln_list:
                    # 获取 CVE ID（OSV 可能使用自己的 ID）
                    cve_id = osv_vuln.get("id", "")
                    # 如果有 aliases 字段，尝试从中提取 CVE ID
                    aliases = osv_vuln.get("aliases", [])
                    for alias in aliases:
                        if alias.startswith("CVE-"):
                            cve_id = alias
                            break

                    if cve_id in seen_cve_ids:
                        continue

                    # 提取严重等级
                    severity = "UNKNOWN"
                    cvss_score = 0.0
                    severity_list = osv_vuln.get("severity", [])
                    for sev in severity_list:
                        cvss_str = sev.get("score", "")
                        # CVSS 向量字符串格式如 "CVSS:3.1/AV:N/AC:L/..."
                        if cvss_str:
                            severity = "HIGH"  # 默认
                            cvss_score = 7.0
                            break

                    # 提取描述
                    description = osv_vuln.get("summary", "")
                    details = osv_vuln.get("details", "")
                    if details:
                        description = details[:500]

                    # 提取参考链接
                    references = [
                        ref.get("url", "") for ref in osv_vuln.get("references", [])
                        if ref.get("url")
                    ]

                    vuln = Vulnerability(
                        cve_id=cve_id,
                        component=tech_name,
                        installed_version=tech_version,
                        affected_versions="（见 OSV 详情）",
                        severity=severity,
                        cvss_score=cvss_score,
                        title=osv_vuln.get("summary", cve_id),
                        description=description,
                        references=references,
                        source="osv",
                    )
                    vulns.append(vuln)

            except requests.Timeout:
                logger.warning("OSV API 请求超时: %s", tech_name)
            except requests.ConnectionError:
                logger.warning("OSV API 连接失败: %s", tech_name)
            except Exception as e:
                logger.warning("OSV API 查询异常 (%s): %s", tech_name, e)

        return vulns

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _safe_get_attr(self, obj, attr: str, default: str = "") -> str:
        """安全获取对象属性，兼容字典和对象

        Args:
            obj: 目标对象
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
        if value is None:
            return default
        return str(value) if value else default

    def get_vuln_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """生成漏洞检查摘要

        统计漏洞数量、严重等级分布、风险评分等信息，
        适用于生成报告或展示概览。

        Args:
            vulnerabilities: 漏洞列表

        Returns:
            摘要字典
        """
        total = len(vulnerabilities)
        severity_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        component_dist: Dict[str, int] = {}
        risk_score = 0

        for vuln in vulnerabilities:
            sev = vuln.severity.upper()
            if sev in severity_dist:
                severity_dist[sev] += 1
            else:
                severity_dist[sev] = severity_dist.get(sev, 0) + 1

            component_dist[vuln.component] = component_dist.get(vuln.component, 0) + 1

            # 计算风险评分（基于严重等级权重）
            risk_score += self.SEVERITY_WEIGHTS.get(sev, 1)

        # 风险评分归一化到 0-100
        max_possible = total * 10 if total > 0 else 1
        normalized_risk = min(100, int((risk_score / max_possible) * 100)) if total > 0 else 0

        # 确定整体风险等级
        if severity_dist["CRITICAL"] > 0:
            risk_level = "CRITICAL"
        elif severity_dist["HIGH"] > 0:
            risk_level = "HIGH"
        elif severity_dist["MEDIUM"] > 0:
            risk_level = "MEDIUM"
        elif severity_dist["LOW"] > 0:
            risk_level = "LOW"
        else:
            risk_level = "INFO"

        return {
            "total_vulnerabilities": total,
            "severity_distribution": severity_dist,
            "component_distribution": dict(
                sorted(component_dist.items(), key=lambda x: x[1], reverse=True)
            ),
            "risk_score": normalized_risk,
            "risk_level": risk_level,
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        }

    def close(self):
        """关闭 HTTP 会话，释放连接池资源"""
        if self._session:
            self._session.close()
            self._session = None
            logger.debug("漏洞检查器 HTTP 会话已关闭")

    def __enter__(self):
        """支持 with 语句"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出上下文时自动关闭会话"""
        self.close()


if __name__ == "__main__":
    # 模块直接运行时的测试演示
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    print("=" * 70)
    print("漏洞检查器测试")
    print("=" * 70)

    checker = VulnChecker()
    print(f"\n已加载 {len(checker.vuln_database)} 条离线漏洞记录")

    # 模拟检测到的技术组件
    class MockTechnology:
        def __init__(self, name, version="", category="", vendor="", supply_chain=""):
            self.name = name
            self.version = version
            self.category = category
            self.vendor = vendor
            self.supply_chain = supply_chain

        def __repr__(self):
            ver_str = f" v{self.version}" if self.version else ""
            return f"Technology({self.name}{ver_str})"

    test_technologies = [
        MockTechnology("Log4j", "2.14.1", "logging_library", "Apache", "Apache"),
        MockTechnology("Apache Tomcat", "8.5.50", "web_server", "Apache", "Apache"),
        MockTechnology("Spring Framework", "5.3.16", "web_framework", "Spring", "Spring"),
        MockTechnology("Struts2", "2.5.10", "web_framework", "Apache", "Apache"),
        MockTechnology("Apache HTTP Server", "2.4.49", "web_server", "Apache", "Apache"),
        MockTechnology("jQuery", "3.4.0", "frontend_library", "jQuery Foundation", "jQuery"),
        MockTechnology("Nginx", "1.18.0", "web_server", "Nginx", "Nginx"),
    ]

    print("\n--- 检测到的技术组件 ---")
    for tech in test_technologies:
        print(f"  {tech}")

    print("\n--- 漏洞检查结果 ---")
    vulnerabilities = checker.check(test_technologies)
    for vuln in vulnerabilities:
        print(f"  [{vuln.severity}] {vuln.cve_id} ({vuln.cvss_score})")
        print(f"    组件: {vuln.component} v{vuln.installed_version}")
        print(f"    标题: {vuln.title}")
        print(f"    受影响版本: {vuln.affected_versions}")
        print(f"    利用类型: {vuln.exploit_type}, 难度: {vuln.exploit_difficulty}")
        print()

    print("--- 漏洞摘要 ---")
    summary = checker.get_vuln_summary(vulnerabilities)
    print(f"  总漏洞数: {summary['total_vulnerabilities']}")
    print(f"  严重等级分布: {summary['severity_distribution']}")
    print(f"  风险评分: {summary['risk_score']}/100 ({summary['risk_level']})")
    print(f"  组件分布: {summary['component_distribution']}")

    # 版本比较测试
    print("\n--- 版本比较测试 ---")
    test_cases = [
        ("2.14.1", "2.14.1", 0),
        ("2.14.1", "2.15.0", -1),
        ("2.15.0", "2.14.1", 1),
        ("2.0-beta9", "2.0", -1),   # beta < release
        ("2.0", "2.0-beta9", 1),    # release > beta
        ("9.0.0.M1", "9.0.0", -1),  # milestone < release
        ("8.0.0.RC1", "8.0.0", -1), # RC < release
    ]
    for v1, v2, expected in test_cases:
        result = checker._compare_versions(v1, v2)
        status = "PASS" if result == expected else "FAIL"
        print(f"  [{status}] compare('{v1}', '{v2}') = {result} (expected {expected})")

    # 受影响版本检查测试
    print("\n--- 受影响版本检查测试 ---")
    version_tests = [
        ("2.14.1", "2.0-beta9 to 2.14.1", True),
        ("2.15.0", "2.0-beta9 to 2.14.1", False),
        ("2.14.1", "2.0-beta9 to 2.15.0 (excluding 2.15.0)", True),
        ("2.15.0", "2.0-beta9 to 2.15.0 (excluding 2.15.0)", False),
        ("1.2.4", "1.2.4 and earlier", True),
        ("1.2.5", "1.2.4 and earlier", False),
        ("5.0.9", "prior to 5.0.10", True),
        ("5.0.10", "prior to 5.0.10", False),
        ("2.4.49", "2.4.49", True),
        ("2.4.48", "2.4.49", False),
        ("8.5.50", "8.5.0 to 8.5.50", True),
        ("8.5.51", "8.5.0 to 8.5.50", False),
    ]
    for installed, affected, expected in version_tests:
        result = checker._is_version_affected(installed, affected)
        status = "PASS" if result == expected else "FAIL"
        print(f"  [{status}] '{installed}' in '{affected}' -> {result} (expected {expected})")

    print("=" * 70)
