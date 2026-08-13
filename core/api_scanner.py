"""
API 发现和安全分析器 - 发现资产上的 API 端点并进行安全分析

本模块负责对目标资产进行 API 端点发现和安全评估，包括：
1. API 端点发现：检查常见 API 路径（/api/、/v1/、/swagger-ui/、/graphql 等），
   并从 HTTP 响应头和 HTML 内容中提取 API 端点信息。
2. API 安全分析：评估认证机制、授权控制、注入风险、信息泄露、
   速率限制和加密传输等安全维度。

主要功能：
- discover(asset)：发现资产上的 API 端点
- analyze_security(asset, endpoints)：分析 API 安全问题
- scan(asset)：完整扫描，返回 API 端点列表
"""
import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, urlsplit

try:
    import requests
    from requests.exceptions import RequestException, Timeout, ConnectionError as ReqConnError
except ImportError:
    requests = None
    RequestException = Exception
    Timeout = Exception
    ReqConnError = Exception

logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    """API 端点数据模型

    存储单个 API 端点的信息，包括 URL、HTTP 方法、认证要求、
    响应状态码、内容类型和安全问题等。
    """
    url: str
    method: str  # GET, POST, PUT, DELETE, PATCH 等
    auth_required: bool = False  # 是否需要认证
    auth_type: str = ""  # 认证类型：Bearer, Basic, Cookie, APIKey, None
    params: List[str] = None  # 参数列表
    response_code: int = 0  # HTTP 响应状态码
    content_type: str = ""  # 响应内容类型
    security_issues: List[str] = None  # 安全问题列表
    risk_level: str = "info"  # info, low, medium, high, critical
    description: str = ""  # 端点描述

    def __post_init__(self):
        """初始化后处理：确保列表字段不为 None"""
        if self.params is None:
            self.params = []
        if self.security_issues is None:
            self.security_issues = []

    def add_issue(self, issue: str):
        """添加安全问题

        Args:
            issue: 安全问题描述
        """
        if issue and issue not in self.security_issues:
            self.security_issues.append(issue)
            # 根据安全问题严重程度更新风险等级
            self._update_risk_level(issue)

    def _update_risk_level(self, issue: str):
        """根据安全问题更新风险等级

        Args:
            issue: 安全问题描述
        """
        issue_lower = issue.lower()
        if any(kw in issue_lower for kw in ["rce", "远程代码执行", "sql 注入", "命令注入"]):
            if self.risk_level != "critical":
                self.risk_level = "critical"
        elif any(kw in issue_lower for kw in ["未授权", "认证缺失", "敏感信息泄露", "越权"]):
            if self.risk_level not in ("high", "critical"):
                self.risk_level = "high"
        elif any(kw in issue_lower for kw in ["xss", "跨站脚本", "无速率限制", "http 明文"]):
            if self.risk_level not in ("medium", "high", "critical"):
                self.risk_level = "medium"
        elif self.risk_level == "info":
            self.risk_level = "low"

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典，便于序列化"""
        return {
            "url": self.url,
            "method": self.method,
            "auth_required": self.auth_required,
            "auth_type": self.auth_type,
            "params": self.params,
            "response_code": self.response_code,
            "content_type": self.content_type,
            "security_issues": self.security_issues,
            "risk_level": self.risk_level,
            "description": self.description,
        }


@dataclass
class APISecurityReport:
    """API 安全报告数据模型

    汇总整个资产的 API 扫描结果，包括所有端点、安全问题、
    风险评分和摘要信息。
    """
    asset_url: str
    total_endpoints: int = 0
    endpoints: List[APIEndpoint] = field(default_factory=list)
    security_issues: List[Dict] = field(default_factory=list)  # 安全问题汇总
    risk_score: int = 0  # 0-100 风险评分
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典，便于序列化"""
        return {
            "asset_url": self.asset_url,
            "total_endpoints": self.total_endpoints,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "security_issues": self.security_issues,
            "risk_score": self.risk_score,
            "summary": self.summary,
        }


class APIScanner:
    """API 发现和安全分析器

    对目标资产进行 API 端点发现和安全评估。
    支持从常见 API 路径、HTTP 响应头和 HTML 内容中发现 API 端点，
    并对发现的端点进行多维度的安全分析。

    使用示例::

        scanner = APIScanner()
        endpoints = scanner.scan(asset)
        for ep in endpoints:
            print(f"[{ep.risk_level}] {ep.method} {ep.url}")
            for issue in ep.security_issues:
                print(f"  - {issue}")

        # 获取完整安全报告
        report = scanner.generate_report(asset, endpoints)
        print(f"风险评分: {report.risk_score}/100")
    """

    # 常见 API 路径列表
    COMMON_API_PATHS = [
        "/api/",
        "/api/v1/",
        "/api/v2/",
        "/api/v3/",
        "/v1/",
        "/v2/",
        "/v3/",
        "/rest/",
        "/rest/v1/",
        "/rest/api/",
        "/graphql",
        "/graphiql",
        "/swagger-ui/",
        "/swagger-ui.html",
        "/swagger-resources",
        "/api-docs",
        "/api-docs/",
        "/v2/api-docs",
        "/v3/api-docs",
        "/openapi.json",
        "/openapi.yaml",
        "/swagger.json",
        "/api/swagger.json",
        "/api/openapi.json",
        "/apispec_1.json",
        "/api/apispec_1.json",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/info",
        "/actuator/mappings",
        "/actuator/beans",
        "/actuator/configprops",
        "/actuator/heapdump",
        "/debug",
        "/debug/pprof",
        "/health",
        "/healthz",
        "/metrics",
        "/env",
        "/info",
        "/config",
        "/status",
        "/.well-known/openid-configuration",
        "/oauth/token",
        "/oauth/authorize",
        "/auth/login",
        "/auth/register",
        "/admin/api/",
        "/api/admin/",
        "/api/users",
        "/api/user",
        "/api/login",
        "/api/auth",
        "/api/config",
        "/api/settings",
    ]

    # 常见 HTTP 方法
    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

    # 默认请求超时时间（秒）
    DEFAULT_TIMEOUT = 10

    # 风险等级权重
    RISK_WEIGHTS = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 0,
    }

    # 敏感信息关键词
    SENSITIVE_KEYWORDS = [
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "access_key", "private_key", "credentials", "session",
        "jwt", "bearer", "authorization", "cookie",
        "internal", "debug", "stack", "trace", "exception",
        "sql", "query", "database", "connection_string",
        "username", "email", "phone", "ssn", "credit_card",
    ]

    # 调试信息特征
    DEBUG_PATTERNS = [
        r"stack\s*trace",
        r"at\s+[\w.$]+\([\w.]+:\d+\)",
        r"Exception\s+in\s+thread",
        r"Traceback\s+\(most\s+recent\s+call\s+last\)",
        r"PHP\s+(?:Fatal\s+error|Warning|Notice)",
        r"System\.Error|System\.Exception",
        r"debug\s*info",
        r"x-debug",
        r"server-info|server-status",
    ]

    # SQL 注入特征
    SQL_INJECTION_PATTERNS = [
        r"sql\s+syntax|sql\s+error|mysql_|you have an error in your sql",
        r"ora-\d{5}|oracle error|oracle driver",
        r"postgresql.*error|pg_query|psql",
        r"microsoft sql server|sqlserver|oledb error",
        r"sqlite3?\.operationalerror|sqlite error",
    ]

    # 常见 API 文档/规范响应中的端点提取正则
    SWAGGER_PATH_REGEX = re.compile(
        r'"(/[^"]*?)"\s*:', re.IGNORECASE
    )
    # HTML 中的 API URL 提取正则
    HTML_API_URL_REGEX = re.compile(
        r'(?:fetch|axios|XMLHttpRequest|\.open)\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)?["\']?\s*,?\s*["\']([^"\']+)["\']',
        re.IGNORECASE
    )
    # HTML script src 提取正则
    SCRIPT_SRC_REGEX = re.compile(
        r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE
    )
    # HTML form action 提取正则
    FORM_ACTION_REGEX = re.compile(
        r'<form[^>]+action=["\']([^"\']+)["\']', re.IGNORECASE
    )
    # HTML a href 提取正则
    LINK_HREF_REGEX = re.compile(
        r'<a[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE
    )

    def __init__(self,
                 timeout: int = DEFAULT_TIMEOUT,
                 verify_ssl: bool = False,
                 max_endpoints: int = 100,
                 user_agent: str = ""):
        """初始化 API 扫描器

        Args:
            timeout: HTTP 请求超时时间（秒），默认 10
            verify_ssl: 是否验证 SSL 证书，默认 False
            max_endpoints: 最大发现的端点数量，默认 100
            user_agent: 自定义 User-Agent，为空时使用默认值
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_endpoints = max_endpoints

        # 设置默认请求头
        self.default_headers = {
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }

        # 初始化 HTTP 会话
        self._session = None
        if requests is not None:
            self._session = requests.Session()
            self._session.headers.update(self.default_headers)

        logger.info("API 扫描器初始化完成 (timeout=%ds, max_endpoints=%d)",
                    self.timeout, self.max_endpoints)

    # ------------------------------------------------------------------
    # 资产 URL 构造
    # ------------------------------------------------------------------

    def _get_asset_url(self, asset) -> str:
        """从资产对象构造基础 URL

        优先使用 asset.url，如果为空则从 host、protocol、port 构造。

        Args:
            asset: 资产对象（Asset 或兼容对象）

        Returns:
            基础 URL 字符串，如 "http://example.com:8080"
        """
        # 优先使用已有的 URL
        url = self._safe_get_attr(asset, "url", "")
        if url:
            # 确保 URL 包含协议
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "http://" + url
            return url.rstrip("/")

        # 从 host、protocol、port 构造
        host = self._safe_get_attr(asset, "host", "")
        protocol = self._safe_get_attr(asset, "protocol", "http")
        port = self._safe_get_attr(asset, "port", 0)

        if not host:
            return ""

        # 规范化协议
        if not protocol:
            protocol = "http"

        # 构造 URL
        try:
            port_int = int(port) if port else 0
        except (ValueError, TypeError):
            port_int = 0

        if port_int and port_int not in (80, 443):
            return f"{protocol}://{host}:{port_int}"
        return f"{protocol}://{host}"

    # ------------------------------------------------------------------
    # API 端点发现
    # ------------------------------------------------------------------

    def discover(self, asset) -> List[APIEndpoint]:
        """发现资产上的 API 端点

        通过以下方式发现 API 端点：
        1. 检查常见 API 路径（/api/、/v1/、/swagger-ui/、/graphql 等）
        2. 从 HTTP 响应头中发现 API 端点线索
        3. 从 HTML 内容中提取 API 端点（script src、form action、fetch 调用等）

        Args:
            asset: 资产对象（Asset 或兼容对象）

        Returns:
            发现的 API 端点列表
        """
        if requests is None:
            logger.error("requests 库未安装，无法进行 API 发现")
            return []

        base_url = self._get_asset_url(asset)
        if not base_url:
            logger.warning("无法从资产中获取有效 URL")
            return []

        logger.info("开始 API 端点发现: %s", base_url)

        endpoints: List[APIEndpoint] = []
        seen_urls: set = set()

        # 第一步：访问首页，获取基本信息和 HTML 内容
        homepage_response = self._make_request(base_url, method="GET")
        homepage_body = ""
        homepage_headers = {}
        if homepage_response:
            homepage_body = homepage_response.get("body", "")
            homepage_headers = homepage_response.get("headers", {})

        # 第二步：从首页响应中发现 API 端点
        if homepage_body or homepage_headers:
            discovered = self._discover_from_response(
                base_url, homepage_body, homepage_headers
            )
            for ep in discovered:
                if ep.url not in seen_urls:
                    endpoints.append(ep)
                    seen_urls.add(ep.url)

        # 第三步：检查常见 API 路径
        for path in self.COMMON_API_PATHS:
            if len(endpoints) >= self.max_endpoints:
                logger.info("已达到最大端点数量限制 (%d)", self.max_endpoints)
                break

            full_url = urljoin(base_url + "/", path.lstrip("/"))
            if full_url in seen_urls:
                continue

            response = self._make_request(full_url, method="GET")
            if response and response.get("status_code", 0) not in (0, 404, 405):
                # 排除明确的 404/405 响应
                endpoint = APIEndpoint(
                    url=full_url,
                    method="GET",
                    response_code=response.get("status_code", 0),
                    content_type=response.get("content_type", ""),
                    description=self._describe_endpoint(path),
                )

                # 解析 OpenAPI/Swagger 规范，提取更多端点
                if "openapi" in path or "swagger" in path or "api-docs" in path:
                    extra_endpoints = self._parse_openapi_spec(
                        base_url, response.get("body", "")
                    )
                    for extra_ep in extra_endpoints:
                        if extra_ep.url not in seen_urls and len(endpoints) < self.max_endpoints:
                            endpoints.append(extra_ep)
                            seen_urls.add(extra_ep.url)

                endpoints.append(endpoint)
                seen_urls.add(full_url)
                logger.debug("发现 API 端点: %s (%d)", full_url, endpoint.response_code)

        # 第四步：对已发现的端点尝试 OPTIONS 方法，发现支持的 HTTP 方法
        for ep in endpoints[:20]:  # 限制 OPTIONS 请求的数量
            response = self._make_request(ep.url, method="OPTIONS")
            if response:
                allow_header = response.get("headers", {}).get("Allow", "")
                if allow_header:
                    ep.description += f" [Allow: {allow_header}]"

        logger.info("API 端点发现完成，共发现 %d 个端点", len(endpoints))
        return endpoints

    def _discover_from_response(self, base_url: str,
                                body: str,
                                headers: Dict[str, str]) -> List[APIEndpoint]:
        """从 HTTP 响应中发现 API 端点

        从响应头和 HTML 内容中提取 API 端点信息。

        Args:
            base_url: 基础 URL
            body: 响应正文
            headers: 响应头字典

        Returns:
            发现的 API 端点列表
        """
        endpoints: List[APIEndpoint] = []

        # 从响应头中发现线索
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            # Link 头可能包含 API 端点
            if header_lower == "link":
                # 解析 Link 头，格式如: <https://api.example.com/users>; rel="users"
                links = re.findall(r'<([^>]+)>', header_value)
                for link in links:
                    full_url = urljoin(base_url, link)
                    if self._is_api_url(full_url):
                        endpoints.append(APIEndpoint(
                            url=full_url,
                            method="GET",
                            description="从 Link 响应头发现",
                        ))
            # Location 头
            if header_lower == "location":
                full_url = urljoin(base_url, header_value)
                if self._is_api_url(full_url):
                    endpoints.append(APIEndpoint(
                        url=full_url,
                        method="GET",
                        description="从 Location 响应头发现",
                    ))
            # X-Powered-By 或 Server 头可能暗示 API 框架
            if header_lower in ("x-powered-by", "server"):
                if any(fw in header_value.lower() for fw in
                       ["express", "django", "flask", "spring", "rails", "laravel", "asp.net"]):
                    # 框架特定路径推断
                    framework = header_value.lower()
                    if "express" in framework:
                        endpoints.append(APIEndpoint(
                            url=urljoin(base_url + "/", "api/"),
                            method="GET",
                            description="Express 框架推断",
                        ))

        # 从 HTML 内容中发现 API 端点
        if body:
            # 提取 fetch/axios/XMLHttpRequest 调用中的 URL
            for match in self.HTML_API_URL_REGEX.finditer(body):
                url = match.group(1)
                full_url = urljoin(base_url, url)
                if self._is_api_url(full_url):
                    endpoints.append(APIEndpoint(
                        url=full_url,
                        method="GET",
                        description="从 JavaScript fetch 调用发现",
                    ))

            # 提取 script src 中的 API 相关 URL
            for match in self.SCRIPT_SRC_REGEX.finditer(body):
                src = match.group(1)
                full_url = urljoin(base_url, src)
                if self._is_api_url(full_url):
                    endpoints.append(APIEndpoint(
                        url=full_url,
                        method="GET",
                        description="从 script src 发现",
                    ))

            # 提取 form action 中的 API URL
            for match in self.FORM_ACTION_REGEX.finditer(body):
                action = match.group(1)
                full_url = urljoin(base_url, action)
                if self._is_api_url(full_url):
                    endpoints.append(APIEndpoint(
                        url=full_url,
                        method="POST",
                        description="从 form action 发现",
                    ))

            # 提取 a href 中的 API URL
            for match in self.LINK_HREF_REGEX.finditer(body):
                href = match.group(1)
                full_url = urljoin(base_url, href)
                if self._is_api_url(full_url):
                    endpoints.append(APIEndpoint(
                        url=full_url,
                        method="GET",
                        description="从 a href 发现",
                    ))

            # 提取内联 JavaScript 中的 API 路径
            # 匹配 "/api/xxx" 或 "/v1/xxx" 格式的路径
            api_paths = re.findall(r'["\']((?:/api/|/v\d+/|/rest/)[^"\'\s]+)["\']', body)
            for path in api_paths:
                full_url = urljoin(base_url, path)
                if self._is_api_url(full_url):
                    endpoints.append(APIEndpoint(
                        url=full_url,
                        method="GET",
                        description="从内联 JavaScript 发现",
                    ))

        # 去重
        seen = set()
        unique_endpoints = []
        for ep in endpoints:
            if ep.url not in seen:
                seen.add(ep.url)
                unique_endpoints.append(ep)

        return unique_endpoints

    def _is_api_url(self, url: str) -> bool:
        """判断 URL 是否为 API 端点

        根据路径特征判断 URL 是否为 API 端点。

        Args:
            url: 待判断的 URL

        Returns:
            是否为 API 端点
        """
        if not url:
            return False
        parsed = urlsplit(url)
        path = parsed.path.lower()
        api_indicators = [
            "/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql",
            "/swagger", "/openapi", "/api-docs", "/actuator",
            "/oauth", "/auth",
        ]
        return any(ind in path for ind in api_indicators)

    def _parse_openapi_spec(self, base_url: str, body: str) -> List[APIEndpoint]:
        """解析 OpenAPI/Swagger 规范，提取 API 端点

        从 OpenAPI/Swagger JSON 规范中提取所有 API 路径和方法。

        Args:
            base_url: 基础 URL
            body: OpenAPI/Swagger 规范 JSON 字符串

        Returns:
            从规范中提取的 API 端点列表
        """
        endpoints: List[APIEndpoint] = []

        if not body:
            return endpoints

        import json
        try:
            spec = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            logger.debug("OpenAPI 规范 JSON 解析失败")
            return endpoints

        # OpenAPI 3.x 使用 "paths"，Swagger 2.x 也使用 "paths"
        paths = spec.get("paths", {})
        if not isinstance(paths, dict):
            return endpoints

        # 获取基础路径
        base_path = spec.get("basePath", "")
        if base_path:
            base_url = base_url.rstrip("/") + base_path

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                method_upper = method.upper()
                if method_upper not in self.HTTP_METHODS:
                    continue

                full_url = urljoin(base_url + "/", path.lstrip("/"))
                description = details.get("summary", "") or details.get("description", "")

                # 提取参数列表
                params = []
                for param in details.get("parameters", []):
                    param_name = param.get("name", "")
                    if param_name:
                        params.append(f"{param_name}({param.get('in', 'query')})")

                endpoints.append(APIEndpoint(
                    url=full_url,
                    method=method_upper,
                    params=params,
                    description=f"OpenAPI 规范: {description}" if description else "从 OpenAPI 规范发现",
                ))

        logger.debug("从 OpenAPI 规范中提取 %d 个端点", len(endpoints))
        return endpoints

    def _describe_endpoint(self, path: str) -> str:
        """根据路径描述端点

        Args:
            path: API 路径

        Returns:
            端点描述
        """
        path_lower = path.lower()
        descriptions = {
            "/graphql": "GraphQL API 端点",
            "/swagger-ui": "Swagger UI 文档界面",
            "/swagger-ui.html": "Swagger UI 文档界面",
            "/api-docs": "API 文档（Swagger）",
            "/openapi.json": "OpenAPI 规范文档",
            "/openapi.yaml": "OpenAPI 规范文档（YAML）",
            "/actuator": "Spring Boot Actuator 端点",
            "/actuator/health": "健康检查端点",
            "/actuator/env": "环境变量端点（敏感）",
            "/actuator/beans": "Bean 列表端点（敏感）",
            "/actuator/heapdump": "堆转储端点（高危）",
            "/actuator/mappings": "URL 映射端点",
            "/debug": "调试端点",
            "/debug/pprof": "Go pprof 性能分析端点",
            "/metrics": "指标端点",
            "/env": "环境端点（敏感）",
            "/health": "健康检查端点",
            "/oauth/token": "OAuth 令牌端点",
            "/oauth/authorize": "OAuth 授权端点",
        }
        for key, desc in descriptions.items():
            if key in path_lower:
                return desc
        if "/api/" in path_lower:
            return "REST API 端点"
        if "/v1/" in path_lower or "/v2/" in path_lower:
            return "版本化 API 端点"
        return "API 端点"

    # ------------------------------------------------------------------
    # API 安全分析
    # ------------------------------------------------------------------

    def analyze_security(self, asset, endpoints: List[APIEndpoint]) -> List[APIEndpoint]:
        """分析 API 安全问题

        对发现的 API 端点进行多维度安全分析：
        1. 认证检查：是否需要认证、认证方式是否安全
        2. 授权检查：是否有越权风险
        3. 注入检查：SQL注入、命令注入、XSS
        4. 信息泄露：是否暴露调试信息、错误详情、敏感字段
        5. 速率限制：是否有速率限制
        6. HTTPS：是否使用加密传输

        Args:
            asset: 资产对象
            endpoints: 待分析的 API 端点列表

        Returns:
            分析后的端点列表（每个端点的 security_issues 和 risk_level 已更新）
        """
        if not endpoints:
            return []

        base_url = self._get_asset_url(asset)
        logger.info("开始 API 安全分析: %s (%d 个端点)", base_url, len(endpoints))

        # 检查 HTTPS 使用情况
        is_https = base_url.startswith("https://")

        for endpoint in endpoints:
            # 1. HTTPS 检查
            if not is_https and not endpoint.url.startswith("https://"):
                endpoint.add_issue("HTTP 明文传输 - API 端点未使用 HTTPS 加密，存在数据窃听风险")

            # 发送测试请求进行分析
            response = self._make_request(endpoint.url, method=endpoint.method)

            if response:
                # 2. 认证检查
                self._check_authentication(endpoint, response)

                # 3. 信息泄露检查
                self._check_info_disclosure(endpoint, response)

                # 4. 注入检查
                self._check_injection(endpoint, response)

                # 5. 速率限制检查
                self._check_rate_limiting(endpoint, response)

                # 6. CORS 配置检查
                self._check_cors(endpoint, response)

            # 7. 特定端点风险检查
            self._check_endpoint_specific_risks(endpoint)

        logger.info("API 安全分析完成")
        return endpoints

    def _check_authentication(self, endpoint: APIEndpoint, response: Dict):
        """检查认证机制

        分析响应判断端点是否需要认证以及认证方式是否安全。

        Args:
            endpoint: API 端点对象
            response: HTTP 响应字典
        """
        status_code = response.get("status_code", 0)
        headers = response.get("headers", {})

        # 检查响应状态码判断是否需要认证
        if status_code == 401:
            endpoint.auth_required = True
            # 检查认证方式
            www_authenticate = headers.get("WWW-Authenticate", "").lower()
            if "bearer" in www_authenticate:
                endpoint.auth_type = "Bearer"
            elif "basic" in www_authenticate:
                endpoint.auth_type = "Basic"
            elif "digest" in www_authenticate:
                endpoint.auth_type = "Digest"
            else:
                endpoint.auth_type = "Unknown"
        elif status_code == 403:
            endpoint.auth_required = True
            endpoint.auth_type = "Role-based"
        elif status_code == 200:
            # 200 响应可能意味着不需要认证（未授权访问）
            # 对于敏感端点，这是安全问题
            if any(sensitive in endpoint.url.lower() for sensitive in
                   ["/admin", "/actuator/env", "/actuator/beans", "/actuator/heapdump",
                    "/debug", "/config", "/env", "/metrics"]):
                endpoint.auth_required = False
                endpoint.add_issue("未授权访问 - 敏感端点无需认证即可访问，存在信息泄露风险")

        # 检查是否使用不安全的认证方式
        if endpoint.auth_type == "Basic":
            # Basic 认证如果通过 HTTP 传输则不安全
            if not endpoint.url.startswith("https://"):
                endpoint.add_issue("不安全的认证传输 - Basic 认证通过 HTTP 明文传输，存在凭证窃取风险")

    def _check_info_disclosure(self, endpoint: APIEndpoint, response: Dict):
        """检查信息泄露

        检查响应中是否包含调试信息、错误详情、敏感字段等。

        Args:
            endpoint: API 端点对象
            response: HTTP 响应字典
        """
        body = response.get("body", "")
        headers = response.get("headers", {})
        content_type = response.get("content_type", "")

        # 检查调试信息头
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            if "debug" in header_lower or "x-debug" in header_lower:
                endpoint.add_issue(f"调试信息泄露 - 响应头中包含调试信息: {header_name}")
            if header_lower in ("x-powered-by", "server") and header_value:
                endpoint.add_issue(f"服务器信息泄露 - {header_name} 头暴露服务器信息: {header_value}")
            if header_lower == "x-aspnet-version" or header_lower == "x-aspnetmvc-version":
                endpoint.add_issue(f"框架版本泄露 - {header_name} 头暴露框架版本: {header_value}")

        # 检查响应体中的调试信息和错误详情
        if body:
            body_lower = body.lower()

            # 检查堆栈跟踪
            for pattern in self.DEBUG_PATTERNS:
                if re.search(pattern, body_lower):
                    endpoint.add_issue("调试信息泄露 - 响应体中包含堆栈跟踪或调试信息")
                    break

            # 检查敏感字段
            found_sensitive = []
            for keyword in self.SENSITIVE_KEYWORDS:
                if keyword in body_lower:
                    found_sensitive.append(keyword)
            if found_sensitive:
                # 只报告前 5 个，避免过多
                endpoint.add_issue(
                    f"敏感信息泄露 - 响应体中包含敏感字段: {', '.join(found_sensitive[:5])}"
                )

            # 检查 API 密钥/令牌格式
            token_patterns = [
                (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
                (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", "JWT Token"),
                (r"ghp_[a-zA-Z0-9]{36}", "GitHub Token"),
                (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
                (r"xox[baprs]-[a-zA-Z0-9-]+", "Slack Token"),
            ]
            for pattern, token_type in token_patterns:
                if re.search(pattern, body):
                    endpoint.add_issue(f"凭证泄露 - 响应体中包含疑似 {token_type}")
                    break

    def _check_injection(self, endpoint: APIEndpoint, response: Dict):
        """检查注入风险

        通过分析响应判断是否存在 SQL 注入、命令注入或 XSS 等风险。

        Args:
            endpoint: API 端点对象
            response: HTTP 响应字典
        """
        body = response.get("body", "")
        status_code = response.get("status_code", 0)
        content_type = response.get("content_type", "")

        if not body:
            return

        body_lower = body.lower()

        # SQL 注入错误特征检测
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, body_lower):
                endpoint.add_issue("SQL 注入风险 - 响应中包含数据库错误信息，可能存在 SQL 注入漏洞")
                break

        # 命令注入特征检测
        command_patterns = [
            r"root:.*:0:0:",  # /etc/passwd 内容
            r"uid=\d+\(.*\) gid=\d+",  # id 命令输出
            r"total \d+\s",  # ls 命令输出
            r"drwx[-rwx]{8}",  # 文件权限
            r"indows\\System32",  # Windows 路径
        ]
        for pattern in command_patterns:
            if re.search(pattern, body):
                endpoint.add_issue("命令注入风险 - 响应中包含系统命令输出特征，可能存在命令注入漏洞")
                break

        # XSS 风险检测：检查用户输入是否未转义地反映在响应中
        if "text/html" in content_type:
            # 检查是否存在未转义的 HTML 标签注入点
            if re.search(r"<script[^>]*>.*?</script>", body, re.IGNORECASE | re.DOTALL):
                # 如果响应是 HTML 且包含 script 标签，检查是否是反射的
                # 这里只做被动检测，不主动注入
                pass

        # 检查错误信息中是否反映了用户输入
        if status_code == 500:
            endpoint.add_issue("服务端错误 - 端点返回 500 错误，可能存在未处理的异常或注入点")

    def _check_rate_limiting(self, endpoint: APIEndpoint, response: Dict):
        """检查速率限制

        检查响应头中是否包含速率限制相关的头信息。

        Args:
            endpoint: API 端点对象
            response: HTTP 响应字典
        """
        headers = response.get("headers", {})

        # 速率限制相关头
        rate_limit_headers = [
            "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
            "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
            "x-rate-limit-limit", "x-rate-limit-remaining", "x-rate-limit-reset",
            "retry-after",
        ]

        has_rate_limit = False
        for header_name in headers:
            if header_name.lower() in rate_limit_headers:
                has_rate_limit = True
                break

        if not has_rate_limit:
            endpoint.add_issue("无速率限制 - API 端点未设置速率限制，存在暴力破解和 DoS 风险")

    def _check_cors(self, endpoint: APIEndpoint, response: Dict):
        """检查 CORS 配置

        检查跨域资源共享配置是否安全。

        Args:
            endpoint: API 端点对象
            response: HTTP 响应字典
        """
        headers = response.get("headers", {})

        # 检查 CORS 头
        cors_origin = ""
        for header_name, header_value in headers.items():
            if header_name.lower() == "access-control-allow-origin":
                cors_origin = header_value
            if header_name.lower() == "access-control-allow-credentials":
                if header_value.lower() == "true" and cors_origin == "*":
                    endpoint.add_issue(
                        "CORS 配置不安全 - 允许任意来源 (*) 且允许携带凭证 (credentials)，"
                        "存在跨域数据窃取风险"
                    )

        # 如果允许任意来源
        if cors_origin == "*":
            endpoint.add_issue("CORS 配置宽松 - 允许任意来源 (*) 跨域访问 API")

    def _check_endpoint_specific_risks(self, endpoint: APIEndpoint):
        """检查特定端点的安全风险

        根据端点路径特征检查特定的安全风险。

        Args:
            endpoint: API 端点对象
        """
        url_lower = endpoint.url.lower()

        # GraphQL 端点特有风险
        if "graphql" in url_lower:
            endpoint.add_issue("GraphQL 端点 - 需检查查询深度限制、批量查询限制和内省是否关闭")

        # Actuator 端点特有风险
        if "/actuator" in url_lower:
            if any(sensitive in url_lower for sensitive in
                   ["/env", "/beans", "/heapdump", "/configprops", "/mappings", "/threaddump"]):
                endpoint.add_issue("Actuator 敏感端点 - 暴露服务器内部信息，应限制访问或禁用")

        # Swagger/OpenAPI 文档风险
        if any(doc in url_lower for doc in ["/swagger", "/api-docs", "/openapi"]):
            endpoint.add_issue("API 文档暴露 - API 规范文档对外可访问，可能泄露 API 结构和参数信息")

        # 调试端点风险
        if any(debug in url_lower for debug in ["/debug", "/pprof", "/trace"]):
            endpoint.add_issue("调试端点暴露 - 调试端点对外可访问，存在敏感信息泄露风险")

        # OAuth 端点风险
        if "/oauth/token" in url_lower:
            endpoint.add_issue("OAuth 令牌端点 - 需检查 client_secret 验证、令牌有效期和刷新令牌安全")

    # ------------------------------------------------------------------
    # 完整扫描
    # ------------------------------------------------------------------

    def scan(self, asset) -> List[APIEndpoint]:
        """完整 API 扫描

        执行完整的 API 发现和安全分析流程：
        1. 发现 API 端点
        2. 对发现的端点进行安全分析

        Args:
            asset: 资产对象

        Returns:
            分析后的 API 端点列表（包含安全问题信息）

        示例::

            scanner = APIScanner()
            endpoints = scanner.scan(asset)
            for ep in endpoints:
                print(f"[{ep.risk_level}] {ep.method} {ep.url}")
        """
        logger.info("开始 API 完整扫描")

        # 第一步：发现 API 端点
        endpoints = self.discover(asset)

        if not endpoints:
            logger.info("未发现 API 端点")
            return []

        # 第二步：安全分析
        endpoints = self.analyze_security(asset, endpoints)

        # 按风险等级排序
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        endpoints.sort(key=lambda e: risk_order.get(e.risk_level, 5))

        logger.info("API 完整扫描完成，共发现 %d 个端点", len(endpoints))
        return endpoints

    # ------------------------------------------------------------------
    # 报告生成
    # ------------------------------------------------------------------

    def generate_report(self, asset, endpoints: List[APIEndpoint]) -> APISecurityReport:
        """生成 API 安全报告

        汇总扫描结果，生成包含风险评分和摘要的完整安全报告。

        Args:
            asset: 资产对象
            endpoints: API 端点列表

        Returns:
            APISecurityReport 安全报告对象
        """
        base_url = self._get_asset_url(asset)

        # 统计安全问题
        all_issues: List[Dict] = []
        for ep in endpoints:
            for issue in ep.security_issues:
                all_issues.append({
                    "url": ep.url,
                    "method": ep.method,
                    "issue": issue,
                    "risk_level": ep.risk_level,
                })

        # 计算风险评分
        risk_score = self._calculate_risk_score(endpoints)

        # 生成摘要
        summary = self._generate_summary(base_url, endpoints, all_issues)

        report = APISecurityReport(
            asset_url=base_url,
            total_endpoints=len(endpoints),
            endpoints=endpoints,
            security_issues=all_issues,
            risk_score=risk_score,
            summary=summary,
        )

        logger.info("API 安全报告生成完成 (风险评分: %d/100)", risk_score)
        return report

    def _calculate_risk_score(self, endpoints: List[APIEndpoint]) -> int:
        """计算整体风险评分

        基于各端点的风险等级和安全问题数量计算 0-100 的风险评分。

        Args:
            endpoints: API 端点列表

        Returns:
            风险评分 (0-100)
        """
        if not endpoints:
            return 0

        total_score = 0
        for ep in endpoints:
            # 基于风险等级的分数
            level_score = self.RISK_WEIGHTS.get(ep.risk_level, 0)
            # 安全问题数量加权
            issue_count = len(ep.security_issues)
            total_score += level_score + min(issue_count * 2, 10)

        # 归一化到 0-100
        max_possible = len(endpoints) * 35  # 每个端点最大 25+10=35
        if max_possible > 0:
            normalized = min(100, int((total_score / max_possible) * 100))
        else:
            normalized = 0

        return normalized

    def _generate_summary(self, base_url: str,
                          endpoints: List[APIEndpoint],
                          issues: List[Dict]) -> str:
        """生成扫描摘要

        Args:
            base_url: 资产 URL
            endpoints: API 端点列表
            issues: 安全问题列表

        Returns:
            摘要字符串
        """
        if not endpoints:
            return f"未在 {base_url} 上发现 API 端点。"

        # 统计风险等级分布
        risk_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for ep in endpoints:
            risk_dist[ep.risk_level] = risk_dist.get(ep.risk_level, 0) + 1

        # 统计认证情况
        no_auth_count = sum(1 for ep in endpoints if not ep.auth_required and ep.response_code == 200)

        # 生成摘要
        lines = [
            f"API 安全扫描摘要 - {base_url}",
            f"共发现 {len(endpoints)} 个 API 端点，{len(issues)} 个安全问题。",
            f"风险等级分布: 严重({risk_dist['critical']}) 高危({risk_dist['high']}) "
            f"中危({risk_dist['medium']}) 低危({risk_dist['low']}) 信息({risk_dist['info']})。",
        ]

        if no_auth_count > 0:
            lines.append(f"警告: {no_auth_count} 个端点无需认证即可访问。")

        if risk_dist["critical"] > 0:
            lines.append(f"紧急: 发现 {risk_dist['critical']} 个严重风险端点，建议立即修复。")
        elif risk_dist["high"] > 0:
            lines.append(f"注意: 发现 {risk_dist['high']} 个高风险端点，建议尽快修复。")

        # 列出关键安全问题
        critical_issues = [i for i in issues if i["risk_level"] == "critical"]
        if critical_issues:
            lines.append("关键安全问题:")
            for issue in critical_issues[:5]:
                lines.append(f"  - [{issue['method']}] {issue['url']}: {issue['issue']}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # HTTP 请求辅助
    # ------------------------------------------------------------------

    def _make_request(self, url: str, method: str = "GET",
                      data: str = None, headers: Dict = None) -> Optional[Dict]:
        """发送 HTTP 请求

        封装 requests 库的请求操作，提供统一的错误处理和响应格式。

        Args:
            url: 请求 URL
            method: HTTP 方法
            data: 请求体数据
            headers: 额外请求头

        Returns:
            响应字典，包含 status_code, headers, body, content_type 等。
            请求失败返回 None。
        """
        if self._session is None:
            logger.error("requests 库未安装或会话未初始化")
            return None

        if not url:
            return None

        method = method.upper()
        request_headers = {}
        if headers:
            request_headers.update(headers)

        try:
            if method == "GET":
                resp = self._session.get(
                    url, timeout=self.timeout, verify=self.verify_ssl,
                    allow_redirects=True, headers=request_headers,
                )
            elif method == "POST":
                resp = self._session.post(
                    url, data=data, timeout=self.timeout, verify=self.verify_ssl,
                    allow_redirects=True, headers=request_headers,
                )
            elif method == "OPTIONS":
                resp = self._session.options(
                    url, timeout=self.timeout, verify=self.verify_ssl,
                    allow_redirects=True, headers=request_headers,
                )
            elif method == "PUT":
                resp = self._session.put(
                    url, data=data, timeout=self.timeout, verify=self.verify_ssl,
                    allow_redirects=True, headers=request_headers,
                )
            elif method == "DELETE":
                resp = self._session.delete(
                    url, timeout=self.timeout, verify=self.verify_ssl,
                    allow_redirects=True, headers=request_headers,
                )
            elif method == "PATCH":
                resp = self._session.patch(
                    url, data=data, timeout=self.timeout, verify=self.verify_ssl,
                    allow_redirects=True, headers=request_headers,
                )
            else:
                logger.warning("不支持的 HTTP 方法: %s", method)
                return None

            # 解析响应
            try:
                body = resp.text
            except Exception:
                body = ""

            # 限制 body 大小，避免处理超大响应
            if len(body) > 100000:
                body = body[:100000]

            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": body,
                "content_type": resp.headers.get("Content-Type", ""),
            }

        except Timeout:
            logger.debug("请求超时: %s %s", method, url)
        except ReqConnError:
            logger.debug("连接失败: %s %s", method, url)
        except RequestException as e:
            logger.debug("请求异常: %s %s - %s", method, url, e)
        except Exception as e:
            logger.debug("未知请求异常: %s %s - %s", method, url, e)

        return None

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

    def close(self):
        """关闭 HTTP 会话，释放连接池资源"""
        if self._session:
            self._session.close()
            self._session = None
            logger.debug("API 扫描器 HTTP 会话已关闭")

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
    print("API 发现和安全分析器测试")
    print("=" * 70)

    scanner = APIScanner(timeout=5)
    print(f"\nAPI 扫描器已初始化 (超时: {scanner.timeout}s)")
    print(f"常见 API 路径数量: {len(scanner.COMMON_API_PATHS)}")

    # 模拟资产对象
    class MockAsset:
        def __init__(self):
            self.host = "example.com"
            self.ip = "93.184.216.34"
            self.port = 443
            self.title = "Example API"
            self.server = "nginx/1.18.0"
            self.header = (
                "Server: nginx/1.18.0\n"
                "Content-Type: text/html\n"
                "X-Powered-By: Express"
            )
            self.banner = ""
            self.protocol = "https"
            self.country = "US"
            self.city = ""
            self.domain = "example.com"
            self.url = "https://example.com"
            self.icp = ""

    # 测试 URL 构造
    print("\n--- URL 构造测试 ---")
    asset = MockAsset()
    base_url = scanner._get_asset_url(asset)
    print(f"  资产 URL: {base_url}")

    # 测试 API URL 判断
    print("\n--- API URL 判断测试 ---")
    test_urls = [
        ("https://example.com/api/users", True),
        ("https://example.com/v1/products", True),
        ("https://example.com/graphql", True),
        ("https://example.com/swagger-ui/", True),
        ("https://example.com/static/image.png", False),
        ("https://example.com/about", False),
    ]
    for url, expected in test_urls:
        result = scanner._is_api_url(url)
        status = "PASS" if result == expected else "FAIL"
        print(f"  [{status}] is_api_url('{url}') = {result} (expected {expected})")

    # 测试端点描述
    print("\n--- 端点描述测试 ---")
    test_paths = [
        "/api/v1/users",
        "/graphql",
        "/swagger-ui.html",
        "/actuator/env",
        "/actuator/heapdump",
        "/oauth/token",
    ]
    for path in test_paths:
        desc = scanner._describe_endpoint(path)
        print(f"  {path}: {desc}")

    # 测试 OpenAPI 规范解析
    print("\n--- OpenAPI 规范解析测试 ---")
    mock_openapi = """
    {
        "openapi": "3.0.0",
        "paths": {
            "/api/users": {
                "get": {
                    "summary": "获取用户列表",
                    "parameters": [
                        {"name": "page", "in": "query"},
                        {"name": "limit", "in": "query"}
                    ]
                },
                "post": {
                    "summary": "创建用户"
                }
            },
            "/api/users/{id}": {
                "get": {
                    "summary": "获取用户详情",
                    "parameters": [
                        {"name": "id", "in": "path"}
                    ]
                },
                "delete": {
                    "summary": "删除用户"
                }
            }
        }
    }
    """
    parsed_endpoints = scanner._parse_openapi_spec("https://example.com", mock_openapi)
    print(f"  从 OpenAPI 规范中解析出 {len(parsed_endpoints)} 个端点:")
    for ep in parsed_endpoints:
        params_str = f", params={ep.params}" if ep.params else ""
        print(f"    [{ep.method}] {ep.url}{params_str} - {ep.description}")

    # 测试安全分析（模拟响应）
    print("\n--- 安全分析测试 ---")
    test_endpoint = APIEndpoint(
        url="http://example.com/api/users",
        method="GET",
        response_code=200,
    )

    # 模拟响应
    mock_response = {
        "status_code": 200,
        "headers": {
            "Content-Type": "application/json",
            "Server": "Apache/2.4.49",
            "X-Powered-By": "PHP/7.4.3",
        },
        "body": '{"users": [{"id": 1, "username": "admin", "password": "123456", "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}]}',
        "content_type": "application/json",
    }

    # 执行各项安全检查
    scanner._check_authentication(test_endpoint, mock_response)
    scanner._check_info_disclosure(test_endpoint, mock_response)
    scanner._check_injection(test_endpoint, mock_response)
    scanner._check_rate_limiting(test_endpoint, mock_response)
    scanner._check_cors(test_endpoint, mock_response)
    scanner._check_endpoint_specific_risks(test_endpoint)

    # 手动添加 HTTP 明文传输问题
    test_endpoint.add_issue("HTTP 明文传输 - API 端点未使用 HTTPS 加密，存在数据窃听风险")

    print(f"  端点: {test_endpoint.method} {test_endpoint.url}")
    print(f"  响应码: {test_endpoint.response_code}")
    print(f"  风险等级: {test_endpoint.risk_level}")
    print(f"  安全问题 ({len(test_endpoint.security_issues)} 个):")
    for issue in test_endpoint.security_issues:
        print(f"    - {issue}")

    # 测试报告生成
    print("\n--- 报告生成测试 ---")
    test_endpoints = [
        APIEndpoint(
            url="http://example.com/api/users",
            method="GET",
            response_code=200,
            risk_level="high",
            security_issues=["未授权访问", "敏感信息泄露", "无速率限制"],
        ),
        APIEndpoint(
            url="http://example.com/api/login",
            method="POST",
            response_code=200,
            risk_level="medium",
            security_issues=["无速率限制"],
        ),
        APIEndpoint(
            url="http://example.com/actuator/env",
            method="GET",
            response_code=200,
            risk_level="critical",
            security_issues=["未授权访问 - 敏感端点", "Actuator 敏感端点暴露"],
        ),
    ]

    report = scanner.generate_report(asset, test_endpoints)
    print(f"  资产 URL: {report.asset_url}")
    print(f"  端点总数: {report.total_endpoints}")
    print(f"  安全问题数: {len(report.security_issues)}")
    print(f"  风险评分: {report.risk_score}/100")
    print(f"  摘要:\n{report.summary}")

    # 测试风险评分计算
    print("\n--- 风险评分计算测试 ---")
    score = scanner._calculate_risk_score(test_endpoints)
    print(f"  3 个端点的风险评分: {score}/100")

    scanner.close()
    print("\n" + "=" * 70)
