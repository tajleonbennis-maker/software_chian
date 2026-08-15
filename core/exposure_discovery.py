"""Read-only frontend route discovery with redacted exposure findings."""
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List
from urllib.parse import urljoin, urlsplit

import requests


@dataclass
class ExposureFinding:
    url: str
    source: str
    status_code: int = 0
    content_type: str = ""
    publicly_accessible: bool = False
    sensitive_field_types: List[str] = field(default_factory=list)
    risk_level: str = "info"
    evidence: str = ""
    confirmed_secret: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "source": self.source,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "publicly_accessible": self.publicly_accessible,
            "sensitive_field_types": self.sensitive_field_types,
            "risk_level": self.risk_level,
            "evidence": self.evidence,
            "confirmed_secret": self.confirmed_secret,
        }


class FrontendExposureDiscovery:
    """Discover same-origin frontend routes without storing response bodies."""

    SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
    LINK_RE = re.compile(r'(?:href|router\.push|router\.replace)\s*(?:=|\()\s*["\']([^"\']+)', re.I)
    ROUTE_RE = re.compile(r'["\'](/(?:settings|admin|manage|config|dashboard|internal|debug|api)(?:/[A-Za-z0-9._~!$&()*+,;=:@%-]+)*)["\']', re.I)
    NEXT_MANIFEST_RE = re.compile(r'["\'](/[^"\']+)["\']\s*:', re.I)
    SENSITIVE_FIELDS = {
        "API 密钥": ("api key", "api_key", "apikey"),
        "访问令牌": ("access token", "access_token", "bearer token"),
        "密码": ("password", "passwd"),
        "私钥": ("private key", "private_key"),
        "云凭据": ("access_key", "secret_key", "aws_access_key"),
        "LLM 配置": ("base url", "model_catalog", "llm", "模型列表"),
    }

    def __init__(self, timeout: int = 10, max_scripts: int = 30,
                 max_routes: int = 100, max_bytes: int = 2_000_000):
        self.timeout = timeout
        self.max_scripts = max_scripts
        self.max_routes = max_routes
        self.max_bytes = max_bytes
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "SupplyChainSecurityAnalyzer/1.0 (read-only exposure discovery)"

    def discover(self, base_url: str) -> List[ExposureFinding]:
        base_url = self._normalize_base(base_url)
        if not base_url:
            return []
        homepage = self._get_text(base_url)
        if not homepage:
            return []
        routes: Dict[str, str] = {}
        self._collect_routes(homepage["text"], base_url, "首页", routes)

        scripts = [urljoin(base_url + "/", src) for src in self.SCRIPT_RE.findall(homepage["text"])]
        # Next.js manifests expose page routes even when links are not rendered.
        build_id = self._extract_next_build_id(homepage["text"])
        if build_id:
            scripts.extend([
                urljoin(base_url + "/", f"/_next/static/{build_id}/_buildManifest.js"),
                urljoin(base_url + "/", f"/_next/static/{build_id}/_ssgManifest.js"),
            ])

        seen_scripts = set()
        for script_url in scripts:
            if len(seen_scripts) >= self.max_scripts or script_url in seen_scripts:
                break
            if not self._same_origin(base_url, script_url):
                continue
            seen_scripts.add(script_url)
            script = self._get_text(script_url)
            if script:
                source = "Next.js Manifest" if "Manifest.js" in script_url else "JavaScript Bundle"
                self._collect_routes(script["text"], base_url, source, routes)

        findings = []
        for url, source in list(routes.items())[:self.max_routes]:
            response = self._get_text(url)
            if not response:
                continue
            fields = self._detect_sensitive_fields(response["text"])
            accessible = response["status_code"] == 200
            sensitive_route = bool(re.search(r"/(settings|admin|manage|config|internal|debug)(/|$)", urlsplit(url).path, re.I))
            # Field labels such as "password" or "api_key" are common in login
            # forms and settings UIs. They describe an attack surface, not a
            # credential leak. Actual values are handled by the dedicated secret
            # scanners and must never be inferred from labels alone.
            risk = "medium" if accessible and sensitive_route else "info"
            evidence = (
                "公开页面包含敏感字段名称（未发现凭据值）" if fields
                else "公开可达的管理/配置路由" if accessible and sensitive_route
                else "发现前端路由"
            )
            findings.append(ExposureFinding(
                url=url, source=source, status_code=response["status_code"],
                content_type=response["content_type"], publicly_accessible=accessible,
                sensitive_field_types=fields, risk_level=risk, evidence=evidence,
                confirmed_secret=False,
            ))
        return findings

    def close(self):
        self.session.close()

    def _get_text(self, url: str):
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True, stream=True)
            data = response.raw.read(self.max_bytes, decode_content=True)
            return {"text": data.decode(response.encoding or "utf-8", errors="replace"),
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type", "")}
        except requests.RequestException:
            return None

    def _collect_routes(self, text: str, base_url: str, source: str, routes: Dict[str, str]):
        candidates = list(self.LINK_RE.findall(text)) + list(self.ROUTE_RE.findall(text))
        if "Manifest" in source:
            candidates += self.NEXT_MANIFEST_RE.findall(text)
        for path in candidates:
            if path.startswith(("javascript:", "mailto:", "#", "//")):
                continue
            url = urljoin(base_url + "/", path)
            if self._same_origin(base_url, url) and urlsplit(url).path not in ("", "/"):
                routes.setdefault(url.split("#", 1)[0], source)

    def _detect_sensitive_fields(self, text: str) -> List[str]:
        lowered = text.lower()
        return [label for label, needles in self.SENSITIVE_FIELDS.items() if any(needle in lowered for needle in needles)]

    @staticmethod
    def _extract_next_build_id(text: str) -> str:
        match = re.search(r'["\']buildId["\']\s*:\s*["\']([^"\']+)', text)
        return match.group(1) if match else ""

    @staticmethod
    def _normalize_base(url: str) -> str:
        parsed = urlsplit(url if "://" in url else "http://" + url)
        return f"{parsed.scheme}://{parsed.netloc}" if parsed.hostname else ""

    @staticmethod
    def _same_origin(base_url: str, url: str) -> bool:
        base, target = urlsplit(base_url), urlsplit(url)
        return (base.scheme, base.hostname, base.port) == (target.scheme, target.hostname, target.port)
