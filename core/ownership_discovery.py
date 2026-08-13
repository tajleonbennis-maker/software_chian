"""Passive organization/contact clues for responsible disclosure."""
import html
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List
from urllib.parse import urljoin, urlsplit

import requests


@dataclass
class OwnershipProfile:
    site_title: str = ""
    organization: str = ""
    copyright_notice: str = ""
    icp: str = ""
    security_contacts: List[str] = field(default_factory=list)
    public_emails: List[str] = field(default_factory=list)
    public_phones: List[str] = field(default_factory=list)
    source_urls: List[str] = field(default_factory=list)
    confidence: str = "low"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "site_title": self.site_title,
            "organization": self.organization,
            "copyright_notice": self.copyright_notice,
            "icp": self.icp,
            "security_contacts": self.security_contacts,
            "public_emails": self.public_emails,
            "public_phones": self.public_phones,
            "source_urls": self.source_urls,
            "confidence": self.confidence,
        }


class OwnershipDiscovery:
    """Collect only public organizational contacts from a small page set."""

    ROLE_EMAIL_RE = re.compile(r'\b(?:security|abuse|support|admin|contact|help|service|webmaster)@[A-Z0-9.-]+\.[A-Z]{2,}\b', re.I)
    PHONE_RE = re.compile(r'(?<!\d)(?:\+?86[- ]?)?(?:400[- ]?\d{3}[- ]?\d{4}|800[- ]?\d{3}[- ]?\d{4}|0\d{2,3}[- ]?\d{7,8})(?!\d)')
    ICP_RE = re.compile(r'(?:京|津|冀|晋|蒙|辽|吉|黑|沪|苏|浙|皖|闽|赣|鲁|豫|鄂|湘|粤|桂|琼|渝|川|贵|云|藏|陕|甘|青|宁|新)ICP备\d+号?(?:-\d+)?', re.I)
    TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)
    OG_SITE_RE = re.compile(r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']+)', re.I)
    COPYRIGHT_RE = re.compile(r'((?:©|&copy;|copyright)\s*(?:\d{4}(?:\s*[-–]\s*\d{4})?)?\s*[^<\n]{2,120})', re.I)
    JSON_LD_RE = re.compile(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.I | re.S)

    def __init__(self, timeout: int = 10, max_bytes: int = 1_000_000):
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "SupplyChainSecurityAnalyzer/1.0 (responsible disclosure contact discovery)"

    def discover(self, base_url: str) -> OwnershipProfile:
        base = self._base(base_url)
        profile = OwnershipProfile()
        if not base:
            return profile
        pages = [
            (base, "home"),
            (urljoin(base + "/", ".well-known/security.txt"), "security"),
            (urljoin(base + "/", "security.txt"), "security"),
            (urljoin(base + "/", "contact"), "contact"),
            (urljoin(base + "/", "about"), "about"),
        ]
        for url, kind in pages:
            response = self._get(url)
            if not response or response["status_code"] != 200:
                continue
            text = response["text"]
            profile.source_urls.append(response["url"])
            if kind == "home":
                profile.site_title = self._clean(self._first(self.TITLE_RE, text))
                profile.organization = self._organization(text) or self._clean(self._first(self.OG_SITE_RE, text))
                copyright_text = self._clean(self._first(self.COPYRIGHT_RE, text))
                # Keep the attribution, discard trailing contact/user content.
                copyright_text = re.split(r'\s+(?:联系|电话|邮箱|用户|手机|tel|email)\b', copyright_text, maxsplit=1, flags=re.I)[0]
                copyright_text = re.sub(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b.*$', '', copyright_text, flags=re.I)
                profile.copyright_notice = copyright_text.strip()
                icp = self.ICP_RE.search(text)
                profile.icp = icp.group(0) if icp else ""
            role_emails = self.ROLE_EMAIL_RE.findall(text)
            if kind == "security":
                profile.security_contacts.extend(role_emails)
                profile.security_contacts.extend(re.findall(r'(?im)^Contact:\s*(?:mailto:)?([^\s]+)', text))
            elif kind in ("home", "contact", "about"):
                profile.public_emails.extend(role_emails)
                # Only business switchboard/service phone patterns, never mobile numbers.
                profile.public_phones.extend(self.PHONE_RE.findall(text))

        for field_name in ("security_contacts", "public_emails", "public_phones", "source_urls"):
            setattr(profile, field_name, list(dict.fromkeys(getattr(profile, field_name)))[:20])
        signals = sum(bool(value) for value in (
            profile.organization, profile.copyright_notice, profile.icp,
            profile.security_contacts, profile.public_emails, profile.public_phones,
        ))
        profile.confidence = "high" if profile.security_contacts or signals >= 4 else "medium" if signals >= 2 else "low"
        return profile

    def close(self):
        self.session.close()

    def _get(self, url: str):
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True, stream=True)
            if not self._same_site(url, response.url):
                return None
            data = response.raw.read(self.max_bytes, decode_content=True)
            return {"text": data.decode(response.encoding or "utf-8", errors="replace"),
                    "status_code": response.status_code, "url": response.url}
        except requests.RequestException:
            return None

    def _organization(self, text: str) -> str:
        for raw in self.JSON_LD_RE.findall(text):
            try:
                value = json.loads(html.unescape(raw))
                items = value if isinstance(value, list) else [value]
                for item in items:
                    if isinstance(item, dict) and item.get("@type") in ("Organization", "Corporation"):
                        return self._clean(str(item.get("name", "")))
            except (ValueError, TypeError):
                continue
        return ""

    @staticmethod
    def _first(pattern, text):
        match = pattern.search(text)
        return match.group(1) if match else ""

    @staticmethod
    def _clean(value: str) -> str:
        return re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', value))).strip()[:200]

    @staticmethod
    def _base(url: str) -> str:
        parsed = urlsplit(url if "://" in url else "http://" + url)
        return f"{parsed.scheme}://{parsed.netloc}" if parsed.hostname else ""

    @staticmethod
    def _same_site(original: str, final: str) -> bool:
        left, right = urlsplit(original), urlsplit(final)
        return left.hostname == right.hostname or (left.hostname or "").endswith("." + (right.hostname or "")) or (right.hostname or "").endswith("." + (left.hostname or ""))
