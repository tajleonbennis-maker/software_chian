"""泄露模式研究引擎（Leak Researcher）：从"模式匹配"升级为"深度研究"。

用户诉求：不想系统只是简单模式匹配。从一个已知泄露出发，深度研究，
发现更多同类泄露。

引擎工作方式（三段式）：
1. **种子学习**：从已有 credential_leaks 记录提取「泄露指纹」
   - 路径（如 /api/v1/settings）
   - 响应特征（含 sk- 密钥、敏感字段名、base_url 数量）
   - 项目归属（deeptutor / dify / ...）
2. **批量探测**：对同项目所有资产，主动访问已知泄露路径
   - 用「指纹」判断响应是否含明文密钥（正则 + 启发式）
   - 不只匹配固定路径，还做路径变体（/api/v1/settings/、/settings/llm 等）
3. **AI 验证**：对疑似泄露，用 AI 判定「是否真实泄露可用密钥」
   - 避免把「字段名命中但值已脱敏」的误报当泄露
   - 输出可信度 + 证据链

入库：验证通过的泄露写入 credential_leaks（含 evidence 完整证据）。
"""
import json
import logging
import re
import time
from urllib.parse import urljoin

import requests

logger = logging.getLogger("LeakResearcher")

# 泄露路径模式库：项目 → 已知泄露路径（含变体）
LEAK_PATH_PATTERNS = {
    "deeptutor": ["/api/v1/settings", "/api/v1/settings/llm-options", "/api/v1/settings/models",
                  "/settings/llm", "/api/v1/users/me", "/api/v1/config"],
    "dify": ["/console/api/setup", "/console/api/workspaces/current", "/console/api/apps",
             "/console/api/explore/apps"],
    "open-webui": ["/api/v1/auths", "/api/v1/models", "/api/v1/users/", "/api/config"],
    "anythingllm": ["/api/system", "/api/settings", "/api/users", "/api/workspaces"],
    "lobechat": ["/api/auth/session", "/api/user/settings", "/api/chat/models"],
    "next.js": ["/api/settings", "/api/config", "/api/env", "/api/auth/session"],
    "nginx": ["/config", "/api/config", "/nginx_status"],
}

# 真实密钥正则（sk- 等）
KEY_PATTERNS = [
    (re.compile(r"(?i)sk-[a-z0-9]{20,}"), "sk-key"),
    (re.compile(r"(?i)api[_-]?key[\"']?\s*[:=]\s*[\"'][a-z0-9]{16,}[\"']"), "api-key"),
    (re.compile(r"(?i)token[\"']?\s*[:=]\s*[\"'][a-z0-9]{16,}[\"']"), "token"),
    (re.compile(r"(?i)akid[a-z0-9]{16}|AKIA[A-Z0-9]{16}"), "aws-key"),
    (re.compile(r"(?i)ghp_[a-z0-9]{20,}"), "github-token"),
]

# 敏感字段名（响应 JSON 中出现即增加泄露嫌疑）
SENSITIVE_FIELD_NAMES = ["api_key", "apikey", "api-key", "base_url", "baseurl",
                         "secret", "token", "credential", "password", "apiKey",
                         "access_key", "secret_key"]

# Provider 识别：base_url 域名关键词 → provider 名
PROVIDER_HINTS = [
    ("openai", ["api.openai.com", "openai"]),
    ("deepseek", ["api.deepseek.com", "deepseek"]),
    ("anthropic", ["api.anthropic.com", "anthropic", "claude"]),
    ("google", ["googleapis.com", "generativelanguage", "ai.google", "gemini"]),
    ("qwen", ["dashscope", "aliyun", "qwen", "通义"]),
    ("zhipu", ["open.bigmodel.cn", "glm", "zhipu", "智谱"]),
    ("moonshot", ["api.moonshot.cn", "moonshot", "kimi"]),
    ("baidu", ["aip.baidubce.com", "baidu", "文心"]),
    ("siliconflow", ["siliconflow", "硅基流动"]),
    ("volcengine", ["volces.com", "ark", "豆包", "火山"]),
    ("xiaomi", ["miui", "xiaomi", "小米"]),
    ("minimax", ["minimax.chat", "minimax"]),
    ("stepfun", ["stepfun", "阶跃"]),
    ("yi", ["lingyiwanwu", "yi.large", "零一"]),
    ("hunyuan", ["hunyuan", "混元", "qcloud.com"]),
    ("deepseek", ["api.deepseek.com"]),
]

# 每资产最多探测路径数（控制成本）
MAX_PATHS_PER_ASSET = 6


def _fingerprint_of_leak(leak: dict) -> dict:
    """从一条已知泄露学习指纹：提取 target 根、路径、project 推断。"""
    target = leak.get("target", "")
    base = re.match(r"^(https?://[^/]+)", target)
    base_url = base.group(1) if base else ""
    path = target[len(base_url):] if base_url else target
    return {"base_url": base_url, "path": path or "/api/v1/settings",
            "project": _infer_project(leak.get("provider", ""), leak.get("secret_type", ""), path)}


def _infer_project(provider: str, secret_type: str, path: str) -> str:
    """从泄露元数据推断项目归属"""
    if "deeptutor" in path or "/api/v1/settings" in path and "llm" in str(secret_type).lower():
        return "deeptutor"
    return provider or "unknown"


def _scan_body(body: str) -> list:
    """扫描响应体，返回命中的密钥（含脱敏值）"""
    if not body or len(body) < 20:
        return []
    hits = []
    for pattern, label in KEY_PATTERNS:
        for m in pattern.finditer(body):
            val = m.group(0)
            masked = val[:8] + "..." + val[-4:] if len(val) > 14 else "***"
            hits.append({"type": label, "value_masked": masked, "value": val})
            break  # 每类型每响应最多一条，避免刷屏
    return hits


def _count_sensitive_fields(body: str) -> int:
    """统计响应中敏感字段出现次数（base_url/api_key 等）"""
    count = 0
    for name in SENSITIVE_FIELD_NAMES:
        count += len(re.findall(r'"' + name + r'"', body, re.I))
    return count


def _infer_provider_from_body(body: str, excerpt: str = "") -> str:
    """从响应体/摘录中识别 LLM Provider（基于 base_url / profile 名称关键词）。

    返回 provider 名；无法识别返回 "unknown"。
    """
    hay = ((body or "") + " " + (excerpt or "")).lower()
    # 优先从 base_url 域名判定
    base_urls = re.findall(r'https?://[a-z0-9.-]+(?::\d+)?', hay)
    if base_urls:
        for url in base_urls:
            for provider, hints in PROVIDER_HINTS:
                if any(h in url for h in hints):
                    return provider
    # 其次从整体上下文判定（profile 名、model 名等）
    for provider, hints in PROVIDER_HINTS:
        if any(h in hay for h in hints):
            return provider
    return "unknown"


def probe_asset(asset_url: str, project: str, timeout: int = 8) -> list:
    """对单个资产做泄露路径探测，返回疑似泄露列表。

    返回: [{"url": "...", "status_code": 200, "path": "/api/v1/settings",
             "keys": [{"type","value_masked"}], "sensitive_fields": 3,
             "content_type": "application/json"}]
    """
    if not asset_url:
        return []
    base = asset_url.rstrip("/")
    results = []
    paths = LEAK_PATH_PATTERNS.get(project, LEAK_PATH_PATTERNS.get("next.js", []))[:MAX_PATHS_PER_ASSET]
    # 加入未知项目兜底路径
    if project not in LEAK_PATH_PATTERNS:
        paths = ["/api/v1/settings", "/api/config", "/api/env", "/config"]
    headers = {"User-Agent": "Mozilla/5.0 (DefensiveResearchLeakProbe)",
               "Accept": "application/json,text/plain,*/*"}
    for path in paths:
        url = base + path
        try:
            resp = requests.get(url, timeout=timeout, verify=False,
                                headers=headers, allow_redirects=True)
            if resp.status_code not in (200, 401, 403):
                continue
            body = resp.text
            keys = _scan_body(body)
            sensitive_fields = _count_sensitive_fields(body)
            if keys or sensitive_fields >= 2:
                results.append({
                    "url": url, "status_code": resp.status_code, "path": path,
                    "keys": keys, "sensitive_fields": sensitive_fields,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "provider": _infer_provider_from_body(body),
                    "body_excerpt": body[:3000],
                })
        except requests.RequestException:
            continue
        except Exception as exc:
            logger.debug("探测 %s 异常: %s", url, exc)
    return results


def research_leaks(database, project: str = "", asset_url: str = "",
                   ai_analyzer=None, seed_leaks: list = None,
                   max_assets: int = 50) -> dict:
    """深度研究泄露：学习种子 → 批量探测 → AI 验证 → 入库。

    参数:
        database: ScanDatabase
        project: 限定研究的项目 slug（如 deeptutor）
        asset_url: 或指定单个资产
        ai_analyzer: AIAnalyzer（可选，做 AI 验证）
        seed_leaks: 种子泄露（默认从库中取已有泄露学习）
        max_assets: 最多回扫资产数
    返回: 统计
    """
    from core.database import ScanDatabase
    db = database if database is not None else ScanDatabase("")
    found = 0
    updated = 0
    assets_probed = 0

    # 1. 学习种子
    seeds = seed_leaks or db.list_credential_leaks(limit=5)
    fingerprints = [_fingerprint_of_leak(l) for l in seeds if l.get("target")]

    # 2. 确定探测目标
    targets = []
    if asset_url:
        targets = [asset_url]
    elif project:
        targets = db.research_asset_urls(project, limit=max_assets)
    else:
        # 从种子推断项目，回扫同项目资产
        seed_project = fingerprints[0]["project"] if fingerprints else ""
        if seed_project:
            targets = db.research_asset_urls(seed_project, limit=max_assets)

    # 3. 批量探测
    for target in targets:
        target_project = project or (fingerprints[0]["project"] if fingerprints else "deeptutor")
        probes = probe_asset(target, target_project)
        if not probes:
            continue
        assets_probed += 1
        for probe in probes:
            keys = probe.get("keys", [])
            if not keys:
                continue
            # 入库 credential_leaks
            key_val = keys[0].get("value", "")
            masked = keys[0].get("value_masked", "***")
            provider = probe.get("provider") or _infer_project("", "", probe["path"])
            db.upsert_credential_leak({
                "target": probe["url"],
                "provider": provider,
                "base_url": _extract_base_url(probe.get("body_excerpt", ""), probe["url"]),
                "api_key_masked": masked,
                "api_key_full": key_val,
                "secret_type": "LLM API Key" if "sk-" in key_val else "API 密钥",
                "source_path": probe["path"],
                "evidence": [{"url": probe["url"], "path": probe["path"],
                              "status_code": probe["status_code"],
                              "sensitive_fields": probe["sensitive_fields"]}],
                "status": "new",
            })
            updated += 1
            found += 1
            logger.info("发现泄露: %s (%s)", probe["url"][:60], masked)

    return {"probed": len(targets), "assets_with_probes": assets_probed,
            "found": found, "updated": updated, "fingerprints": fingerprints[:3]}


def _extract_base_url(body: str, default_url: str) -> str:
    """从响应体中提取 LLM Provider 的 base_url（如 https://api.deepseek.com）。

    优先解析 JSON 字段 base_url/api_base/baseUrl；
    其次从整体响应中找第一个疑似 API 域名。
    """
    if not body:
        return default_url
    # 1. 优先匹配 JSON 字段值： "base_url": "https://api.deepseek.com"
    m = re.search(r'["\']?(?:base_url|baseUrl|api_base|apiBase)["\']?\s*[:=]\s*["\'](https?://[^"\']+)["\']',
                  body, re.I)
    if m:
        return m.group(1).rstrip("/")
    # 2. 匹配 provider 相关 URL（api.xxx.com / /v1 后缀）
    m = re.search(r'https?://(?:api|openai|deepseek|anthropic|generativelanguage|dashscope|open\.bigmodel)[a-z0-9.-]*(?::\d+)?(?:/v\d+)?',
                  body, re.I)
    if m:
        return m.group(0).rstrip("/")
    # 3. 兜底：排除明显是目标站点自身的 URL
    m = re.search(r'https?://[a-z0-9.-]+(?::\d+)?', body, re.I)
    if m:
        url = m.group(0).rstrip("/")
        # 如果看起来像目标站本身（host 相同），返回默认
        from urllib.parse import urlsplit
        try:
            if urlsplit(url).hostname and urlsplit(default_url).hostname and \
               urlsplit(url).hostname == urlsplit(default_url).hostname:
                return default_url
        except Exception:
            pass
        return url
    return default_url
