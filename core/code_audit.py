"""代码审计 v1（Issue #10 目标 1/6）：clone 热门开源项目 → 定位敏感代码 → 联网 AI 审计。

聚焦目标：回答「为什么这个项目会被攻击 / 有什么问题」。
不修改、不执行项目代码，仅静态分析 + AI 研判（防御性用途）。
"""
import json
import logging
import os
import re
import shutil
import subprocess
import time

logger = logging.getLogger("CodeAudit")

# 安全敏感文件定位模式（按风险类型分组）
SENSITIVE_PATTERNS = {
    "api_auth": [r"api.*\.py$", r"auth.*\.py$", r"auth.*\.js$", r"routes/.*\.py$", r"controllers/.*\.py$",
                r"endpoints?/.*\.py$", r"schemas?/.*\.py$"],
    "config_secrets": [r"config.*\.(py|js|ts|env)", r"settings.*\.(py|js)", r"\.env", r".*_config\.py$"],
    "db_queries": [r"db.*\.py$", r"repository.*\.py$", r"models?/.*\.py$", r"schema.*\.sql",
                   r"migrations?/.*\.py$"],
    "file_upload": [r"upload.*\.(py|js)$", r"file.*\.(py|js)$"],
    "http_client": [r"client.*\.py$", r"http.*\.py$", r"request.*\.py$", r"service[s]?/.*\.py$"],
    "middleware": [r"middleware.*\.py$", r"decorators?/.*\.py$", r"security.*\.py$"],
}

# 危险代码模式（静态标记）
DANGER_PATTERNS = [
    (r"os\.system\(|subprocess\.(call|run|Popen)\(", "命令执行"),
    (r"eval\(|exec\(", "代码执行"),
    (r"pickle\.loads|yaml\.load\([^)]*Loader=.*[^S]afe", "反序列化"),
    (r"SELECT.*FROM.*WHERE.*[+]|f\".*SELECT.*\{\}|f'.*SELECT.*\{\}'", "SQL 注入"),
    (r"render_template_string|mark_safe|dangerouslySetInnerHTML", "模板注入/XSS"),
    (r"super\(\)\.save\(.*validate=False", "跳过校验"),
    (r"allow_redirects=False|verify=False", "忽略证书校验"),
    (r"debug\s*=\s*True|DEBUG\s*=\s*True", "调试模式"),
    (r"Session\(\)|session\.get\(|urllib\.request", "直接发起请求"),
    (r"request\.(get|post|put|delete)\([^)]*verify\s*=\s*False", "关闭TLS校验"),
    (r"@app\.(get|post|put|delete)\(", "API路由"),
    (r"jwt\.decode\(|create_token|generate_token", "Token处理"),
    (r"(?i)(api[_-]?key|secret|token|password|credential)\s*[=:]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']", "硬编码密钥"),
    (r"(?i)sk-[A-Za-z0-9]{16,}|AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{20}|Bearer\s+[A-Za-z0-9]{20,}", "泄露密钥值"),
]


# 分组优先级：安全敏感度高的先扫
GROUP_PRIORITY = ["api_auth", "db_queries", "middleware", "file_upload", "http_client", "config_secrets"]


def _find_files(repo_dir: str, limit: int = 200) -> list:
    """扫描 repo 中感兴趣的源码文件，按安全敏感度优先级排序"""
    found = []
    for root, dirs, files in os.walk(repo_dir):
        # 跳过无关目录
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv",
                                                "__pycache__", "dist", "build", ".next",
                                                "static", "public", "tests", "test", "docs",
                                                ".github", "web", "ui", "frontend", "scripts",
                                                ".claude", ".vscode", "docker", "deploy")]
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, repo_dir)
            for group, patterns in SENSITIVE_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, rel):
                        found.append((group, rel, fpath))
                        break
                else:
                    continue
                break
    # 按分组优先级排序，每组内稳定
    found.sort(key=lambda x: (GROUP_PRIORITY.index(x[0]) if x[0] in GROUP_PRIORITY else 99, x[1]))
    return found[:limit]


def _scan_danger(path: str, max_size: int = 150_000) -> list:
    """对单文件做静态危险模式扫描"""
    try:
        if os.path.getsize(path) > max_size:
            return []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return []
    hits = []
    for pat, label in DANGER_PATTERNS:
        for m in re.finditer(pat, content, re.IGNORECASE):
            line_no = content[:m.start()].count("\n") + 1
            line = content.split("\n")[line_no - 1].strip()[:100]
            hits.append({"pattern": label, "line": line_no, "snippet": line})
            break  # 每个模式每文件只报一次
    return hits


def clone_repo(url: str, work_dir: str, timeout: int = 120) -> str:
    """浅克隆仓库到工作目录，返回仓库路径。已存在且完整则复用（避免重复下载大仓库）。"""
    name = url.rstrip("/").split("/")[-1].replace(".git", "")
    target = os.path.join(work_dir, name)
    os.makedirs(work_dir, exist_ok=True)
    # 完整仓库判定：.git 存在 + 工作树非空（排除中断 clone 留下的空壳）
    is_complete = (os.path.isdir(os.path.join(target, ".git"))
                   and any(os.scandir(target)))
    if is_complete:
        logger.info("仓库已存在且完整，复用: %s", target)
        return target
    if os.path.isdir(target):
        shutil.rmtree(target, ignore_errors=True)
    subprocess.run(["git", "clone", "--depth", "1", url, target],
                   capture_output=True, timeout=timeout, check=True)
    return target


def audit_repo(repo_url: str, work_dir: str, ai_analyzer=None,
               max_files: int = 80) -> dict:
    """审计一个仓库：结构 → 静态扫描 → AI 研判高风险文件

    返回审计报告（不执行任何项目代码，防御性静态分析）。
    """
    started = time.time()
    repo_path = clone_repo(repo_url, work_dir)
    files = _find_files(repo_path, limit=max_files)
    logger.info("代码审计 %s: 定位 %d 个敏感文件", repo_url, len(files))

    findings = []
    for group, rel, fpath in files:
        danger = _scan_danger(fpath)
        if danger:
            findings.append({"group": group, "file": rel, "dangers": danger[:5],
                             "danger_count": len(danger)})

    # 汇总统计
    danger_by_type = {}
    for f in findings:
        for d in f["dangers"]:
            danger_by_type[d["pattern"]] = danger_by_type.get(d["pattern"], 0) + 1
    top_dangers = sorted(danger_by_type.items(), key=lambda kv: -kv[1])[:10]

    # AI 研判（如果配置了）
    ai_report = None
    if ai_analyzer and findings:
        try:
            ai_report = _ai_review(ai_analyzer, repo_url, findings, danger_by_type)
        except Exception as exc:
            logger.warning("AI 代码审计失败: %s", exc)
            ai_report = {"error": str(exc)}

    return {
        "repo": repo_url,
        "repo_path": repo_path,
        "files_scanned": len(files),
        "files_with_danger": len(findings),
        "danger_by_type": dict(top_dangers),
        "findings": findings[:15],
        "ai_report": ai_report,
        "duration_seconds": round(time.time() - started, 1),
    }


def _ai_review(ai_analyzer, repo_url: str, findings: list,
               danger_by_type: dict) -> dict:
    """用 AI 研判审计发现，输出风险结论"""
    summary_lines = []
    for f in findings[:8]:
        dangers = ", ".join(d["pattern"] for d in f["dangers"][:3])
        summary_lines.append(f"- {f['file']}: {dangers}（{f['danger_count']} 处）")
    prompt = (
        "你是防御性开源安全代码审计员。基于以下静态扫描结果，判断该开源项目的真实安全风险。"
        "不要给出攻击步骤或利用代码，只做风险研判与修复建议。"
        "用中文返回 JSON：{\"risk_level\":\"low|medium|high|critical\","
        "\"top_risks\":[{\"risk\":\"...\",\"file\":\"...\",\"suggestion\":\"...\"}],"
        "\"summary\":\"一句话结论\"}"
    )
    content = f"项目: {repo_url}\n静态扫描发现（按类型统计）: {json.dumps(danger_by_type, ensure_ascii=False)}\n\n关键文件:\n" + "\n".join(summary_lines)
    # 推理模型（deepseek-v4-pro）reasoning 会占用大量 token，需放大上限保证 content 有空间
    raw = ai_analyzer._call_api(prompt, content, 3000)
    return ai_analyzer._extract_json(raw)
