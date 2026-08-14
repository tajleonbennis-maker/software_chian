"""Obsidian 大脑记忆库生成器（Brain Vault）。

把大脑记忆（研究项目、泄露发现、安全经验、洞察结论）落成标准 Obsidian Vault：
- 每个项目一张笔记（frontmatter + 双链）
- 每个泄露一条笔记（含验证状态）
- 经验库（来自 insight / code_audits / threat_intel）
- MOC 索引页 + 每日活动日志

生成的目录结构：
    brain_vault/
    ├── 00-索引/000-大脑MOC.md        ← 总入口
    ├── 01-项目/{slug}.md
    ├── 02-泄露/{leak_id}.md
    ├── 03-经验/安全经验-{主题}.md
    ├── 04-日志/2026-08-14.md
    └── .obsidian/（最小配置，可直接被 Obsidian 打开）
"""
import json
import logging
import os
import re
import time
from datetime import datetime

logger = logging.getLogger("BrainVault")

VAULT_NAME = "大脑记忆库"
VAULT_SUBDIR = "brain_vault"


def _safe_name(name: str) -> str:
    """文件名安全化：去掉路径非法字符"""
    name = re.sub(r'[\\/:*?"<>|]', "-", name).strip()
    return name[:80]


def _fmt_ts(ts) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "-"


def _frontmatter(fields: dict) -> str:
    lines = ["---"]
    for k, v in fields.items():
        if isinstance(v, bool):
            lines.append(f"{k}: {'true' if v else 'false'}")
        elif isinstance(v, (int, float)):
            lines.append(f"{k}: {v}")
        else:
            lines.append(f'{k}: "{str(v).replace(chr(34), chr(39))}"')
    lines.append("---")
    return "\n".join(lines)


def generate_vault(database, vault_root: str = None) -> dict:
    """生成完整 Obsidian Vault，返回统计。

    Args:
        database: ScanDatabase 实例
        vault_root: 目标根目录（默认 <data>/brain_vault）
    """
    if vault_root is None:
        vault_root = os.path.join(os.path.dirname(database.path), VAULT_SUBDIR)
    os.makedirs(vault_root, exist_ok=True)
    stats = {"projects": 0, "leaks": 0, "experience": 0, "logs": 0}

    # 目录
    dirs = ["00-索引", "01-项目", "02-泄露", "03-经验", "04-日志", ".obsidian"]
    for d in dirs:
        os.makedirs(os.path.join(vault_root, d), exist_ok=True)

    # .obsidian 最小配置（让 Obsidian 识别为 vault）
    app_json = os.path.join(vault_root, ".obsidian", "app.json")
    with open(app_json, "w") as f:
        json.dump({"alwaysUpdateLinks": True, "attachmentFolderPath": "99-附件"}, f)
    if not os.path.isdir(os.path.join(vault_root, "99-附件")):
        os.makedirs(os.path.join(vault_root, "99-附件"), exist_ok=True)

    project_links = []
    leak_links = []

    # ============ 1. 项目笔记 ============
    projects = database.research_overview().get("projects", [])
    for p in projects:
        slug = p.get("slug", "")
        if not slug:
            continue
        insight = p.get("insight") or {}
        fm = _frontmatter({
            "title": p.get("name", slug), "slug": slug,
            "category": p.get("category", ""), "priority": p.get("priority", 0),
            "repository": p.get("repository", ""), "license": p.get("license", ""),
            "upstream": p.get("upstream", ""), "enabled": bool(p.get("enabled")),
            "tags": "大脑记忆/项目",
        })
        body = [fm, f"# {p.get('name', slug)}", ""]
        body.append(f"> 仓库：{p.get('repository','')}  ")
        body.append(f"> 类别：{p.get('category','')} · 优先级 {p.get('priority', 0)}  ")
        body.append(f"> 上游：{p.get('upstream','')}")
        body.append("")
        body.append("## 📊 研究现状")
        metrics = p.get("metrics") or {}
        body.append(f"- 候选资产：{metrics.get('candidate_count', '?')}")
        body.append(f"- 已确认部署：{metrics.get('confirmed_count', '?')}")
        body.append(f"- 被拒绝：{metrics.get('rejected_count', '?')}")
        body.append("")
        if insight:
            body.append("## 🧠 洞察")
            body.append(f"**{insight.get('headline','')}**")
            if insight.get("summary"):
                body.append("")
                body.append(insight["summary"])
            body.append("")
        if p.get("rationale"):
            body.append("## 🎯 选题理由")
            body.append(p["rationale"])
            body.append("")
        body.append("## 🔗 相关")
        body.append(f"- 相关泄露：[[02-泄露/DeepTutor 泄露案例]]（如有）")
        body.append("")
        fname = _safe_name(f"{p.get('name', slug)}")
        path = os.path.join(vault_root, "01-项目", f"{fname}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(body))
        project_links.append(f"- [[{fname}|{p.get('name', slug)}]]")
        stats["projects"] += 1

    # ============ 2. 泄露笔记 ============
    leaks = database.list_credential_leaks(limit=200)
    for l in leaks:
        leak_id = l.get("leak_id", "")
        target = l.get("target", "")
        masked = l.get("api_key_masked", "")
        status = l.get("verified_status", "unverified")
        provider = l.get("provider", "unknown")
        base_url = l.get("base_url", "")
        vstatus = {"valid": "✅ 有效", "invalid": "❌ 失效", "error": "⚠️ 无法判定",
                   "unverified": "❓ 未验证"}.get(status, status)
        fm = _frontmatter({
            "title": f"泄露 {masked}", "leak_id": leak_id,
            "provider": provider, "verified": status,
            "secret_type": l.get("secret_type", ""), "source": target,
            "tags": "大脑记忆/泄露",
        })
        body = [fm, f"# 密钥泄露 {masked}", ""]
        body.append(f"- **目标**：{target}")
        body.append(f"- **Provider**：{provider}  ")
        body.append(f"- **LLM API**：{base_url or '-'}")
        body.append(f"- **验证状态**：{vstatus}")
        body.append(f"- **类型**：{l.get('secret_type','')}")
        body.append(f"- **首次发现**：{_fmt_ts(l.get('first_seen'))}")
        body.append("")
        if l.get("verified_detail"):
            body.append(f"> {l['verified_detail']}")
            body.append("")
        body.append("## 🔗 相关项目")
        body.append(f"- [[DeepTutor|DeepTutor]]（来源：`{target[:40]}...`）")
        body.append("")
        fname = _safe_name(f"泄露 {masked}")
        path = os.path.join(vault_root, "02-泄露", f"{fname}.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(body))
        leak_links.append(f"- [[{fname}|{masked}]]")
        stats["leaks"] += 1

    # ============ 3. 经验笔记（从 threat_intel + code_audits 提炼） ============
    try:
        ti = database.threat_intel_overview()
        bc = ti.get("by_component", {})
        if bc:
            fm = _frontmatter({"title": "在野利用组件（CISA KEV）", "tags": "大脑记忆/经验"})
            body = [fm, "# 🔴 在野利用组件（CISA KEV）", "",
                    "> 以下组件存在 CISA 确认的在野利用记录，遇到对应部署应重点检查。", ""]
            for comp, cnt in sorted(bc.items(), key=lambda x: -x[1])[:20]:
                body.append(f"- **{comp}**：{cnt} 条在野利用漏洞")
            body.append("")
            path = os.path.join(vault_root, "03-经验", "在野利用组件 CISA KEV.md")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(body))
            stats["experience"] += 1
    except Exception as e:
        logger.warning("经验笔记(threat_intel)生成失败: %s", e)

    try:
        audits = database.list_code_audits(limit=5)
        if audits:
            fm = _frontmatter({"title": "代码审计结论", "tags": "大脑记忆/经验"})
            body = [fm, "# 🔍 代码审计结论", ""]
            for a in audits:
                report = a.get("report") or {}
                ai = report.get("ai_report") or {}
                body.append(f"## {a.get('repo','')}")
                body.append(f"- 风险等级：**{ai.get('risk_level','unknown')}**")
                if ai.get("summary"):
                    body.append(f"- 结论：{ai['summary']}")
                for risk in (ai.get("top_risks") or [])[:3]:
                    body.append(f"- ⚠️ {risk.get('risk','')}（{risk.get('file','')}）")
                body.append("")
            path = os.path.join(vault_root, "03-经验", "代码审计结论.md")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(body))
            stats["experience"] += 1
    except Exception as e:
        logger.warning("经验笔记(code_audit)生成失败: %s", e)

    # ============ 4. 索引 MOC ============
    fm = _frontmatter({"title": "大脑记忆总入口", "tags": "MOC/大脑记忆"})
    moc = [fm, "# 🧠 大脑记忆总入口", "",
           "> 供应链 · API 安全情报系统的长期记忆库。所有内容自动生成。", "",
           "## 📦 研究项目", ""]
    moc.extend(sorted(project_links))
    moc += ["", "## 🔑 密钥泄露", ""]
    moc.extend(sorted(leak_links))
    moc += ["", "## 📚 经验知识", "",
            "- [[在野利用组件 CISA KEV]]", "- [[代码审计结论]]", "",
            "## 📅 每日活动", "- [[每日日志]]", ""]
    path = os.path.join(vault_root, "00-索引", "000-大脑MOC.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(moc))

    # ============ 5. 每日日志 ============
    events = database.brain_events(limit=50)
    today = datetime.now().strftime("%Y-%m-%d")
    fm = _frontmatter({"title": f"活动日志 {today}", "tags": "大脑记忆/日志"})
    log = [fm, f"# 📅 活动日志 {today}", ""]
    if events:
        log.append("| 时间 | 动作 | 详情 |")
        log.append("| --- | --- | --- |")
        for e in events[:40]:
            log.append(f"| {_fmt_ts(e.get('ts'))} | {e.get('action','')} | {str(e.get('detail',''))[:50]} |")
    else:
        log.append("_暂无活动_")
    log.append("")
    path = os.path.join(vault_root, "04-日志", f"{today}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(log))
    stats["logs"] = 1

    return {"vault_root": vault_root, "stats": stats}
