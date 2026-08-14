"""攻击情报源（Issue #10 目标 3）：CISA KEV「正在被利用漏洞」清单。

KEV（Known Exploited Vulnerabilities）是 CISA 官方维护的、确认在野被利用的漏洞清单，
用于标记「某个组件正在被攻击」。配合研判卡生成，让高风险组件带上攻击情报标记。
"""
import json
import logging
import time
import urllib.request

logger = logging.getLogger("ThreatIntel")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# 常用组件的 vendor/product 关键词映射（用于把 KEV 条目关联到我们的组件名）
COMPONENT_KEYWORDS = {
    "nginx": ["nginx", "f5 nginx"],
    "tomcat": ["apache tomcat", "tomcat"],
    "apache": ["apache http server", "apache", "apache commons"],
    "spring": ["spring framework", "spring boot", "spring"],
    "struts2": ["apache struts"],
    "weblogic": ["oracle weblogic"],
    "jenkins": ["jenkins"],
    "metabase": ["metabase"],
    "next.js": ["next.js", "vercel"],
    "node.js": ["node.js", "nodejs", "express"],
    "log4j": ["apache log4j"],
    "fastjson": ["fastjson"],
    "gitlab": ["gitlab"],
    "dify": ["dify"],
    "open-webui": ["open webui"],
    "deepseek": ["deepseek"],
    "redis": ["redis"],
    "mikrotik": ["mikrotik"],
    "fortinet": ["fortinet"],
    "citrix": ["citrix"],
    "joomla": ["joomla"],
    "wordpress": ["wordpress"],
    "dedecms": ["dedecms", "织梦"],
    "yii": ["yii framework"],
    "ant design": ["ant design"],
    "drupal": ["drupal"],
    "cisco": ["cisco"],
    "microsoft": ["microsoft", "windows"],
}


def fetch_kev(timeout: int = 20) -> list:
    """拉取 CISA KEV 清单，返回漏洞列表"""
    req = urllib.request.Request(KEV_URL, headers={
        "User-Agent": "SupplyChainBrain/1.0 (defensive research)",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("vulnerabilities", [])


def map_component(entry: dict) -> str:
    """把 KEV 条目映射到我们的组件名（未命中返回空字符串）"""
    hay = " ".join([
        str(entry.get("vendorProject", "")),
        str(entry.get("product", "")),
        str(entry.get("vulnerabilityName", "")),
    ]).lower()
    for component, keywords in COMPONENT_KEYWORDS.items():
        for kw in keywords:
            if kw in hay:
                return component
    return ""


def fetch_attack_intel(database, component_map: dict = None) -> dict:
    """拉取 KEV 并入库。返回 {"total_kev": n, "matched": {组件名: [cve列表]}}"""
    matched = {}
    try:
        kev = fetch_kev()
        logger.info("KEV 拉取成功: %d 条已利用漏洞", len(kev))
        now = time.time()
        for entry in kev:
            cve = entry.get("cveID", "")
            component = map_component(entry)
            if not component:
                continue
            # 入库 threat_intel
            if database:
                database.upsert_threat_intel({
                    "cve_id": cve,
                    "component": component,
                    "vendor": entry.get("vendorProject", ""),
                    "product": entry.get("product", ""),
                    "name": entry.get("vulnerabilityName", ""),
                    "date_added": entry.get("dateAdded", ""),
                    "due_date": entry.get("dueDate", ""),
                    "known_ransomware": bool(entry.get("knownRansomwareCampaignUse", "No") == "Yes"),
                    "source": "cisa-kev",
                })
            matched.setdefault(component, []).append(cve)
        logger.info("KEV 组件匹配完成: %d 个组件命中 %d 条", len(matched),
                    sum(len(v) for v in matched.values()))
        return {"total_kev": len(kev), "matched": matched, "ts": now}
    except Exception as exc:
        logger.warning("KEV 拉取失败: %s", exc)
        return {"total_kev": 0, "matched": {}, "error": str(exc)}


def component_attack_status(database, component: str) -> dict:
    """查询某组件的攻击情报状态"""
    try:
        return database.threat_intel_for_component(component)
    except Exception:
        return {"total": 0, "items": []}
