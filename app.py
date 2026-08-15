"""
软件供应链安全分析平台 - Flask 主应用

本应用提供 Web 界面，整合 FOFA 资产搜索、技术指纹检测、供应链映射、
漏洞检查、利用方式查找和 API 安全扫描等核心模块，
对目标资产进行综合性的软件供应链安全分析。

运行方式：
    python app.py

功能概览：
    - 支持 FOFA 搜索和手动输入两种资产来源
    - 异步分析（后台线程执行），前端轮询进度
    - 生成综合分析报告与汇总统计
"""
import os
import sys
import hashlib
import uuid
import time
import logging
import threading
import json
import requests
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from dataclasses import asdict

# ============================================================
# 路径处理：确保能正确导入 core 目录下的模块
# ============================================================
# 获取本文件所在目录（项目根目录）
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 将项目根目录加入 Python 模块搜索路径
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from functools import wraps

from flask import Flask, render_template, request, jsonify, abort, send_from_directory

# 导入配置
from config import Config

# 导入会话管理
from core.auth import SessionManager
from core.database import ScanDatabase

# 导入核心模块
from core.fofa_client import FofaClient, Asset, FofaError, FofaAuthError, FofaApiError
from core.tech_detector import TechDetector
from core.supply_chain import SupplyChainMapper
from core.vuln_checker import VulnChecker
from core.exploit_finder import ExploitFinder
from core.api_scanner import APIScanner
from core.exposure_discovery import FrontendExposureDiscovery
from core.ownership_discovery import OwnershipDiscovery
from core.infrastructure_intelligence import (
    PassiveInfrastructureCollector, declared_services_graph, evidence_supply_chain_graph,
    generate_infrastructure_decision_cards, merge_graphs,
)
from core.research_brain import ResearchBrain
from core.dispatcher import TaskDispatcher
# 导入 AI 分析器（DeepSeek API，可选模块，未配置 API Key 时自动禁用）
from core.ai_analyzer import AIAnalyzer

# ============================================================
# 日志配置
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("SupplyChainAnalyzer")


def configured_platform_dependency_graph() -> Dict[str, Any]:
    """Return credential-free runtime provider declarations."""
    return declared_services_graph("Supply Chain Brain", [
        {"name": "FOFA", "provider": "FOFA", "base_url": "https://fofa.info",
         "enabled": bool(Config.FOFA_KEY), "purpose": "public asset discovery"},
        {"name": "DeepSeek", "provider": "DeepSeek",
         "base_url": Config.DEEPSEEK_BASE_URL,
         "enabled": bool(Config.DEEPSEEK_API_KEY and Config.AI_ANALYSIS_ENABLED),
         "purpose": "primary research analysis", "model": Config.DEEPSEEK_MODEL},
        {"name": "OpenAI", "provider": "OpenAI",
         "base_url": Config.OPENAI_BASE_URL, "enabled": bool(Config.OPENAI_API_KEY),
         "purpose": "AI analysis fallback", "model": Config.OPENAI_MODEL},
        {"name": "Kafka", "provider": "Self-hosted",
         "base_url": "", "enabled": bool(Config.KAFKA_ENABLED),
         "purpose": "optional task transport"},
    ])


def enrich_passive_infrastructure(report: Dict[str, Any], task_context: Dict[str, Any]):
    """Build supplier relationships for already-authorized completed assets.

    This hook performs passive DNS/RDAP/BGP enrichment only.  It never creates
    research assets and therefore cannot expand the Worker's active scan scope.
    """
    project_slug = str(task_context.get("project_slug") or "")
    allowed_projects = set(Config.RESEARCH_ALLOWED_PROJECTS or ())
    if allowed_projects and project_slug not in allowed_projects:
        return
    collector = PassiveInfrastructureCollector()
    for experiment in report.get("experiments", []):
        if experiment.get("status") != "completed":
            continue
        for item in experiment.get("evidence", []):
            if not isinstance(item, dict):
                continue
            target = str(item.get("target") or item.get("url") or "").strip()
            if not target:
                continue
            parsed = urlparse(target if "://" in target else "//" + target)
            hostname = (parsed.hostname or "").lower()
            if Config.AUTHORIZED_SCAN_DOMAINS and not any(
                    hostname == domain or hostname.endswith("." + domain)
                    for domain in Config.AUTHORIZED_SCAN_DOMAINS):
                logger.warning("供应链被动补全跳过越界目标: %s", target)
                continue
            asset = item.get("asset") if isinstance(item.get("asset"), dict) else {}
            known_ips = [value for value in (item.get("ip"), asset.get("ip")) if value]
            graph = merge_graphs(
                collector.collect(target, known_ips=known_ips),
                evidence_supply_chain_graph(target, item),
            )
            counts = scan_database.upsert_supply_chain_graph(
                project_slug, target.rstrip("/").lower(), graph)
            scan_database.brain_event(
                event_type="result", action="补全基础设施供应链",
                detail=(f"{hostname} 形成 {len(graph.get('relations', []))} 条关系 · "
                        f"新增实体 {counts['new_entities']}"),
                reason="基于 DNS、RDAP 与 BGP 的被动公开数据",
                project=project_slug,
                meta={"target": target, **counts, "errors": graph.get("errors", [])[:5]},
            )
    card_counts = generate_infrastructure_decision_cards(scan_database, project_slug)
    scan_database.brain_event(
        event_type="decision", action="评估基础设施依赖",
        detail=(f"供应链研判卡新增 {card_counts['created']} · "
                f"更新 {card_counts['updated']}"),
        reason="根据当前 DNS、BGP、RDAP、TLS 与 Worker 证据形成可行动结论",
        project=project_slug, meta=card_counts,
    )


def identify_project_family(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Enrich stored observations with an upstream project attribution.

    Upstream authorship is intentionally kept separate from ownership of a
    public deployment. No network request is made here.
    """
    asset = item.get("asset") or {}
    owner = item.get("ownership_profile") or {}
    title = " ".join(filter(None, (asset.get("title"), owner.get("site_title")))).lower()
    observed_paths = {
        urlparse(record.get("url", "")).path.rstrip("/").lower()
        for key in ("exposure_findings", "api_endpoints")
        for record in item.get(key, [])
    }
    evidence = []
    if "deeptutor" in title:
        evidence.append("网站标题包含 DeepTutor")
    matched_paths = sorted(observed_paths & {
        "/settings/llm", "/api/v1/settings", "/api/v1/settings/llm-options",
    })
    if matched_paths:
        evidence.append("匹配项目特征路由：" + "、".join(matched_paths))
    if not evidence:
        return None
    return {
        "name": "DeepTutor",
        "upstream": "HKUDS / Data Intelligence Lab @ HKU",
        "repository": "https://github.com/HKUDS/DeepTutor",
        "license": "Apache-2.0",
        "deployment_relation": "第三方自行部署",
        "deployment_owner": "待确认",
        "confidence": "high" if len(evidence) > 1 else "medium",
        "evidence": evidence,
        "notice": "上游项目归属不等于该公网实例的资产归属或安全责任。",
    }


def classify_vulnerability_evidence(vulnerability: Dict[str, Any], item: Dict[str, Any]) -> Dict[str, Any]:
    """Describe what the stored evidence proves instead of overclaiming."""
    component = (vulnerability.get("component") or "").lower()
    matching_tech = next((tech for tech in item.get("technologies", [])
                          if (tech.get("name") or "").lower() == component), None)
    observed_version = (matching_tech or {}).get("version") or ""
    enriched = dict(vulnerability)
    enriched["observed_version"] = observed_version or None
    enriched["verification_status"] = "高度疑似" if observed_version else "待核实"
    enriched["verification_level"] = "L1"
    enriched["verification_reason"] = (
        "已识别组件版本；仍需核对受影响版本区间与利用前置条件"
        if observed_version else "仅匹配到组件指纹，缺少准确版本和利用前置条件证据"
    )
    return enriched

# ============================================================
# Flask 应用初始化
# ============================================================
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.config["JSON_AS_ASCII"] = False  # 允许 JSON 中直接包含中文

# ============================================================
# 会话管理器（基于内存的会话存储，支持管理员/游客两种角色）
# ============================================================
session_manager = SessionManager(
    admin_password=Config.ADMIN_PASSWORD,
    session_timeout=86400,  # 24 小时
)



# ============================================================
# 认证装饰器
# ============================================================

def require_admin(f):
    """要求管理员权限的装饰器
    
    从 Cookie 中读取 session_id，验证是否为管理员会话。
    非管理员或未登录时返回 403 错误。
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        session_id = request.cookies.get("session_id")
        session = session_manager.get_session(session_id)
        if not session or not session.is_admin:
            return jsonify({"error": "需要管理员权限"}), 403
        return f(*args, **kwargs)
    return decorated


# ============================================================
# 全局状态：任务存储（内存字典，线程安全）
# ============================================================
# tasks 字典结构：
#   task_id -> {
#       "status": "pending" | "running" | "completed" | "error" | "cancelled",
#       "progress": int (0-100),
#       "current_step": str,        # 当前步骤描述
#       "analyzed_count": int,      # 已分析资产数
#       "total_count": int,         # 总资产数
#       "results": dict | None,     # 分析结果（完成后填充）
#       "error": str | None,        # 错误信息（失败时填充）
#       "created_at": float,        # 创建时间戳
#   }
tasks: Dict[str, Dict[str, Any]] = {}
# 线程锁，保护 tasks 字典的并发访问
tasks_lock = threading.Lock()
scan_database = ScanDatabase(Config.DATABASE_PATH)
_platform_project = next(iter(Config.RESEARCH_ALLOWED_PROJECTS), "system")
scan_database.upsert_supply_chain_graph(
    _platform_project, "system:supply-chain-brain", configured_platform_dependency_graph())

# 注入数据库到告警模块（outbox 持久化）
from core.notifier import set_database, flush_outbox
set_database(scan_database)

# 全局核心模块实例（避免每次分析重复加载签名/漏洞数据库）
tech_detector = TechDetector()
supply_chain_mapper = SupplyChainMapper()
exploit_finder = ExploitFinder()


# ============================================================
# 辅助函数
# ============================================================

def generate_task_id() -> str:
    """生成唯一的任务 ID"""
    return uuid.uuid4().hex[:16]


def serialize_technologies(technologies: List) -> List[Dict]:
    """将技术列表序列化为可 JSON 化的字典列表"""
    result = []
    for tech in technologies:
        if hasattr(tech, "to_dict"):
            result.append(tech.to_dict())
        else:
            # 兼容字典或其他对象
            result.append({
                "name": getattr(tech, "name", ""),
                "version": getattr(tech, "version", ""),
                "category": getattr(tech, "category", ""),
                "vendor": getattr(tech, "vendor", ""),
                "supply_chain": getattr(tech, "supply_chain", ""),
            })
    return result


def parse_urls_to_assets(url_text: str) -> List[Asset]:
    """将手动输入的 URL 文本解析为 Asset 对象列表

    Args:
        url_text: 每行一个 URL 的文本

    Returns:
        Asset 对象列表
    """
    assets = []
    for line in url_text.strip().splitlines():
        url = line.strip()
        if not url:
            continue
        # 如果没有协议前缀，默认添加 http://
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if parsed.scheme not in ("http", "https") or not host:
                logger.warning("忽略无效 URL: %s", url)
                continue
            port = parsed.port or 0
            protocol = parsed.scheme or "http"

            asset = Asset(
                host=host,
                ip="",
                port=port,
                title="",
                server="",
                header="",
                banner="",
                protocol=protocol,
                country="",
                city="",
                domain=host,
                url=url,
                icp="",
            )
            assets.append(asset)
        except Exception as e:
            logger.warning("解析 URL 失败 '%s': %s", url, e)
            continue

    return assets


def determine_asset_risk_level(vulnerabilities: List) -> str:
    """根据漏洞列表确定单个资产的风险等级

    Args:
        vulnerabilities: 漏洞对象列表

    Returns:
        风险等级字符串（CRITICAL / HIGH / MEDIUM / LOW / INFO）
    """
    if not vulnerabilities:
        return "INFO"

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    highest = "INFO"
    for vuln in vulnerabilities:
        sev = getattr(vuln, "severity", "").upper()
        if sev in severity_order:
            if highest == "INFO" or severity_order[sev] < severity_order.get(highest, 99):
                highest = sev
    return highest


def calculate_risk_score(all_vulns: List) -> int:
    """根据所有漏洞计算整体风险评分（0-100）

    基于 VulnChecker 的严重等级权重计算。

    Args:
        all_vulns: 所有漏洞对象列表

    Returns:
        归一化的风险评分（0-100）
    """
    if not all_vulns:
        return 0

    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
    total_score = 0
    for vuln in all_vulns:
        sev = getattr(vuln, "severity", "").upper()
        total_score += weights.get(sev, 1)

    max_possible = len(all_vulns) * 10
    normalized = min(100, int((total_score / max_possible) * 100)) if max_possible > 0 else 0
    return normalized


def determine_overall_risk_level(severity_dist: Dict[str, int]) -> str:
    """根据严重等级分布确定整体风险等级"""
    if severity_dist.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if severity_dist.get("HIGH", 0) > 0:
        return "HIGH"
    if severity_dist.get("MEDIUM", 0) > 0:
        return "MEDIUM"
    if severity_dist.get("LOW", 0) > 0:
        return "LOW"
    return "INFO"


def update_task(task_id: str, **kwargs):
    """线程安全地更新任务状态"""
    with tasks_lock:
        if task_id in tasks:
            tasks[task_id].update(kwargs)
    scan_database.update_task(task_id, kwargs)


def get_task(task_id: str) -> Optional[Dict[str, Any]]:
    """Read active task from memory, falling back to persisted history."""
    with tasks_lock:
        task = tasks.get(task_id)
        if task:
            return dict(task)
    return scan_database.get_task(task_id)


def task_is_cancelled(task_id: str) -> bool:
    """返回任务是否已被用户取消。"""
    with tasks_lock:
        task = tasks.get(task_id)
        return bool(task and task.get("cancel_requested"))


def finish_cancelled_task(task_id: str):
    """将任务置为取消状态（运行中的网络请求无法强制中断，会在步骤间停止）。"""
    update_task(
        task_id,
        status="cancelled",
        current_step="分析已取消",
        error=None,
    )


def analyze_asset(asset: Asset, scan_api: bool, online_query: bool,
                  vuln_checker: VulnChecker, api_scanner: APIScanner,
                  scan_exposure: bool = None) -> Dict[str, Any]:
    """对单个资产执行完整的安全分析

    分析流程：
    1. 技术指纹检测
    2. 供应链映射
    3. 漏洞检查
    4. 利用方式查找
    5. API 安全扫描（可选）
    6. 前端暴露面发现 / SK 检测（可独立于 API 扫描执行）

    Args:
        asset: 资产对象
        scan_api: 是否扫描 API 端点
        online_query: 是否在线查询 NVD/OSV（已通过 vuln_checker 配置）
        vuln_checker: 漏洞检查器实例
        api_scanner: API 扫描器实例
        scan_exposure: 是否执行前端暴露面发现（含 SK 检测）。
            默认 None → 跟随 scan_api；显式 True 时即使不扫 API 也做 SK 检测
            （Issue 修复：真实部署即使确认未通过，也应检测前端泄露的密钥）。

    Returns:
        单个资产的完整分析结果字典
    """
    if scan_exposure is None:
        scan_exposure = scan_api
    # 步骤 1：技术指纹检测
    technologies = tech_detector.detect_from_fofa(asset)
    # FOFA provides discovery metadata; actively inspect the authorized target to
    # fill gaps in component detection.
    http_technologies = tech_detector.detect_from_http(
        asset.url, timeout=Config.SCAN_TIMEOUT, verify_ssl=False
    ) if asset.url else []
    detected = {tech.name.lower(): tech for tech in technologies}
    for tech in http_technologies:
        existing = detected.get(tech.name.lower())
        if not existing or (not existing.version and tech.version):
            detected[tech.name.lower()] = tech
    technologies = list(detected.values())

    # 步骤 2：供应链映射
    supply_chains = supply_chain_mapper.map(technologies)

    # 步骤 3：漏洞检查
    vulnerabilities = vuln_checker.check(technologies)
    # 漏洞级验证语义（Codex P0-2）：研究大脑做了主动 HTTP 探测 + 指纹命中 → condition_matched
    if scan_api:
        for v in vulnerabilities:
            if getattr(v, "verification_status", "suspected") == "suspected":
                v.verification_status = "condition_matched"
                v.verification_method = "active_http_probe_fingerprint"
                v.verified_at = time.time()

    # 步骤 4：利用方式查找
    exploits = exploit_finder.find(vulnerabilities)

    # 步骤 5：API 安全扫描（可选）
    api_endpoints = []
    api_report = None
    exposure_findings = []
    ownership_profile = {}
    if scan_api:
        try:
            api_endpoints = api_scanner.scan(asset)
            if api_endpoints:
                api_report = api_scanner.generate_report(asset, api_endpoints)
        except Exception as e:
            logger.warning("资产 %s 的 API 扫描失败: %s", asset.url, e)
    # 步骤 6：前端暴露面发现 / SK 检测（可独立于 API 扫描执行）
    if scan_exposure:
        try:
            exposure_discovery = FrontendExposureDiscovery(timeout=Config.SCAN_TIMEOUT)
            exposure_findings = exposure_discovery.discover(asset.url)
            exposure_discovery.close()
        except Exception as e:
            logger.warning("资产 %s 的前端暴露面发现失败: %s", asset.url, e)
        try:
            ownership_discovery = OwnershipDiscovery(timeout=Config.SCAN_TIMEOUT)
            ownership_profile = ownership_discovery.discover(asset.url).to_dict()
            ownership_discovery.close()
        except Exception as e:
            logger.warning("资产 %s 的责任主体线索发现失败: %s", asset.url, e)

    # 确定资产风险等级
    risk_level = determine_asset_risk_level(vulnerabilities)

    # 构建结果字典（所有核心对象通过 to_dict() 序列化）
    result = {
        "asset": asset.to_dict(),
        "technologies": serialize_technologies(technologies),
        "supply_chains": [sc.to_dict() for sc in supply_chains],
        "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        "exploits": [e.to_dict() for e in exploits],
        "api_endpoints": [ep.to_dict() for ep in api_endpoints],
        "api_report": api_report.to_dict() if api_report else None,
        "exposure_findings": [finding.to_dict() for finding in exposure_findings],
        "ownership_profile": ownership_profile,
        "vuln_count": len(vulnerabilities),
        "tech_count": len(technologies),
        "risk_level": risk_level,
    }
    return result


def analyze_research_candidate(asset_data: Dict[str, Any], full: bool = True) -> Dict[str, Any]:
    """Bounded L1/L2 analysis used by the autonomous research engine.

    - full=True: 完整分析（API 扫描 + 前端暴露面 + SK 检测）
    - full=False: 轻量确认分析，但**仍执行前端暴露面发现（含 SK 检测）**——
      避免真实部署因确认门槛被拒后从未做 SK 检测（Issue 修复：DeepTutor 大量
      部署通过前端 JS 泄露密钥，必须对所有资产做暴露面检测）。
    """
    allowed = {key: asset_data.get(key) for key in Asset.__dataclass_fields__}
    asset = Asset(**allowed)
    checker = VulnChecker(enable_nvd=False, enable_osv=False, timeout=Config.SCAN_TIMEOUT)
    scanner = APIScanner(timeout=Config.SCAN_TIMEOUT, verify_ssl=False)
    # light 模式也做暴露面发现（含 SK/敏感字段检测），仅跳过完整 API 扫描
    light_scan = False if full else True
    return analyze_asset(asset, scan_api=full, online_query=False,
                         scan_exposure=light_scan or full,
                         vuln_checker=checker, api_scanner=scanner)


def probe_research_project(project_slug: str, asset_data: Dict[str, Any]) -> Dict[str, Any]:
    """Probe at most two project-specific public endpoints for identity only."""
    paths = {
        "deeptutor": ("/api/v1/settings", "/settings/llm"),
        "dify": ("/console/api/setup", "/console/api/version"),
        "open-webui": ("/api/config", "/api/v1/auths/signin"),
        "anythingllm": ("/api/system/system-vectors", "/api/system"),
        "lobechat": ("/api/config", "/settings/provider"),
    }.get(project_slug, ())
    base = (asset_data.get("url") or "").rstrip("/")
    observations = []
    aliases = project_slug.replace("-", " ").split()
    for path in paths[:3]:
        try:
            response = requests.get(base + path, timeout=min(6, Config.SCAN_TIMEOUT),
                                    verify=False, allow_redirects=False,
                                    headers={"User-Agent": "DefensiveResearchIdentityProbe/1.0"})
            body = response.text[:4096].lower()
            content_type = response.headers.get("Content-Type", "").lower()
            # 放宽匹配：JSON 响应即算命中（部署常自定义品牌名，不能要求正文含项目名）
            matched = response.status_code < 400 and (
                "json" in content_type or response.status_code == 200
                or any(alias in body for alias in aliases)
            )
            observations.append({"path": path, "status_code": response.status_code,
                                 "matched": matched})
            if matched:
                return {"matched": True, "observations": observations}
        except requests.RequestException:
            observations.append({"path": path, "status_code": 0, "matched": False})
    return {"matched": False, "observations": observations}


# Start only after all shared detectors and the bounded execution callback exist.
# research_brain is initialized below after node_planner is created.


def _alert_outbox_worker():
    """后台线程：定时重试待投递告警（失败重试，Codex P1）"""
    while True:
        try:
            flush_outbox(webhook_url=Config.ALERT_WEBHOOK_URL,
                         bot_token=Config.ALERT_TELEGRAM_TOKEN,
                         chat_id=Config.ALERT_TELEGRAM_CHAT_ID)
        except Exception as exc:
            logger.warning("告警 outbox 重试失败: %s", exc)
        time.sleep(60)


threading.Thread(target=_alert_outbox_worker, daemon=True).start()


def _task_lease_reaper_worker():
    """Recover abandoned Worker attempts independently of task claiming."""
    while True:
        try:
            result = scan_database.reap_expired_node_tasks()
            if result.get("expired"):
                scan_database.brain_event(
                    event_type="warn", action="回收过期任务租约",
                    detail=(f"过期 {result['expired']} · 等待重试 {result['retry_wait']} · "
                            f"进入 dead {result['dead']}"),
                    reason="周期性租约回收，避免任务永久停留 running",
                    meta=result,
                )
        except Exception as exc:
            logger.warning("任务租约回收失败: %s", exc)
        time.sleep(30)


threading.Thread(target=_task_lease_reaper_worker, daemon=True,
                 name="task-lease-reaper").start()

# 大脑端任务分发器：向执行引擎（worker 节点）下发任务并回收结果
task_dispatcher = TaskDispatcher(scan_database, Config)

# 节点集群调度器：把研究大脑的资产分析分发给多台节点并行执行
from core.node_planner import NodePlanner
node_planner = NodePlanner(task_dispatcher, scan_database, Config)

# 研究大脑：编排选题 → 发现 → 分析（本地确认 + 节点并行深度分析）
research_brain = ResearchBrain(scan_database, Config, analyze_research_candidate,
                               probe_research_project, node_planner)
research_brain.start()


def run_analysis(task_id: str, mode: str, fofa_query: str, fofa_key: str,
                 fofa_size: int, url_text: str,
                 scan_api: bool, online_query: bool):
    """在后台线程中执行完整的分析流程

    Args:
        task_id: 任务 ID
        mode: 分析模式（"fofa" 或 "manual"）
        fofa_query: 测绘平台查询语句
        fofa_key: FOFA Key
        fofa_size: FOFA 返回结果数量
        url_text: 手动输入的 URL 文本
        scan_api: 是否扫描 API
        online_query: 是否在线查询 NVD/OSV
    """
    logger.info("任务 %s 开始执行分析 (mode=%s)", task_id, mode)

    try:
        # ============================================================
        # 阶段 1：获取资产列表
        # ============================================================
        update_task(task_id, status="running", progress=5,
                    current_step="正在获取资产列表...")

        assets: List[Asset] = []

        if mode == "fofa":
            # FOFA 搜索模式
            if not fofa_query:
                raise ValueError("资产查询语句不能为空")

            # 凭据优先级：环境变量 > 表单输入
            key = Config.FOFA_KEY or fofa_key

            if not key:
                raise ValueError("缺少资产数据源访问凭据，请联系管理员配置")

            logger.info("任务 %s: 使用测绘平台搜索 '%s', size=%d", task_id, fofa_query, fofa_size)
            client = FofaClient(key=key, timeout=Config.SCAN_TIMEOUT + 20)
            try:
                assets = client.search_all(fofa_query, max_results=fofa_size)
            finally:
                client.close()

        elif mode == "manual":
            # 手动输入模式
            logger.info("任务 %s: 使用手动输入的 URL 列表", task_id)
            assets = parse_urls_to_assets(url_text)
        else:
            raise ValueError(f"不支持的分析模式: {mode}")

        if task_is_cancelled(task_id):
            finish_cancelled_task(task_id)
            return

        if not assets:
            update_task(task_id, status="completed", progress=100,
                        current_step="未找到任何资产",
                        results={"summary": _empty_summary(), "assets": [], "ai_analysis": None})
            logger.info("任务 %s 完成：未找到资产", task_id)
            return

        total = len(assets)
        logger.info("任务 %s: 共获取 %d 个资产，开始分析", task_id, total)
        update_task(task_id, total_count=total, progress=10,
                    current_step=f"已获取 {total} 个资产，开始技术检测...")

        # ============================================================
        # 初始化分析器（根据在线查询选项配置漏洞检查器）
        # ============================================================
        vuln_checker = VulnChecker(
            enable_nvd=online_query,
            enable_osv=online_query,
            timeout=Config.SCAN_TIMEOUT + 5,
        )
        api_scanner = APIScanner(
            timeout=Config.SCAN_TIMEOUT,
            verify_ssl=False,
            max_endpoints=50,
        )

        # ============================================================
        # 阶段 2-6：逐个资产分析
        # ============================================================
        asset_results: List[Dict[str, Any]] = []
        all_vulnerabilities = []

        for index, asset in enumerate(assets):
            if task_is_cancelled(task_id):
                vuln_checker.close()
                api_scanner.close()
                finish_cancelled_task(task_id)
                return

            # 更新进度
            progress = 10 + int((index / total) * 85)  # 10% ~ 95%
            update_task(
                task_id,
                progress=progress,
                analyzed_count=index,
                current_step=f"正在分析资产 {index + 1}/{total}: {asset.url or asset.host}",
            )

            logger.debug("任务 %s: 分析资产 %d/%d - %s", task_id, index + 1, total, asset.url)

            try:
                result = analyze_asset(
                    asset, scan_api, online_query, vuln_checker, api_scanner
                )
                asset_results.append(result)

                # 收集所有漏洞用于汇总统计
                all_vulnerabilities.extend(result.get("vulnerabilities", []))

            except Exception as e:
                logger.error("任务 %s: 资产 %s 分析失败: %s", task_id, asset.url, e, exc_info=True)
                # 单个资产分析失败不影响整体，记录错误信息
                asset_results.append({
                    "asset": asset.to_dict(),
                    "technologies": [],
                    "supply_chains": [],
                    "vulnerabilities": [],
                    "exploits": [],
                    "api_endpoints": [],
                    "api_report": None,
                    "exposure_findings": [],
                    "ownership_profile": {},
                    "vuln_count": 0,
                    "tech_count": 0,
                    "risk_level": "INFO",
                    "error": str(e),
                })

            update_task(task_id, analyzed_count=index + 1)

        # 关闭分析器会话
        vuln_checker.close()
        api_scanner.close()

        # ============================================================
        # 阶段 7：生成汇总统计
        # ============================================================
        update_task(task_id, progress=95, current_step="正在生成汇总报告...")

        summary = _build_summary(asset_results, all_vulnerabilities)

        final_results = {
            "summary": summary,
            "assets": asset_results,
        }

        if task_is_cancelled(task_id):
            finish_cancelled_task(task_id)
            return

        # ============================================================
        # 阶段 8：AI 深度分析（可选）
        # ============================================================
        # 仅当配置了 DEEPSEEK_API_KEY 且 AI_ANALYSIS_ENABLED 为 true 时执行
        # AI 分析失败不影响主流程，仅在结果中记录错误信息
        ai_analysis = None
        if Config.DEEPSEEK_API_KEY and Config.AI_ANALYSIS_ENABLED:
            update_task(task_id, progress=97, current_step="AI 正在进行深度安全分析...")
            try:
                ai_analyzer = AIAnalyzer(
                    api_key=Config.DEEPSEEK_API_KEY,
                    base_url=Config.DEEPSEEK_BASE_URL,
                    model=Config.DEEPSEEK_MODEL,
                    timeout=Config.AI_TIMEOUT,
                )
                ai_analysis = ai_analyzer.analyze(final_results).to_dict()
                logger.info("任务 %s: AI 分析完成", task_id)
            except Exception as e:
                logger.warning("任务 %s: AI 分析失败: %s", task_id, e)
                ai_analysis = {"error": str(e)}
        else:
            # 未启用 AI 分析时记录原因（便于前端展示状态）
            if not Config.DEEPSEEK_API_KEY:
                logger.info("任务 %s: 未配置 DEEPSEEK_API_KEY，跳过 AI 分析", task_id)
                ai_analysis = {"disabled": True, "reason": "未配置 DEEPSEEK_API_KEY"}
            elif not Config.AI_ANALYSIS_ENABLED:
                logger.info("任务 %s: AI 分析已被 AI_ANALYSIS_ENABLED=false 关闭", task_id)
                ai_analysis = {"disabled": True, "reason": "AI 分析已被全局关闭"}

        final_results["ai_analysis"] = ai_analysis

        if task_is_cancelled(task_id):
            finish_cancelled_task(task_id)
            return

        update_task(
            task_id,
            status="completed",
            progress=100,
            analyzed_count=total,
            current_step="分析完成",
            results=final_results,
        )
        logger.info("任务 %s 分析完成: %d 个资产, %d 个漏洞", task_id, total, summary["total_vulnerabilities"])

    except (FofaAuthError, FofaApiError, FofaError) as e:
        logger.error("任务 %s FOFA 错误: %s", task_id, e)
        update_task(task_id, status="error", error=f"资产数据源错误: {e}", current_step="分析失败")
    except ValueError as e:
        logger.error("任务 %s 参数错误: %s", task_id, e)
        update_task(task_id, status="error", error=str(e), current_step="分析失败")
    except Exception as e:
        logger.error("任务 %s 未知错误: %s", task_id, e, exc_info=True)
        update_task(task_id, status="error", error=f"分析过程中发生错误: {e}", current_step="分析失败")


def _empty_summary() -> Dict[str, Any]:
    """生成空的汇总统计"""
    return {
        "total_assets": 0,
        "total_technologies": 0,
        "total_vulnerabilities": 0,
        "total_exploits": 0,
        "total_api_endpoints": 0,
        "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "risk_score": 0,
        "risk_level": "INFO",
    }


def _build_summary(asset_results: List[Dict], all_vulns: List[Dict]) -> Dict[str, Any]:
    """构建汇总统计

    Args:
        asset_results: 所有资产的分析结果列表
        all_vulns: 所有漏洞的字典列表

    Returns:
        汇总统计字典
    """
    total_assets = len(asset_results)
    total_technologies = sum(ar.get("tech_count", 0) for ar in asset_results)
    total_vulnerabilities = len(all_vulns)
    total_exploits = sum(len(ar.get("exploits", [])) for ar in asset_results)
    total_api_endpoints = sum(len(ar.get("api_endpoints", [])) for ar in asset_results)

    # 严重等级分布
    severity_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for vuln in all_vulns:
        sev = vuln.get("severity", "").upper()
        if sev in severity_dist:
            severity_dist[sev] += 1
        else:
            severity_dist[sev] = severity_dist.get(sev, 0) + 1

    # 风险评分（基于严重等级权重）
    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
    raw_score = sum(weights.get(v.get("severity", "").upper(), 1) for v in all_vulns)
    max_possible = total_vulnerabilities * 10 if total_vulnerabilities > 0 else 1
    risk_score = min(100, int((raw_score / max_possible) * 100)) if total_vulnerabilities > 0 else 0

    risk_level = determine_overall_risk_level(severity_dist)

    return {
        "total_assets": total_assets,
        "total_technologies": total_technologies,
        "total_vulnerabilities": total_vulnerabilities,
        "total_exploits": total_exploits,
        "total_api_endpoints": total_api_endpoints,
        "severity_distribution": severity_dist,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


# ============================================================
# 路由定义
# ============================================================

@app.route("/")
def index():
    """主页 - 渲染查询输入界面"""
    # 将环境变量中的 FOFA 凭据状态传递给前端（只传递是否已配置，不传递实际值）
    return render_template(
        "index.html",
        fofa_key_configured=bool(Config.FOFA_KEY),
        admin_password_configured=Config.ADMIN_PASSWORD_CONFIGURED,
    )


@app.route("/dashboard")
def dashboard():
    """大脑监控中心 - 实时节点状态 / 数据可视化 / 对话接口"""
    resp = send_from_directory(BASE_DIR, "dashboard.html")
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp


@app.route("/situation")
def situation():
    """态势感知大屏 - 全屏实时安全态势可视化"""
    return send_from_directory(BASE_DIR, "situation.html")


@app.route("/api/analyze", methods=["POST"])
@require_admin
def api_analyze():
    """执行分析 - 接收 FOFA 查询参数，启动后台分析线程（需要管理员权限）

    请求参数（JSON 或表单）：
        query: 测绘平台查询语句
        fofa_key: FOFA Key（可选）
        size: 返回结果数量（默认 100）
        scan_api: 是否扫描 API（"true"/"false"）
        online_query: 是否在线查询 NVD/OSV（"true"/"false"）
    """
    data = request.get_json(silent=True) or request.form

    fofa_query = (data.get("query") or "").strip()
    fofa_key = (data.get("fofa_key") or "").strip()
    try:
        fofa_size = int(data.get("size", Config.FOFA_SIZE))
    except (ValueError, TypeError):
        fofa_size = Config.FOFA_SIZE
    if fofa_size < 1:
        return jsonify({"error": "结果数量必须大于 0"}), 400

    scan_api = str(data.get("scan_api", "false")).lower() == "true"
    online_query = str(data.get("online_query", "false")).lower() == "true"

    if not fofa_query:
        return jsonify({"error": "资产查询语句不能为空"}), 400

    # 创建任务
    task_id = generate_task_id()
    with tasks_lock:
        tasks[task_id] = {
            "status": "pending",
            "progress": 0,
            "current_step": "等待开始分析...",
            "analyzed_count": 0,
            "total_count": 0,
            "results": None,
            "error": None,
            "created_at": time.time(),
            "cancel_requested": False,
        }
        new_task = dict(tasks[task_id])
    scan_database.create_task(task_id, new_task, {
        "mode": "fofa", "query_text": fofa_query, "requested_size": fofa_size,
        "scan_api": scan_api, "online_query": online_query,
    })

    # 启动后台分析线程
    thread = threading.Thread(
        target=run_analysis,
        args=(task_id, "fofa", fofa_query, fofa_key,
              fofa_size, "", scan_api, online_query),
        daemon=True,
    )
    thread.start()

    logger.info("已创建测绘平台分析任务: %s (query=%r)", task_id, fofa_query)
    return jsonify({"task_id": task_id, "status": "pending"})


@app.route("/api/analyze/status/<task_id>")
def api_analyze_status(task_id):
    """获取分析进度

    返回任务当前状态、进度百分比、当前步骤等信息。
    """
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    return jsonify({
        "task_id": task_id,
        "status": task["status"],
        "progress": task["progress"],
        "current_step": task["current_step"],
        "analyzed_count": task["analyzed_count"],
        "total_count": task["total_count"],
        "error": task["error"],
    })


@app.route("/api/results/<task_id>")
def api_results(task_id):
    """获取分析结果

    仅在任务状态为 completed 时返回完整结果。
    """
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404

    if task["status"] != "completed":
        return jsonify({
            "error": "分析尚未完成",
            "status": task["status"],
            "progress": task["progress"],
        }), 202

    return jsonify(task["results"])


@app.route("/api/manual", methods=["POST"])
@require_admin
def api_manual():
    """手动输入资产进行分析 - 不通过 FOFA，直接输入 URL 列表（需要管理员权限）

    请求参数（JSON 或表单）：
        urls: URL 列表文本（每行一个）
        scan_api: 是否扫描 API
        online_query: 是否在线查询 NVD/OSV
    """
    data = request.get_json(silent=True) or request.form

    url_text = data.get("urls") or ""
    scan_api = str(data.get("scan_api", "false")).lower() == "true"
    online_query = str(data.get("online_query", "false")).lower() == "true"

    if not url_text.strip():
        return jsonify({"error": "请输入至少一个 URL"}), 400

    if not parse_urls_to_assets(url_text):
        return jsonify({"error": "没有可用的 URL，请输入 http:// 或 https:// 地址"}), 400

    # 创建任务
    task_id = generate_task_id()
    with tasks_lock:
        tasks[task_id] = {
            "status": "pending",
            "progress": 0,
            "current_step": "等待开始分析...",
            "analyzed_count": 0,
            "total_count": 0,
            "results": None,
            "error": None,
            "created_at": time.time(),
            "cancel_requested": False,
        }
        new_task = dict(tasks[task_id])
    scan_database.create_task(task_id, new_task, {
        "mode": "manual", "query_text": url_text, "requested_size": len(parse_urls_to_assets(url_text)),
        "scan_api": scan_api, "online_query": online_query,
    })

    # 启动后台分析线程
    thread = threading.Thread(
        target=run_analysis,
        args=(task_id, "manual", "", "", 0, url_text, scan_api, online_query),
        daemon=True,
    )
    thread.start()

    logger.info("已创建手动分析任务: %s", task_id)
    return jsonify({"task_id": task_id, "status": "pending"})


@app.route("/api/analyze/cancel/<task_id>", methods=["POST"])
@require_admin
def api_cancel_analysis(task_id):
    """请求取消任务；当前单个网络请求结束后停止后续分析。"""
    task = get_task(task_id)
    if not task:
        return jsonify({"error": "任务不存在"}), 404
    if task["status"] in ("completed", "error", "cancelled"):
        return jsonify({"error": "任务已结束", "status": task["status"]}), 409
    update_task(task_id, cancel_requested=True, current_step="正在停止分析...")
    return jsonify({"success": True, "status": "cancelling"})


@app.route("/api/tasks")
def api_task_history():
    """Public read-only scan history; reports remain available after restart."""
    try:
        limit = max(1, min(200, int(request.args.get("limit", 50))))
    except ValueError:
        limit = 50
    return jsonify({"tasks": scan_database.list_tasks(limit)})


# ============================================================
# 认证相关路由
# ============================================================

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    """登录 - 支持管理员和游客两种角色
    
    请求参数（JSON）：
        role: 角色（admin/guest），默认 guest
        password: 密码（admin 角色需要验证）
    """
    data = request.get_json()
    role = data.get("role", "admin")
    password = data.get("password", "")

    if role != "admin":
        return jsonify({"error": "不支持的登录角色"}), 400

    session = session_manager.create_session(role, password)
    if not session:
        return jsonify({"error": "密码错误"}), 401

    response = jsonify({
        "session_id": session.session_id,
        "role": session.role,
    })
    response.set_cookie("session_id", session.session_id, max_age=86400, httponly=True)
    return response


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    """登出 - 销毁当前会话并清除 Cookie"""
    session_id = request.cookies.get("session_id")
    if session_id:
        session_manager.destroy_session(session_id)
    response = jsonify({"success": True})
    response.delete_cookie("session_id")
    return response


@app.route("/api/auth/status")
def api_auth_status():
    """获取当前会话状态
    
    返回当前登录状态、角色信息，前端据此控制 UI 显示。
    """
    session_id = request.cookies.get("session_id")
    session = session_manager.get_session(session_id)
    if session:
        return jsonify({
            "logged_in": True,
            "role": session.role,
            "is_admin": session.is_admin,
        })
    return jsonify({"logged_in": False, "role": "guest", "is_admin": False})


@app.route("/api/fofa/config")
def api_fofa_config():
    """返回 FOFA 凭据配置状态（前端用于判断是否需要手动输入）"""
    return jsonify({
        "fofa_key_configured": bool(Config.FOFA_KEY),
        "default_size": Config.FOFA_SIZE,
    })


@app.route("/api/ai/config")
def api_ai_config():
    """返回 AI 分析配置状态

    前端据此判断是否展示 AI 分析面板以及提示用户配置 API Key。
    仅返回配置状态，不返回实际的 API Key。
    """
    return jsonify({
        # AI 分析是否可用（同时要求 API Key 已配置且开关已开启）
        "ai_enabled": bool(Config.DEEPSEEK_API_KEY) and Config.AI_ANALYSIS_ENABLED,
        # API Key 是否已配置（不含实际值）
        "api_key_configured": bool(Config.DEEPSEEK_API_KEY),
        # AI 分析全局开关
        "analysis_enabled": Config.AI_ANALYSIS_ENABLED,
        # 使用的模型名称
        "model": Config.DEEPSEEK_MODEL,
        # 主模型失败时自动使用的 OpenAI-compatible 备用模型
        "fallback_configured": bool(Config.OPENAI_API_KEY),
        "fallback_model": Config.OPENAI_MODEL if Config.OPENAI_API_KEY else "",
        # 请求超时时间
        "timeout": Config.AI_TIMEOUT,
    })


@app.route("/api/showcase")
def api_showcase():
    """Return all completed scans as one deduplicated public inventory."""
    completed = [
        task for task in scan_database.list_tasks(200)
        if task.get("status") == "completed"
    ]
    if not completed:
        # 无手动扫描任务时，仍返回研究资产库真实统计（与 Dashboard 同源），避免首页全 0
        try:
            sc = api_supply_chain_overview_data()
            empty_summary = {
                "total_assets": 0, "total_technologies": 0, "total_api_endpoints": 0,
                "total_vulnerabilities": 0, "identified_project_families": 0,
                "research_assets_total": sc.get("total_assets", 0),
                "research_assets_analyzed": sc.get("analyzed_assets", 0),
                "research_vuln_total": sc.get("vuln_total", 0),
                "research_vuln_suspected": sc.get("vuln_suspected", 0),
                "research_vuln_condition_matched": sc.get("vuln_condition_matched", 0),
                "research_vuln_verified": sc.get("vuln_verified", 0),
                "research_risk_critical_high": (sc.get("risk_buckets") or {}).get("CRITICAL", 0)
                    + (sc.get("risk_buckets") or {}).get("HIGH", 0),
                "research_api_exposed": sc.get("api_exposed_assets", 0),
                "avg_components": sc.get("avg_components", 0),
            }
        except Exception:
            empty_summary = {}
        return jsonify({"task_count": 0, "summary": empty_summary, "assets": [],
                        "risk_events": [], "action_summary": {"action_assets": 0}})

    # Tasks are newest first. Keep the newest observation for each URL or
    # IP/port identity while retaining provenance and first-seen time.
    inventory = {}
    for task_meta in completed:
        task = scan_database.get_task(task_meta["task_id"])
        results = task.get("results") or {}
        for item in results.get("assets", []):
            asset = item.get("asset", {})
            identity = (
                (asset.get("url") or "").rstrip("/").lower()
                or f"{asset.get('ip', '')}:{asset.get('port', 0)}"
            )
            if not identity:
                continue
            if identity in inventory:
                inventory[identity]["first_seen"] = min(
                    inventory[identity]["first_seen"], task.get("created_at", 0)
                )
                inventory[identity]["scan_count"] += 1
                continue
            inventory[identity] = {
                "first_seen": task.get("created_at", 0),
                "last_seen": task.get("updated_at", 0),
                "scan_count": 1,
                "asset": {
                    key: asset.get(key, "") for key in (
                        "host", "ip", "port", "title", "server", "protocol",
                        "country", "city", "domain", "url", "icp",
                    )
                },
                "technologies": item.get("technologies", []),
                "supply_chains": item.get("supply_chains", []),
                "vulnerabilities": item.get("vulnerabilities", []),
                "api_endpoints": item.get("api_endpoints", []),
                "api_report": item.get("api_report"),
                "exposure_findings": item.get("exposure_findings", []),
                "ownership_profile": item.get("ownership_profile", {}),
                "tech_count": item.get("tech_count", 0),
                "vuln_count": item.get("vuln_count", 0),
                "risk_level": item.get("risk_level", "INFO"),
                "error": item.get("error"),
            }

    public_assets = list(inventory.values())
    # Promote completed autonomous-engine observations into the same public
    # inventory. Candidate-only records remain in the research overview.
    for item in scan_database.analyzed_research_assets(2000):
        asset = item.get("asset") or {}
        identity = ((asset.get("url") or "").rstrip("/").lower()
                    or f"{asset.get('ip', '')}:{asset.get('port', 0)}")
        if identity and identity not in inventory:
            inventory[identity] = item
    public_assets = list(inventory.values())
    # Active HTTP collection is generally more reliable than sparse discovery
    # metadata. Promote it into the public asset title without mutating history.
    for item in public_assets:
        owner = item.get("ownership_profile") or {}
        if not item["asset"].get("title") and owner.get("site_title"):
            item["asset"]["title"] = owner["site_title"]
        item["project_family"] = item.get("project_family") or identify_project_family(item)
        item["vulnerabilities"] = [
            classify_vulnerability_evidence(vulnerability, item)
            for vulnerability in item["vulnerabilities"]
        ]
    severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in public_assets:
        for vuln in item["vulnerabilities"]:
            severity = (vuln.get("severity") or "").upper()
            if severity in severity_distribution:
                severity_distribution[severity] += 1

    summary = {
        "total_assets": len(public_assets),
        "total_technologies": sum(len(item["technologies"]) for item in public_assets),
        "total_api_endpoints": sum(len(item["api_endpoints"]) for item in public_assets),
        "total_vulnerabilities": sum(len(item["vulnerabilities"]) for item in public_assets),
        "identified_project_families": len({
            item["project_family"]["name"] for item in public_assets
            if item.get("project_family")
        }),
        "severity_distribution": severity_distribution,
    }
    # 补充研究资产库真实统计（与 Dashboard 同源：research_assets 全量 + 分析结果）
    try:
        sc_overview = api_supply_chain_overview_data()
        summary["research_assets_total"] = sc_overview.get("total_assets", 0)
        summary["research_assets_analyzed"] = sc_overview.get("analyzed_assets", 0)
        summary["research_vuln_total"] = sc_overview.get("vuln_total", 0)
        summary["research_vuln_suspected"] = sc_overview.get("vuln_suspected", 0)
        summary["research_vuln_condition_matched"] = sc_overview.get("vuln_condition_matched", 0)
        summary["research_vuln_verified"] = sc_overview.get("vuln_verified", 0)
        summary["research_risk_critical_high"] = (sc_overview.get("risk_buckets") or {}).get("CRITICAL", 0) + \
            (sc_overview.get("risk_buckets") or {}).get("HIGH", 0)
        summary["research_api_exposed"] = sc_overview.get("api_exposed_assets", 0)
        summary["avg_components"] = sc_overview.get("avg_components", 0)
    except Exception as exc:
        logger.warning("补充研究资产统计失败: %s", exc)
    event_groups = {}
    for item in public_assets:
        asset = item["asset"]
        owner = item.get("ownership_profile") or {}
        for finding in item.get("exposure_findings", []):
            fields = finding.get("sensitive_field_types") or []
            if not (finding.get("publicly_accessible") and fields):
                continue
            credential_related = any(field in fields for field in (
                "API 密钥", "访问令牌", "密码", "私钥", "云凭据",
            ))
            event_type = "疑似凭据暴露" if credential_related else "敏感配置页面公开"
            group_key = (asset.get("ip") or asset.get("host") or asset.get("url"), event_type)
            if group_key in event_groups:
                event = event_groups[group_key]
                route_key = (urlparse(finding.get("url", "")).path, tuple(fields))
                known_keys = {(route["path"], tuple(route["field_types"])) for route in event["evidence_routes"]}
                if route_key not in known_keys:
                    event["evidence_routes"].append({
                        "path": route_key[0], "url": finding.get("url", ""),
                        "field_types": fields, "source": finding.get("source", ""),
                        "status_code": finding.get("status_code", 0),
                    })
                event["protocols"] = sorted(set(event["protocols"] + [asset.get("protocol", "")]))
                event["field_types"] = sorted(set(event["field_types"] + fields))
                continue
            event_groups[group_key] = {
                "event_id": f"public-risk-{len(event_groups) + 1}",
                "priority": "P0" if credential_related else "P1",
                "event_type": event_type,
                "verification_status": "待人工确认",
                "confidence": "high" if finding.get("source") in ("JavaScript Bundle", "Next.js Manifest") else "medium",
                "asset": {
                    "ip": asset.get("ip", ""), "url": asset.get("url", ""),
                    "title": asset.get("title", ""), "domain": asset.get("domain", ""),
                },
                "finding_url": finding.get("url", ""),
                "field_types": fields,
                "protocols": [asset.get("protocol", "")],
                "evidence_routes": [{
                    "path": urlparse(finding.get("url", "")).path,
                    "url": finding.get("url", ""), "field_types": fields,
                    "source": finding.get("source", ""),
                    "status_code": finding.get("status_code", 0),
                }],
                "evidence": finding.get("evidence", ""),
                "source": finding.get("source", ""),
                "status_code": finding.get("status_code", 0),
                "owner": owner.get("organization") or "待确认",
                "disclosure_status": "待确认责任方",
                "last_seen": item.get("last_seen", 0),
            }
    risk_events = list(event_groups.values())
    risk_events.sort(key=lambda event: (event["priority"], event["asset"].get("ip", "")))
    action_summary = {
        "action_assets": len({event["asset"].get("ip") or event["asset"].get("url") for event in risk_events}),
        "credential_exposures": sum(event["event_type"] == "疑似凭据暴露" for event in risk_events),
        "configuration_exposures": sum(event["event_type"] == "敏感配置页面公开" for event in risk_events),
        "identified_owners": len({
            event["asset"].get("ip") for event in risk_events if event["owner"] != "待确认"
        }),
    }
    return jsonify({
        "task_count": len(completed),
        "updated_at": max(task.get("updated_at", 0) for task in completed),
        "summary": summary,
        "risk_events": risk_events,
        "action_summary": action_summary,
        "assets": public_assets,
    })


@app.route("/api/research/overview")
def api_research_overview():
    """Public, sanitized status of autonomous project research."""
    from core.research_brain import SEED_PROJECTS
    from core.database import ScanDatabase

    overview = scan_database.research_overview()
    # 查询各项目已分析资产的漏洞，计算高危 CVE / 公开部署估算
    db = ScanDatabase(Config.DATABASE_PATH)
    project_critical = {}
    project_analyzed_assets = {}
    try:
        conn = db._connect()
        rows = conn.execute(
            "SELECT project_slug, analysis_json FROM research_assets "
            "WHERE analysis_json IS NOT NULL AND analysis_json != ''").fetchall()
        conn.close()
        for row in rows:
            slug = row["project_slug"]
            project_analyzed_assets.setdefault(slug, 0)
            project_analyzed_assets[slug] += 1
            try:
                an = json.loads(row["analysis_json"])
            except Exception:
                continue
            for v in (an.get("vulnerabilities") or []):
                sev = (v.get("severity") or "").upper()
                if sev in ("CRITICAL", "HIGH"):
                    project_critical.setdefault(slug, [])
                    project_critical[slug].append(v.get("cve_id") or v.get("id") or "")
        for slug in project_critical:
            project_critical[slug] = list(dict.fromkeys(
                c for c in project_critical[slug] if c))[:5]
    except Exception as exc:
        logger.warning("统计项目高危漏洞失败: %s", exc)

    seed_map = {p.get("slug"): p for p in SEED_PROJECTS}
    projects = []
    for project in overview["projects"]:
        if not project.get("enabled"):
            continue
        item = {
            key: project.get(key) for key in (
                "slug", "name", "repository", "upstream", "license", "category",
                "priority", "rationale", "last_run_at", "next_run_at", "asset_count",
                "analyzed_count", "pending_count", "rejected_count", "insight", "insight_updated_at",
            )
        }
        seed = seed_map.get(project.get("slug"), {})
        item["discovery_query"] = seed.get("discovery_query", "")
        item["critical_cves"] = project_critical.get(project.get("slug"), [])
        # 公开部署估算：analyzed_count 已分析数量 + pending 待处理
        item["deployment_estimate"] = (project.get("asset_count") or 0)
        projects.append(item)
    runs = [{
        key: run.get(key) for key in (
            "project_name", "status", "reason", "discovered_count", "new_count",
            "started_at", "finished_at",
        )
    } for run in overview["runs"]]
    return jsonify({
        "enabled": Config.RESEARCH_BRAIN_ENABLED,
        "model": Config.RESEARCH_AI_MODEL if Config.DEEPSEEK_API_KEY else "规则回退",
        "interval_seconds": Config.RESEARCH_INTERVAL_SECONDS,
        "total_candidate_assets": sum(project.get("asset_count") or 0 for project in projects),
        "projects": projects, "runs": runs,
        "trends": {
            "signals": overview.get("intelligence", {}).get("signals", []),
            "last_sync": overview.get("intelligence", {}).get("last_sync"),
        },
    })


@app.route("/api/lab/overview")
@require_admin
def api_lab_overview():
    return jsonify(scan_database.lab_overview())


# ============================================================
# 大脑端：任务分发 API（向执行引擎下发任务 / 查看节点）
# ============================================================
@app.route("/api/dispatch", methods=["POST"])
def api_dispatch():
    """向执行引擎下发任务。Body: {"type": "scan", "params": {...}, "broadcast": false}"""
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    broadcast = bool(payload.get("broadcast", False))
    task = {"type": payload.get("type", "scan"), "params": payload.get("params", {})}
    if broadcast:
        results = task_dispatcher.dispatch_to_all(task)
        return jsonify({"ok": True, "results": results})
    result = task_dispatcher.dispatch(task)
    return jsonify(result), (200 if result.get("ok") else 502)


@app.route("/api/nodes/status")
def api_nodes_status():
    """节点集群实时状态（供态势大屏展示每台节点在干什么）"""
    planner = globals().get("node_planner")
    if planner:
        return jsonify(planner.node_status())
    return jsonify({"nodes": [], "total": 0, "online": 0})


@app.route("/api/nodes/pump", methods=["POST"])
def api_nodes_pump():
    """手动给节点集群派活：把某项目的待分析资产分发给节点。
    Body: {"project": "dify", "limit": 40}
    """
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    project = (payload.get("project") or "").strip()
    limit = min(int(payload.get("limit", 40)), 100)
    planner = globals().get("node_planner")
    if not planner:
        return jsonify({"error": "node_planner 未初始化"}), 500
    if not project:
        # 未指定项目：找下一个有 pending 资产的项目
        proj = scan_database.next_project_with_pending_assets()
        if not proj:
            return jsonify({"ok": False, "error": "没有待分析项目"})
        project = proj["slug"]
    pending = scan_database.pending_research_assets(project, limit)
    targets = [c["asset"].get("url") for c in pending if c.get("asset", {}).get("url")]
    name = project
    proj_row = scan_database.next_project_with_pending_assets()
    if proj_row and proj_row.get("slug") == project:
        name = proj_row.get("name", project)
    result = planner.dispatch_pending(project, targets, name)
    return jsonify(result), (200 if result.get("ok") else 502)


@app.route("/api/nodes")
def api_nodes():
    """查看配置的执行引擎节点列表"""
    nodes = []
    for n in task_dispatcher.list_nodes():
        nodes.append({k: n[k] for k in ("node_id", "name", "url", "capabilities", "enabled")})
    return jsonify({"nodes": nodes})


@app.route("/api/tasks/assign")
def api_tasks_assign():
    """Lease one durable task to a worker (outbound-only worker topology)."""
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    node_id = (request.args.get("node_id") or request.headers.get("X-Node-Id") or "").strip()
    if not node_id:
        return jsonify({"error": "node_id required"}), 400
    task_id = (request.args.get("task_id") or "").strip()
    task = scan_database.claim_node_task(node_id, lease_seconds=300, task_id=task_id)
    return jsonify({"task": task})


@app.route("/api/tasks/lease/renew", methods=["POST"])
def api_tasks_lease_renew():
    """Renew one active Worker attempt lease."""
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    node_id = (payload.get("node_id") or request.headers.get("X-Node-Id") or "").strip()
    task_id = (payload.get("task_id") or "").strip()
    attempt_id = (payload.get("attempt_id") or "").strip()
    if not node_id or not task_id or not attempt_id:
        return jsonify({"error": "node_id, task_id and attempt_id required"}), 400
    ok = scan_database.renew_node_task_lease(
        task_id, attempt_id, node_id, lease_seconds=300)
    return jsonify({"ok": ok}), (200 if ok else 409)


@app.route("/api/tasks/<task_id>/attempts")
@require_admin
def api_task_attempts(task_id):
    """Admin-only task attempt timeline; payloads and evidence are omitted."""
    attempts = scan_database.node_task_attempts(task_id)
    return jsonify({"task_id": task_id, "attempts": attempts})


@app.route("/api/tasks/dead")
@require_admin
def api_dead_tasks():
    """Admin-only dead-letter queue view; target and result payloads are omitted."""
    try:
        limit = min(200, max(1, int(request.args.get("limit", 50))))
    except (TypeError, ValueError):
        return jsonify({"error": "limit must be an integer"}), 400
    project_slug = (request.args.get("project_slug") or "").strip()
    tasks = scan_database.dead_node_tasks(limit=limit, project_slug=project_slug)
    return jsonify({"tasks": tasks, "count": len(tasks)})


@app.route("/api/tasks/<task_id>/retry", methods=["POST"])
@require_admin
def api_retry_dead_task(task_id):
    """Grant exactly one additional attempt to a terminal dead-letter task."""
    payload = request.get_json(silent=True) or {}
    reason = str(payload.get("reason") or "管理员人工重试").strip()[:500]
    retried = scan_database.retry_dead_node_task(task_id)
    if not retried:
        return jsonify({"ok": False, "error": "task not found or not dead"}), 409
    scan_database.brain_event(
        event_type="action", action="重试死信任务",
        detail=(f"任务 {task_id} 已重新进入 pending · "
                f"attempt {retried['attempt_count'] + 1}/{retried['max_attempts']}"),
        reason=reason, meta={"task_id": task_id, **retried},
    )
    return jsonify({"ok": True, "task": retried})


# ============================================================
# 大脑端：实时监控 / 数据可视化 / 对话接口
# ============================================================
def _monitor_summary() -> Dict[str, Any]:
    lab = scan_database.lab_overview()
    nodes = lab.get("nodes", [])
    experiments = lab.get("experiments", [])
    return {
        "total_nodes": len(nodes),
        "online_nodes": sum(1 for node in nodes if node.get("online")),
        "total_experiments": len(experiments),
        "completed_experiments": sum(
            1 for experiment in experiments if experiment.get("status") == "completed"),
        "error_experiments": sum(
            1 for experiment in experiments if experiment.get("status") == "error"),
    }


@app.route("/api/monitor/summary")
def api_monitor_summary():
    """Small public health response without node, task or evidence details."""
    return jsonify({"status": "ok", "summary": _monitor_summary()})


@app.route("/api/monitor/overview")
@require_admin
def api_monitor_overview():
    """实时监控总览：各节点在线状态 + 最近任务 + 实验统计"""
    lab = scan_database.lab_overview()
    nodes = lab.get("nodes", [])
    experiments = lab.get("experiments", [])
    tasks = scan_database.list_tasks(limit=20)

    summary = {
        "total_nodes": len(nodes),
        "online_nodes": sum(1 for n in nodes if n.get("online")),
        "total_experiments": len(experiments),
        "completed_experiments": sum(1 for e in experiments if e.get("status") == "completed"),
        "error_experiments": sum(1 for e in experiments if e.get("status") == "error"),
        "total_tasks": len(tasks),
    }

    # 节点实时状态（含资源指标）
    node_status = []
    for n in nodes:
        metrics = n.get("metrics", {})
        node_status.append({
            "node_id": n.get("node_id"),
            "name": n.get("name"),
            "online": n.get("online"),
            "status": n.get("status"),
            "last_heartbeat": n.get("last_heartbeat"),
            "capabilities": n.get("capabilities", []),
            "metrics": {
                "cpu_percent": metrics.get("cpu_percent"),
                "mem_total": metrics.get("mem_total"),
                "mem_used": metrics.get("mem_used"),
                "mem_available": metrics.get("mem_available"),
                "load1": metrics.get("load1"),
                "disk_total": metrics.get("disk_total"),
                "disk_free": metrics.get("disk_free"),
                "uptime": metrics.get("uptime"),
                "pid": metrics.get("pid"),
            },
        })

    return jsonify({"summary": summary, "nodes": node_status,
                    "worker_queue": scan_database.node_task_overview(),
                    "recent_tasks": tasks,
                    "recent_experiments": experiments[:20]})


@app.route("/api/monitor/node/<node_id>")
@require_admin
def api_monitor_node(node_id):
    """单个节点详情（从数据库 lab_nodes 查）"""
    lab = scan_database.lab_overview()
    for n in lab.get("nodes", []):
        if n.get("node_id") == node_id:
            return jsonify(n)
    return jsonify({"error": "node not found"}), 404


@app.route("/api/experiments")
@require_admin
def api_experiments():
    """实验结果列表（含完整 evidence），支持 ?node_id= 过滤"""
    lab = scan_database.lab_overview()
    experiments = lab.get("experiments", [])
    node_id = request.args.get("node_id")
    if node_id:
        experiments = [e for e in experiments if e.get("node_id") == node_id]
    # 精简输出：完整返回 evidence
    out = []
    for e in experiments:
        item = {
            "experiment_id": e.get("experiment_id"),
            "node_id": e.get("node_id"),
            "project_slug": e.get("project_slug"),
            "project_name": e.get("project_name"),
            "version": e.get("version"),
            "status": e.get("status"),
            "hypothesis": e.get("hypothesis"),
            "public_observation": e.get("public_observation"),
            "reproduction_summary": e.get("reproduction_summary"),
            "remediation": e.get("remediation"),
            "conclusion_boundary": e.get("conclusion_boundary"),
            "created_at": e.get("created_at"),
            "updated_at": e.get("updated_at"),
            "evidence": e.get("evidence", []),
        }
        out.append(item)
    return jsonify({"experiments": out, "total": len(out)})


@app.route("/api/experiments/<experiment_id>")
@require_admin
def api_experiment_detail(experiment_id):
    """单个实验结果详情"""
    lab = scan_database.lab_overview()
    for e in lab.get("experiments", []):
        if e.get("experiment_id") == experiment_id:
            return jsonify(e)
    return jsonify({"error": "experiment not found"}), 404


@app.route("/api/assets")
def api_assets():
    """测绘平台风格资产列表：聚合 research_assets + 实验 evidence 中的资产

    ?query= 搜索过滤（host/ip/title）
    ?limit= 条数（默认 100，求质不求量）
    """
    from core.database import ScanDatabase
    db = ScanDatabase(Config.DATABASE_PATH)
    query = (request.args.get("query") or "").strip().lower()
    limit = min(int(request.args.get("limit", "100")), 500)

    assets = []
    seen = set()

    # 1. 从 research_assets 取（合并分析结果：风险评分 / 组件指纹 / 漏洞数）
    try:
        conn = db._connect()
        rows = conn.execute(
            "SELECT a.asset_json, a.project_slug, a.analysis_json, a.analysis_status, a.analyzed_at "
            "FROM research_assets a JOIN research_projects p ON p.slug=a.project_slug "
            "WHERE p.enabled=1 ORDER BY "
            "CASE WHEN a.analysis_status='completed' AND a.analysis_json IS NOT NULL THEN 0 ELSE 1 END, "
            "a.analyzed_at DESC, a.last_seen DESC LIMIT ?",
            (limit * 3,)).fetchall()
        conn.close()
        for row in rows:
            try:
                asset = json.loads(row["asset_json"])
            except Exception:
                continue
            key = asset.get("host") or asset.get("ip") or asset.get("url")
            if not key or key in seen:
                continue
            asset.setdefault("project_slug", row["project_slug"])
            # 附加分析摘要（风险评分 / 组件 / 漏洞 / 分析时间）
            asset["analysis_status"] = row["analysis_status"] or ""
            asset["analyzed_at"] = row["analyzed_at"] or 0
            if row["analysis_json"]:
                try:
                    an = json.loads(row["analysis_json"])
                    asset["risk_level"] = an.get("risk_level", "")
                    asset["risk_score"] = an.get("risk_score", 0)
                    asset["vuln_count"] = an.get("vuln_count", 0)
                    asset["tech_count"] = an.get("tech_count", 0)
                    asset["components"] = [
                        {"name": t.get("name", ""), "version": t.get("version", ""),
                         "category": t.get("category", "")}
                        for t in (an.get("technologies") or [])
                    ][:10]
                    asset["api_count"] = len(an.get("api_endpoints") or [])
                    asset["critical_count"] = sum(
                        1 for v in (an.get("vulnerabilities") or [])
                        if (v.get("severity") or "").upper() in ("CRITICAL", "HIGH"))
                except Exception:
                    pass
            assets.append(asset)
            seen.add(key)
            if len(assets) >= limit:
                break
    except Exception as exc:
        logger.warning("读取 research_assets 失败: %s", exc)

    # 2. 从实验 evidence 补（fofa 资产类型的 evidence）
    if len(assets) < limit:
        lab = scan_database.lab_overview()
        for e in lab.get("experiments", []):
            for item in e.get("evidence", []):
                if "host" in item or "ip" in item or "url" in item:
                    key = item.get("host") or item.get("ip") or item.get("url")
                    if key in seen:
                        continue
                    asset = dict(item)
                    asset.setdefault("project_slug", e.get("project_slug"))
                    assets.append(asset)
                    seen.add(key)
                    if len(assets) >= limit:
                        break
            if len(assets) >= limit:
                break

    # 过滤
    if query:
        assets = [a for a in assets if query in (a.get("host") or "").lower()
                  or query in (a.get("ip") or "").lower()
                  or query in (a.get("title") or "").lower()]

    return jsonify({"total": len(assets), "assets": assets})


@app.route("/api/asset/detail")
def api_asset_detail():
    """单资产深度详情：组件树 + 供应链 + 漏洞 + API + 敏感信息

    ?host= 资产 host/ip/url（必填）
    数据来源：research_assets.analysis_json（研究大脑深度分析结果）
    """
    host = (request.args.get("host") or "").strip()
    if not host:
        return jsonify({"error": "host 必填"}), 400

    from core.database import ScanDatabase
    db = ScanDatabase(Config.DATABASE_PATH)
    detail = {
        "asset": None, "technologies": [], "supply_chains": [], "vulnerabilities": [],
        "exploits": [], "api_endpoints": [], "api_report": None,
        "exposure_findings": [], "ownership_profile": {},
        "vuln_count": 0, "tech_count": 0, "risk_level": "INFO", "risk_score": 0,
        "confidence": "low", "finding_summary": [],
        "analysis_status": "", "analyzed_at": 0, "source": "database",
    }
    # 1. 从 research_assets 的 analysis_json 取（前端路由暴露 / 项目确认等）
    try:
        conn = db._connect()
        row = conn.execute(
            "SELECT a.asset_json, a.analysis_json, a.analysis_status, a.analyzed_at, a.project_slug "
            "FROM research_assets a JOIN research_projects p ON p.slug=a.project_slug "
            "WHERE p.enabled=1 AND a.asset_json LIKE ? ORDER BY a.analyzed_at DESC LIMIT 1",
            ("%" + host + "%",)).fetchone()
        if row:
            try:
                an = json.loads(row["analysis_json"]) if row["analysis_json"] else {}
                if an:
                    detail["asset"] = json.loads(row["asset_json"])
                    detail.update({k: an.get(k) for k in (
                        "technologies", "supply_chains", "vulnerabilities", "exploits",
                        "api_endpoints", "api_report", "exposure_findings",
                        "ownership_profile", "vuln_count", "tech_count", "risk_level",
                        "risk_score", "confidence", "finding_summary")})
                    detail["analysis_status"] = row["analysis_status"] or ""
                    detail["analyzed_at"] = row["analyzed_at"] or 0
                    detail["project_slug"] = row["project_slug"]
                    detail["source"] = "database"
            except Exception:
                pass
        conn.close()
    except Exception as exc:
        logger.warning("读取资产详情失败: %s", exc)

    # 2. 从实验 evidence 补充深度分析结果（deep_analysis / api_crawl 的漏洞、组件、API、敏感信息）
    #    —— 与 database 数据合并：experiments 的结果往往更全
    lab = scan_database.lab_overview()
    merged_evidence = None
    for e in lab.get("experiments", []):
        for item in e.get("evidence", []):
            target = item.get("target") or item.get("host") or item.get("url") or ""
            if host in target or target in host:
                # 若已有 database 数据且该 evidence 漏洞/组件较少，跳过
                if merged_evidence is None and (item.get("vulnerabilities") or item.get("technologies")
                                                or item.get("api_endpoints") or item.get("sensitive_hits")):
                    merged_evidence = item
                    break
        if merged_evidence is not None:
            break
    if merged_evidence:
        if not detail.get("asset"):
            detail["asset"] = {"host": merged_evidence.get("target") or host,
                               "ip": merged_evidence.get("ip"), "port": merged_evidence.get("port"),
                               "title": merged_evidence.get("title"), "protocol": merged_evidence.get("protocol"),
                               "country": merged_evidence.get("country"), "city": merged_evidence.get("city")}
            detail["source"] = "experiment"
        # 合并：漏洞 / 技术 / API / 敏感信息（数据库缺失时补充，存在时去重合并）
        def _merge_into(key):
            existing = detail.get(key) or []
            add = merged_evidence.get(key) or []
            if not existing:
                detail[key] = add
            elif add:
                seen_keys = set()
                merged = list(existing)
                for x in add:
                    k = x.get("cve_id") or x.get("name") or x.get("url") or x.get("path") or json.dumps(x, sort_keys=True)
                    if k not in seen_keys:
                        seen_keys.add(k)
                        merged.append(x)
                detail[key] = merged
        for k in ("vulnerabilities", "technologies", "api_endpoints", "sensitive_hits",
                  "exposure_findings", "js_secret_scan"):
            _merge_into(k)
        detail["vuln_count"] = len(detail.get("vulnerabilities") or [])
        detail["tech_count"] = len(detail.get("technologies") or [])
        if not detail.get("project_slug"):
            detail["project_slug"] = merged_evidence.get("project_slug") or e.get("project_slug")

    if not detail.get("asset"):
        return jsonify({"error": "资产不存在", "host": host}), 404

    # 3. 关联 credential_leaks（SK 泄露直接显示在资产详情）
    try:
        leaks = scan_database.list_credential_leaks(limit=20, target=host)
        if leaks:
            for l in leaks:
                l.pop("api_key_full", None)
            detail["credential_leaks"] = leaks
            if not detail.get("sensitive_hits"):
                detail["sensitive_hits"] = []
            detail["sensitive_hits"].extend([{
                "secret_type": l.get("secret_type") or "API Key",
                "value_masked": l.get("api_key_masked") or "",
                "source": (l.get("base_url") or "") + " (" + (l.get("provider") or "") + ")",
            } for l in leaks])
    except Exception as exc:
        logger.warning("读取凭据泄露失败: %s", exc)

    # 汇总风险等级：根据漏洞严重程度推导
    if not detail.get("risk_level") or detail["risk_level"] == "INFO":
        vulns = detail.get("vulnerabilities") or []
        verified = [v for v in vulns if
                    (v.get("verification_status") or "suspected").lower() == "actively_verified"]
        conditions = [v for v in vulns if
                      (v.get("verification_status") or "suspected").lower() == "condition_matched"]
        if any((v.get("severity") or "").upper() == "CRITICAL" for v in verified):
            detail["risk_level"] = "CRITICAL"
        elif any((v.get("severity") or "").upper() == "HIGH" for v in verified):
            detail["risk_level"] = "HIGH"
        elif verified or conditions:
            detail["risk_level"] = "MEDIUM"
        elif detail.get("exposure_findings") or detail.get("sensitive_hits") or detail.get("credential_leaks"):
            detail["risk_level"] = "LOW"

    # 置信度推导（Grok 建议：指纹多特征命中=高；仅 title/URL 模糊=低）
    if not detail.get("confidence"):
        conf = "low"
        if any((v.get("verification_status") or "").lower() == "actively_verified"
               for v in detail.get("vulnerabilities") or []):
            conf = "high"
        elif detail.get("api_endpoints") or detail.get("exposure_findings") or detail.get("credential_leaks"):
            conf = "medium"
        detail["confidence"] = conf
    # 数据来源标签：FOFA / 主动探测 / 实验
    detail["data_source"] = "测绘平台" if detail.get("source") == "database" else "主动探测"
    return jsonify(detail)


@app.route("/api/supply-chain/overview")
def api_supply_chain_overview():
    """供应链健康仪表盘：资产组件分布、漏洞组件占比、高风险组件 TopN、API 暴露率"""
    return jsonify(api_supply_chain_overview_data())


def api_supply_chain_overview_data() -> Dict[str, Any]:
    """供应链健康统计（可被 /api/showcase 复用）"""
    from core.database import ScanDatabase
    db = ScanDatabase(Config.DATABASE_PATH)

    total_assets = 0
    analyzed_assets = 0
    component_counter = {}
    vuln_component_counter = {}
    component_vulns = {}
    api_asset_count = 0
    risk_buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    vuln_total = 0
    # 口径拆分（Codex P0-2，漏洞级）：suspected / condition_matched / actively_verified
    vuln_suspected = 0
    vuln_condition_matched = 0
    vuln_verified = 0
    verified_assets = 0

    try:
        conn = db._connect()
        rows = conn.execute(
            "SELECT a.asset_json, a.analysis_json, a.analysis_status FROM research_assets a "
            "JOIN research_projects p ON p.slug=a.project_slug WHERE p.enabled=1").fetchall()
        conn.close()
        for row in rows:
            total_assets += 1
            if not row["analysis_json"] or row["analysis_status"] not in ("analyzed", "completed", None):
                # 仍统计但有分析结果才计入组件
                if not row["analysis_json"]:
                    continue
            try:
                an = json.loads(row["analysis_json"])
            except Exception:
                continue
            if not an:
                continue
            analyzed_assets += 1
            risk_level = (an.get("risk_level") or "INFO").upper()
            risk_buckets[risk_level if risk_level in risk_buckets else "INFO"] += 1
            vulns = an.get("vulnerabilities") or []
            vuln_total += len(vulns)
            # 漏洞级 verification 统计：只聚合明确 verified；condition_matched 单独口径
            has_verified = False
            for v in vulns:
                vs = (v.get("verification_status") or "suspected").lower()
                if vs == "actively_verified":
                    vuln_verified += 1
                    has_verified = True
                elif vs == "condition_matched":
                    vuln_condition_matched += 1
                else:
                    vuln_suspected += 1
            if has_verified:
                verified_assets += 1
            vuln_assets = {v.get("component") for v in vulns if v.get("component")}
            if vulns:
                for v in vulns:
                    c = v.get("component") or "unknown"
                    component_vulns.setdefault(c, []).append(v)
            # 组件统计
            techs = an.get("technologies") or []
            for t in techs:
                c = t.get("name") or "unknown"
                component_counter[c] = component_counter.get(c, 0) + 1
                if c in vuln_assets:
                    vuln_component_counter[c] = vuln_component_counter.get(c, 0) + 1
            if an.get("api_endpoints"):
                api_asset_count += 1
    except Exception as exc:
        logger.warning("供应链统计失败: %s", exc)

    # 高风险组件 TopN（按漏洞数排序）
    top_risk_components = sorted(
        component_vulns.items(), key=lambda kv: len(kv[1]), reverse=True)[:10]
    top_risk = [{
        "component": c,
        "vuln_count": len(vs),
        "critical": sum(1 for v in vs if (v.get("severity") or "").upper() == "CRITICAL"),
        "cve_ids": [v.get("cve_id") for v in vs[:3]],
    } for c, vs in top_risk_components]

    # 常见组件 TopN（部署最广）
    top_components = sorted(component_counter.items(), key=lambda kv: kv[1], reverse=True)[:10]
    top_component_list = [{"component": c, "assets": n,
                           "vuln_assets": vuln_component_counter.get(c, 0)}
                          for c, n in top_components]

    return {
        "total_assets": total_assets,
        "analyzed_assets": analyzed_assets,
        "vuln_total": vuln_total,
        "vuln_suspected": vuln_suspected,
        "vuln_condition_matched": vuln_condition_matched,
        "vuln_verified": vuln_verified,
        "verified_assets": verified_assets,
        "risk_buckets": risk_buckets,
        "api_exposure_rate": round(api_asset_count / analyzed_assets, 3) if analyzed_assets else 0,
        "api_exposed_assets": api_asset_count,
        "top_risk_components": top_risk,
        "top_components": top_component_list,
        "avg_components": round(sum(component_counter.values()) / analyzed_assets, 2) if analyzed_assets else 0,
    }


# ============================================================
# 研判卡（decision cards）：判断与克制（Codex 方向评审）
# ============================================================
def generate_decision_cards() -> int:
    """从研究资产生成研判卡：按 topic（组件/项目）聚合，确定性打分排序。

    返回本次新增卡数。证据不足的 topic 生成弃权卡（insufficient）。
    """
    from core.analyst import build_card
    from core.database import ScanDatabase

    db = ScanDatabase(Config.DATABASE_PATH)
    cards_created = 0

    # 1. 组件级研判卡：聚合 supply-chain 数据的 top_risk_components + top_components
    try:
        sc = api_supply_chain_overview_data()
        now = time.time()
        for comp in (sc.get("top_risk_components") or [])[:15]:
            comp_name = comp.get("component", "")
            sev = "CRITICAL" if comp.get("critical") else "HIGH"
            # 攻击情报标记（Issue #10 目标 3）：查询该组件是否有 CISA KEV 在野利用记录
            attack = {}
            try:
                attack = scan_database.threat_intel_for_component(comp_name.lower())
            except Exception:
                pass
            attack_note = ""
            if attack.get("total"):
                sev = "CRITICAL"  # 在野被利用 → 直接 CRITICAL
                attack_note = f"⚠️ 正在被利用：CISA KEV 记录 {attack['total']} 条" + \
                              ("（含勒索软件利用）" if attack.get("ransomware") else "")
            card = build_card(
                comp_name,
                severity=sev,
                evidence_level=2,                      # L2 版本+漏洞条件匹配
                asset_count=comp.get("vuln_count", 0),
                is_new=False,
                has_api=False,
                source="supply-chain",
                fofa_query=f'header="{comp_name}" || app="{comp_name}"',
                change_text=f"{comp_name} 关联 {comp.get('vuln_count', 0)} 个漏洞观测{(' · ' + attack_note) if attack_note else ''}",
                why_worth=attack_note if attack_note else "高频组件 + 已知漏洞，值得确认是否命中受影响版本",
                evidence_says=f"在资产库中检测到 {comp.get('vuln_count', 0)} 条漏洞记录（组件维度）",
                evidence_limits="版本区间匹配（L2），未经授权验证不能确认可利用",
                next_step="打开资产库筛选该组件 → 复核版本 → 确认是否命中受影响区间",
                abort_condition="版本均不在受影响区间，或样本全部消失",
                card_type="component",
                payload={"kev_total": attack.get("total", 0), "kev_ransomware": attack.get("ransomware", 0)},
            )
            if db.card_insert(card):
                cards_created += 1
    except Exception as exc:
        logger.warning("生成组件研判卡失败: %s", exc)

    # 2. 项目级研判卡：从 research_overview 的资产/分析情况
    try:
        overview = scan_database.research_overview()
        for p in (overview.get("projects") or []):
            if not p.get("enabled"):
                continue
            ac = p.get("asset_count") or 0
            if ac <= 0:
                continue
            sev = "HIGH" if (p.get("analyzed_count") or 0) >= 20 else "MEDIUM"
            card = build_card(
                p.get("name") or p.get("slug", ""),
                severity=sev,
                evidence_level=1,
                asset_count=ac,
                is_new=True,
                has_api=False,
                source="research",
                fofa_query=f'title="{p.get("name", "")}"',
                change_text=f"{p.get('name')} 观测到 {ac} 个公网部署资产",
                why_worth=f"{p.get('category', '')} 热门项目，公网暴露面较大，值得抽样复核",
                evidence_says=f"测绘观测 {ac} 资产，已分析 {p.get('analyzed_count', 0)}",
                evidence_limits="L1 指纹观测，未逐资产授权验证",
                next_step=f"查看 {p.get('name')} 专项分析 → 抽样确认 → 决定继续关注或放弃",
                abort_condition="样本无新变化连续多日，或确认均为正常部署",
                card_type="project",
            )
            if db.card_insert(card):
                cards_created += 1
    except Exception as exc:
        logger.warning("生成项目研判卡失败: %s", exc)

    # 3. 热搜变化研判卡：新出现的 trend-* 项目
    try:
        if not Config.TREND_INTELLIGENCE_ENABLED:
            raise StopIteration
        overview = scan_database.research_overview()
        signals = (overview.get("intelligence") or {}).get("signals", []) or []
        for s in signals[:20]:
            name = s.get("name", "")
            if not name or s.get("status") not in ("promoted", "new"):
                continue
            card = build_card(
                f"热搜:{name}",
                severity="MEDIUM",
                evidence_level=0,
                asset_count=0,
                is_new=True,
                has_api=False,
                source="fofa-trend",
                fofa_query=f'"{name}"',
                change_text=f"{name} 进入测绘平台热搜（momentum={s.get('momentum', '?')}）",
                why_worth="热搜上升通常伴随注意力/风险集中，值得先快速看一眼",
                evidence_says="测绘平台热搜信号（L0 观测）",
                evidence_limits="仅热度信号，无资产级证据",
                next_step="用 FOFA 语法快速抽查公开部署 → 有信号则转正式研判卡",
                abort_condition="抽查无异常部署，热度回落",
                card_type="trend",
            )
            if db.card_insert(card):
                cards_created += 1
    except StopIteration:
        pass
    except Exception as exc:
        logger.warning("生成热搜研判卡失败: %s", exc)

    logger.info("研判卡生成完成：新增 %d 张", cards_created)
    return cards_created


@app.route("/api/cards", methods=["GET"])
def api_cards():
    """研判卡列表（pending 优先，按评分降序）。?decision= / ?topic= / ?limit= """
    limit = min(int(request.args.get("limit", "50")), 200)
    decision = request.args.get("decision", "")
    topic = request.args.get("topic", "")
    cards = scan_database.card_list(limit=limit, decision=decision, topic=topic)
    return jsonify({"total": len(cards), "cards": cards, "stats": scan_database.card_stats()})


@app.route("/api/cards/generate", methods=["POST"])
def api_cards_generate():
    """手动触发研判卡生成。Body: {"token": "..."} 或 X-Lab-Token 头"""
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    n = generate_decision_cards()
    return jsonify({"ok": True, "created": n, "stats": scan_database.card_stats()})


@app.route("/api/cards/<card_id>/decide", methods=["POST"])
def api_cards_decide(card_id):
    """反馈标记：worth（值得研究）/ noise（噪音）/ insufficient（证据不足）/ done（已处理）"""
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(silent=True) or {}
    decision = (body.get("decision") or "").strip()
    if scan_database.card_decide(card_id, decision):
        return jsonify({"ok": True, "decision": decision})
    return jsonify({"error": "decision 必须是 worth/noise/insufficient/done"}), 400


@app.route("/api/brain/events")
def api_brain_events():
    """大脑活动流（思考可视化）：研究大脑每一步动作 + 理由 + AI 思考摘要"""
    limit = min(int(request.args.get("limit", "50")), 200)
    event_type = request.args.get("type", "")
    events = scan_database.brain_events(limit=limit, event_type=event_type)
    return jsonify({"total": len(events), "events": events})


@app.route("/api/brain/vault", methods=["POST"])
def api_brain_vault():
    """生成 Obsidian 大脑记忆库（Brain Vault）：项目/泄露/经验/日志 → .md 笔记"""
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    from core.brain_vault import generate_vault
    vault_root = os.path.join(BASE_DIR, "data", "brain_vault")
    result = generate_vault(scan_database, vault_root=vault_root)
    scan_database.brain_event(event_type="result", action="Obsidian 记忆库生成",
                              detail=f"项目 {result['stats']['projects']} · 泄露 {result['stats']['leaks']} · 经验 {result['stats']['experience']}",
                              reason="大脑长期记忆落盘为 Obsidian vault",
                              meta=result["stats"])
    return jsonify(result)


@app.route("/api/threat-intel/sync", methods=["POST"])
def api_threat_intel_sync():
    """手动同步 CISA KEV 攻击情报（Issue #10 目标 3）"""
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    from core.threat_intel import fetch_attack_intel
    result = fetch_attack_intel(scan_database)
    scan_database.brain_event(event_type="sync", action="攻击情报同步",
                              detail=f"KEV 拉取 {result.get('total_kev', 0)} 条",
                              reason="CISA KEV 在野利用漏洞清单",
                              meta={"kev_total": result.get("total_kev", 0),
                                    "matched_components": len(result.get("matched", {}))})
    return jsonify(result)


@app.route("/api/threat-intel")
def api_threat_intel():
    """攻击情报概览 + 指定组件详情。?component=nginx"""
    component = request.args.get("component", "")
    if component:
        return jsonify(scan_database.threat_intel_for_component(component))
    return jsonify(scan_database.threat_intel_overview())


@app.route("/api/code-audit", methods=["POST"])
def api_code_audit():
    """代码审计（Issue #10 目标 1/6）。Body: {"repo": "..."}
    异步执行：立即返回 audit_id，前端轮询 /api/code-audits 查看结果。
    """
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    repo = (payload.get("repo") or "").strip()
    if not repo:
        return jsonify({"error": "repo 必填"}), 400
    audit_id = hashlib.md5(repo.encode()).hexdigest()

    def _run_audit():
        try:
            from core.code_audit import audit_repo
            from core.ai_analyzer import AIAnalyzer
            work_dir = os.path.join(BASE_DIR, "data", "audits")
            os.makedirs(work_dir, exist_ok=True)
            ai = None
            if Config.DEEPSEEK_API_KEY:
                ai = AIAnalyzer(Config.DEEPSEEK_API_KEY, Config.DEEPSEEK_BASE_URL,
                                Config.DEEPSEEK_MODEL, Config.AI_TIMEOUT)
            scan_database.brain_event(event_type="action", action="代码审计",
                                      detail=f"开始审计 {repo}",
                                      reason="Issue #10 目标 1/6：回答为什么这个项目会出安全问题")
            report = audit_repo(repo, work_dir, ai_analyzer=ai)
            scan_database.save_code_audit(report)
            risk = (report.get("ai_report") or {}).get("risk_level", "unknown")
            scan_database.brain_event(event_type="result", action="审计完成",
                                      detail=f"{repo} 风险等级 {risk} · {report.get('files_with_danger', 0)} 个文件有发现",
                                      reason="静态扫描 + AI 研判")
        except Exception as exc:
            logger.warning("代码审计失败 %s: %s", repo, exc)
            scan_database.save_code_audit({
                "repo": repo, "repo_path": "", "files_scanned": 0, "files_with_danger": 0,
                "ai_report": {"error": str(exc), "risk_level": "unknown"},
                "findings": [], "danger_by_type": {}, "duration_seconds": 0,
            })

    threading.Thread(target=_run_audit, daemon=True).start()
    return jsonify({"ok": True, "audit_id": audit_id, "repo": repo,
                    "status": "running", "note": "审计后台执行中，轮询 /api/code-audits 查看"})


@app.route("/api/code-audits")
def api_code_audits():
    """代码审计记录列表"""
    limit = min(int(request.args.get("limit", "20")), 50)
    return jsonify({"audits": scan_database.list_code_audits(limit=limit)})


@app.route("/api/analysis/project")
def api_analysis_project():
    """热门组件专项分析（Dify 样板间）：版本分布 / 高危标记 / FOFA 语法 / 复验状态

    ?slug=dify 项目 slug（默认 dify）
    数据来源：research_assets（该项目的已分析资产）
    """
    from core.database import ScanDatabase
    from core.research_brain import SEED_PROJECTS

    slug = (request.args.get("slug") or "dify").strip().lower()
    db = ScanDatabase(Config.DATABASE_PATH)

    # 项目元信息（FOFA 语法来自种子配置）
    project_meta = next((p for p in SEED_PROJECTS if p.get("slug", "").lower() == slug), {})
    fofa_query = project_meta.get("discovery_query", "")
    name = project_meta.get("name", slug)

    total = 0
    analyzed = 0
    version_counter = {}
    component_counter = {}
    vuln_assets = []
    api_exposed = 0
    critical_hits = 0
    high_hits = 0
    verified = 0

    try:
        conn = db._connect()
        rows = conn.execute(
            "SELECT asset_json, analysis_json, analysis_status, analyzed_at "
            "FROM research_assets WHERE project_slug=?",
            (slug,)).fetchall()
        conn.close()
        total = len(rows)
        for row in rows:
            if not row["analysis_json"]:
                continue
            try:
                an = json.loads(row["analysis_json"])
            except Exception:
                continue
            analyzed += 1
            asset = json.loads(row["asset_json"]) if row["asset_json"] else {}
            vulns = an.get("vulnerabilities") or []
            techs = an.get("technologies") or []
            # 版本分布：尝试从 title/header/tech 提取组件版本
            for t in techs:
                tn = t.get("name", "")
                tv = t.get("version", "")
                component_counter[tn] = component_counter.get(tn, 0) + 1
                if tv:
                    key = f"{tn} {tv}"
                    version_counter[key] = version_counter.get(key, 0) + 1
            for v in vulns:
                sev = (v.get("severity") or "").upper()
                if sev == "CRITICAL":
                    critical_hits += 1
                elif sev == "HIGH":
                    high_hits += 1
                if sev in ("CRITICAL", "HIGH"):
                    vuln_assets.append({
                        "host": asset.get("host") or asset.get("ip") or "",
                        "cve": v.get("cve_id") or v.get("id", ""),
                        "severity": sev,
                        "component": v.get("component", ""),
                        "analyzed_at": row["analyzed_at"] or 0,
                    })
            if an.get("api_endpoints"):
                api_exposed += 1
            # 复验状态：analysis_status completed + 有实际分析输出
            if row["analysis_status"] in ("completed", "analyzed"):
                verified += 1
    except Exception as exc:
        logger.warning("项目专项分析失败: %s", exc)

    # 高风险 CVE 去重汇总
    cve_summary = {}
    for va in vuln_assets:
        c = va["cve"]
        if c not in cve_summary:
            cve_summary[c] = {"cve": c, "count": 0, "severity": va["severity"],
                              "component": va["component"]}
        cve_summary[c]["count"] += 1
    top_cves = sorted(cve_summary.values(), key=lambda x: -x["count"])[:10]

    return jsonify({
        "slug": slug,
        "name": name,
        "fofa_query": fofa_query,
        "total_assets": total,
        "analyzed_assets": analyzed,
        "version_distribution": sorted(version_counter.items(), key=lambda kv: -kv[1])[:15],
        "component_distribution": sorted(component_counter.items(), key=lambda kv: -kv[1])[:15],
        "critical_hits": critical_hits,
        "high_hits": high_hits,
        "api_exposed_assets": api_exposed,
        "verified_assets": verified,
        "vuln_assets": vuln_assets[:50],
        "top_cves": top_cves,
    })


@app.route("/api/leaks")
def api_leaks():
    """凭据泄露查询（专属数据表 credential_leaks）

    ?full=1 需 X-Lab-Token 管理员授权，且记录审计日志（谁/何时/哪条）。
    默认仅返回 masked key（api_key_full 不在结果中）。
    """
    limit = min(int(request.args.get("limit", "100")), 500)
    status = request.args.get("status", "")
    target = request.args.get("target", "")
    full = request.args.get("full") == "1"
    authorized = bool(Config.LAB_REPORT_TOKEN) and request.headers.get("X-Lab-Token") == Config.LAB_REPORT_TOKEN
    if full and not authorized:
        return jsonify({"error": "unauthorized: full key 需要 X-Lab-Token"}), 401
    leaks = scan_database.list_credential_leaks(
        limit=limit, status=status, target=target, include_full=(full and authorized))
    if full and authorized:
        # 审计日志：完整密钥读取记录（Codex P0-1）
        audit_line = {
            "time": time.time(), "ip": request.remote_addr or "",
            "target": target or "*", "count": len(leaks),
        }
        try:
            with open(os.path.join(BASE_DIR, "data", "leak_audit.log"), "a") as af:
                af.write(json.dumps(audit_line, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.warning("凭据审计日志写入失败: %s", exc)
    return jsonify({"total": len(leaks), "leaks": leaks})


@app.route("/api/leaks/stats")
def api_leaks_stats():
    """凭据泄露统计"""
    return jsonify(scan_database.credential_leak_stats())


@app.route("/api/leaks/verify", methods=["POST"])
def api_leaks_verify():
    """批量验证泄露 key 有效性（只读 /v1/models 请求，不触发计费调用）。

    Body: {"leak_ids": ["..."]}（可选，不传则验证全部未验证的）
    """
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    leak_ids = payload.get("leak_ids") or []
    from core.key_verifier import verify_leaks
    scan_database.brain_event(event_type="action", action="密钥有效性验证",
                              detail=f"验证 {len(leak_ids) or '全部'} 个泄露 key",
                              reason="只读 /v1/models 探测，判定密钥是否仍有效")
    result = verify_leaks(scan_database, leak_ids=leak_ids, limit=100)
    scan_database.brain_event(event_type="result", action="密钥验证完成",
                              detail=f"有效 {result['valid']} · 失效 {result['invalid']} · 无法判定 {result['error']}",
                              reason="OpenAI 兼容 /v1/models 只读探测",
                              meta={"valid": result["valid"], "invalid": result["invalid"],
                                    "error": result["error"]})
    return jsonify(result)


@app.route("/api/leaks/research", methods=["POST"])
def api_leaks_research():
    """深度研究泄露（Leak Researcher）：从已知泄露学习指纹 → 批量回扫同项目资产 → 入库。

    异步执行：立即返回，后台线程探测（100 资产 × 6 路径约 3-5 分钟）。
    Body: {"project": "deeptutor", "asset_url": "...", "max_assets": 50}
    """
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    project = (payload.get("project") or "").strip()
    asset_url = (payload.get("asset_url") or "").strip()
    max_assets = min(int(payload.get("max_assets", 50)), 200)

    def _run():
        try:
            from core.leak_researcher import research_leaks
            result = research_leaks(scan_database, project=project, asset_url=asset_url,
                                    max_assets=max_assets)
            scan_database.brain_event(event_type="result", action="泄露研究完成",
                                      detail=f"探测 {result['probed']} 资产 · 新增 {result['found']} 泄露",
                                      reason="模式指纹 + 密钥正则 + 敏感字段启发式",
                                      meta={"found": result["found"], "probed": result["probed"]})
        except Exception as exc:
            logger.warning("泄露深度研究失败: %s", exc)
            scan_database.brain_event(event_type="error", action="泄露研究失败",
                                      detail=f"{project or asset_url}: {str(exc)[:100]}")

    scan_database.brain_event(event_type="action", action="泄露深度研究",
                              detail=f"回扫 {project or asset_url}",
                              reason="从已知泄露学习模式，批量发现同类泄露（用户诉求：非简单模式匹配）",
                              meta={"project": project, "asset_url": asset_url})
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True, "status": "running", "project": project, "asset_url": asset_url})


@app.route("/api/analytics")
def api_analytics():
    """数据可视化聚合：实验/任务/节点统计图表数据"""
    lab = scan_database.lab_overview()
    nodes = lab.get("nodes", [])
    experiments = lab.get("experiments", [])

    # 按节点统计实验数
    by_node = {}
    for e in experiments:
        nid = e.get("node_id", "unknown")
        by_node.setdefault(nid, 0)
        by_node[nid] += 1

    # 按状态统计
    by_status = {}
    for e in experiments:
        st = e.get("status", "unknown")
        by_status.setdefault(st, 0)
        by_status[st] += 1

    # 按项目统计
    by_project = {}
    for e in experiments:
        slug = e.get("project_slug", "unknown")
        by_project.setdefault(slug, 0)
        by_project[slug] += 1

    # 时间序列（按创建时间粗略分桶，最近24h按小时）
    import collections
    hourly = collections.Counter()
    for e in experiments:
        ts = e.get("created_at") or 0
        from datetime import datetime, timezone
        hour = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%m-%d %H:00")
        hourly[hour] += 1
    time_series = [{"hour": k, "count": v} for k, v in sorted(hourly.items())]

    return jsonify({
        "nodes": len(nodes),
        "experiments_total": len(experiments),
        "by_node": by_node,
        "by_status": by_status,
        "by_project": by_project,
        "time_series": time_series,
    })


@app.route("/api/chat", methods=["POST"])
def api_chat():
    """与大脑对话接口：自然语言指令 → 解析为任务 → 下发执行引擎 → 返回结果摘要

    Body: {"message": "扫描一下 nginx 资产", "fofa_key": "可选"}
    或    {"message": "查看所有节点状态"}
    或    {"message": "统计实验数据"}
    """
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    message = (payload.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message 不能为空"}), 400

    msg_lower = message.lower()

    # ---- 意图 1: 查看节点状态 ----
    if any(k in msg_lower for k in ("节点", "状态", "在线", "node", "overview", "机器")):
        lab = scan_database.lab_overview()
        nodes = lab.get("nodes", [])
        lines = [f"共 {len(nodes)} 个执行引擎节点："]
        for n in nodes:
            metrics = n.get("metrics", {})
            cpu = metrics.get("cpu_percent")
            mem = metrics.get("mem_used")
            mem_total = metrics.get("mem_total")
            mem_str = f"{mem/1024/1024/1024:.1f}G/{mem_total/1024/1024/1024:.1f}G" if mem and mem_total else "N/A"
            lines.append(
                f"  • {n.get('name')} ({n.get('node_id')}) - "
                f"{'在线' if n.get('online') else '离线'} | "
                f"CPU {cpu if cpu is not None else 'N/A'}% | 内存 {mem_str}")
        return jsonify({"ok": True, "intent": "node_status", "reply": "\n".join(lines), "data": nodes})

    # ---- 意图 2: 统计/可视化 ----
    if any(k in msg_lower for k in ("统计", "可视化", "图表", "多少", "数据", "实验", "analytics")):
        lab = scan_database.lab_overview()
        experiments = lab.get("experiments", [])
        by_status = {}
        for e in experiments:
            st = e.get("status", "unknown")
            by_status[st] = by_status.get(st, 0) + 1
        reply = (f"当前共有 {len(experiments)} 条实验结果。\n"
                 f"状态分布：{', '.join(f'{k}={v}' for k, v in by_status.items())}")
        return jsonify({"ok": True, "intent": "analytics", "reply": reply,
                        "data": {"experiments": len(experiments), "by_status": by_status}})

    # ---- 意图 3: 下发扫描任务 ----
    # 识别任务类型
    task_type = None
    params = {}
    if any(k in msg_lower for k in ("fofa", "资产", "发现", "搜索")):
        task_type = "fofa_discovery"
        params["size"] = 100
        import re
        m = re.search(r"(\d+)", message)
        if m:
            params["size"] = int(m.group(1))
        # 提取查询：去掉命令前缀
        for kw in ("扫描", "搜索", "查找", "fofa", "资产", "发现", "一下", "的", "用", "查询"):
            message = message.replace(kw, " ")
        params["query"] = message.strip() or 'domain="chuhaijian.com"'
    elif any(k in msg_lower for k in ("漏洞", "vuln", "检测")):
        task_type = "vuln_check"
        params["targets"] = ["https://www.chuhaijian.com/sc"]
    elif any(k in msg_lower for k in ("api", "接口")):
        task_type = "api_scan"
        params["targets"] = ["https://www.chuhaijian.com/sc"]
    elif any(k in msg_lower for k in ("技术", "tech", "指纹")):
        task_type = "tech_detect"
        params["targets"] = ["https://www.chuhaijian.com/sc"]

    if task_type:
        task = {"type": task_type, "params": params}
        result = task_dispatcher.dispatch(task)
        if result.get("ok"):
            return jsonify({"ok": True, "intent": "dispatch",
                            "reply": f"已向 {result.get('node_id')} 下发 {task_type} 任务（task_id: {result.get('task_id')[:12]}...）",
                            "data": result})
        return jsonify({"ok": False, "intent": "dispatch", "reply": f"任务下发失败：{result.get('error')}",
                        "data": result}), 502

    # ---- 意图 4: 帮助 ----
    reply = ("我支持以下指令：\n"
             "  1. 查看节点状态（如：所有节点状态）\n"
             "  2. 数据统计（如：统计实验数据）\n"
             "  3. 下发扫描任务（如：用 fofa 扫描 50 个 nginx 资产 / 检测漏洞 / 扫描 API / 技术指纹）")
    return jsonify({"ok": True, "intent": "help", "reply": reply})


def _finalize_worker_value(task_context: Dict[str, Any]):
    """Convert a completed Worker task into project-level product output."""
    project_slug = task_context.get("project_slug", "")
    if not project_slug:
        return
    try:
        overview = scan_database.research_overview()
        project = next((row for row in overview.get("projects", [])
                        if row.get("slug") == project_slug and row.get("enabled")), None)
        if not project:
            return
        research_brain._analyze_project_results(project)
        cards_created = generate_decision_cards()
        refreshed = scan_database.research_overview()
        updated_project = next((row for row in refreshed.get("projects", [])
                                if row.get("slug") == project_slug), {})
        insight = updated_project.get("insight") or {}
        scan_database.brain_event(
            event_type="result", action="形成研究结论",
            detail=(f"{project.get('name', project_slug)} 已完成项目复盘 · "
                    f"研判卡新增 {cards_created}"),
            reason="Worker 原始证据已转化为风险结论、项目洞察和待研判事项",
            project=project_slug,
            ai_thought=str(insight.get("summary") or insight.get("headline") or "")[:500],
            meta={"task_id": task_context.get("task_id"),
                  "cards_created": cards_created,
                  "analyzed_count": updated_project.get("analyzed_count", 0)},
        )
    except Exception:
        logger.exception("Worker 结果价值化失败: project=%s task=%s",
                         project_slug, task_context.get("task_id"))


@app.route("/api/lab/report", methods=["POST"])
def api_lab_report():
    if not Config.LAB_REPORT_TOKEN or request.headers.get("X-Lab-Token") != Config.LAB_REPORT_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    report = request.get_json(silent=True) or {}
    if not report.get("node_id"):
        return jsonify({"error": "node_id required"}), 400
    # Reconcile the durable task ledger and research asset state. This is
    # idempotent for repeated reports from a worker after a network timeout.
    # A stale attempt may update its node heartbeat, but it must never write
    # experiments, assets, or credential findings.
    report_task_id = report.get("task_id", "")
    report_attempt_id = report.get("attempt_id", "")
    report_experiments = report.get("experiments", [])
    task_context = scan_database.node_task_summary(report_task_id) if report_task_id else None
    should_finalize = bool(task_context and task_context.get("status") in ("leased", "running")
                           and report_experiments
                           and report_experiments[0].get("status") == "completed")
    if report_task_id and report_attempt_id and report_experiments:
        scan_database.upsert_lab_report(report, include_experiments=False)
        if not scan_database.complete_node_task(
                report_task_id, report_attempt_id, report_experiments[0]):
            return jsonify({"error": "stale or unknown task attempt"}), 409
        scan_database.upsert_lab_report(report)
        if should_finalize and task_context:
            threading.Thread(
                target=enrich_passive_infrastructure,
                args=(report, task_context), daemon=True,
                name=f"supply-chain-{report_task_id[:12]}",
            ).start()
    else:
        scan_database.upsert_lab_report(report)

    # 解析 evidence 中的凭据泄露（api_crawl 任务的 secrets）→ 写入 credential_leaks 表
    node_id = report.get("node_id", "")
    leak_count = 0
    for experiment in report.get("experiments", []):
        for item in experiment.get("evidence", []):
            secrets = item.get("secrets", []) if isinstance(item, dict) else []
            for s in secrets:
                leak = {
                    "target": s.get("source_url") or item.get("target", ""),
                    "node_id": node_id,
                    "provider": s.get("provider", "unknown"),
                    "base_url": s.get("base_url", ""),
                    "api_key_masked": s.get("key_masked", ""),
                    "api_key_full": s.get("api_key", ""),
                    "secret_type": "LLM API Key",
                    "source_path": s.get("path", ""),
                    "evidence": [{"url": s.get("source_url", ""), "path": s.get("path", "")}],
                    "status": "new",
                }
                if leak["api_key_full"]:
                    scan_database.upsert_credential_leak(leak)
                    leak_count += 1
            # deep_analysis 的 panel/js 扫描结果也入库
            for hit in item.get("panel_secret_scan", []) + item.get("js_secret_scan", []) or []:
                if not isinstance(hit, dict):
                    continue
                api_key = ""
                # 从 value_masked 无法还原，但 source_url/secret_type 有价值
                leak = {
                    "target": item.get("target", ""),
                    "node_id": node_id,
                    "provider": hit.get("app", "unknown"),
                    "base_url": hit.get("source", "") or hit.get("url", ""),
                    "api_key_masked": hit.get("value_masked", ""),
                    "api_key_full": "",
                    "secret_type": hit.get("secret_type", "敏感信息"),
                    "source_path": hit.get("path", ""),
                    "evidence": [{"type": hit.get("type", ""), "matched": hit.get("matched", "")}],
                    "status": "new",
                }
                scan_database.upsert_credential_leak(leak)
                leak_count += 1
    if leak_count:
        logger.info("lab report: 新增 %d 条凭据泄露记录", leak_count)
    # ---- 告警推送：新 SK 泄露 ----
    if leak_count and Config.ALERT_NOTIFY_LEAKS:
        try:
            from core.notifier import notify
            for experiment in report.get("experiments", []):
                for item in experiment.get("evidence", []):
                    secrets = item.get("secrets", []) if isinstance(item, dict) else []
                    for s in secrets:
                        key_full = s.get("api_key", "")
                        if not key_full:
                            continue
                        alert = {
                            "type": "SK 泄露",
                            "severity": "CRITICAL",
                            "asset": s.get("source_url") or item.get("target", ""),
                            "component": s.get("provider", "unknown"),
                            "version": s.get("base_url", ""),
                            "summary": "发现公开可达的 LLM API Key",
                            "source": f"node-{node_id}",
                            "confidence": "high",
                            "api_key": key_full,
                            "link": f"https://www.cyberstroll.cn/sc/dashboard#leaks",
                        }
                        notify(alert,
                               webhook_url=Config.ALERT_WEBHOOK_URL,
                               bot_token=Config.ALERT_TELEGRAM_TOKEN,
                               chat_id=Config.ALERT_TELEGRAM_CHAT_ID)
        except Exception as exc:
            logger.warning("SK 告警推送失败: %s", exc)

    # ---- 告警推送：CRITICAL 漏洞资产 ----
    try:
        from core.notifier import notify
        min_level = (Config.ALERT_MIN_LEVEL or "CRITICAL").upper()
        for experiment in report.get("experiments", []):
            for item in experiment.get("evidence", []):
                vulns = item.get("vulnerabilities") or []
                for v in vulns:
                    sev = (v.get("severity") or "").upper()
                    if sev != "CRITICAL":
                        continue
                    alert = {
                        "type": "CRITICAL 漏洞",
                        "severity": "CRITICAL",
                        "asset": item.get("target") or item.get("host", ""),
                        "component": v.get("component", ""),
                        "version": v.get("installed_version", ""),
                        "cve_id": v.get("cve_id", ""),
                        "summary": f"{v.get('cve_id', '')} · {v.get('title', '')[:80]}",
                        "source": f"node-{node_id}",
                        "confidence": "medium",
                        "link": f"https://www.cyberstroll.cn/sc/dashboard#assets",
                    }
                    notify(alert,
                           webhook_url=Config.ALERT_WEBHOOK_URL,
                           bot_token=Config.ALERT_TELEGRAM_TOKEN,
                           chat_id=Config.ALERT_TELEGRAM_CHAT_ID)
    except Exception as exc:
        logger.warning("CRITICAL 告警推送失败: %s", exc)

    if should_finalize and task_context:
        threading.Thread(
            target=_finalize_worker_value, args=(task_context,), daemon=True,
            name=f"value-{report_task_id[:8]}",
        ).start()

    return jsonify({"ok": True, "leaks_ingested": leak_count})


@app.route("/api/infrastructure-supply-chain/overview")
@require_admin
def api_infrastructure_supply_chain_overview():
    """Internal supplier concentration view; never returns Worker credentials."""
    project_slug = (request.args.get("project_slug") or "").strip()
    return jsonify(scan_database.supply_chain_overview(project_slug))


@app.route("/api/infrastructure-supply-chain/asset")
@require_admin
def api_infrastructure_supply_chain_asset():
    """Internal evidence-backed infrastructure relationships for one asset."""
    project_slug = (request.args.get("project_slug") or "").strip()
    asset_identity = (request.args.get("asset") or "").strip().rstrip("/").lower()
    if not project_slug or not asset_identity:
        return jsonify({"error": "project_slug and asset are required"}), 400
    return jsonify(scan_database.supply_chain_for_asset(project_slug, asset_identity))

# ============================================================
# 定期清理过期任务（简单的内存管理）
# ============================================================

def cleanup_expired_tasks():
    """清理超过 2 小时的已完成/已失败任务，避免内存无限增长"""
    current_time = time.time()
    expired_ids = []
    with tasks_lock:
        for tid, task in tasks.items():
            # 超过 2 小时且已完成或失败的任务
            if (current_time - task.get("created_at", 0) > 7200
                    and task["status"] in ("completed", "error", "cancelled")):
                expired_ids.append(tid)
        for tid in expired_ids:
            del tasks[tid]
    if expired_ids:
        logger.info("已清理 %d 个过期任务", len(expired_ids))


@app.before_request
def _before_request_cleanup():
    """每次请求前尝试清理过期任务（轻量操作）"""
    cleanup_expired_tasks()


# ============================================================
# 应用入口
# ============================================================

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("软件供应链安全分析平台")
    logger.info("监听地址: %s:%d", Config.HOST, Config.PORT)
    logger.info("调试模式: %s", Config.DEBUG)
    logger.info("FOFA Key: %s", "已配置" if Config.FOFA_KEY else "未配置（需手动输入）")
    logger.info("管理员密码: %s", "已配置" if Config.ADMIN_PASSWORD_CONFIGURED else "使用本地临时密码 admin123（建议修改）")
    # DeepSeek AI 配置状态（不输出实际密钥）
    if Config.DEEPSEEK_API_KEY:
        ai_status = "已启用" if Config.AI_ANALYSIS_ENABLED else "已配置但被全局开关关闭"
        logger.info("DeepSeek AI: %s (模型: %s, 超时: %ds)",
                    ai_status, Config.DEEPSEEK_MODEL, Config.AI_TIMEOUT)
    else:
        logger.info("DeepSeek AI: 未配置 API Key（AI 分析功能不可用，参考 .env.example 配置）")
    logger.info("=" * 60)

    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        threaded=True,  # 启用多线程处理请求
    )
