"""Autonomous, bounded research planner and passive asset discovery loop."""
import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from core.ai_analyzer import AIAnalyzer
from core.fofa_client import FofaClient
from core.trend_intelligence import FofaHotSearchSource, slugify_trend

logger = logging.getLogger("ResearchBrain")


SEED_PROJECTS = [
    {
        "slug": "deeptutor", "name": "DeepTutor",
        "repository": "https://github.com/HKUDS/DeepTutor",
        "upstream": "HKUDS / Data Intelligence Lab @ HKU", "license": "Apache-2.0",
        "discovery_query": 'title="DeepTutor"', "category": "AI 应用",
        "priority": 100, "rationale": "近期热门开源 AI 教学项目；已有公开部署与配置暴露观察样本。",
    },
    {
        "slug": "open-webui", "name": "Open WebUI",
        "repository": "https://github.com/open-webui/open-webui",
        "upstream": "Open WebUI Community", "license": "BSD-3-Clause",
        "discovery_query": 'title="Open WebUI"', "category": "AI 应用",
        "priority": 92, "rationale": "广泛部署的开源 LLM Web 应用，具有认证、模型代理和插件供应链研究价值。",
    },
    {
        "slug": "dify", "name": "Dify",
        "repository": "https://github.com/langgenius/dify",
        "upstream": "LangGenius", "license": "Apache-2.0 with additional conditions",
        "discovery_query": 'title="Dify"', "category": "AI 应用平台",
        "priority": 90, "rationale": "热门开源 LLM 应用平台，包含 API、工作流、插件与密钥管理攻击面。",
    },
    {
        "slug": "anythingllm", "name": "AnythingLLM",
        "repository": "https://github.com/Mintplex-Labs/anything-llm",
        "upstream": "Mintplex Labs", "license": "MIT",
        "discovery_query": 'title="AnythingLLM"', "category": "AI 应用",
        "priority": 86, "rationale": "常见自托管 RAG/Agent 项目，适合研究默认部署、API 与连接凭据边界。",
    },
    {
        "slug": "lobechat", "name": "LobeChat",
        "repository": "https://github.com/lobehub/lobe-chat",
        "upstream": "LobeHub", "license": "MIT",
        "discovery_query": 'title="LobeChat" || title="Lobe Chat"', "category": "AI 应用",
        "priority": 84, "rationale": "流行的 AI 聊天前端，适合研究前端配置、服务代理与快速部署风险。",
    },
]

OFFICIAL_DOMAINS = {
    "deeptutor": ("deeptutor.info",),
    "open-webui": ("openwebui.com", "openwebui.com.cn"),
    "dify": ("dify.ai", "dify.com"),
    "anythingllm": ("anythingllm.com", "mintplexlabs.com"),
    "lobechat": ("lobehub.com", "lobechat.com"),
}


class ResearchBrain:
    def __init__(self, database, config, analyze_callback=None, probe_callback=None):
        self.database = database
        self.config = config
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.analyze_callback = analyze_callback
        self.probe_callback = probe_callback
        self._last_intelligence_sync = 0.0
        self.database.seed_research_projects(SEED_PROJECTS)

    def start(self):
        if not self.config.RESEARCH_BRAIN_ENABLED or self.thread:
            return
        self.thread = threading.Thread(target=self._loop, name="research-brain", daemon=True)
        self.thread.start()
        logger.info("研究大脑已启动，周期=%ds，模型=%s",
                    self.config.RESEARCH_INTERVAL_SECONDS, self.config.RESEARCH_AI_MODEL)

    def _loop(self):
        # Give the web worker a short startup window, then run immediately.
        self.stop_event.wait(5)
        while not self.stop_event.is_set():
            try:
                # Discovery and execution use independent clocks: discovery is
                # periodic, while the engine continuously drains stored work.
                self.run_intelligence_once()
                self.run_discovery_once()
                self.run_execution_once()
            except Exception:
                logger.exception("研究大脑轮次异常")
            self.stop_event.wait(60)

    def _choose_project(self, due_projects: List[Dict[str, Any]]) -> Dict[str, Any]:
        fallback = due_projects[0]
        if not self.config.DEEPSEEK_API_KEY or len(due_projects) < 2:
            return fallback
        analyzer = AIAnalyzer(self.config.DEEPSEEK_API_KEY, self.config.DEEPSEEK_BASE_URL,
                              self.config.RESEARCH_AI_MODEL, self.config.AI_TIMEOUT)
        prompt = (
            "你是防御性开源项目安全研究编排器。只能从给定候选中选择一个项目。"
            "目标是增加项目类型多样性并优先研究公开部署风险，不生成新的网络目标、"
            "不修改查询、不建议利用。只返回 JSON：{\"slug\":\"...\",\"reason\":\"...\"}。"
        )
        public_candidates = [{k: row.get(k) for k in
                              ("slug", "name", "category", "priority", "rationale", "last_run_at")}
                             for row in due_projects]
        try:
            raw = analyzer._call_api(prompt, json.dumps(public_candidates, ensure_ascii=False), 500)
            decision = analyzer._extract_json(raw)
            return next((row for row in due_projects if row["slug"] == decision.get("slug")), fallback)
        except Exception as exc:
            logger.warning("AI 选题失败，使用确定性回退: %s", exc)
            return fallback

    def run_once(self):
        """Compatibility entrypoint for one full planner/engine tick."""
        self.run_intelligence_once(force=True)
        self.run_discovery_once()
        return self.run_execution_once()

    def run_intelligence_once(self, force: bool = False) -> int:
        """Turn public trend observations into bounded, persisted research projects."""
        if not self.config.TREND_INTELLIGENCE_ENABLED:
            return 0
        now = time.time()
        if not force and now - self._last_intelligence_sync < self.config.TREND_INTELLIGENCE_INTERVAL_SECONDS:
            return 0
        sync_id = uuid.uuid4().hex
        self.database.start_intelligence_sync(sync_id, "external_product_trends")
        try:
            signals = FofaHotSearchSource(timeout=min(30, self.config.SCAN_TIMEOUT + 10)).fetch()
            decisions = self._classify_trend_signals(signals)
            promoted = 0
            ranked = sorted(signals, key=lambda row: (not row["is_hot"], -row["hot_score"], row["rank"]))
            for signal in ranked:
                decision = decisions.get(signal["signal_key"], self._fallback_trend_decision(signal))
                self.database.upsert_trend_signal(signal, decision)
                if decision.get("status") != "research" or promoted >= self.config.TREND_INTELLIGENCE_PROJECT_LIMIT:
                    continue
                self.database.upsert_dynamic_research_project(self._trend_project(signal, decision))
                promoted += 1
            self.database.finish_intelligence_sync(sync_id, "completed", len(signals), promoted)
            self._last_intelligence_sync = now
            logger.info("趋势情报同步完成: observed=%d promoted=%d", len(signals), promoted)
            return promoted
        except Exception as exc:
            self.database.finish_intelligence_sync(sync_id, "error", error=str(exc))
            # Avoid hammering a changing upstream endpoint every minute.
            self._last_intelligence_sync = now - self.config.TREND_INTELLIGENCE_INTERVAL_SECONDS + 900
            logger.warning("趋势情报同步失败: %s", exc)
            return 0

    def _classify_trend_signals(self, signals: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        if not self.config.DEEPSEEK_API_KEY:
            return {row["signal_key"]: self._fallback_trend_decision(row) for row in signals}
        analyzer = AIAnalyzer(self.config.DEEPSEEK_API_KEY, self.config.DEEPSEEK_BASE_URL,
                              self.config.RESEARCH_AI_MODEL, self.config.AI_TIMEOUT)
        prompt = (
            "你是防御性软件供应链研究选题器。判断趋势条目是否是值得研究的可部署软件、"
            "开源项目或关键组件。排除纯硬件型号、运营商页面、模糊厂商名和无法形成软件研究"
            "对象的词。不得修改查询语句，不得提出攻击或利用。只返回JSON："
            "{\"decisions\":[{\"index\":1,\"status\":\"research|observe|noise\","
            "\"category\":\"...\",\"reason\":\"...\"}]}。"
        )
        public_items = [{"index": index, "name": row["name"], "rank": row["rank"],
                         "is_hot": row["is_hot"], "hot_score": row["hot_score"],
                         "momentum": row["momentum"]}
                        for index, row in enumerate(signals, 1)]
        try:
            raw = analyzer._call_api(prompt, json.dumps(public_items, ensure_ascii=False), 1800)
            parsed = analyzer._extract_json(raw)
            output = {}
            for item in parsed.get("decisions", []):
                index = int(item.get("index", 0)) - 1
                if not 0 <= index < len(signals):
                    continue
                status = item.get("status") if item.get("status") in {"research", "observe", "noise"} else "observe"
                output[signals[index]["signal_key"]] = {
                    "status": status,
                    "category": str(item.get("category") or "趋势软件")[:80],
                    "reason": str(item.get("reason") or "外部热度变化")[:300],
                    "model": self.config.RESEARCH_AI_MODEL,
                }
            return output
        except Exception as exc:
            logger.warning("AI 趋势研判失败，使用规则回退: %s", exc)
            return {row["signal_key"]: self._fallback_trend_decision(row) for row in signals}

    @staticmethod
    def _fallback_trend_decision(signal: Dict[str, Any]) -> Dict[str, Any]:
        # A product fingerprint plus strong recent interest is enough to queue
        # observation; the later identity pass still prevents false promotion.
        lowered = signal["name"].lower()
        network_hardware = ("adsl", "router", "switch", "network communication", "网络通信设备")
        research = (signal["query"].startswith("fid=") and
                    not any(term in lowered for term in network_hardware) and
                    (signal["is_hot"] or signal["hot_score"] >= 250))
        return {
            "status": "research" if research else "observe",
            "category": "趋势软件 / 组件",
            "reason": "近期关注度显著上升，进入公开部署与供应链证据研究队列" if research else "保留趋势快照，等待更强信号",
            "model": "规则趋势研究器",
        }

    @staticmethod
    def _trend_project(signal: Dict[str, Any], decision: Dict[str, Any]) -> Dict[str, Any]:
        priority = min(99, 60 + (18 if signal["is_hot"] else 0) + max(0, signal["hot_score"]) / 50)
        return {
            "slug": slugify_trend(signal["name"]), "name": signal["name"],
            "discovery_query": signal["query"], "category": decision.get("category", "趋势软件 / 组件"),
            "priority": round(priority, 1), "source_signal_key": signal["signal_key"],
            "rationale": f"趋势情报：{decision.get('reason', '近期关注度上升')}。需核实项目来源、版本、组件、API 与公开配置证据。",
        }

    def run_discovery_once(self):
        project = self.database.next_research_project()
        if not project:
            return
        # Fetch a small due set for AI choice while retaining deterministic bounds.
        overview = self.database.research_overview()
        now = time.time()
        due = [row for row in overview["projects"] if row.get("enabled") and
               (not row.get("next_run_at") or row["next_run_at"] <= now)]
        if due:
            due.sort(key=lambda row: (-row["priority"], row.get("last_run_at") or 0))
            project = self._choose_project(due[:10])
        run_id = uuid.uuid4().hex
        reason = f"自动研究：{project['rationale']}"
        self.database.start_research_run(run_id, project["slug"], reason)
        next_run = now + self.config.RESEARCH_INTERVAL_SECONDS * max(1, len(overview["projects"]))
        if not self.config.FOFA_KEY:
            self.database.finish_research_run(run_id, project["slug"], "waiting", error="资产数据源凭据未配置",
                                              next_run_at=now + self.config.RESEARCH_INTERVAL_SECONDS)
            return
        try:
            client = FofaClient(key=self.config.FOFA_KEY, timeout=30, max_retries=2)
            assets = client.search_all(project["discovery_query"], self.config.RESEARCH_DISCOVERY_SIZE)
            public_assets = [asset.to_dict() for asset in assets]
            new_count = self.database.upsert_research_assets(project["slug"], public_assets)
            self.database.finish_research_run(run_id, project["slug"], "completed",
                                              len(public_assets), new_count, next_run_at=next_run)
            logger.info("发现轮次完成: %s discovered=%d new=%d",
                        project["name"], len(public_assets), new_count)
        except Exception as exc:
            self.database.finish_research_run(run_id, project["slug"], "error", error=str(exc),
                                              next_run_at=now + self.config.RESEARCH_INTERVAL_SECONDS)
            logger.warning("研究轮次失败: %s: %s", project["name"], exc)

    def run_execution_once(self) -> int:
        project = self.database.next_project_with_pending_assets()
        if not project:
            return 0
        analyzed_count = self._execute_analysis(project)
        if analyzed_count:
            self._analyze_project_results(project)
        logger.info("执行轮次完成: %s confirmed=%d batch=%d", project["name"],
                    analyzed_count, self.config.RESEARCH_ANALYSIS_BATCH)
        return analyzed_count

    def _execute_analysis(self, project: Dict[str, Any]) -> int:
        """Run the bounded L1/L2 engine over a small pending batch."""
        if not self.analyze_callback:
            return 0
        pending = self.database.pending_research_assets(
            project["slug"], self.config.RESEARCH_ANALYSIS_BATCH
        )
        completed = 0

        def process(candidate):
            try:
                # Identity pass is intentionally cheap. Full API analysis only
                # runs after the deployment is confirmed.
                light_result = self.analyze_callback(candidate["asset"], False)
                if self.probe_callback:
                    light_result["project_probe"] = self.probe_callback(project["slug"], candidate["asset"])
                confirmation = self._confirm_project(project, candidate["asset"], light_result)
                if not confirmation["confirmed"]:
                    light_result["project_confirmation"] = confirmation
                    self.database.save_research_analysis(candidate["identity"], project["slug"],
                                                         light_result, status="rejected")
                    return False
                result = self.analyze_callback(candidate["asset"], True)
                result["project_confirmation"] = confirmation
                result["project_probe"] = light_result.get("project_probe", {})
                self.database.save_research_analysis(candidate["identity"], project["slug"], result)
                return True
            except Exception as exc:
                self.database.save_research_analysis(candidate["identity"], project["slug"], None, str(exc))
                logger.warning("研究资产分析失败 %s: %s", candidate["identity"], exc)
                return False

        with ThreadPoolExecutor(max_workers=self.config.RESEARCH_ANALYSIS_WORKERS,
                                thread_name_prefix="research-engine") as pool:
            futures = [pool.submit(process, candidate) for candidate in pending]
            for future in as_completed(futures):
                if future.result():
                    completed += 1
        return completed

    @staticmethod
    def _confirm_project(project: Dict[str, Any], discovered: Dict[str, Any],
                         analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Require multiple independent signals before promotion to inventory."""
        from urllib.parse import urlsplit
        slug, name = project["slug"], project["name"]
        host = (urlsplit(discovered.get("url") or "").hostname or discovered.get("host") or "").lower()
        if any(host == domain or host.endswith("." + domain) for domain in OFFICIAL_DOMAINS.get(slug, ())):
            return {"confirmed": False, "confidence": "excluded", "score": 0,
                    "evidence": ["上游官方网站/文档域名，不属于第三方部署"]}
        title = " ".join(filter(None, (discovered.get("title"), analysis.get("asset", {}).get("title")))).lower()
        technologies = {(tech.get("name") or "").lower() for tech in analysis.get("technologies", [])}
        paths = {urlsplit(record.get("url") or "").path.lower()
                 for key in ("api_endpoints", "exposure_findings")
                 for record in analysis.get(key, [])}
        evidence, score = [], 0
        aliases = {"open-webui": ("open webui",), "anythingllm": ("anythingllm",),
                   "lobechat": ("lobechat", "lobe chat"), "deeptutor": ("deeptutor",),
                   "dify": ("dify",)}.get(slug, (name.lower(),))
        if project.get("origin") == "trend":
            evidence.append("外部产品指纹命中"); score += 1
        if any(alias in title for alias in aliases):
            evidence.append("页面标题匹配项目名称"); score += 1
        if technologies & {"next.js", "react", "vue.js"}:
            evidence.append("前端技术栈与项目部署形态一致"); score += 1
        project_paths = {
            "dify": ("/console/api", "/files/upload", "/signin"),
            "deeptutor": ("/settings/llm", "/api/v1/settings"),
            "open-webui": ("/api/v1/auths", "/api/config"),
            "anythingllm": ("/api/system", "/api/workspace"),
            "lobechat": ("/api/chat", "/settings/provider"),
        }.get(slug, ())
        if any(any(path.startswith(prefix) for prefix in project_paths) for path in paths):
            evidence.append("匹配项目专属路由"); score += 2
        probe = analysis.get("project_probe") or {}
        if probe.get("matched"):
            evidence.append("项目专属端点返回匹配响应"); score += 2
        confirmed = score >= 2
        if not confirmed:
            evidence.append("证据不足：仅标题命中或没有项目专属指纹")
        return {"confirmed": confirmed, "confidence": "high" if score >= 3 else "medium" if confirmed else "low",
                "score": score, "evidence": evidence}

    def _analyze_project_results(self, project: Dict[str, Any]):
        results = self.database.project_analysis_data(project["slug"])
        if not results:
            return
        compact = [{
            "title": row.get("asset", {}).get("title"),
            "technologies": [tech.get("name") for tech in row.get("technologies", [])],
            "cve_count": len(row.get("vulnerabilities", [])),
            "api_count": len(row.get("api_endpoints", [])),
            "exposure_types": sorted({field for finding in row.get("exposure_findings", [])
                                      for field in finding.get("sensitive_field_types", [])}),
            "risk_level": row.get("risk_level"),
        } for row in results[:50]]
        fallback = {
            "headline": f"{project['name']} 已分析 {len(results)} 个公开部署样本",
            "summary": "研究引擎正在积累组件、API 与公开配置证据。",
            "signals": [f"已分析样本 {len(results)}", f"候选部署持续更新"],
            "next_focus": "继续扩大样本并核实版本与风险前置条件",
            "model": "规则汇总",
        }
        if not self.config.DEEPSEEK_API_KEY:
            self.database.save_project_insight(project["slug"], fallback)
            return
        analyzer = AIAnalyzer(self.config.DEEPSEEK_API_KEY, self.config.DEEPSEEK_BASE_URL,
                              self.config.RESEARCH_AI_MODEL, self.config.AI_TIMEOUT)
        prompt = (
            "你是防御性开源项目安全研究分析师。根据聚合后的脱敏观测总结项目级结论，"
            "不能声称未验证的漏洞成立，不能输出攻击步骤。仅返回 JSON，字段为 headline、"
            "summary、signals(最多5条)、next_focus。"
        )
        try:
            raw = analyzer._call_api(prompt, json.dumps({"project": project["name"], "observations": compact}, ensure_ascii=False), 1200)
            insight = analyzer._extract_json(raw)
            insight["model"] = self.config.RESEARCH_AI_MODEL
            self.database.save_project_insight(project["slug"], insight)
        except Exception as exc:
            logger.warning("AI 项目复盘失败，保存规则汇总: %s", exc)
            self.database.save_project_insight(project["slug"], fallback)
