"""Autonomous, bounded research planner and passive asset discovery loop."""
import json
import logging
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from core.ai_analyzer import AIAnalyzer
from core.fofa_client import FofaClient

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
    {
        "slug": "firecrawl", "name": "Firecrawl",
        "repository": "https://github.com/firecrawl/firecrawl",
        "upstream": "Firecrawl", "license": "AGPL-3.0",
        "discovery_query": 'title="Firecrawl"', "category": "AI 数据抓取",
        "priority": 82, "rationale": "热门的 AI 网页抓取服务，自托管部署常见，API 密钥与服务端请求伪造风险值得研究。",
    },
]


class ResearchBrain:
    def __init__(self, database, config, analyze_callback=None):
        self.database = database
        self.config = config
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.analyze_callback = analyze_callback
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
                self.run_once()
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
            analyzed_count = self._execute_analysis(project)
            self._analyze_project_results(project)
            self.database.finish_research_run(run_id, project["slug"], "completed",
                                              len(public_assets), new_count, next_run_at=next_run)
            logger.info("研究轮次完成: %s discovered=%d new=%d analyzed=%d",
                        project["name"], len(public_assets), new_count, analyzed_count)
        except Exception as exc:
            self.database.finish_research_run(run_id, project["slug"], "error", error=str(exc),
                                              next_run_at=now + self.config.RESEARCH_INTERVAL_SECONDS)
            logger.warning("研究轮次失败: %s: %s", project["name"], exc)

    def _execute_analysis(self, project: Dict[str, Any]) -> int:
        """Run the bounded L1/L2 engine over a small pending batch."""
        if not self.analyze_callback:
            return 0
        pending = self.database.pending_research_assets(
            project["slug"], self.config.RESEARCH_ANALYSIS_BATCH
        )
        completed = 0
        for candidate in pending:
            try:
                result = self.analyze_callback(candidate["asset"])
                self.database.save_research_analysis(candidate["identity"], project["slug"], result)
                completed += 1
            except Exception as exc:
                self.database.save_research_analysis(candidate["identity"], project["slug"], None, str(exc))
                logger.warning("研究资产分析失败 %s: %s", candidate["identity"], exc)
        return completed

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
