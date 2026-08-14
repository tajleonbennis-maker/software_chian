"""SQLite persistence for scan tasks and reports."""
import hashlib
import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional


class ScanDatabase:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self._connect() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS scan_tasks (
                    task_id TEXT PRIMARY KEY,
                    mode TEXT NOT NULL,
                    query_text TEXT NOT NULL DEFAULT '',
                    requested_size INTEGER NOT NULL DEFAULT 0,
                    scan_api INTEGER NOT NULL DEFAULT 0,
                    online_query INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    current_step TEXT NOT NULL DEFAULT '',
                    analyzed_count INTEGER NOT NULL DEFAULT 0,
                    total_count INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    results_json TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_scan_tasks_created ON scan_tasks(created_at DESC)")
            db.execute("""
                CREATE TABLE IF NOT EXISTS research_projects (
                    slug TEXT PRIMARY KEY, name TEXT NOT NULL, repository TEXT,
                    upstream TEXT, license TEXT, discovery_query TEXT NOT NULL,
                    category TEXT NOT NULL, priority REAL NOT NULL DEFAULT 50,
                    rationale TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                    last_run_at REAL, next_run_at REAL, created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS research_runs (
                    run_id TEXT PRIMARY KEY, project_slug TEXT NOT NULL,
                    status TEXT NOT NULL, reason TEXT NOT NULL,
                    discovered_count INTEGER NOT NULL DEFAULT 0,
                    new_count INTEGER NOT NULL DEFAULT 0, error TEXT,
                    started_at REAL NOT NULL, finished_at REAL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS research_assets (
                    identity TEXT NOT NULL, project_slug TEXT NOT NULL,
                    asset_json TEXT NOT NULL, first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL, observation_count INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (identity, project_slug)
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_research_runs_started ON research_runs(started_at DESC)")
            db.execute("""CREATE TABLE IF NOT EXISTS lab_nodes (
                node_id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL,
                capabilities_json TEXT NOT NULL, metrics_json TEXT NOT NULL,
                last_heartbeat REAL NOT NULL, created_at REAL NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS lab_experiments (
                experiment_id TEXT PRIMARY KEY, node_id TEXT NOT NULL,
                project_slug TEXT NOT NULL, project_name TEXT NOT NULL,
                version TEXT, status TEXT NOT NULL, hypothesis TEXT NOT NULL,
                public_observation TEXT, reproduction_summary TEXT,
                evidence_json TEXT NOT NULL, remediation TEXT,
                conclusion_boundary TEXT NOT NULL, created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS research_hypotheses (
                hypothesis_id TEXT PRIMARY KEY, project_slug TEXT NOT NULL,
                question TEXT NOT NULL, rationale TEXT NOT NULL,
                method TEXT NOT NULL, expected_signal TEXT NOT NULL,
                status TEXT NOT NULL, conclusion TEXT,
                confidence REAL NOT NULL DEFAULT 0,
                metrics_json TEXT NOT NULL, model TEXT NOT NULL,
                created_at REAL NOT NULL, updated_at REAL NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_hypotheses_updated ON research_hypotheses(updated_at DESC)")
            db.execute("""CREATE TABLE IF NOT EXISTS intelligence_signals (
                signal_key TEXT PRIMARY KEY, source TEXT NOT NULL, name TEXT NOT NULL,
                query_text TEXT NOT NULL, rank INTEGER NOT NULL, is_hot INTEGER NOT NULL,
                hot_score REAL NOT NULL, momentum REAL NOT NULL,
                status TEXT NOT NULL, decision_json TEXT, raw_json TEXT NOT NULL,
                first_seen REAL NOT NULL, last_seen REAL NOT NULL,
                observation_count INTEGER NOT NULL DEFAULT 1
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS intelligence_syncs (
                sync_id TEXT PRIMARY KEY, source TEXT NOT NULL, status TEXT NOT NULL,
                item_count INTEGER NOT NULL DEFAULT 0, promoted_count INTEGER NOT NULL DEFAULT 0,
                error TEXT, started_at REAL NOT NULL, finished_at REAL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_intelligence_seen ON intelligence_signals(last_seen DESC)")
            db.execute("""CREATE TABLE IF NOT EXISTS credential_leaks (
                leak_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                node_id TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '',
                base_url TEXT NOT NULL DEFAULT '',
                api_key_masked TEXT NOT NULL DEFAULT '',
                api_key_full TEXT NOT NULL DEFAULT '',
                secret_type TEXT NOT NULL DEFAULT '',
                source_path TEXT NOT NULL DEFAULT '',
                evidence TEXT,
                status TEXT NOT NULL DEFAULT 'new',
                verified_status TEXT NOT NULL DEFAULT 'unverified',
                verified_detail TEXT NOT NULL DEFAULT '',
                verified_at REAL,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_leaks_status ON credential_leaks(status)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_leaks_target ON credential_leaks(target)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_leaks_api_key ON credential_leaks(api_key_full)")
            db.execute("""CREATE TABLE IF NOT EXISTS alert_outbox (
                alert_id TEXT PRIMARY KEY,
                dedup_key TEXT NOT NULL,
                channel TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                payload_json TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                delivered_at REAL,
                last_attempt_at REAL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_outbox_key ON alert_outbox(dedup_key)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_outbox_status ON alert_outbox(status)")
            db.execute("""CREATE TABLE IF NOT EXISTS decision_cards (
                card_id TEXT PRIMARY KEY,
                topic TEXT NOT NULL,
                card_type TEXT NOT NULL DEFAULT 'component',
                change_text TEXT NOT NULL DEFAULT '',
                why_worth TEXT NOT NULL DEFAULT '',
                evidence_says TEXT NOT NULL DEFAULT '',
                evidence_limits TEXT NOT NULL DEFAULT '',
                next_step TEXT NOT NULL DEFAULT '',
                abort_condition TEXT NOT NULL DEFAULT '',
                evidence_level INTEGER NOT NULL DEFAULT 0,
                severity TEXT NOT NULL DEFAULT 'MEDIUM',
                confidence TEXT NOT NULL DEFAULT 'medium',
                source TEXT NOT NULL DEFAULT '',
                fofa_query TEXT NOT NULL DEFAULT '',
                asset_count INTEGER NOT NULL DEFAULT 0,
                dedup_key TEXT NOT NULL DEFAULT '',
                decision TEXT NOT NULL DEFAULT 'pending',
                score REAL NOT NULL DEFAULT 0,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                decided_at REAL,
                payload_json TEXT
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_cards_topic ON decision_cards(topic)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_cards_decision ON decision_cards(decision)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_cards_dedup ON decision_cards(dedup_key)")
            db.execute("""CREATE TABLE IF NOT EXISTS brain_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                event_type TEXT NOT NULL,
                action TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                project TEXT NOT NULL DEFAULT '',
                ai_thought TEXT NOT NULL DEFAULT '',
                meta_json TEXT NOT NULL DEFAULT ''
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_brain_events_ts ON brain_events(ts DESC)")
            db.execute("""CREATE TABLE IF NOT EXISTS threat_intel (
                cve_id TEXT PRIMARY KEY,
                component TEXT NOT NULL DEFAULT '',
                vendor TEXT NOT NULL DEFAULT '',
                product TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL DEFAULT '',
                date_added TEXT NOT NULL DEFAULT '',
                due_date TEXT NOT NULL DEFAULT '',
                known_ransomware INTEGER NOT NULL DEFAULT 0,
                source TEXT NOT NULL DEFAULT 'cisa-kev',
                first_seen REAL NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_threat_component ON threat_intel(component)")
            db.execute("""CREATE TABLE IF NOT EXISTS code_audits (
                audit_id TEXT PRIMARY KEY,
                repo TEXT NOT NULL,
                repo_path TEXT NOT NULL DEFAULT '',
                files_scanned INTEGER NOT NULL DEFAULT 0,
                files_with_danger INTEGER NOT NULL DEFAULT 0,
                risk_level TEXT NOT NULL DEFAULT 'unknown',
                summary TEXT NOT NULL DEFAULT '',
                report_json TEXT NOT NULL,
                created_at REAL NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_audits_repo ON code_audits(repo)")
            asset_columns = {row[1] for row in db.execute("PRAGMA table_info(research_assets)")}
            for name, definition in (
                ("analysis_status", "TEXT NOT NULL DEFAULT 'pending'"),
                ("analysis_json", "TEXT"), ("analyzed_at", "REAL"),
                ("analysis_error", "TEXT"),
            ):
                if name not in asset_columns:
                    db.execute(f"ALTER TABLE research_assets ADD COLUMN {name} {definition}")
            project_columns = {row[1] for row in db.execute("PRAGMA table_info(research_projects)")}
            for name, definition in (("insight_json", "TEXT"), ("insight_updated_at", "REAL"),
                                     ("origin", "TEXT NOT NULL DEFAULT 'seed'"),
                                     ("source_signal_key", "TEXT")):
                if name not in project_columns:
                    db.execute(f"ALTER TABLE research_projects ADD COLUMN {name} {definition}")
            db.execute("""
                UPDATE scan_tasks SET status='error', error='服务重启导致任务中断',
                    current_step='任务已中断', updated_at=?
                WHERE status IN ('pending', 'running')
            """, (time.time(),))

    def create_task(self, task_id: str, task: Dict[str, Any], metadata: Dict[str, Any]):
        now = task.get("created_at", time.time())
        with self._lock, self._connect() as db:
            db.execute("""
                INSERT INTO scan_tasks (
                    task_id, mode, query_text, requested_size, scan_api, online_query,
                    status, progress, current_step, analyzed_count, total_count, error,
                    cancel_requested, results_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task_id, metadata.get("mode", "manual"), metadata.get("query_text", ""),
                metadata.get("requested_size", 0), bool(metadata.get("scan_api")),
                bool(metadata.get("online_query")), task["status"], task["progress"],
                task["current_step"], task["analyzed_count"], task["total_count"],
                task.get("error"), bool(task.get("cancel_requested")), None, now, now,
            ))

    def update_task(self, task_id: str, changes: Dict[str, Any]):
        allowed = {"status", "progress", "current_step", "analyzed_count", "total_count", "error", "cancel_requested"}
        values = {key: value for key, value in changes.items() if key in allowed}
        if "results" in changes:
            values["results_json"] = json.dumps(changes["results"], ensure_ascii=False)
        if not values:
            return
        values["updated_at"] = time.time()
        columns = ", ".join(f"{key}=?" for key in values)
        with self._lock, self._connect() as db:
            db.execute(f"UPDATE scan_tasks SET {columns} WHERE task_id=?", (*values.values(), task_id))

    def get_task(self, task_id: str, include_results: bool = True) -> Optional[Dict[str, Any]]:
        with self._connect() as db:
            row = db.execute("SELECT * FROM scan_tasks WHERE task_id=?", (task_id,)).fetchone()
        return self._row_to_dict(row, include_results) if row else None

    def list_tasks(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM scan_tasks ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_dict(row, False) for row in rows]

    def seed_research_projects(self, projects: List[Dict[str, Any]]):
        now = time.time()
        with self._lock, self._connect() as db:
            for project in projects:
                db.execute("""
                    INSERT INTO research_projects
                    (slug,name,repository,upstream,license,discovery_query,category,priority,rationale,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(slug) DO UPDATE SET
                    name=excluded.name, repository=excluded.repository,
                    upstream=excluded.upstream, license=excluded.license,
                    discovery_query=excluded.discovery_query, category=excluded.category,
                    priority=excluded.priority, rationale=excluded.rationale,
                    updated_at=excluded.updated_at
                """, (project["slug"], project["name"], project.get("repository", ""),
                      project.get("upstream", ""), project.get("license", ""),
                      project["discovery_query"], project["category"], project["priority"],
                      project["rationale"], now, now))

    def upsert_trend_signal(self, signal: Dict[str, Any], decision: Dict[str, Any]) -> bool:
        """Persist an immutable-ish raw observation and its latest research decision."""
        now = time.time()
        with self._lock, self._connect() as db:
            exists = db.execute("SELECT 1 FROM intelligence_signals WHERE signal_key=?",
                                (signal["signal_key"],)).fetchone()
            db.execute("""INSERT INTO intelligence_signals
                (signal_key,source,name,query_text,rank,is_hot,hot_score,momentum,status,
                 decision_json,raw_json,first_seen,last_seen,observation_count)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1)
                ON CONFLICT(signal_key) DO UPDATE SET rank=excluded.rank,is_hot=excluded.is_hot,
                hot_score=excluded.hot_score,momentum=excluded.momentum,status=excluded.status,
                decision_json=excluded.decision_json,raw_json=excluded.raw_json,
                last_seen=excluded.last_seen,observation_count=observation_count+1""", (
                signal["signal_key"], signal["source"], signal["name"], signal["query"],
                signal["rank"], signal["is_hot"], signal["hot_score"], signal["momentum"],
                decision.get("status", "observed"), json.dumps(decision, ensure_ascii=False),
                json.dumps(signal["raw"], ensure_ascii=False), now, now))
        return not bool(exists)

    def upsert_dynamic_research_project(self, project: Dict[str, Any]):
        now = time.time()
        with self._lock, self._connect() as db:
            db.execute("""INSERT INTO research_projects
                (slug,name,repository,upstream,license,discovery_query,category,priority,
                 rationale,origin,source_signal_key,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(slug) DO UPDATE SET
                name=excluded.name,discovery_query=excluded.discovery_query,
                category=excluded.category,priority=excluded.priority,
                rationale=excluded.rationale,origin=excluded.origin,
                source_signal_key=excluded.source_signal_key,enabled=1,updated_at=excluded.updated_at""", (
                project["slug"], project["name"], project.get("repository", ""),
                project.get("upstream", "待研究"), project.get("license", "待研究"),
                project["discovery_query"], project["category"], project["priority"],
                project["rationale"], "trend", project["source_signal_key"], now, now))

    def start_intelligence_sync(self, sync_id: str, source: str):
        with self._lock, self._connect() as db:
            db.execute("INSERT INTO intelligence_syncs (sync_id,source,status,started_at) VALUES (?,?,?,?)",
                       (sync_id, source, "running", time.time()))

    def finish_intelligence_sync(self, sync_id: str, status: str, item_count: int = 0,
                                 promoted_count: int = 0, error: str = ""):
        with self._lock, self._connect() as db:
            db.execute("""UPDATE intelligence_syncs SET status=?,item_count=?,promoted_count=?,
                error=?,finished_at=? WHERE sync_id=?""",
                (status, item_count, promoted_count, error[:1000], time.time(), sync_id))

    def intelligence_overview(self, limit: int = 20) -> Dict[str, Any]:
        with self._connect() as db:
            signals = [dict(row) for row in db.execute("""SELECT name,rank,is_hot,hot_score,
                momentum,status,last_seen,observation_count FROM intelligence_signals
                ORDER BY last_seen DESC,is_hot DESC,hot_score DESC LIMIT ?""", (limit,)).fetchall()]
            last_sync = db.execute("""SELECT status,item_count,promoted_count,error,started_at,finished_at
                FROM intelligence_syncs ORDER BY started_at DESC LIMIT 1""").fetchone()
        return {"signals": signals, "last_sync": dict(last_sync) if last_sync else None}

    def next_research_project(self) -> Optional[Dict[str, Any]]:
        now = time.time()
        with self._connect() as db:
            row = db.execute("""
                SELECT * FROM research_projects WHERE enabled=1 AND
                (next_run_at IS NULL OR next_run_at<=?)
                ORDER BY CASE WHEN last_run_at IS NULL THEN 0 ELSE 1 END,
                         priority DESC, last_run_at ASC LIMIT 1
            """, (now,)).fetchone()
        return dict(row) if row else None

    def start_research_run(self, run_id: str, project_slug: str, reason: str):
        with self._lock, self._connect() as db:
            db.execute("INSERT INTO research_runs (run_id,project_slug,status,reason,started_at) VALUES (?,?,?,?,?)",
                       (run_id, project_slug, "running", reason, time.time()))

    def finish_research_run(self, run_id: str, project_slug: str, status: str,
                            discovered: int = 0, new_count: int = 0, error: str = "",
                            next_run_at: float = 0):
        now = time.time()
        with self._lock, self._connect() as db:
            db.execute("""UPDATE research_runs SET status=?, discovered_count=?, new_count=?,
                       error=?, finished_at=? WHERE run_id=?""",
                       (status, discovered, new_count, error[:1000], now, run_id))
            db.execute("UPDATE research_projects SET last_run_at=?,next_run_at=?,updated_at=? WHERE slug=?",
                       (now, next_run_at, now, project_slug))

    def upsert_research_assets(self, project_slug: str, assets: List[Dict[str, Any]]) -> int:
        now, new_count = time.time(), 0
        with self._lock, self._connect() as db:
            for asset in assets:
                identity = (asset.get("url") or f"{asset.get('ip','')}:{asset.get('port',0)}").rstrip("/").lower()
                if not identity:
                    continue
                exists = db.execute("SELECT 1 FROM research_assets WHERE identity=? AND project_slug=?",
                                    (identity, project_slug)).fetchone()
                if exists:
                    db.execute("""UPDATE research_assets SET asset_json=?,last_seen=?,
                               observation_count=observation_count+1 WHERE identity=? AND project_slug=?""",
                               (json.dumps(asset, ensure_ascii=False), now, identity, project_slug))
                else:
                    new_count += 1
                    db.execute("""INSERT INTO research_assets
                        (identity,project_slug,asset_json,first_seen,last_seen,observation_count)
                        VALUES (?,?,?,?,?,1)""",
                               (identity, project_slug, json.dumps(asset, ensure_ascii=False), now, now))
        return new_count

    def pending_research_assets(self, project_slug: str, limit: int) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as db:
            rows = db.execute("""SELECT identity,asset_json FROM research_assets
                WHERE project_slug=? AND analysis_status IN ('pending','error')
                ORDER BY first_seen ASC LIMIT ?""", (project_slug, limit)).fetchall()
            identities = [row["identity"] for row in rows]
            if identities:
                placeholders = ",".join("?" for _ in identities)
                db.execute(f"UPDATE research_assets SET analysis_status='running' WHERE project_slug=? AND identity IN ({placeholders})",
                           (project_slug, *identities))
        return [{"identity": row["identity"], "asset": json.loads(row["asset_json"])} for row in rows]

    def next_project_with_pending_assets(self) -> Optional[Dict[str, Any]]:
        """Pick the project whose pending queue has waited the longest."""
        with self._connect() as db:
            row = db.execute("""
                SELECT p.*, MIN(a.first_seen) AS oldest_pending
                FROM research_projects p JOIN research_assets a ON a.project_slug=p.slug
                WHERE p.enabled=1 AND a.analysis_status IN ('pending','error')
                GROUP BY p.slug ORDER BY oldest_pending ASC, p.priority DESC LIMIT 1
            """).fetchone()
        return dict(row) if row else None

    def save_research_analysis(self, identity: str, project_slug: str,
                               analysis: Optional[Dict[str, Any]], error: str = "",
                               status: str = "completed"):
        with self._lock, self._connect() as db:
            db.execute("""UPDATE research_assets SET analysis_status=?,analysis_json=?,
                       analyzed_at=?,analysis_error=? WHERE identity=? AND project_slug=?""",
                       (status if analysis else "error",
                        json.dumps(analysis, ensure_ascii=False) if analysis else None,
                        time.time(), error[:1000], identity, project_slug))

    def project_analysis_data(self, project_slug: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("""SELECT analysis_json FROM research_assets
                WHERE project_slug=? AND analysis_status='completed' AND analysis_json IS NOT NULL
                ORDER BY analyzed_at DESC LIMIT ?""", (project_slug, limit)).fetchall()
        return [json.loads(row["analysis_json"]) for row in rows]

    def save_project_insight(self, project_slug: str, insight: Dict[str, Any]):
        with self._lock, self._connect() as db:
            db.execute("UPDATE research_projects SET insight_json=?,insight_updated_at=?,updated_at=? WHERE slug=?",
                       (json.dumps(insight, ensure_ascii=False), time.time(), time.time(), project_slug))

    def project_research_metrics(self, project_slug: str) -> Dict[str, Any]:
        with self._connect() as db:
            counts = {row[0]: row[1] for row in db.execute("""
                SELECT analysis_status,COUNT(*) FROM research_assets
                WHERE project_slug=? GROUP BY analysis_status
            """, (project_slug,)).fetchall()}
            samples = [json.loads(row[0]) for row in db.execute("""
                SELECT analysis_json FROM research_assets WHERE project_slug=?
                AND analysis_json IS NOT NULL ORDER BY analyzed_at DESC LIMIT 30
            """, (project_slug,)).fetchall()]
        total_decided = counts.get("completed", 0) + counts.get("rejected", 0)
        confirmed = counts.get("completed", 0)
        return {
            "candidate_count": sum(counts.values()), "confirmed_count": confirmed,
            "rejected_count": counts.get("rejected", 0),
            "pending_count": counts.get("pending", 0) + counts.get("running", 0),
            "reject_reasons": {} if not samples else {},
            "confirmed_samples": samples,
            "confirmation_rate": round(confirmed / total_decided, 4) if total_decided else None,
            "samples": [{
                "confirmation": sample.get("project_confirmation", {}),
                "technologies": [tech.get("name") for tech in sample.get("technologies", [])],
                "api_count": len(sample.get("api_endpoints", [])),
                "exposure_types": sorted({field for finding in sample.get("exposure_findings", [])
                    for field in finding.get("sensitive_field_types", [])}),
            } for sample in samples],
        }

    def research_asset_urls(self, project_slug: str, limit: int = 100) -> List[str]:
        """取某项目研究资产的 url 列表（用于泄露回扫等批量探测）"""
        with self._connect() as db:
            rows = db.execute("""SELECT asset_json FROM research_assets
                WHERE project_slug=? LIMIT ?""", (project_slug, limit)).fetchall()
        urls = []
        for row in rows:
            try:
                a = json.loads(row["asset_json"])
                u = a.get("url") or ""
                if u:
                    urls.append(u)
            except Exception:
                continue
        return urls

    def save_research_hypothesis(self, hypothesis: Dict[str, Any]):
        now = time.time()
        with self._lock, self._connect() as db:
            db.execute("""INSERT INTO research_hypotheses
                (hypothesis_id,project_slug,question,rationale,method,expected_signal,
                 status,conclusion,confidence,metrics_json,model,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(hypothesis_id) DO UPDATE SET
                status=excluded.status,conclusion=excluded.conclusion,
                confidence=excluded.confidence,metrics_json=excluded.metrics_json,
                updated_at=excluded.updated_at""", (
                hypothesis["hypothesis_id"], hypothesis["project_slug"], hypothesis["question"],
                hypothesis["rationale"], hypothesis["method"], hypothesis["expected_signal"],
                hypothesis.get("status", "active"), hypothesis.get("conclusion", ""),
                hypothesis.get("confidence", 0),
                json.dumps(hypothesis.get("metrics", {}), ensure_ascii=False),
                hypothesis.get("model", "规则研究器"), now, now))

    def recent_research_hypotheses(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self._connect() as db:
            rows = [dict(row) for row in db.execute("""SELECT h.*,p.name AS project_name
                FROM research_hypotheses h JOIN research_projects p ON p.slug=h.project_slug
                ORDER BY h.updated_at DESC LIMIT ?""", (limit,)).fetchall()]
        for row in rows:
            row["metrics"] = json.loads(row.pop("metrics_json"))
        return rows

    def analyzed_research_assets(self, limit: int = 1000) -> List[Dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("""SELECT a.*,p.name AS project_name,p.upstream,p.repository,p.license
                FROM research_assets a JOIN research_projects p ON p.slug=a.project_slug
                WHERE a.analysis_status='completed' AND a.analysis_json IS NOT NULL
                ORDER BY a.analyzed_at DESC LIMIT ?""", (limit,)).fetchall()
        result = []
        for row in rows:
            item = json.loads(row["analysis_json"])
            item["project_family"] = {
                "name": row["project_name"], "upstream": row["upstream"],
                "repository": row["repository"], "license": row["license"],
                "deployment_relation": "第三方自行部署", "deployment_owner": "待确认",
                "confidence": "medium", "evidence": ["项目专用发现规则与公开页面指纹"],
                "notice": "上游项目归属不等于该公网实例的资产归属或安全责任。",
            }
            item.update({"first_seen": row["first_seen"], "last_seen": row["last_seen"],
                         "scan_count": row["observation_count"], "research_managed": True})
            result.append(item)
        return result

    def research_overview(self) -> Dict[str, Any]:
        with self._connect() as db:
            projects = [dict(row) for row in db.execute("""
                SELECT p.*, COUNT(DISTINCT a.identity) AS asset_count,
                    SUM(CASE WHEN a.analysis_status='completed' THEN 1 ELSE 0 END) AS analyzed_count,
                    SUM(CASE WHEN a.analysis_status='pending' THEN 1 ELSE 0 END) AS pending_count,
                    SUM(CASE WHEN a.analysis_status='rejected' THEN 1 ELSE 0 END) AS rejected_count
                FROM research_projects p LEFT JOIN research_assets a ON a.project_slug=p.slug
                GROUP BY p.slug ORDER BY p.priority DESC, p.name
            """).fetchall()]
            runs = [dict(row) for row in db.execute("""
                SELECT r.*, p.name AS project_name FROM research_runs r
                JOIN research_projects p ON p.slug=r.project_slug
                ORDER BY r.started_at DESC LIMIT 30
            """).fetchall()]
        for project in projects:
            project["insight"] = json.loads(project.pop("insight_json")) if project.get("insight_json") else None
        return {"projects": projects, "runs": runs,
                "hypotheses": self.recent_research_hypotheses(),
                "intelligence": self.intelligence_overview(),
                "total_candidate_assets": sum(row["asset_count"] for row in projects)}

    def upsert_lab_report(self, report: Dict[str, Any]):
        now = time.time()
        node_id = report["node_id"]
        with self._lock, self._connect() as db:
            db.execute("""INSERT INTO lab_nodes
                (node_id,name,status,capabilities_json,metrics_json,last_heartbeat,created_at)
                VALUES (?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET
                name=excluded.name,status=excluded.status,
                capabilities_json=excluded.capabilities_json,
                metrics_json=excluded.metrics_json,last_heartbeat=excluded.last_heartbeat""",
                (node_id, report.get("name", node_id), report.get("status", "ready"),
                 json.dumps(report.get("capabilities", []), ensure_ascii=False),
                 json.dumps(report.get("metrics", {}), ensure_ascii=False), now, now))
            for experiment in report.get("experiments", []):
                db.execute("""INSERT INTO lab_experiments
                    (experiment_id,node_id,project_slug,project_name,version,status,hypothesis,
                     public_observation,reproduction_summary,evidence_json,remediation,
                     conclusion_boundary,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(experiment_id) DO UPDATE SET
                    status=excluded.status,version=excluded.version,
                    reproduction_summary=excluded.reproduction_summary,
                    evidence_json=excluded.evidence_json,remediation=excluded.remediation,
                    updated_at=excluded.updated_at""",
                    (experiment["experiment_id"], node_id, experiment["project_slug"],
                     experiment["project_name"], experiment.get("version", "待确认"),
                     experiment.get("status", "planned"), experiment["hypothesis"],
                     experiment.get("public_observation", ""), experiment.get("reproduction_summary", ""),
                     json.dumps(experiment.get("evidence", []), ensure_ascii=False),
                     experiment.get("remediation", ""), experiment.get("conclusion_boundary",
                     "靶场复现不等同于第三方公网实例已被利用。"), now, now))

    def lab_overview(self) -> Dict[str, Any]:
        with self._connect() as db:
            nodes = [dict(row) for row in db.execute("SELECT * FROM lab_nodes ORDER BY last_heartbeat DESC").fetchall()]
            experiments = [dict(row) for row in db.execute("SELECT * FROM lab_experiments ORDER BY updated_at DESC").fetchall()]
        now = time.time()
        for node in nodes:
            node["capabilities"] = json.loads(node.pop("capabilities_json"))
            node["metrics"] = json.loads(node.pop("metrics_json"))
            node["online"] = now - node["last_heartbeat"] < 300
        for experiment in experiments:
            experiment["evidence"] = json.loads(experiment.pop("evidence_json"))
        return {"nodes": nodes, "experiments": experiments}

    # ============================================================
    # 凭据泄露表（credential_leaks）
    # ============================================================
    def upsert_credential_leak(self, leak: Dict[str, Any]):
        """写入/更新一条凭据泄露记录（按 target+api_key_full 去重）

        api_key_full 落库前加密（Codex P0-1）：明文不落盘，只存 Fernet 密文。
        """
        from core.secrets_crypto import encrypt_secret, encryption_available
        now = time.time()
        full_key = leak.get("api_key_full", "") or ""
        # 已加密的密文不再二次加密；明文则加密（或未配置 SECRET_KEY 时不存完整密钥）
        stored_key = full_key
        if full_key:
            if full_key.startswith("enc:v1:"):
                stored_key = full_key
            elif encryption_available():
                stored_key = encrypt_secret(full_key)
            else:
                stored_key = ""  # 无 SECRET_KEY：不持久化完整密钥，仅保留脱敏
        with self._lock, self._connect() as db:
            existing = db.execute(
                "SELECT leak_id, last_seen FROM credential_leaks WHERE target=? AND api_key_full=?",
                (leak.get("target", ""), stored_key)).fetchone()
            if existing:
                db.execute("""UPDATE credential_leaks SET last_seen=?, status=?,
                    provider=?, base_url=?, evidence=?, node_id=?
                    WHERE leak_id=?""",
                    (now, leak.get("status", "new"), leak.get("provider", ""),
                     leak.get("base_url", ""), json.dumps(leak.get("evidence", []), ensure_ascii=False),
                     leak.get("node_id", ""), existing["leak_id"]))
                return existing["leak_id"]
            leak_id = leak.get("leak_id") or (hashlib.md5(
                (str(leak.get("target", "")) + "|" + str(full_key)).encode()).hexdigest())
            db.execute("""INSERT OR IGNORE INTO credential_leaks
                (leak_id, target, node_id, provider, base_url, api_key_masked, api_key_full,
                 secret_type, source_path, evidence, status, first_seen, last_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (leak_id, leak.get("target", ""), leak.get("node_id", ""),
                 leak.get("provider", ""), leak.get("base_url", ""),
                 leak.get("api_key_masked", ""), stored_key,
                 leak.get("secret_type", ""), leak.get("source_path", ""),
                 json.dumps(leak.get("evidence", []), ensure_ascii=False),
                 leak.get("status", "new"), now, now))
            return leak_id

    def update_credential_leak_verification(self, leak_id: str, verified_status: str,
                                            detail: str = "", base_url: str = "",
                                            provider: str = ""):
        """更新泄露 key 的有效性验证结果（verified_status: valid/invalid/error）"""
        with self._lock, self._connect() as db:
            db.execute("""UPDATE credential_leaks SET verified_status=?, verified_detail=?,
                       verified_at=?, base_url=CASE WHEN ?!='' THEN ? ELSE base_url END,
                       provider=CASE WHEN ?!='' THEN ? ELSE provider END
                       WHERE leak_id=?""",
                       (verified_status, detail[:500], time.time(),
                        base_url, base_url, provider, provider, leak_id))

    def list_credential_leaks(self, limit: int = 100, status: str = "",
                              target: str = "", include_full: bool = False) -> List[Dict[str, Any]]:
        """查询凭据泄露记录

        include_full=False 时删除 api_key_full（前端仅用 masked）；
        include_full=True 时解密返回完整密钥（仅限已授权管理员调用）。
        """
        from core.secrets_crypto import decrypt_secret
        sql = "SELECT * FROM credential_leaks WHERE 1=1"
        params: list = []
        if status:
            sql += " AND status=?"
            params.append(status)
        if target:
            sql += " AND target LIKE ?"
            params.append("%" + target + "%")
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        with self._connect() as db:
            rows = db.execute(sql, params).fetchall()
        leaks = [dict(row) for row in rows]
        for l in leaks:
            if include_full:
                # 返回原始存储值（可能是 enc:v1: 密文或明文），由调用方解密
                l["api_key_full"] = l.get("api_key_full", "") or ""
            else:
                l.pop("api_key_full", None)
        return leaks

    def credential_leak_stats(self) -> Dict[str, Any]:
        """凭据泄露统计"""
        with self._connect() as db:
            total = db.execute("SELECT COUNT(*) c FROM credential_leaks").fetchone()["c"]
            by_provider = dict(db.execute(
                "SELECT provider, COUNT(*) c FROM credential_leaks GROUP BY provider").fetchall())
            by_type = dict(db.execute(
                "SELECT secret_type, COUNT(*) c FROM credential_leaks GROUP BY secret_type").fetchall())
            by_target = dict(db.execute(
                "SELECT target, COUNT(*) c FROM credential_leaks GROUP BY target ORDER BY c DESC LIMIT 20").fetchall())
            verified = {}
            try:
                verified = dict(db.execute(
                    "SELECT verified_status, COUNT(*) c FROM credential_leaks GROUP BY verified_status").fetchall())
            except Exception:
                pass
        return {"total": total, "by_provider": by_provider, "by_type": by_type,
                "by_target": by_target, "by_verified": verified}

    # ============================================================
    # 告警 outbox（持久化投递队列，Codex P1）
    # ============================================================
    def outbox_insert(self, alert_id: str, dedup_key: str, channel: str, payload: Dict[str, Any]):
        """插入一条待投递告警"""
        now = time.time()
        with self._lock, self._connect() as db:
            db.execute("""INSERT OR IGNORE INTO alert_outbox
                (alert_id, dedup_key, channel, status, payload_json, created_at)
                VALUES (?,?,?,?,?,?)""",
                (alert_id, dedup_key, channel, "pending",
                 json.dumps(payload, ensure_ascii=False), now))

    def outbox_pending(self, limit: int = 50) -> List[Dict[str, Any]]:
        """查询待投递（含失败待重试）的告警"""
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM alert_outbox WHERE status IN ('pending','failed') "
                "AND attempt_count < 5 ORDER BY created_at ASC LIMIT ?",
                (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d.pop("payload_json"))
            out.append(d)
        return out

    def outbox_mark(self, alert_id: str, delivered: bool, error: str = ""):
        """标记投递结果：成功置 delivered，失败记录错误并递增尝试次数"""
        now = time.time()
        with self._lock, self._connect() as db:
            if delivered:
                db.execute("UPDATE alert_outbox SET status='delivered', delivered_at=?, last_attempt_at=? "
                           "WHERE alert_id=?", (now, now, alert_id))
            else:
                db.execute("""UPDATE alert_outbox SET status='failed', last_error=?,
                    attempt_count=attempt_count+1, last_attempt_at=? WHERE alert_id=?""",
                    (error[:500], now, alert_id))

    def outbox_delivered_recently(self, dedup_key: str, cooldown: float) -> bool:
        """去重：同一 dedup_key 在冷却期内是否已有 delivered 记录"""
        now = time.time()
        with self._connect() as db:
            row = db.execute(
                "SELECT delivered_at FROM alert_outbox WHERE dedup_key=? AND status='delivered' "
                "ORDER BY delivered_at DESC LIMIT 1", (dedup_key,)).fetchone()
        return bool(row and row["delivered_at"] and (now - row["delivered_at"]) < cooldown)

    def alert_outbox_available(self) -> bool:
        """outbox 表是否可用（存在即可用）"""
        try:
            with self._connect() as db:
                db.execute("SELECT 1 FROM alert_outbox LIMIT 1")
            return True
        except Exception:
            return False

    # ============================================================
    # 研判卡 decision_cards（Codex：判断与克制 / 反馈闭环）
    # ============================================================
    def card_insert(self, card: Dict[str, Any]) -> bool:
        """插入研判卡（按 dedup_key 幂等）。返回是否新插入。"""
        now = time.time()
        card_id = card.get("card_id") or hashlib.md5(
            (card.get("dedup_key") or "").encode()).hexdigest()
        dedup_key = card.get("dedup_key") or card_id
        with self._lock, self._connect() as db:
            existing = db.execute(
                "SELECT card_id FROM decision_cards WHERE dedup_key=?", (dedup_key,)).fetchone()
            if existing:
                # 更新观测（评分/资产数/时间变化）
                db.execute("""UPDATE decision_cards SET last_seen=?, asset_count=?, score=?, 
                    change_text=?, evidence_level=?, severity=?, confidence=?
                    WHERE card_id=?""",
                    (now, card.get("asset_count", 0), card.get("score", 0),
                     card.get("change_text", ""), card.get("evidence_level", 0),
                     card.get("severity", "MEDIUM"), card.get("confidence", "medium"),
                     existing["card_id"]))
                return False
            db.execute("""INSERT INTO decision_cards
                (card_id, topic, card_type, change_text, why_worth, evidence_says, evidence_limits,
                 next_step, abort_condition, evidence_level, severity, confidence, source,
                 fofa_query, asset_count, dedup_key, decision, score, first_seen, last_seen, payload_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (card_id, card.get("topic", ""), card.get("card_type", "component"),
                 card.get("change_text", ""), card.get("why_worth", ""),
                 card.get("evidence_says", ""), card.get("evidence_limits", ""),
                 card.get("next_step", ""), card.get("abort_condition", ""),
                 card.get("evidence_level", 0), card.get("severity", "MEDIUM"),
                 card.get("confidence", "medium"), card.get("source", ""),
                 card.get("fofa_query", ""), card.get("asset_count", 0),
                 dedup_key, card.get("decision", "pending"), card.get("score", 0),
                 now, now, json.dumps(card.get("payload", {}), ensure_ascii=False)))
        return True

    def card_list(self, limit: int = 100, decision: str = "", topic: str = "") -> List[Dict[str, Any]]:
        """查询研判卡（默认 pending 优先、按评分降序）"""
        sql = "SELECT * FROM decision_cards WHERE 1=1"
        params: list = []
        if decision:
            sql += " AND decision=?"
            params.append(decision)
        if topic:
            sql += " AND topic LIKE ?"
            params.append("%" + topic + "%")
        sql += " ORDER BY (decision='pending') DESC, score DESC, last_seen DESC LIMIT ?"
        params.append(limit)
        with self._connect() as db:
            rows = db.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["payload"] = json.loads(d.pop("payload_json") or "{}")
            except Exception:
                d["payload"] = {}
            out.append(d)
        return out

    def card_decide(self, card_id: str, decision: str) -> bool:
        """标记研判卡：值得研究 / 噪音 / 证据不足 / 已处理"""
        allowed = ("worth", "noise", "insufficient", "done")
        if decision not in allowed:
            return False
        with self._lock, self._connect() as db:
            db.execute("UPDATE decision_cards SET decision=?, decided_at=? WHERE card_id=?",
                       (decision, time.time(), card_id))
        return True

    def card_stats(self) -> Dict[str, Any]:
        """研判卡统计（用于反馈闭环评估）"""
        with self._connect() as db:
            total = db.execute("SELECT COUNT(*) c FROM decision_cards").fetchone()["c"]
            by_decision = dict(db.execute(
                "SELECT decision, COUNT(*) c FROM decision_cards GROUP BY decision").fetchall())
            pending = db.execute("SELECT COUNT(*) c FROM decision_cards WHERE decision='pending'").fetchone()["c"]
        return {"total": total, "pending": pending, "by_decision": by_decision}

    # ============================================================
    # 大脑活动流 brain_events（思考可视化）
    # ============================================================
    def brain_event(self, event_type: str, action: str = "", detail: str = "",
                    reason: str = "", project: str = "", ai_thought: str = "",
                    meta: dict = None):
        """记录一条大脑活动（思考过程可视化）"""
        with self._lock, self._connect() as db:
            db.execute("""INSERT INTO brain_events
                (ts, event_type, action, detail, reason, project, ai_thought, meta_json)
                VALUES (?,?,?,?,?,?,?,?)""",
                (time.time(), event_type, action, detail, reason, project, ai_thought,
                 json.dumps(meta or {}, ensure_ascii=False)))
            # 只保留最近 2000 条，避免膨胀
            db.execute("""DELETE FROM brain_events WHERE event_id NOT IN
                (SELECT event_id FROM brain_events ORDER BY event_id DESC LIMIT 2000)""")

    def brain_events(self, limit: int = 100, event_type: str = "") -> List[Dict[str, Any]]:
        """查询大脑活动流（按时间倒序）"""
        sql = "SELECT * FROM brain_events WHERE 1=1"
        params: list = []
        if event_type:
            sql += " AND event_type=?"
            params.append(event_type)
        sql += " ORDER BY event_id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as db:
            rows = db.execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["meta"] = json.loads(d.pop("meta_json") or "{}")
            except Exception:
                d["meta"] = {}
            out.append(d)
        return out

    # ============================================================
    # 攻击情报 threat_intel（CISA KEV，Issue #10 目标 3）
    # ============================================================
    def upsert_threat_intel(self, item: Dict[str, Any]):
        """写入一条 KEV 攻击情报（按 cve_id 幂等）"""
        with self._lock, self._connect() as db:
            db.execute("""INSERT OR IGNORE INTO threat_intel
                (cve_id, component, vendor, product, name, date_added, due_date,
                 known_ransomware, source, first_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (item.get("cve_id", ""), item.get("component", ""), item.get("vendor", ""),
                 item.get("product", ""), item.get("name", ""), item.get("date_added", ""),
                 item.get("due_date", ""), int(bool(item.get("known_ransomware"))),
                 item.get("source", "cisa-kev"), time.time()))

    def threat_intel_for_component(self, component: str) -> Dict[str, Any]:
        """查询某组件的 KEV 攻击情报"""
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM threat_intel WHERE component=? ORDER BY date_added DESC", (component,)).fetchall()
            ransomware = db.execute(
                "SELECT COUNT(*) c FROM threat_intel WHERE component=? AND known_ransomware=1",
                (component,)).fetchone()["c"]
        items = [dict(r) for r in rows]
        return {"total": len(items), "ransomware": ransomware, "items": items}

    def threat_intel_overview(self) -> Dict[str, Any]:
        """攻击情报概览：按组件统计 KEV 命中数"""
        with self._connect() as db:
            total = db.execute("SELECT COUNT(*) c FROM threat_intel").fetchone()["c"]
            by_component = dict(db.execute(
                "SELECT component, COUNT(*) c FROM threat_intel GROUP BY component ORDER BY c DESC").fetchall())
            ransomware_total = db.execute(
                "SELECT COUNT(*) c FROM threat_intel WHERE known_ransomware=1").fetchone()["c"]
            last = db.execute("SELECT MAX(first_seen) m FROM threat_intel").fetchone()["m"]
        return {"total": total, "ransomware_total": ransomware_total,
                "last_sync": last, "by_component": by_component}

    # ============================================================
    # 代码审计 code_audits（Issue #10 目标 1/6）
    # ============================================================
    def save_code_audit(self, report: Dict[str, Any]):
        """保存代码审计结果（按 repo 幂等）"""
        audit_id = hashlib.md5((report.get("repo") or "").encode()).hexdigest()
        ai = report.get("ai_report") or {}
        with self._lock, self._connect() as db:
            db.execute("""INSERT OR REPLACE INTO code_audits
                (audit_id, repo, repo_path, files_scanned, files_with_danger,
                 risk_level, summary, report_json, created_at)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (audit_id, report.get("repo", ""), report.get("repo_path", ""),
                 report.get("files_scanned", 0), report.get("files_with_danger", 0),
                 ai.get("risk_level", "unknown") if isinstance(ai, dict) else "unknown",
                 (ai.get("summary", "") if isinstance(ai, dict) else ""),
                 json.dumps(report, ensure_ascii=False), time.time()))

    def list_code_audits(self, limit: int = 20) -> List[Dict[str, Any]]:
        """查询代码审计记录"""
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM code_audits ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["report"] = json.loads(d.pop("report_json"))
            except Exception:
                d["report"] = {}
            out.append(d)
        return out

    @staticmethod
    def _row_to_dict(row, include_results: bool) -> Dict[str, Any]:
        item = dict(row)
        raw_results = item.pop("results_json", None)
        item["cancel_requested"] = bool(item["cancel_requested"])
        item["scan_api"] = bool(item["scan_api"])
        item["online_query"] = bool(item["online_query"])
        if include_results:
            item["results"] = json.loads(raw_results) if raw_results else None
        return item
