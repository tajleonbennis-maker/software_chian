"""SQLite persistence for scan tasks and reports."""
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
            asset_columns = {row[1] for row in db.execute("PRAGMA table_info(research_assets)")}
            for name, definition in (
                ("analysis_status", "TEXT NOT NULL DEFAULT 'pending'"),
                ("analysis_json", "TEXT"), ("analyzed_at", "REAL"),
                ("analysis_error", "TEXT"),
            ):
                if name not in asset_columns:
                    db.execute(f"ALTER TABLE research_assets ADD COLUMN {name} {definition}")
            project_columns = {row[1] for row in db.execute("PRAGMA table_info(research_projects)")}
            for name, definition in (("insight_json", "TEXT"), ("insight_updated_at", "REAL")):
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

    def save_research_analysis(self, identity: str, project_slug: str,
                               analysis: Optional[Dict[str, Any]], error: str = ""):
        with self._lock, self._connect() as db:
            db.execute("""UPDATE research_assets SET analysis_status=?,analysis_json=?,
                       analyzed_at=?,analysis_error=? WHERE identity=? AND project_slug=?""",
                       ("completed" if analysis else "error",
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
                    SUM(CASE WHEN a.analysis_status='pending' THEN 1 ELSE 0 END) AS pending_count
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
                "total_candidate_assets": sum(row["asset_count"] for row in projects)}

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
