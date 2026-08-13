"""
任务分发器 - 大脑端

负责任务的分配与结果回收：
- 向各执行引擎（worker 节点）下发扫描任务
- 接收执行引擎上报的心跳与实验结果
- 将结果写入统一数据库（lab_nodes / lab_experiments）

执行引擎通过 HTTP 与本模块通信，认证使用共享 token。
"""
import json
import logging
import threading
import time
import uuid
import requests
from typing import Any, Dict, List, Optional

logger = logging.getLogger("TaskDispatcher")


class TaskDispatcher:
    """大脑端任务分发器"""

    def __init__(self, database, config):
        self.database = database
        self.config = config
        self._nodes: List[Dict[str, Any]] = []
        self._reload_nodes()

    # ------------------------------------------------------------
    # 节点管理
    # ------------------------------------------------------------
    def _reload_nodes(self):
        """从配置加载执行引擎节点列表"""
        raw = self.config.EXECUTOR_NODES or []
        self._nodes = []
        for entry in raw:
            if isinstance(entry, dict):
                self._nodes.append({
                    "node_id": entry.get("node_id", ""),
                    "name": entry.get("name", entry.get("node_id", "")),
                    "url": entry.get("url", "").rstrip("/"),
                    "token": entry.get("token", ""),
                    "capabilities": entry.get("capabilities", ["fofa", "vuln", "api", "tech"]),
                    "enabled": entry.get("enabled", True),
                    "last_heartbeat": 0.0,
                })

    def list_nodes(self) -> List[Dict[str, Any]]:
        return self._nodes

    def _node_headers(self, node: Dict[str, Any]) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {node['token']}",
            "Content-Type": "application/json",
            "X-Node-Id": node["node_id"],
        }

    # ------------------------------------------------------------
    # 任务下发
    # ------------------------------------------------------------
    def dispatch(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """向一个执行引擎下发任务。

        Args:
            task: 任务字典，需包含 task_id、type（任务类型）、params（任务参数）
        """
        task_id = task.get("task_id") or uuid.uuid4().hex
        task_type = task.get("type", "scan")
        params = task.get("params", {})

        # 选择能处理该任务的节点
        candidates = [n for n in self._nodes if n["enabled"]]
        if not candidates:
            return {"ok": False, "error": "没有可用的执行引擎节点", "task_id": task_id}

        errors = []
        for node in candidates:
            try:
                url = f"{node['url']}/api/v1/tasks/run"
                resp = requests.post(
                    url,
                    json={"task_id": task_id, "type": task_type, "params": params},
                    headers=self._node_headers(node),
                    timeout=self.config.NODE_HTTP_TIMEOUT,
                )
                if resp.status_code in (200, 202):
                    return {"ok": True, "task_id": task_id, "node_id": node["node_id"]}
                errors.append(f"{node['name']}: HTTP {resp.status_code}")
            except Exception as exc:
                errors.append(f"{node['name']}: {exc}")
                logger.warning("下发任务到 %s 失败: %s", node["name"], exc)

        return {"ok": False, "task_id": task_id, "error": "；".join(errors)}

    def dispatch_to_all(self, task: Dict[str, Any]) -> List[Dict[str, Any]]:
        """向所有启用的执行引擎广播任务"""
        results = []
        for node in [n for n in self._nodes if n["enabled"]]:
            t = dict(task)
            t["task_id"] = task.get("task_id") or uuid.uuid4().hex
            try:
                url = f"{node['url']}/api/v1/tasks/run"
                resp = requests.post(
                    url,
                    json={"task_id": t["task_id"], "type": t.get("type", "scan"),
                          "params": t.get("params", {})},
                    headers=self._node_headers(node),
                    timeout=self.config.NODE_HTTP_TIMEOUT,
                )
                results.append({
                    "node_id": node["node_id"], "ok": resp.status_code in (200, 202),
                    "status_code": resp.status_code,
                })
            except Exception as exc:
                results.append({"node_id": node["node_id"], "ok": False, "error": str(exc)})
        return results

    # ------------------------------------------------------------
    # 结果回收
    # ------------------------------------------------------------
    def receive_report(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """接收执行引擎上报的心跳与实验结果，写入数据库。

        Payload 结构：
        {
            "node_id": "...",
            "name": "...",
            "status": "ready",
            "capabilities": ["fofa", "vuln"],
            "metrics": {...},
            "experiments": [
                {
                    "experiment_id": "...", "project_slug": "...", "project_name": "...",
                    "version": "...", "status": "completed",
                    "hypothesis": "...", "public_observation": "...",
                    "reproduction_summary": "...", "evidence": [...],
                    "remediation": "...", "conclusion_boundary": "...",
                }
            ]
        }
        """
        node_id = payload.get("node_id", "")
        if not node_id:
            return {"ok": False, "error": "缺少 node_id"}
        try:
            self.database.upsert_lab_report(payload)
            logger.info("节点 %s 上报数据已入库 (experiments=%d)",
                        node_id, len(payload.get("experiments", [])))
            return {"ok": True}
        except Exception as exc:
            logger.exception("节点上报入库失败: %s", exc)
            return {"ok": False, "error": str(exc)}
