"""节点集群调度器（Node Planner）：让研究大脑的资产分析任务分发给多台节点执行。

背景：平台已部署多台执行引擎节点（worker.py），但研究大脑一直在主服务器本地
分析资产，节点长期空闲。本模块把「待分析资产列表」按节点轮询分发：

1. 每轮从研究大脑拿 pending 资产
2. 按节点能力与负载轮询选择节点
3. 异步下发 deep_analysis 任务（后台线程，不阻塞研究循环）
4. 大脑活动流记录每个节点「正在干什么」
5. 节点执行后回传 /api/lab/report，主服务器入库（含 SK 泄露自动识别）

能力矩阵（节点 capabilities）：
- fofa: FOFA 测绘搜索
- vuln: 漏洞检查
- api: API 扫描
- tech: 技术指纹
"""
import json
import logging
import threading
import time
import uuid
from urllib.parse import urlsplit

import requests

logger = logging.getLogger("NodePlanner")

# 每节点每轮最多接收的资产数（防止单节点过载）
MAX_ASSETS_PER_NODE = 20
# 单节点任务超时
NODE_TASK_TIMEOUT = 90


class NodePlanner:
    def __init__(self, dispatcher, database, config):
        self.dispatcher = dispatcher
        self.database = database
        self.config = config
        self._dispatch_lock = threading.Lock()
        self._round_counter = 0
        # Kafka 任务队列（优先投递，broker 不可用时回退 HTTP 推送）
        self.kafka = None
        if getattr(config, "KAFKA_ENABLED", True):
            try:
                from core.kafka_pipeline import KafkaProducer
                kafka_bs = getattr(config, "KAFKA_BOOTSTRAP", "") or "127.0.0.1:9092"
                self.kafka = KafkaProducer(bootstrap_servers=kafka_bs)
            except Exception as exc:
                logger.warning("Kafka 生产者初始化失败: %s", exc)
        # 在途任务：node_id -> 派发时间戳。派发后节点标记繁忙，直到回传或超时
        self._in_flight: dict = {}

    def mark_busy(self, node_id: str):
        """标记节点繁忙（派发任务后调用）"""
        with self._dispatch_lock:
            self._in_flight[node_id] = time.time()

    def mark_idle(self, node_id: str):
        """节点回传结果后标记空闲"""
        with self._dispatch_lock:
            self._in_flight.pop(node_id, None)

    def _is_in_flight(self, node_id: str) -> bool:
        """节点是否有在途任务（含超时清理：超过 5 分钟视为超时释放）"""
        with self._dispatch_lock:
            ts = self._in_flight.get(node_id)
            if ts is None:
                return False
            if time.time() - ts > 300:
                self._in_flight.pop(node_id, None)
                return False
            return True

    def list_workers(self, exclude_busy: bool = True) -> list:
        """返回当前可用节点（HTTP 健康检查 + 在途任务检测）"""
        nodes = []
        try:
            for n in self.dispatcher.list_nodes():
                if not n.get("enabled", False):
                    continue
                if not self._node_healthy(n):
                    continue
                if exclude_busy and (self._is_in_flight(n.get("node_id", ""))
                                     or self._node_busy(n.get("node_id", ""))):
                    continue
                n = dict(n)
                n["status"] = "ready"
                nodes.append(n)
        except Exception:
            pass
        return nodes

    def _node_busy(self, node_id: str) -> bool:
        """节点是否忙：最近 NODE_BUSY_WINDOW 秒内有完成/运行的实验任务"""
        window = getattr(self.config, "NODE_BUSY_WINDOW", 180)
        try:
            return self.database.node_recent_activity(node_id, window) > 0
        except Exception:
            return False

    def _node_healthy(self, node: dict) -> bool:
        """轻量健康检查：GET /health，2 秒超时"""
        try:
            url = f"{node['url'].rstrip('/')}/health"
            resp = requests.get(url, timeout=3, headers={
                "Authorization": f"Bearer {node.get('token','')}"})
            return resp.status_code == 200
        except Exception:
            return False

    def _select_node(self, project_slug: str, nodes: list) -> dict:
        """轮询选择节点（round-robin）"""
        if not nodes:
            return {}
        idx = self._round_counter % len(nodes)
        self._round_counter += 1
        return nodes[idx]

    def _dispatch_batch(self, node: dict, project_slug: str, project_name: str,
                        targets: list) -> dict:
        """向单个节点异步下发一批资产分析任务"""
        task_id = uuid.uuid4().hex
        task = {
            "task_id": task_id,
            "type": "deep_analysis",
            "params": {
                "project_slug": project_slug,
                "project_name": project_name,
                "targets": targets,
                "online": True,
            },
        }

        self.mark_busy(node.get("node_id", ""))
        def _run():
            try:
                url = f"{node['url']}/api/v1/tasks/run"
                resp = requests.post(
                    url,
                    json=task,
                    headers={"Authorization": f"Bearer {node.get('token','')}"},
                    timeout=NODE_TASK_TIMEOUT,
                )
                if resp.status_code in (200, 202):
                    data = resp.json()
                    self.database.brain_event(
                        event_type="result", action="节点分析完成",
                        detail=f"[{node['name']}] {project_name} 批次 {len(targets)} 资产 · status={data.get('status')}",
                        reason="节点 deep_analysis 回传完成",
                        project=project_slug,
                        meta={"node_id": node.get("node_id"), "node_name": node.get("name"),
                              "assets": len(targets), "experiment_id": data.get("experiment_id")})
                else:
                    self.database.brain_event(
                        event_type="warn", action="节点分析失败",
                        detail=f"[{node['name']}] {project_name} HTTP {resp.status_code}",
                        reason="节点回传异常", project=project_slug,
                        meta={"node_id": node.get("node_id")})
            except Exception as exc:
                self.database.brain_event(
                    event_type="warn", action="节点任务异常",
                    detail=f"[{node['name']}] {str(exc)[:80]}",
                    reason="节点连接失败", project=project_slug,
                    meta={"node_id": node.get("node_id")})
            finally:
                self.mark_idle(node.get("node_id", ""))

        threading.Thread(target=_run, daemon=True).start()
        return {"ok": True, "task_id": task_id, "node_id": node.get("node_id"),
                "node_name": node.get("name"), "targets": len(targets)}

    def dispatch_pending(self, project_slug: str, targets: list,
                         project_name: str = "") -> dict:
        """把待分析资产分发给节点集群。

        任务总是先进入持久台账。Kafka 可用时发布通知；发布失败时保留为
        pending，由 Worker 的 HTTP Pull 恢复。两种传输共享同一租约和结果协议。
        """
        if not targets:
            return {"ok": True, "dispatched": 0, "reason": "无待分析资产"}

        allowed_domains = tuple(getattr(self.config, "AUTHORIZED_SCAN_DOMAINS", ()) or ())
        unauthorized_targets = []
        if allowed_domains:
            scoped_targets = []
            for target in targets:
                host = (urlsplit(str(target)).hostname or "").lower()
                if any(host == domain or host.endswith("." + domain)
                       for domain in allowed_domains):
                    scoped_targets.append(target)
                else:
                    unauthorized_targets.append(target)
            targets = scoped_targets
        if unauthorized_targets:
            self.database.pause_research_assets(
                project_slug, unauthorized_targets,
                "paused: target outside AUTHORIZED_SCAN_DOMAINS")
            self.database.brain_event(
                event_type="warn", action="阻止越界目标",
                detail=f"{project_name or project_slug} 阻止 {len(unauthorized_targets)} 个目标进入 Worker",
                reason="目标主机不在生产授权域名白名单",
                project=project_slug,
                meta={"blocked_count": len(unauthorized_targets)},
            )
        if not targets:
            return {"ok": False, "dispatched": 0, "scope_blocked": True,
                    "blocked_assets": len(unauthorized_targets),
                    "reason": "所有目标均不在生产授权范围"}

        global_limit = int(getattr(self.config, "TASK_QUEUE_MAX_OUTSTANDING", 100))
        project_limit = int(getattr(self.config, "TASK_QUEUE_MAX_PER_PROJECT", 10))
        global_outstanding = self.database.node_task_outstanding()
        project_outstanding = self.database.node_task_outstanding(project_slug)
        online_workers = self.database.online_worker_count()
        task_capacity = min(global_limit - global_outstanding,
                            project_limit - project_outstanding)
        if online_workers <= 0:
            task_capacity = 0
        accepted_limit = max(0, task_capacity) * MAX_ASSETS_PER_NODE
        accepted_targets = targets[:accepted_limit]
        deferred_targets = targets[len(accepted_targets):]
        if deferred_targets:
            self.database.release_research_assets(
                project_slug, deferred_targets,
                "scheduler backpressure: queue capacity or workers unavailable")
        if not accepted_targets:
            self.database.brain_event(
                event_type="wait", action="调度背压",
                detail=(f"{project_name or project_slug} 暂缓 {len(targets)} 资产 · "
                        f"全局 {global_outstanding}/{global_limit} · "
                        f"项目 {project_outstanding}/{project_limit} · Worker {online_workers}"),
                reason="队列达到水位或没有在线 Worker，资产已安全退回 pending",
                project=project_slug,
                meta={"global_outstanding": global_outstanding,
                      "project_outstanding": project_outstanding,
                      "online_workers": online_workers},
            )
            return {"ok": True, "dispatched": 0, "backpressure": True,
                    "deferred_assets": len(targets), "online_workers": online_workers}

        # Primary channel: durable pull queue. Workers already poll the brain,
        # so the brain does not need inbound access to every short-lived node.
        queued = []
        published = 0
        for i in range(0, len(accepted_targets), MAX_ASSETS_PER_NODE):
            batch = accepted_targets[i:i + MAX_ASSETS_PER_NODE]
            task_id = uuid.uuid4().hex
            self.database.enqueue_node_task({
                "task_id": task_id,
                "type": "deep_analysis",
                "params": {
                    "project_slug": project_slug,
                    "project_name": project_name or project_slug,
                    "targets": batch,
                    "online": True,
                },
            })
            queued.append(task_id)
            if self.kafka and self.kafka.available:
                message = {
                    "task_id": task_id, "type": "deep_analysis",
                    "project_slug": project_slug,
                    "project_name": project_name or project_slug,
                    "targets": batch, "online": True,
                }
                if self.kafka.send_task(message):
                    self.database.mark_node_task_published(task_id)
                    published += 1
        self.database.brain_event(
            event_type="action", action="持久队列分发",
            detail=f"{project_name or project_slug} {len(accepted_targets)} 资产 → {len(queued)} 任务",
            reason="Kafka 通知 Worker，数据库签发执行租约；未发布任务由 HTTP Pull 恢复",
            project=project_slug,
            meta={"channel": "kafka+ledger", "tasks": len(queued),
                  "published": published, "assets": len(accepted_targets),
                  "deferred_assets": len(deferred_targets)})
        return {"ok": True, "dispatched": len(queued), "channel": "kafka+ledger",
                "published": published, "fallback_pull": len(queued) - published,
                "assets": len(accepted_targets), "deferred_assets": len(deferred_targets),
                "blocked_assets": len(unauthorized_targets),
                "task_ids": queued}

    def node_status(self) -> dict:
        """节点实时状态（供可视化）。

        Workers are outbound-only in the Kafka topology, so their public HTTP
        port is not a reliable liveness signal. Prefer the durable heartbeat
        received by the brain and only probe HTTP for nodes that have never
        reported a heartbeat (backwards compatibility with legacy workers).
        """
        nodes = []
        heartbeat_nodes = {}
        try:
            heartbeat_nodes = {
                n.get("node_id"): n
                for n in self.database.lab_overview().get("nodes", [])
                if n.get("node_id")
            }
        except Exception:
            logger.exception("读取节点心跳失败，回退 HTTP 健康检查")
        try:
            for n in self.dispatcher.list_nodes():
                heartbeat = heartbeat_nodes.get(n.get("node_id"))
                healthy = (bool(heartbeat.get("online")) if heartbeat is not None
                           else self._node_healthy(n))
                item = {
                    "node_id": n.get("node_id"), "name": n.get("name"),
                    "url": n.get("url"), "status": "ready" if healthy else "offline",
                    "capabilities": n.get("capabilities", []),
                    "health_source": "heartbeat" if heartbeat is not None else "http",
                }
                if heartbeat is not None:
                    item["last_heartbeat"] = heartbeat.get("last_heartbeat")
                    item["metrics"] = heartbeat.get("metrics", {})
                nodes.append(item)
        except Exception:
            logger.exception("生成节点状态失败")
        return {"nodes": nodes, "total": len(nodes),
                "online": sum(1 for n in nodes if n.get("status") == "ready")}
