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
        try:
            from core.kafka_pipeline import KafkaProducer
            kafka_bs = getattr(config, "KAFKA_BOOTSTRAP", "") or "121.41.98.7:9092"
            self.kafka = KafkaProducer(bootstrap_servers=kafka_bs)
        except Exception as exc:
            logger.warning("Kafka 生产者初始化失败: %s", exc)
            self.kafka = None
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

        优先通过 Kafka 投递（节点消费）；Kafka 不可用时回退 HTTP 推送。
        返回统计；无可用渠道时返回 ok=False。
        """
        if not targets:
            return {"ok": True, "dispatched": 0, "reason": "无待分析资产"}

        # 渠道1: Kafka 投递（节点作为消费者并行消费）
        if self.kafka and self.kafka.available:
            chunk = max(1, len(targets) // 4)  # 每任务最多 20 资产
            tasks = []
            for i in range(0, len(targets), chunk):
                batch = targets[i:i + chunk]
                tasks.append({
                    "task_id": uuid.uuid4().hex,
                    "type": "deep_analysis",
                    "project_slug": project_slug,
                    "project_name": project_name or project_slug,
                    "targets": batch,
                    "online": True,
                })
            sent = self.kafka.send_batch(tasks)
            self.database.brain_event(
                event_type="action", action="Kafka 任务分发",
                detail=f"{project_name or project_slug} {len(targets)} 资产 → Kafka {sent['sent']} 任务",
                reason="节点通过 Kafka 消费 deep_analysis",
                project=project_slug,
                meta={"topic": sent.get("topic"), "sent": sent["sent"], "assets": len(targets)})
            return {"ok": sent["sent"] > 0, "dispatched": sent["sent"],
                    "channel": "kafka", "assets": len(targets), "sent": sent}

        # 渠道2: HTTP 推送（Kafka 不可用）
        nodes = self.list_workers()
        if not nodes:
            return {"ok": False, "reason": "无可用节点且 Kafka 不可用", "dispatched": 0}

        dispatched = []
        chunk = max(1, len(targets) // len(nodes))
        for i in range(0, len(targets), chunk):
            batch = targets[i:i + chunk]
            node = self._select_node(project_slug, nodes)
            if not node:
                break
            r = self._dispatch_batch(node, project_slug, project_name or project_slug, batch)
            dispatched.append(r)

        self.database.brain_event(
            event_type="action", action="节点分发",
            detail=f"{project_name or project_slug} {len(targets)} 资产 → {len(dispatched)} 批次 · 节点 {len(nodes)} 台",
            reason="多节点并行深度分析（deep_analysis）",
            project=project_slug,
            meta={"nodes": len(nodes), "assets": len(targets), "batches": len(dispatched)})
        return {"ok": True, "dispatched": len(dispatched), "nodes": len(nodes),
                "assets": len(targets), "batches": dispatched}

    def node_status(self) -> dict:
        """节点实时状态（供可视化）"""
        nodes = []
        try:
            for n in self.dispatcher.list_nodes():
                healthy = self._node_healthy(n)
                nodes.append({
                    "node_id": n.get("node_id"), "name": n.get("name"),
                    "url": n.get("url"), "status": "ready" if healthy else "offline",
                    "capabilities": n.get("capabilities", []),
                })
        except Exception:
            pass
        return {"nodes": nodes, "total": len(nodes),
                "online": sum(1 for n in nodes if n.get("status") == "ready")}
