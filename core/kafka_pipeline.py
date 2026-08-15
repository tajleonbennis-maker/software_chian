"""Kafka 任务队列管线（Kafka Pipeline）。

把大脑的资产分析任务投递到 Kafka topic，由各执行引擎节点（worker）作为
消费者并行消费执行。相比 HTTP 主动推送，Kafka 提供：
- 解耦：大脑只管生产，节点只管消费
- 持久化：任务落盘，节点重启不丢任务
- 弹性：节点随意增减，自动负载均衡
- 绕过入站防火墙：节点只需能访问 Kafka（出站）即可

Topic 设计：
- supply-chain-tasks：资产分析任务（deep_analysis）
消息格式（JSON）：
{
  "task_id": "...", "type": "deep_analysis",
  "project_slug": "...", "project_name": "...",
  "targets": ["http://..."], "online": true
}
"""
import json
import logging
import os
import threading
import time

logger = logging.getLogger("KafkaPipeline")

DEFAULT_BOOTSTRAP = "127.0.0.1:9092"
DEFAULT_TOPIC = "supply-chain-tasks"


class KafkaProducer:
    """大脑端任务生产者：向 Kafka topic 投递任务"""

    def __init__(self, bootstrap_servers: str = "", topic: str = "",
                 retry_on_failure: bool = True):
        self.bootstrap = bootstrap_servers or DEFAULT_BOOTSTRAP
        self.topic = topic or DEFAULT_TOPIC
        self.retry_on_failure = retry_on_failure
        self._producer = None
        self._lock = threading.Lock()
        self._connect()

    def _connect(self):
        try:
            from kafka import KafkaProducer as KP
            try:
                self._producer = KP(bootstrap_servers=self.bootstrap,
                                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                                    acks="all", retries=3, request_timeout_ms=10000)
                logger.info("Kafka 生产者已连接 %s topic=%s", self.bootstrap, self.topic)
            except Exception:
                # broker 不可达（KafkaError 或其子类）
                logger.warning("Kafka broker 不可达 %s（任务将走 HTTP 推送回退）", self.bootstrap)
                self._producer = None
        except Exception as exc:
            logger.warning("Kafka 初始化失败: %s（回退 HTTP 推送）", exc)
            self._producer = None

    @property
    def available(self) -> bool:
        return self._producer is not None

    def send_task(self, task: dict) -> bool:
        """投递一个任务，返回是否成功"""
        if not self._producer:
            return False
        try:
            with self._lock:
                future = self._producer.send(self.topic, value=task)
                future.get(timeout=10)
            return True
        except Exception as exc:
            logger.warning("Kafka 投递失败: %s", exc)
            if self.retry_on_failure:
                # 触发重连一次
                try:
                    self._producer.close()
                except Exception:
                    pass
                self._producer = None
                self._connect()
            return False

    def send_batch(self, tasks: list) -> dict:
        """批量投递，返回统计"""
        ok = 0
        for t in tasks:
            if self.send_task(t):
                ok += 1
        return {"total": len(tasks), "sent": ok,
                "failed": len(tasks) - ok, "topic": self.topic}

    def close(self):
        try:
            if self._producer:
                self._producer.close()
        except Exception:
            pass


class KafkaConsumer:
    """节点端任务消费者：从 Kafka 拉取任务并交给执行回调"""

    def __init__(self, bootstrap_servers: str = "", topic: str = "",
                 group_id: str = "supply-nodes"):
        self.bootstrap = bootstrap_servers or DEFAULT_BOOTSTRAP
        self.topic = topic or DEFAULT_TOPIC
        self.group_id = group_id
        self._consumer = None
        self._thread = None
        self._stop = threading.Event()

    def _connect(self):
        from kafka import KafkaConsumer as KC
        try:
            self._consumer = KC(
                self.topic,
                bootstrap_servers=self.bootstrap,
                group_id=self.group_id,
                # Decode inside the consume loop so one legacy/corrupt record
                # cannot poison the partition and spin a worker at 100% CPU.
                value_deserializer=None,
                auto_offset_reset="earliest",
                enable_auto_commit=False,
                session_timeout_ms=10000,
                heartbeat_interval_ms=3000,
                # The broker version is managed with this deployment. Avoid
                # auto-version probing, which can exhaust its tiny bootstrap
                # deadline on high-latency workers before the first request.
                api_version=(3, 6, 0),
                request_timeout_ms=30000,
                socket_connection_setup_timeout_ms=30000,
                socket_connection_setup_timeout_max_ms=60000,
                # A deep scan is intentionally synchronous and can run for a
                # long time. Keep the partition lease while that single task
                # is executing instead of triggering a rebalance every five
                # minutes (Kafka's default max poll interval).
                max_poll_interval_ms=int(os.environ.get(
                    "KAFKA_MAX_POLL_INTERVAL_MS", "14400000")),
                max_poll_records=1,
                consumer_timeout_ms=2000,
            )
            return True
        except Exception as exc:
            logger.warning("Kafka broker 不可达 %s（消费端未连接）: %s", self.bootstrap, exc)
            self._consumer = None
            return False

    def start(self, handle_task) -> threading.Thread:
        """启动后台消费线程。handle_task(task) -> bool 处理成功返回 True。

        处理成功后手动 commit offset；失败则回滚给同组其他节点重试。
        """
        if not self._connect():
            logger.warning("Kafka 不可用，消费端未启动（worker 继续走 HTTP 接收）")
            return None

        def _loop():
            logger.info("Kafka 消费者启动: %s topic=%s group=%s",
                        self.bootstrap, self.topic, self.group_id)
            while not self._stop.is_set():
                try:
                    records = self._consumer.poll(timeout_ms=1000)
                    for _tp, msgs in records.items():
                        for msg in msgs:
                            if self._stop.is_set():
                                return
                            try:
                                try:
                                    raw = msg.value.decode("utf-8") if isinstance(msg.value, bytes) else msg.value
                                    task = json.loads(raw) if isinstance(raw, str) else raw
                                    if not isinstance(task, dict):
                                        raise ValueError("task payload must be a JSON object")
                                except Exception as exc:
                                    logger.error("跳过损坏 Kafka 消息 topic=%s partition=%s offset=%s: %s",
                                                 msg.topic, msg.partition, msg.offset, exc)
                                    self._consumer.commit()
                                    continue
                                ok = handle_task(task)
                                if ok:
                                    self._consumer.commit()
                                else:
                                    # Do not acknowledge failed work. Rewind so
                                    # it can be retried by this consumer group.
                                    self._consumer.seek(_tp, msg.offset)
                                    time.sleep(1)
                            except Exception as exc:
                                logger.warning("消费任务异常: %s", exc)
                                self._consumer.seek(_tp, msg.offset)
                                time.sleep(1)
                except Exception as exc:
                    logger.warning("Kafka 消费循环异常: %s", exc)
                    time.sleep(3)

        self._thread = threading.Thread(target=_loop, daemon=True,
                                        name="kafka-consumer")
        self._thread.start()
        return self._thread

    def stop(self):
        self._stop.set()
        try:
            if self._consumer:
                self._consumer.close()
        except Exception:
            pass
