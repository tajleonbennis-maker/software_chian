"""
执行引擎 Worker - 运行在执行节点（公网服务器）上

职责：
1. 定期向大脑（121.41.98.7）上报心跳，宣告自身可用
2. 从大脑拉取任务
3. 执行任务（fofa 资产发现 / 漏洞检测 / API 扫描 / 技术检测）
4. 将结果通过 lab report 回传大脑，由大脑统一存储

依赖：requests、python-dotenv（与主应用相同）
运行方式：python worker.py
"""
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

# 优先加载 worker 专属配置，再加载默认 .env（如果存在）
load_dotenv(".env.worker", override=True)
load_dotenv(".env", override=False)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("WorkerNode")

# ============================================================
# 配置（环境变量）
# ============================================================
BRAIN_URL = os.environ.get("BRAIN_URL", "http://121.41.98.7:5566").rstrip("/")
NODE_ID = os.environ.get("NODE_ID", "")
NODE_NAME = os.environ.get("NODE_NAME", NODE_ID)
NODE_TOKEN = os.environ.get("NODE_TOKEN", "")
HEARTBEAT_INTERVAL = max(30, int(os.environ.get("HEARTBEAT_INTERVAL", "60")))
TASK_POLL_INTERVAL = max(10, int(os.environ.get("TASK_POLL_INTERVAL", "30")))
CAPABILITIES = [c.strip() for c in os.environ.get(
    "NODE_CAPABILITIES", "fofa,vuln,api,tech").split(",") if c.strip()]

# 执行任务时使用的 FoFa 凭据（执行节点自身的，或由大脑下发）
FOFA_KEY = os.environ.get("FOFA_KEY", "")
FOFA_SIZE = int(os.environ.get("FOFA_SIZE", "100"))
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "10"))


def _headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {NODE_TOKEN}",
        "X-Lab-Token": NODE_TOKEN,
        "Content-Type": "application/json",
        "X-Node-Id": NODE_ID,
    }


def _require_node_id():
    if not NODE_ID:
        logger.error("必须配置 NODE_ID 环境变量")
        sys.exit(1)


# ============================================================
# 任务执行器
# ============================================================
def execute_task(task: Dict[str, Any]) -> Dict[str, Any]:
    """执行一个任务，返回实验结果字典（与大数据库实验结构兼容）。"""
    task_id = task.get("task_id", uuid.uuid4().hex)
    task_type = task.get("type", "scan")
    params = task.get("params", {})

    logger.info("执行任务 %s (type=%s)", task_id, task_type)
    result = {
        "experiment_id": task_id,
        "project_slug": params.get("project_slug", "manual"),
        "project_name": params.get("project_name", params.get("project_slug", "manual")),
        "version": params.get("version", "待确认"),
        "status": "completed",
        "hypothesis": params.get("hypothesis", f"任务 {task_id}"),
        "public_observation": "",
        "reproduction_summary": "",
        "evidence": [],
        "remediation": "",
        "conclusion_boundary": "靶场复现不等同于第三方公网实例已被利用。",
    }

    try:
        if task_type == "fofa_discovery":
            result = _run_fofa_discovery(task_id, params, result)
        elif task_type == "vuln_check":
            result = _run_vuln_check(task_id, params, result)
        elif task_type == "api_scan":
            result = _run_api_scan(task_id, params, result)
        elif task_type == "tech_detect":
            result = _run_tech_detect(task_id, params, result)
        elif task_type == "echo":
            # 连通性测试任务
            result["reproduction_summary"] = f"echo ok: {params.get('message', 'ping')}"
            result["evidence"] = [{"type": "echo", "value": params.get("message", "ping")}]
        else:
            result["status"] = "error"
            result["reproduction_summary"] = f"不支持的任务类型: {task_type}"
    except Exception as exc:
        logger.exception("任务 %s 执行失败", task_id)
        result["status"] = "error"
        result["reproduction_summary"] = str(exc)
    return result


def _run_fofa_discovery(task_id: str, params: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    from core.fofa_client import FofaClient
    query = params.get("query", "")
    size = int(params.get("size", FOFA_SIZE))
    key = params.get("fofa_key", FOFA_KEY)
    if not query:
        raise ValueError("fofa_discovery 需要 query 参数")
    if not key:
        raise ValueError("未配置 FoFa 凭据（环境变量 FOFA_KEY 或任务参数 fofa_key）")
    client = FofaClient(key=key, timeout=SCAN_TIMEOUT + 20, max_retries=2)
    try:
        assets = client.search_all(query, max_results=size)
    finally:
        client.close()
    evidence = [a.to_dict() for a in assets]
    result["status"] = "completed"
    result["public_observation"] = f"FoFa 发现 {len(evidence)} 个资产"
    result["reproduction_summary"] = f"query={query}, size={size}, 命中 {len(evidence)}"
    result["evidence"] = evidence
    return result


def _run_vuln_check(task_id: str, params: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    from core.tech_detector import TechDetector
    from core.vuln_checker import VulnChecker
    targets = params.get("targets", [])
    if not targets:
        raise ValueError("vuln_check 需要 targets 参数")
    # 先做技术栈识别，再基于技术栈做漏洞匹配
    detector = TechDetector()
    checker = VulnChecker(enable_nvd=bool(params.get("online")), timeout=SCAN_TIMEOUT)
    evidence = []
    for target in targets:
        try:
            techs = detector.detect_from_http(target, timeout=SCAN_TIMEOUT)
            vulns = checker.check(techs)
            evidence.append({
                "target": target,
                "technologies": [t.to_dict() for t in techs],
                "vulnerabilities": [v.to_dict() for v in vulns],
            })
        except Exception as exc:
            evidence.append({"target": target, "error": str(exc)})
    result["status"] = "completed"
    result["public_observation"] = f"漏洞检测完成，检测 {len(targets)} 个目标"
    result["reproduction_summary"] = json.dumps(evidence, ensure_ascii=False)[:2000]
    result["evidence"] = evidence
    return result


def _run_api_scan(task_id: str, params: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    from core.api_scanner import APIScanner
    from core.fofa_client import Asset
    targets = params.get("targets", [])
    if not targets:
        raise ValueError("api_scan 需要 targets 参数")
    scanner = APIScanner(timeout=SCAN_TIMEOUT)
    evidence = []
    for target in targets:
        try:
            asset = Asset(host=target, ip=target, port=443, protocol="https", url=target)
            endpoints = scanner.scan(asset)
            report = scanner.generate_report(asset, endpoints)
            evidence.append({"target": target, "report": asdict_safe(report)})
        except Exception as exc:
            evidence.append({"target": target, "error": str(exc)})
    result["status"] = "completed"
    result["public_observation"] = f"API 扫描完成，检测 {len(targets)} 个目标"
    result["reproduction_summary"] = json.dumps(evidence, ensure_ascii=False)[:2000]
    result["evidence"] = evidence
    return result


def _run_tech_detect(task_id: str, params: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    from core.tech_detector import TechDetector
    targets = params.get("targets", [])
    if not targets:
        raise ValueError("tech_detect 需要 targets 参数")
    detector = TechDetector()
    evidence = []
    for target in targets:
        try:
            techs = detector.detect_from_http(target, timeout=SCAN_TIMEOUT)
            evidence.append({"target": target, "technologies": [t.to_dict() for t in techs]})
        except Exception as exc:
            evidence.append({"target": target, "error": str(exc)})
    result["status"] = "completed"
    result["public_observation"] = f"技术栈检测完成，检测 {len(targets)} 个目标"
    result["reproduction_summary"] = json.dumps(evidence, ensure_ascii=False)[:2000]
    result["evidence"] = evidence
    return result


def asdict_safe(obj):
    from dataclasses import asdict, is_dataclass
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return obj
    return {"value": str(obj)}


# ============================================================
# Worker 主循环
# ============================================================
class Worker:
    def __init__(self):
        self.stop_event = threading.Event()
        self._http = requests.Session()

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        resp = self._http.post(f"{BRAIN_URL}{path}", json=payload, headers=_headers(), timeout=30)
        resp.raise_for_status()
        return resp.json()

    def heartbeat(self):
        """向大脑上报心跳与能力"""
        payload = {
            "node_id": NODE_ID,
            "name": NODE_NAME,
            "status": "ready",
            "capabilities": CAPABILITIES,
            "metrics": {"ts": time.time(), "pid": os.getpid()},
            "experiments": [],
        }
        try:
            r = self._post("/api/lab/report", payload)
            logger.debug("心跳上报完成: %s", r)
        except Exception as exc:
            logger.warning("心跳上报失败: %s", exc)

    def poll_and_execute(self):
        """拉取任务并执行（此处以本机队列演示；生产可用大脑推送或 Redis 队列）"""
        # 当前实现：心跳 + 直接执行"待分发"任务由大脑侧调度。
        # 为了让链路可测，worker 每次轮询从大脑拉一个示例任务（若大脑配置了待办）。
        try:
            # 拉取任务端点（大脑未配置时返回空）
            resp = self._http.get(
                f"{BRAIN_URL}/api/tasks/assign?node_id={NODE_ID}",
                headers=_headers(), timeout=15)
            if resp.status_code == 200:
                task = resp.json().get("task")
                if task:
                    result = execute_task(task)
                    report = {
                        "node_id": NODE_ID,
                        "name": NODE_NAME,
                        "status": "ready",
                        "capabilities": CAPABILITIES,
                        "metrics": {"ts": time.time()},
                        "experiments": [result],
                    }
                    self._post("/api/lab/report", report)
                    logger.info("任务 %s 结果已回传大脑", task.get("task_id"))
        except requests.exceptions.HTTPError:
            pass  # 大脑未提供 assign 端点时静默
        except Exception as exc:
            logger.warning("轮询任务失败: %s", exc)

    def run(self):
        _require_node_id()
        logger.info("Worker %s 启动: 大脑=%s 能力=%s", NODE_ID, BRAIN_URL, CAPABILITIES)
        while not self.stop_event.is_set():
            self.heartbeat()
            self.poll_and_execute()
            self.stop_event.wait(HEARTBEAT_INTERVAL)


def main():
    worker = Worker()
    def _stop(signum, frame):
        worker.stop_event.set()
        logger.info("收到信号，Worker 停止")
        sys.exit(0)
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    worker.run()


if __name__ == "__main__":
    main()
