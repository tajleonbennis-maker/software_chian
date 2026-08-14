"""告警推送模块：SK 泄露 / CRITICAL 资产 / 高危组件 发现时按最小字段集推送。

支持通道：
- Webhook（任意 HTTP POST，JSON 格式）
- Telegram Bot（配置 bot token + chat id 后走 sendMessage API）

字段集对齐 Grok 建议：
[级别] 类型 / 资产 / 组件版本 / 摘要 / 时间 / 来源 / 置信度 / SK(脱敏) / 链接

去重与投递状态持久化（Codex P1）：使用 SQLite alert_outbox 表，跨 worker 一致、
重启不丢、失败重试（最多 5 次），仅成功投递后登记去重。
"""
import hashlib
import json
import logging
import os
import threading
import time
import urllib.request

logger = logging.getLogger("Notifier")

# 默认冷却时间（秒）：同一 dedup_key 在冷却期内不重复推送
DEFAULT_COOLDOWN = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "3600"))
_lock = threading.Lock()
_db = None  # 延迟注入 ScanDatabase 实例


def set_database(db):
    """注入数据库实例（大脑 app 启动时调用）"""
    global _db
    _db = db


def alert_key(alert: dict) -> str:
    """稳定去重键：asset + type + component（+ cve）"""
    asset = (alert.get("asset") or "").strip()
    atype = (alert.get("type") or "").strip()
    component = (alert.get("component") or "").strip()
    cve = (alert.get("cve_id") or "").strip()
    return f"{asset}|{atype}|{component}|{cve}".lower()


def alert_id(alert: dict) -> str:
    """告警稳定 ID（用于 outbox 幂等）"""
    return hashlib.md5(alert_key(alert).encode()).hexdigest()


def _now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _mask_key(key: str, keep: int = 4) -> str:
    """SK 等密钥脱敏：只保留前 4 后 4，中间掩码"""
    if not key:
        return ""
    key = str(key).strip()
    if len(key) <= keep * 2 + 2:
        return key[:keep] + "***"
    return key[:keep] + "***" + key[-keep:]


def format_alert(alert: dict) -> dict:
    """把告警对象规范化为推送 payload（脱敏后的最小字段集）"""
    sev = (alert.get("severity") or "").upper()
    atype = alert.get("type", "HIGH")
    level = sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else str(atype).upper()
    key_masked = _mask_key(alert.get("api_key", "") or alert.get("api_key_masked", ""))
    return {
        "event": "security_alert",
        "level": level,
        "type": atype,
        "asset": alert.get("asset", ""),
        "component": alert.get("component", ""),
        "version": alert.get("version", ""),
        "summary": alert.get("summary", ""),
        "time": alert.get("time") or _now_str(),
        "source": alert.get("source", "brain"),
        "confidence": alert.get("confidence", "medium"),
        "api_key_masked": key_masked,
        "link": alert.get("link", ""),
        "payload": alert.get("payload", {}),
    }


def send_webhook(url: str, payload: dict, timeout: int = 10) -> bool:
    """POST JSON 到任意 Webhook 端点"""
    if not url:
        return False
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "SupplyChainBrain/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        logger.warning("Webhook 推送失败: %s", exc)
        return False


def send_telegram(bot_token: str, chat_id: str, payload: dict, timeout: int = 10) -> bool:
    """通过 Telegram Bot API 推送（HTML 排版）"""
    if not bot_token or not chat_id:
        return False
    text = (
        f"<b>[{payload.get('level')}] {payload.get('type')}</b>\n"
        f"资产：{payload.get('asset') or '-'}\n"
        f"组件/版本：{payload.get('component') or '-'} {payload.get('version') or ''}\n"
        f"摘要：{payload.get('summary') or '-'}\n"
        f"时间：{payload.get('time')}\n"
        f"来源：{payload.get('source')} · 置信度 {payload.get('confidence')}"
    )
    if payload.get("api_key_masked"):
        text += f"\nSK：{payload['api_key_masked']}"
    if payload.get("link"):
        text += f"\n链接：{payload['link']}"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    body = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                       "disable_web_page_preview": True}).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        logger.warning("Telegram 推送失败: %s", exc)
        return False


def notify(alert: dict, webhook_url: str = "", bot_token: str = "", chat_id: str = "",
           cooldown: int = DEFAULT_COOLDOWN) -> bool:
    """统一告警入口（outbox 持久化版）：
    - 去重查询基于已 delivered 记录（跨 worker 一致、重启不丢）
    - 写入 alert_outbox 并尝试立即投递；失败留待 flush_outbox 重试
    """
    if not (_db is not None and _db.alert_outbox_available()):
        logger.warning("告警 outbox 不可用（未注入数据库），跳过")
        return False
    key = alert_key(alert)
    if not key or key == "|||":
        return False
    # 去重：冷却期内已有 delivered 记录则跳过
    with _lock:
        if _db.outbox_delivered_recently(key, cooldown):
            logger.debug("告警去重命中（已投递）: %s", key)
            return False
        payload = format_alert(alert)
        _db.outbox_insert(alert_id(alert), key, "brain", payload)
    # 立即尝试投递
    return _deliver(alert_id(alert), payload, webhook_url, bot_token, chat_id)


def _deliver(aid: str, payload: dict, webhook_url: str, bot_token: str, chat_id: str) -> bool:
    """投递单条告警；成功标记 delivered，失败标记 failed 待重试"""
    sent = False
    if webhook_url:
        sent = send_webhook(webhook_url, payload) or sent
    if bot_token and chat_id:
        sent = send_telegram(bot_token, chat_id, payload) or sent
    if _db is not None:
        _db.outbox_mark(aid, delivered=sent, error="" if sent else "no channel configured / send failed")
    return sent


def flush_outbox(webhook_url: str = "", bot_token: str = "", chat_id: str = "",
                 max_items: int = 20) -> int:
    """重试待投递告警（失败重试，最多 5 次）。返回本次成功数。"""
    if _db is None:
        return 0
    pending = _db.outbox_pending(limit=max_items)
    delivered = 0
    for item in pending:
        payload = item.get("payload") or {}
        ok = _deliver(item["alert_id"], payload, webhook_url, bot_token, chat_id)
        if ok:
            delivered += 1
    return delivered
