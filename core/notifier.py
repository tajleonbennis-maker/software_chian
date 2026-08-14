"""告警推送模块：SK 泄露 / CRITICAL 资产 / 高危组件 发现时按最小字段集推送。

支持通道：
- Webhook（任意 HTTP POST，JSON 格式）
- Telegram Bot（配置 bot token + chat id 后走 sendMessage API）

字段集对齐 Grok 建议：
[级别] 类型 / 资产 / 组件版本 / 摘要 / 时间 / 来源 / 置信度 / SK(脱敏) / 链接
"""
import json
import logging
import os
import threading
import time
import urllib.request

logger = logging.getLogger("Notifier")

# 告警去重：key -> 上次推送时间戳（防告警风暴，Codex 建议）
_alert_dedup = {}
_alert_lock = threading.Lock()
# 默认冷却时间（秒）：同一资产 + 同一类型的告警，在冷却期内不重复推送
DEFAULT_COOLDOWN = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "3600"))


def _now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def alert_key(alert: dict) -> str:
    """稳定去重键：asset + type + component（+ cve）"""
    asset = (alert.get("asset") or "").strip()
    atype = (alert.get("type") or "").strip()
    component = (alert.get("component") or "").strip()
    cve = (alert.get("cve_id") or "").strip()
    return f"{asset}|{atype}|{component}|{cve}".lower()


def is_duplicate(alert: dict, cooldown: int = DEFAULT_COOLDOWN) -> bool:
    """判断是否冷却期内重复告警；非重复则登记"""
    key = alert_key(alert)
    if not key or key == "|||":
        return False
    now = time.time()
    with _alert_lock:
        last = _alert_dedup.get(key)
        if last and (now - last) < cooldown:
            return True
        _alert_dedup[key] = now
        # 简单内存清理：最多保留 5000 个键
        if len(_alert_dedup) > 5000:
            for k in list(_alert_dedup.keys())[:1000]:
                _alert_dedup.pop(k, None)
    return False


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
    """统一告警入口：去重 → 规范化 payload → 按已配置通道推送

    返回 True 表示推送成功；去重命中（冷却期内）返回 False 且不推送。
    """
    # 去重：同一资产 + 类型 + 组件在冷却期内不重复推送
    if is_duplicate(alert, cooldown):
        logger.debug("告警去重命中，跳过: %s", alert_key(alert))
        return False
    payload = format_alert(alert)
    sent = False
    if webhook_url:
        sent = send_webhook(webhook_url, payload) or sent
    if bot_token and chat_id:
        sent = send_telegram(bot_token, chat_id, payload) or sent
    return sent
