"""API Key 有效性验证器（Key Verifier）。

对从公网发现的 LLM API Key，向其 base_url 发起轻量只读验证请求，
判断密钥是否仍然有效（valid / invalid / error）。

验证策略（OpenAI 兼容协议）：
1. `GET {base}/v1/models`  —— 最轻量，不消耗 token，200 = 有效
2. 若 base 未知名：尝试常见 /v1/models 与 /models 变体
3. 401/403 = 密钥失效；网络异常 = error（无法判定）

安全约束：仅做只读请求，不发起任何计费调用。
"""
import logging
import re

import requests
import urllib3

urllib3.disable_warnings()

logger = logging.getLogger("KeyVerifier")

# base_url → 验证端点模板。key 已存在时即使 base_url 未知也可试探。
VERIFY_PATHS = ["/v1/models", "/models", "/v1/chat/completions"]


def _decrypt_full_key(stored_key: str) -> str:
    """解密 stored_key（支持 enc:v1: 密文或明文）"""
    if not stored_key:
        return ""
    if stored_key.startswith("enc:v1:"):
        try:
            from core.secrets_crypto import decrypt_secret
            return decrypt_secret(stored_key) or ""
        except Exception:
            return ""
    return stored_key


def _guess_base_url(leak: dict) -> str:
    """从泄露记录中推断 base_url（优先库中 base_url，其次从 evidence/target 推断）"""
    base_url = (leak.get("base_url") or "").strip()
    if base_url:
        return base_url.rstrip("/")
    # 从 evidence 或 target 中找 URL
    target = leak.get("target", "")
    m = re.match(r"^(https?://[^/]+)", target)
    return m.group(1) if m else ""


def verify_api_key(leak: dict, timeout: int = 15) -> dict:
    """验证单个泄露 key。

    返回: {"leak_id":..., "verified_status": "valid|invalid|error",
           "detail": "...", "provider": "...", "base_url": "..."}
    """
    leak_id = leak.get("leak_id", "")
    full_key = _decrypt_full_key(leak.get("api_key_full", "") or "")
    if not full_key:
        return {"leak_id": leak_id, "verified_status": "error",
                "detail": "密钥为空或无法解密", "provider": leak.get("provider", ""),
                "base_url": leak.get("base_url", "")}

    base_url = _guess_base_url(leak)
    if not base_url:
        return {"leak_id": leak_id, "verified_status": "error",
                "detail": "无法确定 base_url", "provider": leak.get("provider", ""),
                "base_url": ""}

    headers = {
        "Authorization": "Bearer " + full_key,
        "Content-Type": "application/json",
    }

    # 方法1: GET /v1/models（不消耗 token）
    for path in ["/v1/models", "/models"]:
        try:
            resp = requests.get(base_url + path, headers=headers, timeout=timeout,
                                verify=False)
            if resp.status_code == 200:
                detail = f"GET {path} → 200 有效"
                try:
                    data = resp.json()
                    models = data.get("data") or []
                    if models:
                        detail += f"（可用模型 {len(models)} 个）"
                except Exception:
                    pass
                return {"leak_id": leak_id, "verified_status": "valid", "detail": detail,
                        "provider": leak.get("provider", "") or _infer_provider(base_url),
                        "base_url": base_url}
            if resp.status_code in (401, 403):
                return {"leak_id": leak_id, "verified_status": "invalid",
                        "detail": f"GET {path} → {resp.status_code} 密钥被拒绝",
                        "provider": leak.get("provider", ""), "base_url": base_url}
            if resp.status_code in (404, 405):
                continue  # 端点不存在，尝试下一个
        except requests.Timeout:
            logger.debug("验证超时: %s%s", base_url, path)
            return {"leak_id": leak_id, "verified_status": "error",
                    "detail": f"GET {path} 超时", "provider": leak.get("provider", ""),
                    "base_url": base_url}
        except requests.RequestException as exc:
            return {"leak_id": leak_id, "verified_status": "error",
                    "detail": f"请求异常: {str(exc)[:80]}", "provider": leak.get("provider", ""),
                    "base_url": base_url}

    # 方法2: 最小 chat 调用（需要 token，但不消费完成额度；仅用于判定有效性）
    try:
        resp = requests.post(base_url + "/v1/chat/completions",
                             headers=headers,
                             json={"model": "deepseek-chat",
                                   "messages": [{"role": "user", "content": "hi"}],
                                   "max_tokens": 1},
                             timeout=timeout, verify=False)
        if resp.status_code == 200:
            return {"leak_id": leak_id, "verified_status": "valid",
                    "detail": "POST chat/completions → 200 有效",
                    "provider": leak.get("provider", ""), "base_url": base_url}
        if resp.status_code in (401, 403):
            return {"leak_id": leak_id, "verified_status": "invalid",
                    "detail": f"POST chat/completions → {resp.status_code} 密钥被拒绝",
                    "provider": leak.get("provider", ""), "base_url": base_url}
        return {"leak_id": leak_id, "verified_status": "error",
                "detail": f"POST chat/completions → {resp.status_code}: {resp.text[:100]}",
                "provider": leak.get("provider", ""), "base_url": base_url}
    except Exception as exc:
        return {"leak_id": leak_id, "verified_status": "error",
                "detail": f"验证异常: {str(exc)[:80]}", "provider": leak.get("provider", ""),
                "base_url": base_url}


def verify_leaks(database, leak_ids: list = None, limit: int = 50) -> dict:
    """批量验证泄露 key。返回统计。"""
    leaks = database.list_credential_leaks(limit=limit, include_full=True)
    if leak_ids:
        leaks = [l for l in leaks if l.get("leak_id") in leak_ids]
    results = {"total": len(leaks), "valid": 0, "invalid": 0, "error": 0, "items": []}
    for leak in leaks:
        result = verify_api_key(leak)
        if database:
            database.update_credential_leak_verification(
                result["leak_id"], result["verified_status"], result["detail"],
                result.get("base_url", ""), result.get("provider", ""))
        results["items"].append(result)
        results[result["verified_status"]] = results.get(result["verified_status"], 0) + 1
        logger.info("key %s → %s (%s)", leak.get("api_key_masked", ""),
                    result["verified_status"], result["detail"][:60])
    return results


def _infer_provider(base_url: str) -> str:
    from core.leak_researcher import PROVIDER_HINTS
    lower = base_url.lower()
    for provider, hints in PROVIDER_HINTS:
        if any(h in lower for h in hints):
            return provider
    return "unknown"
