"""凭据加密工具（Codex P0-1：停止明文持久化 api_key_full）。

- 用 Fernet（AES-128-CBC + HMAC）加密完整密钥，落库的 api_key_full 列存密文
- 密钥由 SECRET_KEY 环境变量经 SHA-256 派生；未配置时退化为「不存完整密钥只存脱敏」
- list 接口仅在显式 full=1 且传入解密密钥时才解密
"""
import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet

logger = logging.getLogger("SecretsCrypto")

_PREFIX = "enc:v1:"


def _fernet() -> Fernet:
    """由 SECRET_KEY 派生 Fernet 密钥（32 bytes → base64 urlsafe）"""
    secret = os.environ.get("SECRET_KEY", "").strip()
    if not secret:
        raise ValueError("SECRET_KEY 未配置，无法加解密凭据")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def encrypt_secret(plain: str) -> str:
    """加密明文密钥，返回带前缀的密文"""
    if not plain:
        return ""
    try:
        token = _fernet().encrypt(plain.encode("utf-8"))
        return _PREFIX + token.decode()
    except Exception as exc:
        logger.warning("凭据加密失败: %s", exc)
        return ""


def decrypt_secret(cipher: str) -> str:
    """解密密文；非本系统密文（未加密的旧数据）原样返回（兼容迁移期）"""
    if not cipher:
        return ""
    if not cipher.startswith(_PREFIX):
        return cipher  # 旧明文数据（迁移前），原样返回
    try:
        token = cipher[len(_PREFIX):]
        return _fernet().decrypt(token.encode()).decode("utf-8")
    except Exception as exc:
        logger.warning("凭据解密失败: %s", exc)
        return ""


def encryption_available() -> bool:
    """SECRET_KEY 是否已配置（决定是否启用加密存储）"""
    return bool(os.environ.get("SECRET_KEY", "").strip())
