"""
简单会话管理 - 基于内存的会话存储，支持管理员/游客两种角色

角色说明：
    - admin（管理员）：可以执行所有操作（下发分析任务、查看结果、管理配置）
    - guest（游客）：可以查看所有数据（结果、统计等），但不能执行分析操作
"""
import uuid
import time
import hashlib
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class Session:
    """会话信息"""
    session_id: str
    role: str  # "admin" 或 "guest"
    created_at: float
    expires_at: float

    @property
    def is_expired(self) -> bool:
        """判断会话是否已过期"""
        return time.time() > self.expires_at

    @property
    def is_admin(self) -> bool:
        """判断是否为管理员角色"""
        return self.role == "admin"


class SessionManager:
    """会话管理器
    
    基于内存字典存储会话信息，支持：
    - 管理员密码验证（SHA256 哈希比对）
    - 游客免密登录
    - 会话过期自动清理
    """

    def __init__(self, admin_password: str, session_timeout: int = 86400):
        """
        Args:
            admin_password: 管理员密码（明文，内部会进行 SHA256 哈希存储）
            session_timeout: 会话超时时间（秒），默认 24 小时
        """
        self.admin_password_hash = hashlib.sha256(admin_password.encode()).hexdigest()
        self.session_timeout = session_timeout
        self.sessions: Dict[str, Session] = {}

    def create_session(self, role: str, password: str = "") -> Optional[Session]:
        """创建会话

        Args:
            role: 角色（admin/guest）
            password: 密码（admin 角色需要验证，guest 角色无需密码）
        Returns:
            Session 对象或 None（密码错误时返回 None）
        """
        if role == "admin":
            # 验证管理员密码
            pwd_hash = hashlib.sha256(password.encode()).hexdigest()
            if pwd_hash != self.admin_password_hash:
                return None

        session_id = uuid.uuid4().hex
        now = time.time()
        session = Session(
            session_id=session_id,
            role=role,
            created_at=now,
            expires_at=now + self.session_timeout,
        )
        self.sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """获取会话

        Args:
            session_id: 会话 ID
        Returns:
            Session 对象或 None（不存在或已过期时返回 None）
        """
        session = self.sessions.get(session_id)
        if session and session.is_expired:
            del self.sessions[session_id]
            return None
        return session

    def destroy_session(self, session_id: str):
        """销毁会话

        Args:
            session_id: 会话 ID
        """
        self.sessions.pop(session_id, None)

    def cleanup_expired(self):
        """清理所有过期会话"""
        expired = [sid for sid, s in self.sessions.items() if s.is_expired]
        for sid in expired:
            del self.sessions[sid]
