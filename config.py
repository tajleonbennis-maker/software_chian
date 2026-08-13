"""
配置文件 - 软件供应链安全分析平台的全局配置

通过环境变量和 .env 文件加载配置，支持 FOFA 凭据、
扫描参数、服务监听地址等配置项的灵活设置。
"""
import os
from dotenv import load_dotenv

# 加载 .env 文件中的环境变量（如果存在）
load_dotenv()


class Config:
    """全局配置类

    所有配置项优先从环境变量读取，环境变量不存在时使用默认值。
    可通过项目根目录下的 .env 文件预设环境变量。
    """

    # FOFA API Key（优先使用环境变量，也可通过前端表单传入）
    FOFA_KEY = os.environ.get("FOFA_KEY", "")

    # FOFA 搜索默认返回的结果数量
    FOFA_SIZE = int(os.environ.get("FOFA_SIZE", "100"))

    # HTTP 请求超时时间（秒），用于技术检测和 API 扫描
    SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "10"))

    # 并发分析的最大工作线程数
    MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "5"))

    # 是否开启调试模式
    DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

    # Flask 服务监听地址和端口
    HOST = os.environ.get("HOST", "127.0.0.1")
    PORT = int(os.environ.get("PORT", "5566"))
    _database_path = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "data", "scans.db"))
    DATABASE_PATH = _database_path if os.path.isabs(_database_path) else os.path.join(os.path.dirname(__file__), _database_path)

    # 自动研究大脑：周期性选择项目并执行被动资产发现。
    RESEARCH_BRAIN_ENABLED = os.environ.get("RESEARCH_BRAIN_ENABLED", "true").lower() == "true"
    RESEARCH_INTERVAL_SECONDS = max(300, int(os.environ.get("RESEARCH_INTERVAL_SECONDS", "3600")))
    RESEARCH_DISCOVERY_SIZE = max(1, int(os.environ.get("RESEARCH_DISCOVERY_SIZE", "500")))
    RESEARCH_ANALYSIS_BATCH = max(1, int(os.environ.get("RESEARCH_ANALYSIS_BATCH", "40")))
    RESEARCH_ANALYSIS_WORKERS = max(1, min(16, int(os.environ.get("RESEARCH_ANALYSIS_WORKERS", "4"))))
    TREND_INTELLIGENCE_ENABLED = os.environ.get("TREND_INTELLIGENCE_ENABLED", "true").lower() == "true"
    TREND_INTELLIGENCE_INTERVAL_SECONDS = max(
        900, int(os.environ.get("TREND_INTELLIGENCE_INTERVAL_SECONDS", "21600"))
    )
    TREND_INTELLIGENCE_PROJECT_LIMIT = max(
        1, min(30, int(os.environ.get("TREND_INTELLIGENCE_PROJECT_LIMIT", "10")))
    )
    LAB_REPORT_TOKEN = os.environ.get("LAB_REPORT_TOKEN", "")

    # ============================================================
    # DeepSeek AI API 配置
    # ============================================================
    # DeepSeek API 兼容 OpenAI 接口格式，端点为 /v1/chat/completions
    # 通过环境变量 DEEPSEEK_API_KEY 配置密钥，未配置时 AI 分析功能自动禁用
    DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
    DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-pro")
    RESEARCH_AI_MODEL = os.environ.get("RESEARCH_AI_MODEL", "deepseek-v4-pro")
    # 是否启用 AI 分析（即使配置了 API Key，也可通过此开关全局关闭）
    AI_ANALYSIS_ENABLED = os.environ.get("AI_ANALYSIS_ENABLED", "true").lower() == "true"
    # AI 单次请求超时时间（秒）
    AI_TIMEOUT = int(os.environ.get("AI_TIMEOUT", "60"))

    # ============================================================
    # 管理员配置
    # ============================================================
    # 管理员密码。示例占位符视为未配置，本地开发时使用明确的临时密码。
    _admin_pwd = os.environ.get("ADMIN_PASSWORD", "").strip()
    ADMIN_PASSWORD_CONFIGURED = bool(_admin_pwd and _admin_pwd != "your_admin_password")
    ADMIN_PASSWORD = _admin_pwd if ADMIN_PASSWORD_CONFIGURED else "admin123"
