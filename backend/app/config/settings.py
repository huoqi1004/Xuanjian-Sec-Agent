"""
玄鉴安全智能体 - 配置管理系统
支持三层配置覆盖：环境变量 > 配置文件 > 默认值
"""

from functools import lru_cache
from typing import Optional, List
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerConfig(BaseSettings):
    """服务器配置"""
    host: str = Field(default="0.0.0.0", description="服务绑定地址")
    port: int = Field(default=8001, description="服务端口")
    workers: int = Field(default=4, description="工作进程数")
    debug: bool = Field(default=True, description="调试模式")
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173", "http://localhost:5174"],
        description="CORS允许的源"
    )
    
    model_config = SettingsConfigDict(env_prefix="XUANJIAN_SERVER_")


class DatabaseConfig(BaseSettings):
    """数据库配置"""
    url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/xuanjian",
        description="PostgreSQL连接串"
    )
    pool_size: int = Field(default=10, description="连接池大小")
    max_overflow: int = Field(default=20, description="最大溢出连接数")
    echo: bool = Field(default=False, description="是否打印SQL")
    
    model_config = SettingsConfigDict(env_prefix="XUANJIAN_DB_")


class RedisConfig(BaseSettings):
    """Redis配置"""
    url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis连接URL"
    )
    max_connections: int = Field(default=20, description="最大连接数")
    decode_responses: bool = Field(default=True, description="自动解码响应")
    
    model_config = SettingsConfigDict(env_prefix="XUANJIAN_REDIS_")


class ElasticsearchConfig(BaseSettings):
    """Elasticsearch配置"""
    hosts: List[str] = Field(
        default=["http://localhost:9200"],
        description="ES节点列表"
    )
    username: Optional[str] = Field(default=None, description="ES用户名")
    password: Optional[SecretStr] = Field(default=None, description="ES密码")
    index_prefix: str = Field(default="xuanjian", description="索引前缀")
    
    model_config = SettingsConfigDict(env_prefix="XUANJIAN_ES_")


class LLMConfig(BaseSettings):
    """大语言模型配置"""
    # 监督模型 (DeepSeek API)
    supervisor_api_key: Optional[SecretStr] = Field(default=None, description="DeepSeek API Key")
    supervisor_base_url: str = Field(
        default="https://api.deepseek.com/v1",
        description="DeepSeek API基础URL"
    )
    supervisor_model: str = Field(default="deepseek-reasoner", description="监督模型")
    
    # 执行模型 (Ollama本地)
    executor_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama服务地址"
    )
    executor_model: str = Field(default="qwen2.5-coder:7b", description="执行模型")
    
    # 通用设置
    timeout: int = Field(default=120, description="请求超时秒数")
    max_retries: int = Field(default=3, description="最大重试次数")
    
    model_config = SettingsConfigDict(env_prefix="XUANJIAN_LLM_")


class ThreatIntelConfig(BaseSettings):
    """威胁情报平台配置"""
    # 微步在线
    threatbook_api_key: Optional[SecretStr] = Field(default=None, description="微步在线API Key")
    threatbook_base_url: str = Field(
        default="https://api.threatbook.cn/v3",
        description="微步在线API地址"
    )
    
    # VirusTotal
    virustotal_api_key: Optional[SecretStr] = Field(default=None, description="VirusTotal API Key")
    virustotal_base_url: str = Field(
        default="https://www.virustotal.com/api/v3",
        description="VirusTotal API地址"
    )
    
    # Censys
    censys_api_id: Optional[str] = Field(default=None, description="Censys API ID")
    censys_api_secret: Optional[SecretStr] = Field(default=None, description="Censys API Secret")
    
    # MISP
    misp_url: Optional[str] = Field(default=None, description="MISP实例URL")
    misp_api_key: Optional[SecretStr] = Field(default=None, description="MISP API Key")
    
    # 缓存设置
    cache_ttl: int = Field(default=3600, description="情报缓存时间(秒)")
    
    model_config = SettingsConfigDict(env_prefix="XUANJIAN_INTEL_")


class ToolsConfig(BaseSettings):
    """安全工具配置"""
    # Nmap
    nmap_path: str = Field(default="nmap", description="Nmap可执行文件路径")
    nmap_timeout: int = Field(default=300, description="Nmap扫描超时(秒)")
    nmap_max_concurrent: int = Field(default=3, description="最大并发扫描数")
    
    # Nessus
    nessus_url: Optional[str] = Field(default=None, description="Nessus服务器URL")
    nessus_api_key: Optional[SecretStr] = Field(default=None, description="Nessus API Key")
    
    # CAPE沙箱
    cape_url: Optional[str] = Field(default=None, description="CAPE沙箱URL")
    cape_api_key: Optional[SecretStr] = Field(default=None, description="CAPE API Key")
    
    # 雷池WAF
    safeline_url: Optional[str] = Field(default=None, description="雷池WAF URL")
    safeline_api_key: Optional[SecretStr] = Field(default=None, description="雷池WAF API Key")
    
    model_config = SettingsConfigDict(env_prefix="XUANJIAN_TOOLS_")


class AlertConfig(BaseSettings):
    """告警配置"""
    # 告警级别阈值
    critical_threshold: float = Field(default=90.0, description="严重告警阈值")
    high_threshold: float = Field(default=70.0, description="高危告警阈值")
    medium_threshold: float = Field(default=50.0, description="中危告警阈值")
    
    # 通知渠道
    webhook_urls: List[str] = Field(default=[], description="Webhook通知URL列表")
    email_recipients: List[str] = Field(default=[], description="邮件接收人列表")
    
    # 聚合设置
    aggregation_window: int = Field(default=300, description="告警聚合窗口(秒)")
    cooldown_period: int = Field(default=600, description="告警冷却时间(秒)")
    
    model_config = SettingsConfigDict(env_prefix="XUANJIAN_ALERT_")


class SecurityConfig(BaseSettings):
    """安全配置"""
    # JWT
    jwt_secret_key: SecretStr = Field(
        default=SecretStr("xuanjian-security-secret-key-change-in-production"),
        description="JWT密钥"
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT算法")
    access_token_expire_minutes: int = Field(default=30, description="访问令牌过期时间(分钟)")
    refresh_token_expire_days: int = Field(default=7, description="刷新令牌过期时间(天)")
    
    # 安全设置
    allowed_hosts: List[str] = Field(default=["*"], description="允许的主机")
    rate_limit_per_minute: int = Field(default=100, description="每分钟请求限制")
    
    model_config = SettingsConfigDict(env_prefix="XUANJIAN_SECURITY_")


class AppConfig(BaseSettings):
    """应用根配置"""
    app_name: str = Field(default="玄鉴安全智能体", description="应用名称")
    app_version: str = Field(default="1.0.0", description="应用版本")
    environment: str = Field(default="development", description="运行环境")
    
    # 子配置
    server: ServerConfig = Field(default_factory=ServerConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    elasticsearch: ElasticsearchConfig = Field(default_factory=ElasticsearchConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    threat_intel: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    alert: AlertConfig = Field(default_factory=AlertConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    
    # 日志配置
    log_level: str = Field(default="INFO", description="日志级别")
    log_format: str = Field(default="json", description="日志格式(json/text)")
    
    model_config = SettingsConfigDict(
        env_prefix="XUANJIAN_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


@lru_cache()
def get_settings() -> AppConfig:
    """
    获取应用配置单例
    使用lru_cache确保配置只加载一次
    """
    return AppConfig()
