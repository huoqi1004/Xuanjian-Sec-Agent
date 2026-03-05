"""
玄鉴安全智能体 - 安全工具基类
所有安全工具的抽象基类，定义统一接口规范
"""

import asyncio
import logging
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

T = TypeVar('T')


# ============ 枚举定义 ============

class ToolCategory(str, Enum):
    """工具类别"""
    THREAT_INTEL = "threat_intel"
    SCANNER = "scanner"
    ANALYSIS = "analysis"
    DEFENSE = "defense"
    FORENSICS = "forensics"
    UTILITY = "utility"


class RiskLevel(str, Enum):
    """风险等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolStatus(str, Enum):
    """工具状态"""
    READY = "ready"
    BUSY = "busy"
    ERROR = "error"
    DISABLED = "disabled"


# ============ 数据结构 ============

class ToolError(BaseModel):
    """工具错误"""
    code: str = Field(..., description="错误码")
    message: str = Field(..., description="错误信息")
    recoverable: bool = Field(default=True, description="是否可重试")
    details: Optional[Dict[str, Any]] = Field(default=None, description="详细信息")


class ToolResult(BaseModel):
    """工具执行结果"""
    success: bool = Field(..., description="是否成功")
    tool_name: str = Field(..., description="工具名称")
    execution_id: str = Field(..., description="执行ID")
    timestamp: datetime = Field(default_factory=datetime.now, description="执行时间")
    duration_ms: int = Field(default=0, description="执行耗时(毫秒)")
    data: Optional[Dict[str, Any]] = Field(default=None, description="结果数据")
    error: Optional[ToolError] = Field(default=None, description="错误信息")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="元数据")
    raw_output: Optional[str] = Field(default=None, description="原始输出")

    @classmethod
    def success_result(
        cls,
        tool_name: str,
        data: Dict[str, Any],
        execution_id: Optional[str] = None,
        duration_ms: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "ToolResult":
        """创建成功结果"""
        return cls(
            success=True,
            tool_name=tool_name,
            execution_id=execution_id or str(uuid.uuid4()),
            duration_ms=duration_ms,
            data=data,
            metadata=metadata or {}
        )

    @classmethod
    def error_result(
        cls,
        tool_name: str,
        error_code: str,
        error_message: str,
        execution_id: Optional[str] = None,
        recoverable: bool = True,
        details: Optional[Dict[str, Any]] = None
    ) -> "ToolResult":
        """创建错误结果"""
        return cls(
            success=False,
            tool_name=tool_name,
            execution_id=execution_id or str(uuid.uuid4()),
            error=ToolError(
                code=error_code,
                message=error_message,
                recoverable=recoverable,
                details=details
            )
        )


class ToolConfig(BaseModel):
    """工具配置"""
    timeout: int = Field(default=300, description="超时时间(秒)")
    max_retries: int = Field(default=3, description="最大重试次数")
    retry_delay: float = Field(default=1.0, description="重试延迟(秒)")
    max_concurrent: int = Field(default=5, description="最大并发数")
    cache_ttl: int = Field(default=3600, description="缓存时间(秒)")
    requires_auth: bool = Field(default=False, description="是否需要认证")


class ToolMetadata(BaseModel):
    """工具元数据"""
    name: str = Field(..., description="工具名称")
    description: str = Field(..., description="工具描述")
    category: ToolCategory = Field(..., description="工具类别")
    version: str = Field(default="1.0.0", description="版本")
    author: str = Field(default="XuanJian Team", description="作者")
    tags: List[str] = Field(default_factory=list, description="标签")
    risk_level: RiskLevel = Field(default=RiskLevel.LOW, description="风险等级")
    requires_approval: bool = Field(default=False, description="是否需要审批")
    input_schema: Optional[Dict[str, Any]] = Field(default=None, description="输入参数Schema")
    output_schema: Optional[Dict[str, Any]] = Field(default=None, description="输出参数Schema")


# ============ 装饰器 ============

def retry_on_error(
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,)
):
    """重试装饰器"""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        logger.warning(
                            f"Retry {attempt + 1}/{max_retries} for {func.__name__}: {e}"
                        )
                        await asyncio.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logger.error(f"All retries failed for {func.__name__}: {e}")
            
            raise last_exception
        return wrapper
    return decorator


def timed_execution(func: Callable[..., T]) -> Callable[..., T]:
    """执行计时装饰器"""
    @wraps(func)
    async def wrapper(*args, **kwargs) -> T:
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            duration_ms = int((time.time() - start_time) * 1000)
            logger.info(f"{func.__name__} completed in {duration_ms}ms")
            
            # 如果结果是ToolResult，更新duration_ms
            if isinstance(result, ToolResult):
                result.duration_ms = duration_ms
            
            return result
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.error(f"{func.__name__} failed after {duration_ms}ms: {e}")
            raise
    return wrapper


# ============ 基类定义 ============

class BaseTool(ABC):
    """
    安全工具抽象基类
    
    所有安全工具必须继承此类并实现execute方法
    """
    
    # 类级别元数据（子类应覆盖）
    metadata: ToolMetadata = ToolMetadata(
        name="base_tool",
        description="Base security tool",
        category=ToolCategory.UTILITY
    )
    
    # 类级别配置（子类可覆盖）
    config: ToolConfig = ToolConfig()
    
    def __init__(self):
        self._status: ToolStatus = ToolStatus.READY
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(self.config.max_concurrent)
        self._execution_count: int = 0
        self._error_count: int = 0
        self._total_duration_ms: int = 0
    
    @property
    def name(self) -> str:
        """工具名称"""
        return self.metadata.name
    
    @property
    def description(self) -> str:
        """工具描述"""
        return self.metadata.description
    
    @property
    def category(self) -> ToolCategory:
        """工具类别"""
        return self.metadata.category
    
    @property
    def status(self) -> ToolStatus:
        """工具状态"""
        return self._status
    
    @property
    def stats(self) -> Dict[str, Any]:
        """工具统计信息"""
        return {
            "execution_count": self._execution_count,
            "error_count": self._error_count,
            "error_rate": self._error_count / max(self._execution_count, 1),
            "avg_duration_ms": self._total_duration_ms / max(self._execution_count, 1)
        }
    
    async def __call__(self, **params) -> ToolResult:
        """使工具可调用"""
        return await self.run(**params)
    
    async def run(self, **params) -> ToolResult:
        """
        执行工具（带完整生命周期管理）
        
        流程：验证参数 -> 前置处理 -> 执行 -> 后置处理
        """
        execution_id = str(uuid.uuid4())
        start_time = time.time()
        
        async with self._semaphore:
            try:
                # 验证参数
                validated_params = await self.validate_params(params)
                
                # 前置处理
                await self.pre_execute(validated_params)
                
                # 执行核心逻辑
                result = await self.execute(**validated_params)
                
                # 更新统计
                duration_ms = int((time.time() - start_time) * 1000)
                result.execution_id = execution_id
                result.duration_ms = duration_ms
                
                # 后置处理
                await self.post_execute(result)
                
                self._execution_count += 1
                self._total_duration_ms += duration_ms
                
                return result
                
            except asyncio.TimeoutError:
                self._error_count += 1
                return ToolResult.error_result(
                    tool_name=self.name,
                    error_code="TIMEOUT",
                    error_message=f"执行超时({self.config.timeout}秒)",
                    execution_id=execution_id,
                    recoverable=True
                )
            except Exception as e:
                self._error_count += 1
                logger.exception(f"Tool {self.name} execution failed: {e}")
                return ToolResult.error_result(
                    tool_name=self.name,
                    error_code="EXECUTION_ERROR",
                    error_message=str(e),
                    execution_id=execution_id,
                    recoverable=True
                )
    
    async def validate_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证输入参数
        
        子类可覆盖以添加自定义验证逻辑
        """
        return params
    
    async def pre_execute(self, params: Dict[str, Any]) -> None:
        """
        执行前钩子
        
        子类可覆盖以添加前置处理逻辑
        """
        logger.debug(f"Starting execution of {self.name} with params: {params}")
    
    @abstractmethod
    async def execute(self, **params) -> ToolResult:
        """
        执行核心逻辑
        
        子类必须实现此方法
        """
        raise NotImplementedError("Subclass must implement execute method")
    
    async def post_execute(self, result: ToolResult) -> None:
        """
        执行后钩子
        
        子类可覆盖以添加后置处理逻辑
        """
        logger.debug(f"Finished execution of {self.name}: success={result.success}")
    
    async def health_check(self) -> bool:
        """
        健康检查
        
        子类可覆盖以添加自定义健康检查逻辑
        """
        return self._status == ToolStatus.READY
    
    def to_mcp_tool(self) -> Dict[str, Any]:
        """
        转换为MCP Tool格式
        
        用于注册到MCP Server
        """
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.metadata.input_schema or {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name}, status={self.status})>"


# ============ 特化基类 ============

class NetworkTool(BaseTool):
    """网络类工具基类"""
    
    metadata = ToolMetadata(
        name="network_tool",
        description="Network security tool",
        category=ToolCategory.SCANNER
    )
    
    # 目标白名单（子类可覆盖）
    allowed_targets: List[str] = []
    blocked_targets: List[str] = ["127.0.0.1", "localhost"]
    
    async def validate_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """验证网络目标"""
        params = await super().validate_params(params)
        
        target = params.get("target") or params.get("scope") or params.get("ip")
        if target:
            # 检查是否在黑名单中
            if any(blocked in target for blocked in self.blocked_targets):
                raise ValueError(f"目标 {target} 不允许扫描")
            
            # 如果配置了白名单，检查是否在白名单中
            if self.allowed_targets:
                if not any(allowed in target for allowed in self.allowed_targets):
                    raise ValueError(f"目标 {target} 不在允许列表中")
        
        return params


class ThreatIntelTool(BaseTool):
    """威胁情报类工具基类"""
    
    metadata = ToolMetadata(
        name="threat_intel_tool",
        description="Threat intelligence tool",
        category=ToolCategory.THREAT_INTEL
    )
    
    # API相关配置
    api_base_url: str = ""
    api_key: Optional[str] = None
    rate_limit_per_minute: int = 60
    
    def __init__(self):
        super().__init__()
        self._rate_limiter_tokens: int = self.rate_limit_per_minute
        self._rate_limiter_last_reset: float = time.time()
    
    async def _check_rate_limit(self) -> bool:
        """检查速率限制"""
        current_time = time.time()
        
        # 每分钟重置令牌
        if current_time - self._rate_limiter_last_reset >= 60:
            self._rate_limiter_tokens = self.rate_limit_per_minute
            self._rate_limiter_last_reset = current_time
        
        if self._rate_limiter_tokens > 0:
            self._rate_limiter_tokens -= 1
            return True
        
        return False
    
    async def pre_execute(self, params: Dict[str, Any]) -> None:
        await super().pre_execute(params)
        
        if not await self._check_rate_limit():
            raise Exception("API速率限制，请稍后重试")


class FileScanTool(BaseTool):
    """文件扫描类工具基类"""
    
    metadata = ToolMetadata(
        name="file_scan_tool",
        description="File scanning tool",
        category=ToolCategory.ANALYSIS
    )
    
    # 文件限制
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    allowed_extensions: List[str] = []  # 空列表表示允许所有
    
    async def validate_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """验证文件参数"""
        params = await super().validate_params(params)
        
        file_path = params.get("file_path") or params.get("file")
        if file_path:
            import os
            
            # 检查文件是否存在
            if not os.path.exists(file_path):
                raise ValueError(f"文件不存在: {file_path}")
            
            # 检查文件大小
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                raise ValueError(f"文件过大: {file_size} bytes (最大 {self.max_file_size} bytes)")
            
            # 检查文件扩展名
            if self.allowed_extensions:
                ext = os.path.splitext(file_path)[1].lower()
                if ext not in self.allowed_extensions:
                    raise ValueError(f"不支持的文件类型: {ext}")
        
        return params
