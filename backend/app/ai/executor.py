"""
玄鉴安全智能体 - 执行模型封装
封装Ollama本地模型，作为战术执行者完成具体操作
"""

import asyncio
import logging
import time
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

from app.config import get_settings

logger = logging.getLogger(__name__)


# ============ 枚举和配置 ============

class RiskLevel(str, Enum):
    """风险等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============ 数据结构 ============

class ToolDefinition(BaseModel):
    """工具定义"""
    name: str = Field(..., description="工具名称")
    description: str = Field(..., description="工具描述")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="参数Schema")
    risk_level: RiskLevel = Field(default=RiskLevel.LOW, description="风险等级")


class ToolCall(BaseModel):
    """工具调用"""
    id: str = Field(..., description="调用ID")
    name: str = Field(..., description="工具名称")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="参数")


class ToolResult(BaseModel):
    """工具执行结果"""
    tool_call_id: str
    output: Any = None
    error: Optional[str] = None
    execution_time_ms: int = 0


class ExecutionResult(BaseModel):
    """执行结果"""
    output: str = Field(..., description="输出内容")
    tool_calls_log: List[Dict[str, Any]] = Field(default_factory=list)
    model_used: str = ""
    tokens_used: int = 0
    total_time_ms: int = 0


class ModelConfig(BaseModel):
    """模型配置"""
    model_name: str
    context_window: int = 32768
    supports_tools: bool = True
    capabilities: List[str] = Field(default_factory=list)


# ============ 支持的模型 ============

SUPPORTED_MODELS = {
    "qwen2.5-coder:7b": ModelConfig(
        model_name="qwen2.5-coder:7b",
        context_window=32768,
        supports_tools=True,
        capabilities=["code_gen", "vuln_scan", "log_analysis"]
    ),
    "qwen2.5-coder:32b": ModelConfig(
        model_name="qwen2.5-coder:32b",
        context_window=131072,
        supports_tools=True,
        capabilities=["code_gen", "vuln_scan", "log_analysis", "complex_reasoning"]
    ),
    "glm4:9b": ModelConfig(
        model_name="glm4:9b",
        context_window=131072,
        supports_tools=True,
        capabilities=["report_gen", "chinese_nlp"]
    ),
    "deepseek-coder-v2:16b": ModelConfig(
        model_name="deepseek-coder-v2:16b",
        context_window=65536,
        supports_tools=True,
        capabilities=["code_gen", "vuln_analysis", "exploit_analysis"]
    ),
    "llama3.1:8b": ModelConfig(
        model_name="llama3.1:8b",
        context_window=131072,
        supports_tools=True,
        capabilities=["general_reasoning", "log_analysis"]
    )
}


# ============ 工具注册表 ============

class ExecutorToolRegistry:
    """执行器工具注册表"""
    
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._handlers: Dict[str, Callable] = {}
    
    def register(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        handler: Callable,
        risk_level: RiskLevel = RiskLevel.LOW
    ):
        """注册工具"""
        self._tools[name] = ToolDefinition(
            name=name,
            description=description,
            parameters=parameters,
            risk_level=risk_level
        )
        self._handlers[name] = handler
        logger.info(f"Registered executor tool: {name}")
    
    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """获取工具定义"""
        return self._tools.get(name)
    
    def get_handler(self, name: str) -> Optional[Callable]:
        """获取处理器"""
        return self._handlers.get(name)
    
    def get_schema_list(self) -> List[Dict[str, Any]]:
        """获取工具Schema列表(Ollama格式)"""
        return [
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters
                }
            }
            for tool in self._tools.values()
        ]
    
    def list_tools(self) -> List[str]:
        """列出所有工具"""
        return list(self._tools.keys())


# ============ 执行模型 ============

class OllamaExecutor:
    """
    Ollama执行模型
    
    作为战术执行者，负责：
    - 工具调用执行
    - 代码生成
    - 指令执行
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        default_model: Optional[str] = None,
        tool_registry: Optional[ExecutorToolRegistry] = None
    ):
        settings = get_settings()
        
        self.base_url = base_url or settings.llm.executor_base_url
        self.default_model = default_model or settings.llm.executor_model
        self.tool_registry = tool_registry or ExecutorToolRegistry()
        
        self._client: Optional[httpx.AsyncClient] = None
        self._safety_guard = None  # 延迟设置
    
    def set_safety_guard(self, guard):
        """设置安全防护层"""
        self._safety_guard = guard
    
    async def _get_client(self) -> httpx.AsyncClient:
        """获取HTTP客户端"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=120.0
            )
        return self._client
    
    async def close(self):
        """关闭客户端"""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def execute(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        tools_enabled: bool = True,
        max_iterations: int = 10,
        **kwargs
    ) -> ExecutionResult:
        """
        执行任务
        
        Args:
            prompt: 用户提示
            system_prompt: 系统提示
            model: 使用的模型
            tools_enabled: 是否启用工具调用
            max_iterations: 最大迭代次数
        
        Returns:
            执行结果
        """
        model = model or self.default_model
        start_time = time.time()
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        tool_calls_log = []
        
        if tools_enabled and self.tool_registry.list_tools():
            output = await self._tool_calling_loop(
                messages=messages,
                model=model,
                max_iterations=max_iterations,
                tool_calls_log=tool_calls_log
            )
        else:
            response = await self._call_ollama(messages, model)
            output = response.get("content", "")
        
        return ExecutionResult(
            output=output,
            tool_calls_log=tool_calls_log,
            model_used=model,
            total_time_ms=int((time.time() - start_time) * 1000)
        )
    
    async def _tool_calling_loop(
        self,
        messages: List[Dict[str, str]],
        model: str,
        max_iterations: int,
        tool_calls_log: List[Dict[str, Any]]
    ) -> str:
        """工具调用循环"""
        tools = self.tool_registry.get_schema_list()
        
        for iteration in range(max_iterations):
            response = await self._call_ollama(messages, model, tools=tools)
            
            # 检查是否有工具调用
            tool_calls = response.get("tool_calls", [])
            
            if not tool_calls:
                # 没有工具调用，返回内容
                return response.get("content", "")
            
            # 添加助手消息
            messages.append({
                "role": "assistant",
                "content": response.get("content", ""),
                "tool_calls": tool_calls
            })
            
            # 执行工具调用
            for tc in tool_calls:
                tool_result = await self._dispatch_tool_call(tc)
                
                # 记录日志
                tool_calls_log.append({
                    "iteration": iteration,
                    "tool_name": tc.get("function", {}).get("name"),
                    "arguments": tc.get("function", {}).get("arguments"),
                    "result": tool_result.output if tool_result.output else tool_result.error,
                    "success": tool_result.error is None,
                    "duration_ms": tool_result.execution_time_ms
                })
                
                # 添加工具结果消息
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id"),
                    "content": str(tool_result.output) if tool_result.output else tool_result.error
                })
        
        # 达到最大迭代，返回最后的响应
        return response.get("content", "工具调用循环达到最大迭代次数")
    
    async def _dispatch_tool_call(self, tool_call: Dict[str, Any]) -> ToolResult:
        """分发工具调用"""
        start_time = time.time()
        
        function = tool_call.get("function", {})
        tool_name = function.get("name")
        arguments = function.get("arguments", {})
        
        if isinstance(arguments, str):
            import json
            try:
                arguments = json.loads(arguments)
            except:
                arguments = {}
        
        # 获取工具定义
        tool_def = self.tool_registry.get_tool(tool_name)
        if not tool_def:
            return ToolResult(
                tool_call_id=tool_call.get("id", ""),
                error=f"工具 {tool_name} 未找到"
            )
        
        # 检查风险等级
        if tool_def.risk_level == RiskLevel.CRITICAL:
            if self._safety_guard:
                # TODO: 请求双签审批
                logger.warning(f"Critical tool {tool_name} requires approval")
        
        # 执行工具
        handler = self.tool_registry.get_handler(tool_name)
        if not handler:
            return ToolResult(
                tool_call_id=tool_call.get("id", ""),
                error=f"工具 {tool_name} 没有处理器"
            )
        
        try:
            if asyncio.iscoroutinefunction(handler):
                result = await handler(**arguments)
            else:
                result = handler(**arguments)
            
            return ToolResult(
                tool_call_id=tool_call.get("id", ""),
                output=result,
                execution_time_ms=int((time.time() - start_time) * 1000)
            )
        except Exception as e:
            logger.exception(f"Tool {tool_name} execution failed: {e}")
            return ToolResult(
                tool_call_id=tool_call.get("id", ""),
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000)
            )
    
    async def _call_ollama(
        self,
        messages: List[Dict[str, str]],
        model: str,
        tools: Optional[List[Dict]] = None,
        stream: bool = False
    ) -> Dict[str, Any]:
        """调用Ollama API"""
        client = await self._get_client()
        
        payload = {
            "model": model,
            "messages": messages,
            "stream": stream
        }
        
        if tools:
            payload["tools"] = tools
        
        response = await client.post("/api/chat", json=payload)
        response.raise_for_status()
        
        data = response.json()
        message = data.get("message", {})
        
        return {
            "content": message.get("content", ""),
            "tool_calls": message.get("tool_calls", []),
            "done": data.get("done", True),
            "eval_count": data.get("eval_count", 0)
        }
    
    async def switch_model(self, model_name: str) -> bool:
        """切换模型"""
        if model_name not in SUPPORTED_MODELS:
            logger.warning(f"Model {model_name} not in supported list")
        
        # 检查模型是否可用
        try:
            client = await self._get_client()
            response = await client.post("/api/show", json={"name": model_name})
            
            if response.status_code == 200:
                self.default_model = model_name
                logger.info(f"Switched to model: {model_name}")
                return True
            else:
                # 尝试拉取模型
                logger.info(f"Pulling model: {model_name}")
                # TODO: 实现模型拉取
                return False
        except Exception as e:
            logger.error(f"Failed to switch model: {e}")
            return False
    
    async def list_available_models(self) -> List[Dict[str, Any]]:
        """列出可用模型"""
        try:
            client = await self._get_client()
            response = await client.get("/api/tags")
            
            if response.status_code == 200:
                data = response.json()
                models = data.get("models", [])
                
                return [
                    {
                        "name": m.get("name"),
                        "size": m.get("size"),
                        "modified_at": m.get("modified_at"),
                        "supported": m.get("name") in SUPPORTED_MODELS
                    }
                    for m in models
                ]
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
        
        return []
    
    async def health_check(self) -> bool:
        """健康检查"""
        try:
            client = await self._get_client()
            response = await client.get("/api/tags")
            return response.status_code == 200
        except:
            return False
