"""
玄鉴安全智能体 - 监督模型封装
封装DeepSeek API，作为战略大脑负责规划和审查
"""

import asyncio
import logging
import time
from datetime import datetime
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

from app.config import get_settings

logger = logging.getLogger(__name__)


# ============ 枚举和配置 ============

class SupervisorRole(str, Enum):
    """监督角色"""
    PLANNER = "planner"
    REVIEWER = "reviewer"
    ARBITRATOR = "arbitrator"


class RetryConfig(BaseModel):
    """重试配置"""
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    jitter: float = 0.5


# ============ 数据结构 ============

class SupervisorResponse(BaseModel):
    """监督模型响应"""
    content: str = Field(..., description="响应内容")
    thinking_chain: Optional[str] = Field(default=None, description="推理链")
    usage: Dict[str, int] = Field(default_factory=dict, description="Token使用")
    latency_ms: int = Field(default=0, description="延迟(毫秒)")
    model: str = Field(default="", description="使用的模型")
    finish_reason: str = Field(default="stop", description="结束原因")


class StreamChunk(BaseModel):
    """流式分块"""
    content: str = ""
    reasoning_content: str = ""
    finish_reason: Optional[str] = None
    usage: Dict[str, int] = Field(default_factory=dict)


# ============ Prompt模板 ============

BUILTIN_TEMPLATES = {
    "security_analysis": {
        "system": """你是一位资深的网络安全分析专家。
你的职责是分析安全事件、评估威胁等级、识别攻击手法。
请基于提供的信息进行专业分析，输出结构化的分析报告。
注意识别MITRE ATT&CK框架中的技术和战术。""",
        "user": """请分析以下安全事件：
{event_data}

请提供：
1. 威胁评估（严重程度、置信度）
2. 攻击类型识别
3. 关联的MITRE ATT&CK技术
4. 建议的响应措施"""
    },
    
    "task_planning": {
        "system": """你是一位安全运营专家，负责制定安全任务的执行计划。
根据任务目标，设计合理的执行步骤和工具调用序列。
输出必须是有效的JSON格式。""",
        "user": """请为以下安全任务制定执行计划：
任务目标：{task_description}
可用工具：{available_tools}
约束条件：{constraints}

请输出JSON格式的执行计划，包含：
1. steps: 步骤列表，每步包含tool_name和params
2. estimated_duration: 预计耗时(秒)
3. risk_assessment: 风险评估"""
    },
    
    "result_review": {
        "system": """你是一位安全审计专家，负责审查安全任务的执行结果。
评估结果的准确性、完整性和潜在风险。""",
        "user": """请审查以下任务执行结果：
原始计划：{plan}
执行日志：{execution_log}
输出结果：{output}

请评估：
1. approved: 是否批准(true/false)
2. confidence: 置信度(0-1)
3. issues: 发现的问题列表
4. suggestions: 改进建议"""
    }
}


# ============ 监督模型 ============

class DeepSeekSupervisor:
    """
    DeepSeek监督模型
    
    作为战略大脑，负责：
    - 任务规划
    - 结果审查
    - 风险判断
    - 冲突仲裁
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "deepseek-reasoner",
        retry_config: Optional[RetryConfig] = None
    ):
        settings = get_settings()
        
        self.api_key = api_key or (
            settings.llm.supervisor_api_key.get_secret_value()
            if settings.llm.supervisor_api_key else None
        )
        self.base_url = base_url or settings.llm.supervisor_base_url
        self.model = model
        self.retry_config = retry_config or RetryConfig()
        
        self._client: Optional[httpx.AsyncClient] = None
        self._templates = BUILTIN_TEMPLATES.copy()
    
    async def _get_client(self) -> httpx.AsyncClient:
        """获取HTTP客户端"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                timeout=120.0
            )
        return self._client
    
    async def close(self):
        """关闭客户端"""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def chat(
        self,
        role: SupervisorRole,
        prompt_name: str,
        variables: Dict[str, Any],
        stream: bool = False,
        **kwargs
    ) -> SupervisorResponse:
        """
        执行对话
        
        Args:
            role: 监督角色
            prompt_name: 模板名称
            variables: 模板变量
            stream: 是否流式
            **kwargs: 额外参数
        
        Returns:
            监督响应
        """
        # 渲染模板
        system_prompt, user_prompt = self._render_template(prompt_name, variables)
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        # 执行请求
        start_time = time.time()
        
        if stream:
            content = ""
            thinking = ""
            async for chunk in self._stream_response(messages, kwargs):
                content += chunk.content
                thinking += chunk.reasoning_content
            
            return SupervisorResponse(
                content=content,
                thinking_chain=thinking if thinking else None,
                latency_ms=int((time.time() - start_time) * 1000),
                model=self.model
            )
        else:
            response = await self._execute_with_retry(
                lambda: self._call_api(messages, kwargs)
            )
            
            return SupervisorResponse(
                content=response.get("content", ""),
                thinking_chain=response.get("reasoning_content"),
                usage=response.get("usage", {}),
                latency_ms=int((time.time() - start_time) * 1000),
                model=self.model,
                finish_reason=response.get("finish_reason", "stop")
            )
    
    async def _call_api(
        self,
        messages: List[Dict[str, str]],
        kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """调用API"""
        client = await self._get_client()
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 2048),
            **kwargs
        }
        
        response = await client.post("/chat/completions", json=payload)
        response.raise_for_status()
        
        data = response.json()
        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        
        return {
            "content": message.get("content", ""),
            "reasoning_content": message.get("reasoning_content"),
            "usage": data.get("usage", {}),
            "finish_reason": choice.get("finish_reason", "stop")
        }
    
    async def _stream_response(
        self,
        messages: List[Dict[str, str]],
        kwargs: Dict[str, Any]
    ) -> AsyncGenerator[StreamChunk, None]:
        """流式响应"""
        client = await self._get_client()
        
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 2048)
        }
        
        async with client.stream("POST", "/chat/completions", json=payload) as response:
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    data = line[6:]
                    if data == "[DONE]":
                        break
                    
                    try:
                        import json
                        chunk_data = json.loads(data)
                        delta = chunk_data.get("choices", [{}])[0].get("delta", {})
                        
                        yield StreamChunk(
                            content=delta.get("content", ""),
                            reasoning_content=delta.get("reasoning_content", ""),
                            finish_reason=chunk_data.get("choices", [{}])[0].get("finish_reason")
                        )
                    except Exception as e:
                        logger.warning(f"Failed to parse chunk: {e}")
    
    async def _execute_with_retry(self, func) -> Any:
        """带重试的执行"""
        last_exception = None
        delay = self.retry_config.base_delay
        
        for attempt in range(self.retry_config.max_retries + 1):
            try:
                return await func()
            except httpx.HTTPStatusError as e:
                status = e.response.status_code
                
                # 不可重试的错误
                if status in (400, 401, 403, 404):
                    raise
                
                # 可重试的错误
                last_exception = e
                if attempt < self.retry_config.max_retries:
                    import random
                    jitter = random.uniform(0, self.retry_config.jitter)
                    wait_time = min(delay + jitter, self.retry_config.max_delay)
                    
                    logger.warning(
                        f"Retry {attempt + 1}/{self.retry_config.max_retries}, "
                        f"waiting {wait_time:.1f}s: {e}"
                    )
                    await asyncio.sleep(wait_time)
                    delay *= 2
            except Exception as e:
                last_exception = e
                if attempt < self.retry_config.max_retries:
                    await asyncio.sleep(delay)
                    delay *= 2
        
        raise last_exception
    
    def _render_template(
        self,
        template_name: str,
        variables: Dict[str, Any]
    ) -> tuple:
        """渲染模板"""
        if template_name not in self._templates:
            raise ValueError(f"Template {template_name} not found")
        
        template = self._templates[template_name]
        system = template["system"]
        user = template["user"]
        
        # 简单模板替换
        for key, value in variables.items():
            placeholder = "{" + key + "}"
            if isinstance(value, (dict, list)):
                import json
                value = json.dumps(value, ensure_ascii=False, indent=2)
            system = system.replace(placeholder, str(value))
            user = user.replace(placeholder, str(value))
        
        return system, user
    
    def register_template(
        self,
        name: str,
        system_prompt: str,
        user_template: str
    ):
        """注册自定义模板"""
        self._templates[name] = {
            "system": system_prompt,
            "user": user_template
        }
    
    async def analyze_threat(self, event_data: Dict[str, Any]) -> SupervisorResponse:
        """分析威胁"""
        return await self.chat(
            role=SupervisorRole.PLANNER,
            prompt_name="security_analysis",
            variables={"event_data": event_data}
        )
    
    async def plan_task(
        self,
        task_description: str,
        available_tools: List[str],
        constraints: Dict[str, Any] = None
    ) -> SupervisorResponse:
        """规划任务"""
        return await self.chat(
            role=SupervisorRole.PLANNER,
            prompt_name="task_planning",
            variables={
                "task_description": task_description,
                "available_tools": available_tools,
                "constraints": constraints or {}
            }
        )
    
    async def review_result(
        self,
        plan: Dict[str, Any],
        execution_log: List[Dict[str, Any]],
        output: Any
    ) -> SupervisorResponse:
        """审查结果"""
        return await self.chat(
            role=SupervisorRole.REVIEWER,
            prompt_name="result_review",
            variables={
                "plan": plan,
                "execution_log": execution_log,
                "output": output
            }
        )
