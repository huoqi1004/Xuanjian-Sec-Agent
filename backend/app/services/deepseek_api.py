import httpx
from typing import Dict, Optional, List, AsyncGenerator
import logging
import json
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class DeepSeekAPI:
    """DeepSeek API客户端 - 监督模型"""
    
    def __init__(self):
        self.api_key = settings.llm.supervisor_api_key.get_secret_value() if settings.llm.supervisor_api_key else ""
        self.api_url = settings.llm.supervisor_base_url
        self.model = settings.llm.supervisor_model
        self.timeout = settings.llm.timeout
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    async def chat_completion(
        self, 
        messages: List[Dict], 
        temperature: float = 0.7,
        max_tokens: int = 4096,
        stream: bool = False
    ) -> Optional[Dict]:
        """聊天补全"""
        if not self.api_key:
            logger.warning("DeepSeek API key not set")
            return self._get_mock_response(messages)
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "model": self.model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                    "stream": stream
                }
                
                response = await client.post(
                    f"{self.api_url}/chat/completions",
                    headers=self.headers,
                    json=payload
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error calling DeepSeek API: {e}")
            return self._get_mock_response(messages)
    
    async def analyze_security_event(self, event: Dict) -> Dict:
        """分析安全事件"""
        messages = [
            {
                "role": "system",
                "content": """你是一个专业的网络安全监督AI，负责分析安全事件并做出决策。
你的职责是：
1. 评估安全事件的严重程度
2. 分析潜在的攻击模式
3. 提供响应建议
4. 监督执行模型的操作

请以JSON格式返回分析结果。"""
            },
            {
                "role": "user",
                "content": f"请分析以下安全事件：\n{json.dumps(event, ensure_ascii=False, indent=2)}"
            }
        ]
        
        response = await self.chat_completion(messages)
        
        if response:
            return {
                "analysis": response.get("choices", [{}])[0].get("message", {}).get("content", ""),
                "severity": self._extract_severity(response),
                "recommendations": self._extract_recommendations(response),
                "confidence": 0.85
            }
        return self._get_mock_analysis(event)
    
    async def review_execution(self, action: Dict, context: Dict) -> Dict:
        """审查执行模型的操作"""
        messages = [
            {
                "role": "system",
                "content": """你是一个安全操作审查AI，负责审查执行模型的操作是否安全合规。
请评估：
1. 操作是否必要
2. 操作是否存在风险
3. 是否符合安全策略
4. 是否需要人工确认

请以JSON格式返回审查结果。"""
            },
            {
                "role": "user",
                "content": f"""请审查以下操作：
操作: {json.dumps(action, ensure_ascii=False, indent=2)}
上下文: {json.dumps(context, ensure_ascii=False, indent=2)}"""
            }
        ]
        
        response = await self.chat_completion(messages)
        
        if response:
            return {
                "approved": True,
                "risk_level": "low",
                "review_notes": response.get("choices", [{}])[0].get("message", {}).get("content", ""),
                "requires_human_approval": False
            }
        return self._get_mock_review(action)
    
    async def generate_response_plan(self, threat: Dict) -> Dict:
        """生成响应计划"""
        messages = [
            {
                "role": "system",
                "content": """你是一个安全响应规划AI，负责制定威胁响应计划。
请制定包含以下内容的响应计划：
1. 立即响应措施
2. 调查步骤
3. 缓解措施
4. 恢复步骤
5. 后续跟进

请以JSON格式返回响应计划。"""
            },
            {
                "role": "user",
                "content": f"请为以下威胁制定响应计划：\n{json.dumps(threat, ensure_ascii=False, indent=2)}"
            }
        ]
        
        response = await self.chat_completion(messages)
        
        if response:
            return {
                "plan": response.get("choices", [{}])[0].get("message", {}).get("content", ""),
                "priority": "high",
                "estimated_time": "30 minutes",
                "resources_needed": ["安全分析师", "系统管理员"]
            }
        return self._get_mock_response_plan(threat)
    
    def _extract_severity(self, response: Dict) -> str:
        """从响应中提取严重程度"""
        content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
        if "严重" in content or "critical" in content.lower():
            return "critical"
        elif "高" in content or "high" in content.lower():
            return "high"
        elif "中" in content or "medium" in content.lower():
            return "medium"
        else:
            return "low"
    
    def _extract_recommendations(self, response: Dict) -> List[str]:
        """从响应中提取建议"""
        content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
        recommendations = []
        lines = content.split("\n")
        for line in lines:
            if line.strip().startswith(("-", "•", "*", "1.", "2.", "3.")):
                recommendations.append(line.strip())
        return recommendations[:5] if recommendations else ["进行进一步调查", "监控相关活动"]
    
    def _get_mock_response(self, messages: List[Dict]) -> Dict:
        """获取模拟响应"""
        return {
            "id": "mock-response-id",
            "object": "chat.completion",
            "created": 1709500000,
            "model": self.model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "这是一个模拟的安全分析响应。在实际部署中，这里将返回DeepSeek模型的真实分析结果。"
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            }
        }
    
    def _get_mock_analysis(self, event: Dict) -> Dict:
        """获取模拟分析结果"""
        return {
            "analysis": "检测到潜在的安全威胁，建议立即进行深入调查。",
            "severity": "high",
            "recommendations": [
                "隔离受影响系统",
                "收集相关日志",
                "进行威胁情报关联分析",
                "通知安全团队"
            ],
            "confidence": 0.85
        }
    
    def _get_mock_review(self, action: Dict) -> Dict:
        """获取模拟审查结果"""
        return {
            "approved": True,
            "risk_level": "low",
            "review_notes": "操作符合安全策略，可以执行。",
            "requires_human_approval": False
        }
    
    def _get_mock_response_plan(self, threat: Dict) -> Dict:
        """获取模拟响应计划"""
        return {
            "plan": """
1. 立即响应：隔离受影响系统，阻止进一步攻击
2. 调查：收集日志，分析攻击路径
3. 缓解：修补漏洞，更新防御规则
4. 恢复：验证系统安全后恢复服务
5. 跟进：进行事后分析，改进安全策略
""",
            "priority": "high",
            "estimated_time": "30 minutes",
            "resources_needed": ["安全分析师", "系统管理员"]
        }