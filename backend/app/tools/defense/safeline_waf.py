"""
玄鉴安全智能体 - 雷池WAF防御工具
集成雷池WAF进行Web应用防火墙和防御策略管理
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

from ..base_tool import BaseTool, ToolCategory, ToolMetadata, ToolResult, RiskLevel

logger = logging.getLogger(__name__)


class WAFRuleParams(BaseModel):
    """WAF规则参数"""
    name: str = Field(..., description="规则名称")
    rule_type: str = Field(..., description="规则类型: access/deny/log")
    priority: int = Field(default=100, description="优先级")
    conditions: List[Dict[str, Any]] = Field(default_factory=list, description="匹配条件")
    actions: List[str] = Field(default_factory=list, description="执行动作")


class WAFAuditParams(BaseModel):
    """WAF审计参数"""
    start_time: Optional[str] = Field(default=None, description="开始时间")
    end_time: Optional[str] = Field(default=None, description="结束时间")
    limit: int = Field(default=100, description="限制数量")


class SafelineWAFTool(BaseTool):
    """雷池WAF防御工具"""
    
    metadata = ToolMetadata(
        name="safeline_waf",
        category=ToolCategory.DEFENSE,
        description="雷池WAF防御工具，支持Web应用防火墙和防御策略管理",
        version="1.0.0",
        author="玄鉴安全团队",
        tags=["waf", "defense", "web-security"],
        risk_level=RiskLevel.HIGH,
        requires_approval=True
    )
    
    def __init__(self, api_url: str, api_key: str):
        """
        初始化雷池WAF工具
        
        Args:
            api_url: WAF API地址
            api_key: API密钥
        """
        super().__init__()
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """获取HTTP客户端"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=60.0,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
            )
        return self._client
    
    async def get_status(self) -> Dict[str, Any]:
        """
        获取WAF状态
        
        Returns:
            WAF状态信息
        """
        client = await self._get_client()
        url = f"{self.api_url}/api/status"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            result: Dict[str, Any] = response.json()
            return result
        except Exception as e:
            logger.error(f"Get WAF status failed: {e}")
            raise
    
    async def create_rule(self, params: WAFRuleParams) -> Dict[str, Any]:
        """
        创建WAF规则
        
        Args:
            params: 规则参数
            
        Returns:
            创建结果
        """
        client = await self._get_client()
        url = f"{self.api_url}/api/rules"
        
        try:
            response = await client.post(url, json=params.model_dump())
            response.raise_for_status()
            result: Dict[str, Any] = response.json()
            return result
        except Exception as e:
            logger.error(f"Create WAF rule failed: {e}")
            raise
    
    async def delete_rule(self, rule_id: int) -> bool:
        """
        删除WAF规则
        
        Args:
            rule_id: 规则ID
            
        Returns:
            是否成功
        """
        client = await self._get_client()
        url = f"{self.api_url}/api/rules/{rule_id}"
        
        try:
            response = await client.delete(url)
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Delete WAF rule failed: {e}")
            return False
    
    async def list_rules(self) -> List[Dict[str, Any]]:
        """
        列出所有规则
        
        Returns:
            规则列表
        """
        client = await self._get_client()
        url = f"{self.api_url}/api/rules"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("rules", [])
        except Exception as e:
            logger.error(f"List WAF rules failed: {e}")
            return []
    
    async def get_audit_logs(self, params: WAFAuditParams) -> Dict[str, Any]:
        """
        获取审计日志
        
        Args:
            params: 审计参数
            
        Returns:
            审计日志
        """
        client = await self._get_client()
        url = f"{self.api_url}/api/audit/logs"
        
        query_params: Dict[str, Any] = {"limit": params.limit}
        if params.start_time:
            query_params["start_time"] = params.start_time
        if params.end_time:
            query_params["end_time"] = params.end_time
        
        try:
            response = await client.get(url, params=query_params)
            response.raise_for_status()
            result: Dict[str, Any] = response.json()
            return result
        except Exception as e:
            logger.error(f"Get audit logs failed: {e}")
            raise
    
    async def block_ip(self, ip: str, duration: Optional[int] = None) -> bool:
        """
        封禁IP
        
        Args:
            ip: IP地址
            duration: 封禁时长(秒)，None表示永久
            
        Returns:
            是否成功
        """
        client = await self._get_client()
        url = f"{self.api_url}/api/blacklist/ip"
        
        try:
            data = {"ip": ip}
            if duration:
                data["duration"] = str(duration)
            
            response = await client.post(url, json=data)
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Block IP failed: {e}")
            return False
    
    async def unblock_ip(self, ip: str) -> bool:
        """
        解除IP封禁
        
        Args:
            ip: IP地址
            
        Returns:
            是否成功
        """
        client = await self._get_client()
        url = f"{self.api_url}/api/blacklist/ip/{ip}"
        
        try:
            response = await client.delete(url)
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Unblock IP failed: {e}")
            return False
    
    async def get_statistics(self) -> Dict[str, Any]:
        """
        获取统计信息
        
        Returns:
            统计数据
        """
        client = await self._get_client()
        url = f"{self.api_url}/api/statistics"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Get statistics failed: {e}")
            raise
    
    async def execute(self, **kwargs) -> ToolResult:
        """
        执行WAF操作
        
        Args:
            **kwargs: 操作参数
            
        Returns:
            操作结果
        """
        try:
            action = kwargs.get("action", "status")
            start_time = datetime.now()
            
            result_data = {}
            
            if action == "status":
                result_data = await self.get_status()
            elif action == "create_rule":
                params = WAFRuleParams(**kwargs)
                result_data = await self.create_rule(params)
            elif action == "delete_rule":
                rule_id = kwargs.get("rule_id")
                if not rule_id:
                    return ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="MISSING_PARAM",
                        error_message="rule_id参数缺失"
                    )
                success = await self.delete_rule(rule_id)
                result_data = {"success": success}
            elif action == "list_rules":
                rules = await self.list_rules()
                result_data = {"rules": rules, "count": len(rules)}
            elif action == "block_ip":
                ip = kwargs.get("ip")
                if not ip:
                    return ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="MISSING_PARAM",
                        error_message="ip参数缺失"
                    )
                duration = kwargs.get("duration")
                success = await self.block_ip(ip, duration)
                result_data = {"success": success, "ip": ip}
            elif action == "unblock_ip":
                ip = kwargs.get("ip")
                if not ip:
                    return ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="MISSING_PARAM",
                        error_message="ip参数缺失"
                    )
                success = await self.unblock_ip(ip)
                result_data = {"success": success, "ip": ip}
            elif action == "statistics":
                result_data = await self.get_statistics()
            else:
                return ToolResult.error_result(
                    tool_name=self.metadata.name,
                    error_code="INVALID_ACTION",
                    error_message=f"不支持的操作: {action}"
                )
            
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ToolResult.success_result(
                tool_name=self.metadata.name,
                data={
                    "action": action,
                    "result": result_data
                },
                duration_ms=duration_ms,
                metadata={
                    "action": action
                }
            )
            
        except Exception as e:
            logger.error(f"Execute WAF operation failed: {e}", exc_info=True)
            return ToolResult.error_result(
                tool_name=self.metadata.name,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                details={"kwargs": kwargs}
            )
    
    async def close(self):
        """关闭HTTP客户端"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
