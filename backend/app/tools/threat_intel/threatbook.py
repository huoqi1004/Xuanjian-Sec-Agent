"""
玄鉴安全智能体 - 微步在线威胁情报工具
集成微步在线API进行威胁情报查询和分析
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

from ..base_tool import BaseTool, ToolCategory, ToolMetadata, ToolResult

logger = logging.getLogger(__name__)


class ThreatbookQuery(BaseModel):
    """微步在线查询参数"""
    query_type: str = Field(..., description="查询类型: ip/domain/hash/url/email")
    query_value: str = Field(..., description="查询值")
    include_subdomains: bool = Field(default=False, description="是否包含子域名")
    include_siblings: bool = Field(default=False, description="是否包含兄弟域名")


class ThreatbookResponse(BaseModel):
    """微步在线响应数据"""
    threat_level: str = Field(default="")
    confidence: str = Field(default="")
    tags: List[str] = Field(default_factory=list)
    judgements: List[str] = Field(default_factory=list)
    related_malware: List[str] = Field(default_factory=list)
    related_ips: List[str] = Field(default_factory=list)
    related_domains: List[str] = Field(default_factory=list)
    risk_level: str = Field(default="")


class ThreatbookTool(BaseTool):
    """微步在线威胁情报工具"""
    
    metadata = ToolMetadata(
        name="threatbook",
        category=ToolCategory.THREAT_INTEL,
        description="微步在线威胁情报查询，支持IP、域名、Hash等威胁情报检索",
        version="1.0.0",
        author="玄鉴安全团队",
        tags=["threat-intel", "api", "microstep"]
    )
    
    def __init__(self, api_key: str, base_url: str = "https://api.threatbook.cn/v3"):
        """
        初始化微步在线工具
        
        Args:
            api_key: 微步在线API Key
            base_url: API基础URL
        """
        super().__init__()
        self.api_key = api_key
        self.base_url = base_url
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """获取HTTP客户端"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                headers={"Api-Key": self.api_key}
            )
        return self._client
    
    async def query_ip(self, ip: str) -> Dict[str, Any]:
        """
        查询IP威胁情报
        
        Args:
            ip: IP地址
            
        Returns:
            威胁情报数据
        """
        client = await self._get_client()
        url = f"{self.base_url}/scene/reputation/ip"
        
        params = {
            "ip": ip,
            "resource": "ip"
        }
        
        try:
            response = await client.post(url, json=params)
            response.raise_for_status()
            data = response.json()
            
            if data.get("response_code") == 0:
                return data.get("data", {})
            else:
                logger.error(f"Threatbook API error: {data.get('verbose_msg')}")
                return {}
        except Exception as e:
            logger.error(f"Query IP failed: {e}")
            return {}
    
    async def query_domain(self, domain: str) -> Dict[str, Any]:
        """
        查询域名威胁情报
        
        Args:
            domain: 域名
            
        Returns:
            威胁情报数据
        """
        client = await self._get_client()
        url = f"{self.base_url}/scene/reputation/domain"
        
        params = {
            "domain": domain,
            "resource": "domain"
        }
        
        try:
            response = await client.post(url, json=params)
            response.raise_for_status()
            data = response.json()
            
            if data.get("response_code") == 0:
                return data.get("data", {})
            else:
                logger.error(f"Threatbook API error: {data.get('verbose_msg')}")
                return {}
        except Exception as e:
            logger.error(f"Query domain failed: {e}")
            return {}
    
    async def query_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        查询文件Hash威胁情报
        
        Args:
            file_hash: 文件Hash (MD5/SHA1/SHA256)
            
        Returns:
            威胁情报数据
        """
        client = await self._get_client()
        url = f"{self.base_url}/scene/reputation/file"
        
        params = {
            "hash": file_hash,
            "resource": "hash"
        }
        
        try:
            response = await client.post(url, json=params)
            response.raise_for_status()
            data = response.json()
            
            if data.get("response_code") == 0:
                return data.get("data", {})
            else:
                logger.error(f"Threatbook API error: {data.get('verbose_msg')}")
                return {}
        except Exception as e:
            logger.error(f"Query hash failed: {e}")
            return {}
    
    async def execute(self, **kwargs) -> ToolResult:
        """
        执行威胁情报查询
        
        Args:
            **kwargs: 查询参数
            
        Returns:
            查询结果
        """
        try:
            # 解析参数
            params = ThreatbookQuery(**kwargs)
            start_time = datetime.now()
            
            # 根据查询类型执行不同的查询
            if params.query_type.lower() == "ip":
                result_data = await self.query_ip(params.query_value)
            elif params.query_type.lower() == "domain":
                result_data = await self.query_domain(params.query_value)
            elif params.query_type.lower() in ["hash", "file"]:
                result_data = await self.query_hash(params.query_value)
            else:
                return ToolResult.error_result(
                    tool_name=self.metadata.name,
                    error_code="INVALID_QUERY_TYPE",
                    error_message=f"不支持的查询类型: {params.query_type}"
                )
            
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            # 解析响应数据
            threatbook_resp = ThreatbookResponse(**result_data)
            
            # 构造完整结果
            result = {
                "query": {
                    "type": params.query_type,
                    "value": params.query_value
                },
                "threat_intel": threatbook_resp.model_dump(exclude_none=True),
                "raw_data": result_data
            }
            
            return ToolResult.success_result(
                tool_name=self.metadata.name,
                data=result,
                metadata={
                    "query_type": params.query_type,
                    "confidence": threatbook_resp.confidence,
                    "risk_level": threatbook_resp.threat_level
                }
            )
            
        except Exception as e:
            logger.error(f"Execute threatbook query failed: {e}", exc_info=True)
            return ToolResult.error_result(
                tool_name=self.metadata.name,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                details={"kwargs": kwargs}
            )
    
    async def batch_query(self, queries: List[ThreatbookQuery]) -> List[ToolResult]:
        """
        批量查询威胁情报
        
        Args:
            queries: 查询参数列表
            
        Returns:
            查询结果列表
        """
        tasks = [self.execute(**q.model_dump()) for q in queries]
        return await asyncio.gather(*tasks)
    
    async def close(self):
        """关闭HTTP客户端"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
