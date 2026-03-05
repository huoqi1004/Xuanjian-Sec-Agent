"""
玄鉴安全智能体 - Censys互联网资产扫描工具
集成Censys API进行互联网资产发现和扫描
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

from ..base_tool import BaseTool, ToolCategory, ToolMetadata, ToolResult, RiskLevel

logger = logging.getLogger(__name__)


class CensysSearchParams(BaseModel):
    """Censys搜索参数"""
    query: str = Field(..., description="搜索查询语句")
    page: int = Field(default=1, description="页码")
    per_page: int = Field(default=100, description="每页结果数")
    fields: Optional[List[str]] = Field(default=None, description="返回字段")


class CensysViewParams(BaseModel):
    """Censys查看参数"""
    resource_type: str = Field(..., description="资源类型: hosts/ipv6/certificates")
    id: str = Field(..., description="资源ID")


class CensysTool(BaseTool):
    """Censys互联网资产扫描工具"""
    
    metadata = ToolMetadata(
        name="censys",
        category=ToolCategory.SCANNER,
        description="Censys互联网资产扫描工具，支持域名、IP、证书等互联网资产发现",
        version="1.0.0",
        author="玄鉴安全团队",
        tags=["scanner", "asset-discovery", "internet"],
        risk_level=RiskLevel.LOW
    )
    
    def __init__(self, api_id: str, api_secret: str):
        """
        初始化Censys工具
        
        Args:
            api_id: Censys API ID
            api_secret: Censys API Secret
        """
        super().__init__()
        self.api_id = api_id
        self.api_secret = api_secret
        self.base_url = "https://search.censys.io/api/v2"
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """获取HTTP客户端"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=60.0,
                auth=(self.api_id, self.api_secret)
            )
        return self._client
    
    async def search(self, params: CensysSearchParams) -> Dict[str, Any]:
        """
        搜索互联网资产
        
        Args:
            params: 搜索参数
            
        Returns:
            搜索结果
        """
        client = await self._get_client()
        url = f"{self.base_url}/hosts/search"
        
        request_data = {
            "q": params.query,
            "page": params.page,
            "per_page": params.per_page
        }
        
        if params.fields:
            request_data["fields"] = params.fields
        
        try:
            response = await client.post(url, json=request_data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Censys search failed: {e}")
            raise
    
    async def view(self, params: CensysViewParams) -> Dict[str, Any]:
        """
        查看资源详情
        
        Args:
            params: 查看参数
            
        Returns:
            资源详情
        """
        client = await self._get_client()
        url = f"{self.base_url}/{params.resource_type}/{params.id}"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Censys view failed: {e}")
            raise
    
    async def search_by_domain(self, domain: str) -> Dict[str, Any]:
        """
        按域名搜索
        
        Args:
            domain: 域名
            
        Returns:
            搜索结果
        """
        return await self.search(
            params=CensysSearchParams(
                query=f"names: {domain}"
            )
        )
    
    async def search_by_ip(self, ip: str) -> Dict[str, Any]:
        """
        按IP搜索
        
        Args:
            ip: IP地址
            
        Returns:
            搜索结果
        """
        return await self.search(
            params=CensysSearchParams(
                query=f"ip: {ip}"
            )
        )
    
    async def search_by_certificate(self, cert_fingerprint: str) -> Dict[str, Any]:
        """
        按证书指纹搜索
        
        Args:
            cert_fingerprint: 证书指纹
            
        Returns:
            搜索结果
        """
        return await self.search(
            params=CensysSearchParams(
                query=f"fingerprint: {cert_fingerprint}"
            )
        )
    
    async def execute(self, **kwargs) -> ToolResult:
        """
        执行搜索
        
        Args:
            **kwargs: 搜索参数
            
        Returns:
            搜索结果
        """
        try:
            # 判断操作类型
            query_type = kwargs.get("query_type", "search")
            start_time = datetime.now()
            
            result_data = {}
            
            if query_type == "search":
                params = CensysSearchParams(**kwargs)
                result_data = await self.search(params)
            elif query_type == "view":
                params = CensysViewParams(**kwargs)
                result_data = await self.view(params)
            elif query_type == "domain":
                domain = kwargs.get("domain")
                if not domain:
                    return ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="MISSING_PARAM",
                        error_message="domain参数缺失"
                    )
                result_data = await self.search_by_domain(domain)
            elif query_type == "ip":
                ip = kwargs.get("ip")
                if not ip:
                    return ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="MISSING_PARAM",
                        error_message="ip参数缺失"
                    )
                result_data = await self.search_by_ip(ip)
            else:
                return ToolResult.error_result(
                    tool_name=self.metadata.name,
                    error_code="INVALID_QUERY_TYPE",
                    error_message=f"不支持的查询类型: {query_type}"
                )
            
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            # 整理结果
            result = {
                "query_type": query_type,
                "data": result_data,
                "count": result_data.get("result", {}).get("total", 0) if "result" in result_data else 1
            }
            
            return ToolResult.success_result(
                tool_name=self.metadata.name,
                data=result,
                duration_ms=duration_ms,
                metadata={
                    "query_type": query_type,
                    "result_count": result.get("count", 0)
                }
            )
            
        except Exception as e:
            logger.error(f"Execute Censys search failed: {e}", exc_info=True)
            return ToolResult.error_result(
                tool_name=self.metadata.name,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                details={"kwargs": kwargs}
            )
    
    async def batch_search(self, queries: List[str]) -> List[ToolResult]:
        """
        批量搜索
        
        Args:
            queries: 查询语句列表
            
        Returns:
            搜索结果列表
        """
        tasks = [
            self.search(
                params=CensysSearchParams(query=q)
            )
            for q in queries
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        output = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                output.append(
                    ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="SEARCH_ERROR",
                        error_message=str(result)
                    )
                )
            else:
                output.append(
                    ToolResult.success_result(
                        tool_name=self.metadata.name,
                        data={"query": queries[i], "result": result}
                    )
                )
        
        return output
    
    async def close(self):
        """关闭HTTP客户端"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
