"""
玄鉴安全智能体 - ELK Stack日志分析工具
集成Elasticsearch、Logstash、Kibana进行日志分析和可视化
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from elasticsearch import AsyncElasticsearch
from pydantic import BaseModel, Field

from ..base_tool import BaseTool, ToolCategory, ToolMetadata, ToolResult, RiskLevel

logger = logging.getLogger(__name__)


class ESQueryParams(BaseModel):
    """Elasticsearch查询参数"""
    index: str = Field(..., description="索引名称")
    query: Dict[str, Any] = Field(default_factory=dict, description="查询DSL")
    size: int = Field(default=100, description="返回数量")
    sort: Optional[List[Dict[str, Any]]] = Field(default=None, description="排序规则")
    aggs: Optional[Dict[str, Any]] = Field(default=None, description="聚合查询")


class ESAggregationParams(BaseModel):
    """Elasticsearch聚合参数"""
    index: str = Field(..., description="索引名称")
    agg_type: str = Field(..., description="聚合类型")
    field: str = Field(..., description="聚合字段")
    size: int = Field(default=10, description="返回数量")


class ELKStatsParams(BaseModel):
    """ELK统计参数"""
    index: str = Field(..., description="索引名称")
    start_time: Optional[str] = Field(default=None, description="开始时间")
    end_time: Optional[str] = Field(default=None, description="结束时间")
    interval: str = Field(default="1h", description="时间间隔")


class ELKLoggerTool(BaseTool):
    """ELK Stack日志分析工具"""
    
    metadata = ToolMetadata(
        name="elk_logger",
        category=ToolCategory.ANALYSIS,
        description="ELK Stack日志分析工具，支持日志查询、聚合分析和可视化",
        version="1.0.0",
        author="玄鉴安全团队",
        tags=["logging", "elk", "analytics"],
        risk_level=RiskLevel.LOW
    )
    
    def __init__(
        self,
        hosts: List[str],
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None
    ):
        """
        初始化ELK日志工具
        
        Args:
            hosts: ES节点列表
            username: 用户名
            password: 密码
            api_key: API密钥
        """
        super().__init__()
        self.hosts = hosts
        self.username = username
        self.password = password
        self.api_key = api_key
        self._es_client: Optional[AsyncElasticsearch] = None
    
    async def _get_client(self) -> AsyncElasticsearch:
        """获取ES客户端"""
        if self._es_client is None:
            auth = None
            if self.username and self.password:
                auth = (self.username, self.password)
            
            self._es_client = AsyncElasticsearch(
                hosts=self.hosts,
                basic_auth=auth,
                api_key=self.api_key,
                verify_certs=False
            )
        
        return self._es_client
    
    async def query(self, params: ESQueryParams) -> Dict[str, Any]:
        """
        执行查询
        
        Args:
            params: 查询参数
            
        Returns:
            查询结果
        """
        es = await self._get_client()
        
        body: Dict[str, Any] = {"query": params.query}
        
        if params.size:
            body["size"] = params.size
        if params.sort:
            body["sort"] = params.sort
        if params.aggs:
            body["aggs"] = params.aggs
        
        try:
            response = await es.search(
                index=params.index,
                body=body
            )
            return response.body
        except Exception as e:
            logger.error(f"Query failed: {e}")
            raise
    
    async def search_logs(
        self,
        index: str,
        keyword: str,
        time_range: Optional[Dict[str, str]] = None,
        size: int = 100
    ) -> Dict[str, Any]:
        """
        搜索日志
        
        Args:
            index: 索引名称
            keyword: 关键词
            time_range: 时间范围 {"gte": "now-1h", "lte": "now"}
            size: 返回数量
            
        Returns:
            搜索结果
        """
        query = {
            "bool": {
                "must": [
                    {
                        "multi_match": {
                            "query": keyword,
                            "fields": ["message", "log", "raw"],
                            "fuzziness": "AUTO"
                        }
                    }
                ]
            }
        }
        
        if time_range:
            query["bool"]["filter"] = [
                {
                    "range": {
                        "@timestamp": time_range
                    }
                }
            ]
        
        return await self.query(
            params=ESQueryParams(
                index=index,
                query=query,
                size=size,
                sort=[{"@timestamp": {"order": "desc"}}]
            )
        )
    
    async def aggregate(self, params: ESAggregationParams) -> Dict[str, Any]:
        """
        执行聚合查询
        
        Args:
            params: 聚合参数
            
        Returns:
            聚合结果
        """
        es = await self._get_client()
        
        agg_body = {
            f"{params.agg_type}_agg": {
                params.agg_type: {
                    "field": params.field,
                    "size": params.size
                }
            }
        }
        
        try:
            response = await es.search(
                index=params.index,
                body={"aggs": agg_body, "size": 0}
            )
            return response.body
        except Exception as e:
            logger.error(f"Aggregate failed: {e}")
            raise
    
    async def get_statistics(self, params: ELKStatsParams) -> Dict[str, Any]:
        """
        获取统计信息
        
        Args:
            params: 统计参数
            
        Returns:
            统计数据
        """
        es = await self._get_client()
        
        range_filter = None
        if params.start_time or params.end_time:
            range_filter = {"@timestamp": {}}
            if params.start_time:
                range_filter["@timestamp"]["gte"] = params.start_time
            if params.end_time:
                range_filter["@timestamp"]["lte"] = params.end_time
        
        body = {
            "size": 0,
            "query": {
                "match_all": {}
            } if not range_filter else {
                "range": range_filter
            },
            "aggs": {
                "logs_over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": params.interval
                    }
                },
                "by_level": {
                    "terms": {
                        "field": "level",
                        "size": 10
                    }
                },
                "by_host": {
                    "terms": {
                        "field": "host.hostname",
                        "size": 10
                    }
                }
            }
        }
        
        try:
            response = await es.search(
                index=params.index,
                body=body
            )
            return response.body
        except Exception as e:
            logger.error(f"Get statistics failed: {e}")
            raise
    
    async def create_index(self, index_name: str, mapping: Optional[Dict] = None) -> bool:
        """
        创建索引
        
        Args:
            index_name: 索引名称
            mapping: 映射配置
            
        Returns:
            是否成功
        """
        es = await self._get_client()
        
        try:
            if mapping:
                await es.indices.create(
                    index=index_name,
                    body={"mappings": mapping}
                )
            else:
                await es.indices.create(index=index_name)
            
            logger.info(f"Created index {index_name}")
            return True
        except Exception as e:
            logger.error(f"Create index failed: {e}")
            return False
    
    async def delete_index(self, index_name: str) -> bool:
        """
        删除索引
        
        Args:
            index_name: 索引名称
            
        Returns:
            是否成功
        """
        es = await self._get_client()
        
        try:
            await es.indices.delete(index=index_name)
            logger.info(f"Deleted index {index_name}")
            return True
        except Exception as e:
            logger.error(f"Delete index failed: {e}")
            return False
    
    async def execute(self, **kwargs) -> ToolResult:
        """
        执行日志分析
        
        Args:
            **kwargs: 分析参数
            
        Returns:
            分析结果
        """
        try:
            action = kwargs.get("action", "query")
            start_time = datetime.now()
            
            result_data = {}
            
            if action == "query":
                params = ESQueryParams(**kwargs)
                result_data = await self.query(params)
            elif action == "search":
                index = kwargs.get("index")
                keyword = kwargs.get("keyword")
                if not index or not keyword:
                    return ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="MISSING_PARAM",
                        error_message="index和keyword参数缺失"
                    )
                time_range = kwargs.get("time_range")
                size = kwargs.get("size", 100)
                result_data = await self.search_logs(index, keyword, time_range, size)
            elif action == "aggregate":
                params = ESAggregationParams(**kwargs)
                result_data = await self.aggregate(params)
            elif action == "statistics":
                params = ELKStatsParams(**kwargs)
                result_data = await self.get_statistics(params)
            elif action == "create_index":
                index_name = kwargs.get("index_name")
                if not index_name:
                    return ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="MISSING_PARAM",
                        error_message="index_name参数缺失"
                    )
                mapping = kwargs.get("mapping")
                success = await self.create_index(index_name, mapping)
                result_data = {"success": success}
            elif action == "delete_index":
                index_name = kwargs.get("index_name")
                if not index_name:
                    return ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="MISSING_PARAM",
                        error_message="index_name参数缺失"
                    )
                success = await self.delete_index(index_name)
                result_data = {"success": success}
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
            logger.error(f"Execute ELK operation failed: {e}", exc_info=True)
            return ToolResult.error_result(
                tool_name=self.metadata.name,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                details={"kwargs": kwargs}
            )
    
    async def close(self):
        """关闭ES客户端"""
        if self._es_client:
            await self._es_client.close()
            self._es_client = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
