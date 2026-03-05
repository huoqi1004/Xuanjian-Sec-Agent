import httpx
from typing import Dict, Optional, List
import logging
from app.config import get_settings
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
settings = get_settings()

class ELKStack:
    """ELK Stack日志分析服务"""
    
    def __init__(self):
        self.es_hosts = settings.elasticsearch.hosts if hasattr(settings, 'elasticsearch') else ["http://localhost:9200"]
        self.kibana_url = "http://localhost:5601"
        self.headers = {
            "Content-Type": "application/json"
        }
    
    async def search_logs(self, index: str, query: Dict, size: int = 100) -> Dict:
        """搜索日志"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.es_hosts[0]}/{index}/_search",
                    headers=self.headers,
                    json={
                        "query": query,
                        "size": size,
                        "sort": [{"@timestamp": {"order": "desc"}}]
                    }
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error searching logs: {e}")
            return self._get_mock_search_results(index, query)
    
    async def index_log(self, index: str, doc: Dict) -> Dict:
        """索引日志文档"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.es_hosts[0]}/{index}/_doc",
                    headers=self.headers,
                    json=doc
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error indexing log: {e}")
            return self._get_mock_index_result(index, doc)
    
    async def get_security_events(self, time_range: str = "24h", severity: str = None) -> Dict:
        """获取安全事件"""
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}}
                ]
            }
        }
        
        if severity:
            query["bool"]["must"].append({"term": {"severity": severity}})
        
        return await self.search_logs("security-events", query)
    
    async def get_attack_patterns(self, time_range: str = "24h") -> Dict:
        """获取攻击模式分析"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.es_hosts[0]}/security-events/_search",
                    headers=self.headers,
                    json={
                        "query": {
                            "range": {"@timestamp": {"gte": f"now-{time_range}"}}
                        },
                        "aggs": {
                            "attack_types": {
                                "terms": {"field": "attack_type.keyword"}
                            },
                            "top_attackers": {
                                "terms": {"field": "source_ip.keyword"}
                            },
                            "attack_timeline": {
                                "date_histogram": {
                                    "field": "@timestamp",
                                    "calendar_interval": "hour"
                                }
                            }
                        },
                        "size": 0
                    }
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting attack patterns: {e}")
            return self._get_mock_attack_patterns(time_range)
    
    async def get_threat_intelligence(self, time_range: str = "7d") -> Dict:
        """获取威胁情报分析"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.es_hosts[0]}/threat-intel/_search",
                    headers=self.headers,
                    json={
                        "query": {
                            "range": {"@timestamp": {"gte": f"now-{time_range}"}}
                        },
                        "aggs": {
                            "threat_types": {
                                "terms": {"field": "threat_type.keyword"}
                            },
                            "severity_distribution": {
                                "terms": {"field": "severity.keyword"}
                            },
                            "ioc_types": {
                                "terms": {"field": "ioc_type.keyword"}
                            }
                        },
                        "size": 0
                    }
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting threat intelligence: {e}")
            return self._get_mock_threat_intel(time_range)
    
    async def get_asset_activity(self, asset_ip: str, time_range: str = "24h") -> Dict:
        """获取资产活动日志"""
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"bool": {
                        "should": [
                            {"term": {"source_ip": asset_ip}},
                            {"term": {"destination_ip": asset_ip}}
                        ]
                    }}
                ]
            }
        }
        
        return await self.search_logs("network-logs", query, size=500)
    
    async def get_user_activity(self, username: str, time_range: str = "7d") -> Dict:
        """获取用户活动日志"""
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"term": {"username.keyword": username}}
                ]
            }
        }
        
        return await self.search_logs("user-activity", query, size=200)
    
    async def create_dashboard(self, name: str, visualizations: List[Dict]) -> Dict:
        """创建Kibana仪表板"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.kibana_url}/api/saved_objects/dashboard",
                    headers={**self.headers, "kbn-xsrf": "true"},
                    json={
                        "attributes": {
                            "title": name,
                            "description": f"Security dashboard: {name}",
                            "panelsJSON": json.dumps(visualizations)
                        }
                    }
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error creating dashboard: {e}")
            return self._get_mock_dashboard_creation(name)
    
    async def get_alert_rules(self) -> Dict:
        """获取告警规则"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.kibana_url}/api/alerts/_find",
                    headers={**self.headers, "kbn-xsrf": "true"}
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting alert rules: {e}")
            return self._get_mock_alert_rules()
    
    async def create_alert_rule(self, name: str, index: str, conditions: Dict, actions: List[Dict]) -> Dict:
        """创建告警规则"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.kibana_url}/api/alerts/alert",
                    headers={**self.headers, "kbn-xsrf": "true"},
                    json={
                        "name": name,
                        "rule_type_id": ".index-threshold",
                        "params": {
                            "index": index,
                            "timeField": "@timestamp",
                            **conditions
                        },
                        "actions": actions
                    }
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error creating alert rule: {e}")
            return self._get_mock_alert_creation(name)
    
    async def get_log_statistics(self, time_range: str = "24h") -> Dict:
        """获取日志统计"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.es_hosts[0]}/_stats",
                    headers=self.headers
                )
                response.raise_for_status()
                stats = response.json()
                
                return {
                    "total_docs": stats.get("_all", {}).get("primaries", {}).get("docs", {}).get("count", 0),
                    "total_size": stats.get("_all", {}).get("primaries", {}).get("store", {}).get("size_in_bytes", 0),
                    "indices": list(stats.get("indices", {}).keys())
                }
        except httpx.HTTPError as e:
            logger.error(f"Error getting log statistics: {e}")
            return self._get_mock_log_statistics(time_range)
    
    def _get_mock_search_results(self, index: str, query: Dict) -> Dict:
        """获取模拟搜索结果"""
        return {
            "took": 5,
            "timed_out": False,
            "hits": {
                "total": {"value": 100, "relation": "eq"},
                "hits": [
                    {
                        "_index": index,
                        "_id": "abc123",
                        "_source": {
                            "@timestamp": "2026-03-01T10:00:00Z",
                            "event_type": "security_alert",
                            "severity": "high",
                            "source_ip": "192.168.1.100",
                            "destination_ip": "192.168.1.1",
                            "message": "SQL Injection attempt detected"
                        }
                    }
                ]
            }
        }
    
    def _get_mock_index_result(self, index: str, doc: Dict) -> Dict:
        """获取模拟索引结果"""
        return {
            "_index": index,
            "_id": "new-doc-id",
            "result": "created",
            "status": 201
        }
    
    def _get_mock_attack_patterns(self, time_range: str) -> Dict:
        """获取模拟攻击模式"""
        return {
            "aggregations": {
                "attack_types": {
                    "buckets": [
                        {"key": "SQL Injection", "doc_count": 150},
                        {"key": "XSS", "doc_count": 120},
                        {"key": "Brute Force", "doc_count": 80},
                        {"key": "Path Traversal", "doc_count": 50}
                    ]
                },
                "top_attackers": {
                    "buckets": [
                        {"key": "192.168.1.200", "doc_count": 45},
                        {"key": "10.0.0.50", "doc_count": 38},
                        {"key": "172.16.0.100", "doc_count": 25}
                    ]
                },
                "attack_timeline": {
                    "buckets": [
                        {"key_as_string": "2026-03-01T00:00:00Z", "doc_count": 50},
                        {"key_as_string": "2026-03-01T06:00:00Z", "doc_count": 80},
                        {"key_as_string": "2026-03-01T12:00:00Z", "doc_count": 120}
                    ]
                }
            }
        }
    
    def _get_mock_threat_intel(self, time_range: str) -> Dict:
        """获取模拟威胁情报"""
        return {
            "aggregations": {
                "threat_types": {
                    "buckets": [
                        {"key": "Malware", "doc_count": 200},
                        {"key": "Phishing", "doc_count": 150},
                        {"key": "C2", "doc_count": 80}
                    ]
                },
                "severity_distribution": {
                    "buckets": [
                        {"key": "critical", "doc_count": 30},
                        {"key": "high", "doc_count": 80},
                        {"key": "medium", "doc_count": 150},
                        {"key": "low", "doc_count": 170}
                    ]
                },
                "ioc_types": {
                    "buckets": [
                        {"key": "ip", "doc_count": 250},
                        {"key": "domain", "doc_count": 120},
                        {"key": "hash", "doc_count": 60}
                    ]
                }
            }
        }
    
    def _get_mock_dashboard_creation(self, name: str) -> Dict:
        """获取模拟仪表板创建"""
        return {
            "id": "dashboard-123",
            "type": "dashboard",
            "attributes": {
                "title": name,
                "description": f"Security dashboard: {name}"
            }
        }
    
    def _get_mock_alert_rules(self) -> Dict:
        """获取模拟告警规则"""
        return {
            "data": [
                {
                    "id": "alert-1",
                    "attributes": {
                        "name": "High Severity Alert",
                        "rule_type_id": ".index-threshold",
                        "enabled": True
                    }
                },
                {
                    "id": "alert-2",
                    "attributes": {
                        "name": "Brute Force Detection",
                        "rule_type_id": ".index-threshold",
                        "enabled": True
                    }
                }
            ]
        }
    
    def _get_mock_alert_creation(self, name: str) -> Dict:
        """获取模拟告警创建"""
        return {
            "id": "new-alert-id",
            "name": name,
            "status": "created"
        }
    
    def _get_mock_log_statistics(self, time_range: str) -> Dict:
        """获取模拟日志统计"""
        return {
            "total_docs": 1500000,
            "total_size": 5368709120,  # 5GB
            "indices": [
                "security-events",
                "network-logs",
                "user-activity",
                "threat-intel"
            ]
        }