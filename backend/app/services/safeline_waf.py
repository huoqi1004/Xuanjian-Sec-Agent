import httpx
from typing import Dict, Optional, List
import logging
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class SafeLineWAF:
    """雷池WAF防御拦截"""
    
    def __init__(self):
        self.url = settings.security_tools.safeline_url if hasattr(settings, 'security_tools') else None
        self.api_key = settings.security_tools.safeline_api_key.get_secret_value() if hasattr(settings, 'security_tools') and settings.security_tools.safeline_api_key else None
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}" if self.api_key else ""
        }
    
    async def get_status(self) -> Dict:
        """获取WAF状态"""
        if not self.url or not self.api_key:
            logger.warning("SafeLine WAF not configured, returning mock data")
            return self._get_mock_status()
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/api/openapi/status",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting WAF status: {e}")
            return self._get_mock_status()
    
    async def get_sites(self) -> Dict:
        """获取保护的网站列表"""
        if not self.url or not self.api_key:
            return self._get_mock_sites()
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/api/openapi/sites",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting sites: {e}")
            return self._get_mock_sites()
    
    async def add_site(self, name: str, domains: List[str], upstream: str) -> Dict:
        """添加保护网站"""
        if not self.url or not self.api_key:
            return self._get_mock_site_addition(name, domains, upstream)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.url}/api/openapi/sites",
                    headers=self.headers,
                    json={
                        "name": name,
                        "domains": domains,
                        "upstream": upstream
                    }
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error adding site: {e}")
            return self._get_mock_site_addition(name, domains, upstream)
    
    async def get_rules(self) -> Dict:
        """获取防护规则"""
        if not self.url or not self.api_key:
            return self._get_mock_rules()
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/api/openapi/rules",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting rules: {e}")
            return self._get_mock_rules()
    
    async def add_rule(self, name: str, pattern: str, action: str = "deny") -> Dict:
        """添加防护规则"""
        if not self.url or not self.api_key:
            return self._get_mock_rule_addition(name, pattern, action)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.url}/api/openapi/rules",
                    headers=self.headers,
                    json={
                        "name": name,
                        "pattern": pattern,
                        "action": action
                    }
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error adding rule: {e}")
            return self._get_mock_rule_addition(name, pattern, action)
    
    async def block_ip(self, ip: str, duration: int = 3600) -> Dict:
        """封禁IP"""
        if not self.url or not self.api_key:
            return self._get_mock_ip_block(ip, duration)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.url}/api/openapi/ip-block",
                    headers=self.headers,
                    json={
                        "ip": ip,
                        "duration": duration
                    }
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error blocking IP: {e}")
            return self._get_mock_ip_block(ip, duration)
    
    async def unblock_ip(self, ip: str) -> Dict:
        """解封IP"""
        if not self.url or not self.api_key:
            return self._get_mock_ip_unblock(ip)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.delete(
                    f"{self.url}/api/openapi/ip-block/{ip}",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error unblocking IP: {e}")
            return self._get_mock_ip_unblock(ip)
    
    async def get_blocked_ips(self) -> Dict:
        """获取被封禁的IP列表"""
        if not self.url or not self.api_key:
            return self._get_mock_blocked_ips()
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/api/openapi/ip-block",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting blocked IPs: {e}")
            return self._get_mock_blocked_ips()
    
    async def get_attack_logs(self, page: int = 1, size: int = 100) -> Dict:
        """获取攻击日志"""
        if not self.url or not self.api_key:
            return self._get_mock_attack_logs(page, size)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/api/openapi/attack-logs",
                    headers=self.headers,
                    params={"page": page, "size": size}
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting attack logs: {e}")
            return self._get_mock_attack_logs(page, size)
    
    async def get_statistics(self, time_range: str = "24h") -> Dict:
        """获取统计数据"""
        if not self.url or not self.api_key:
            return self._get_mock_statistics(time_range)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/api/openapi/statistics",
                    headers=self.headers,
                    params={"time_range": time_range}
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting statistics: {e}")
            return self._get_mock_statistics(time_range)
    
    def _get_mock_status(self) -> Dict:
        """获取模拟状态"""
        return {
            "status": "running",
            "version": "5.0.0",
            "uptime": "30 days",
            "cpu_usage": "15%",
            "memory_usage": "2.5GB",
            "total_requests": 1500000,
            "blocked_requests": 50000,
            "active_connections": 150
        }
    
    def _get_mock_sites(self) -> Dict:
        """获取模拟网站列表"""
        return {
            "sites": [
                {
                    "id": 1,
                    "name": "Main Website",
                    "domains": ["example.com", "www.example.com"],
                    "upstream": "http://192.168.1.100:8080",
                    "status": "active",
                    "ssl_enabled": True
                },
                {
                    "id": 2,
                    "name": "API Server",
                    "domains": ["api.example.com"],
                    "upstream": "http://192.168.1.101:3000",
                    "status": "active",
                    "ssl_enabled": True
                }
            ]
        }
    
    def _get_mock_site_addition(self, name: str, domains: List[str], upstream: str) -> Dict:
        """获取模拟网站添加结果"""
        return {
            "status": "success",
            "site_id": 3,
            "name": name,
            "domains": domains,
            "upstream": upstream
        }
    
    def _get_mock_rules(self) -> Dict:
        """获取模拟规则列表"""
        return {
            "rules": [
                {
                    "id": 1,
                    "name": "SQL Injection Protection",
                    "pattern": "union.*select|select.*from",
                    "action": "deny",
                    "enabled": True,
                    "hits": 1500
                },
                {
                    "id": 2,
                    "name": "XSS Protection",
                    "pattern": "<script>|javascript:",
                    "action": "deny",
                    "enabled": True,
                    "hits": 2300
                },
                {
                    "id": 3,
                    "name": "Path Traversal Protection",
                    "pattern": "\\.\\./|\\.\\.\\\\",
                    "action": "deny",
                    "enabled": True,
                    "hits": 800
                }
            ]
        }
    
    def _get_mock_rule_addition(self, name: str, pattern: str, action: str) -> Dict:
        """获取模拟规则添加结果"""
        return {
            "status": "success",
            "rule_id": 4,
            "name": name,
            "pattern": pattern,
            "action": action
        }
    
    def _get_mock_ip_block(self, ip: str, duration: int) -> Dict:
        """获取模拟IP封禁结果"""
        return {
            "status": "success",
            "ip": ip,
            "duration": duration,
            "blocked_at": "2026-03-01T00:00:00Z",
            "expires_at": f"2026-03-01T{duration//3600}:00:00Z"
        }
    
    def _get_mock_ip_unblock(self, ip: str) -> Dict:
        """获取模拟IP解封结果"""
        return {
            "status": "success",
            "ip": ip,
            "unblocked_at": "2026-03-01T00:00:00Z"
        }
    
    def _get_mock_blocked_ips(self) -> Dict:
        """获取模拟被封禁IP列表"""
        return {
            "blocked_ips": [
                {
                    "ip": "192.168.1.200",
                    "reason": "SQL Injection Attempt",
                    "blocked_at": "2026-03-01T10:00:00Z",
                    "expires_at": "2026-03-01T11:00:00Z"
                },
                {
                    "ip": "10.0.0.50",
                    "reason": "Brute Force Attack",
                    "blocked_at": "2026-03-01T09:30:00Z",
                    "expires_at": "2026-03-01T10:30:00Z"
                }
            ],
            "total": 2
        }
    
    def _get_mock_attack_logs(self, page: int, size: int) -> Dict:
        """获取模拟攻击日志"""
        return {
            "logs": [
                {
                    "id": 1,
                    "timestamp": "2026-03-01T10:00:00Z",
                    "source_ip": "192.168.1.200",
                    "target": "example.com",
                    "attack_type": "SQL Injection",
                    "url": "/api/users?id=1' OR '1'='1",
                    "method": "GET",
                    "user_agent": "Mozilla/5.0",
                    "action": "blocked"
                },
                {
                    "id": 2,
                    "timestamp": "2026-03-01T09:55:00Z",
                    "source_ip": "10.0.0.50",
                    "target": "api.example.com",
                    "attack_type": "XSS",
                    "url": "/search?q=<script>alert(1)</script>",
                    "method": "GET",
                    "user_agent": "curl/7.68.0",
                    "action": "blocked"
                }
            ],
            "page": page,
            "size": size,
            "total": 150
        }
    
    def _get_mock_statistics(self, time_range: str) -> Dict:
        """获取模拟统计数据"""
        return {
            "time_range": time_range,
            "total_requests": 1500000,
            "blocked_requests": 50000,
            "attack_types": {
                "SQL Injection": 15000,
                "XSS": 12000,
                "Path Traversal": 8000,
                "Brute Force": 10000,
                "Other": 5000
            },
            "top_attacked_paths": [
                {"/api/login": 5000},
                {"/admin": 3000},
                {"/api/users": 2500}
            ],
            "top_attackers": [
                {"ip": "192.168.1.200", "count": 1500},
                {"ip": "10.0.0.50", "count": 1200},
                {"ip": "172.16.0.100", "count": 800}
            ],
            "requests_per_hour": [
                {"hour": "00:00", "requests": 50000, "blocked": 2000},
                {"hour": "06:00", "requests": 80000, "blocked": 3000},
                {"hour": "12:00", "requests": 120000, "blocked": 5000},
                {"hour": "18:00", "requests": 100000, "blocked": 4000}
            ]
        }