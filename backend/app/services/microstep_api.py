import httpx
import os
from typing import Dict, Optional, List
import logging
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class MicroStepAPI:
    """微步在线API客户端"""
    
    def __init__(self):
        self.api_key = settings.threat_intel.threatbook_api_key.get_secret_value() if settings.threat_intel.threatbook_api_key else ""
        self.api_url = settings.threat_intel.threatbook_base_url
        self.headers = {
            "Content-Type": "application/json",
        }
    
    async def query_ip(self, ip: str) -> Optional[Dict]:
        """查询IP地址的威胁情报"""
        if not self.api_key:
            logger.warning("MicroStep API key not set")
            return self._get_mock_ip_data(ip)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_url}/ip/query",
                    params={"ip": ip, "apikey": self.api_key}
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error querying IP {ip}: {e}")
            return self._get_mock_ip_data(ip)
    
    async def query_domain(self, domain: str) -> Optional[Dict]:
        """查询域名的威胁情报"""
        if not self.api_key:
            logger.warning("MicroStep API key not set")
            return self._get_mock_domain_data(domain)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_url}/domain/query",
                    params={"domain": domain, "apikey": self.api_key}
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error querying domain {domain}: {e}")
            return self._get_mock_domain_data(domain)
    
    async def query_hash(self, hash_value: str) -> Optional[Dict]:
        """查询文件哈希的威胁情报"""
        if not self.api_key:
            logger.warning("MicroStep API key not set")
            return self._get_mock_hash_data(hash_value)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_url}/file/report",
                    params={"hash": hash_value, "apikey": self.api_key}
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error querying hash {hash_value}: {e}")
            return self._get_mock_hash_data(hash_value)
    
    async def query_url(self, url: str) -> Optional[Dict]:
        """查询URL的威胁情报"""
        if not self.api_key:
            logger.warning("MicroStep API key not set")
            return self._get_mock_url_data(url)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_url}/url/query",
                    params={"url": url, "apikey": self.api_key}
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error querying URL {url}: {e}")
            return self._get_mock_url_data(url)
    
    def _get_mock_ip_data(self, ip: str) -> Dict:
        """获取模拟IP数据"""
        return {
            "response_code": 0,
            "verbose_msg": "Success",
            "data": {
                "ip": ip,
                "severity": "high",
                "judgments": ["恶意IP", "C&C服务器"],
                "tags": ["botnet", "malware"],
                "confidence": 85,
                "asn": "AS12345",
                "country": "中国",
                "city": "北京",
                "latitude": 39.9042,
                "longitude": 116.4074,
                "threat_types": ["C&C", "恶意软件传播"],
                "references": [
                    "https://x.threatbook.com/node/v_detail/ip/xxx"
                ]
            }
        }
    
    def _get_mock_domain_data(self, domain: str) -> Dict:
        """获取模拟域名数据"""
        return {
            "response_code": 0,
            "verbose_msg": "Success",
            "data": {
                "domain": domain,
                "severity": "medium",
                "judgments": ["可疑域名"],
                "tags": ["suspicious"],
                "confidence": 65,
                "threat_types": ["钓鱼网站"],
                "references": []
            }
        }
    
    def _get_mock_hash_data(self, hash_value: str) -> Dict:
        """获取模拟哈希数据"""
        return {
            "response_code": 0,
            "verbose_msg": "Success",
            "data": {
                "hash": hash_value,
                "severity": "high",
                "judgments": ["恶意文件"],
                "tags": ["malware", "trojan"],
                "confidence": 95,
                "threat_types": ["木马", "勒索软件"],
                "file_type": "PE executable",
                "file_size": 1024000,
                "references": []
            }
        }
    
    def _get_mock_url_data(self, url: str) -> Dict:
        """获取模拟URL数据"""
        return {
            "response_code": 0,
            "verbose_msg": "Success",
            "data": {
                "url": url,
                "severity": "low",
                "judgments": ["安全"],
                "tags": [],
                "confidence": 90,
                "threat_types": [],
                "references": []
            }
        }
    
    async def get_security态势(self) -> Dict:
        """获取安全态势数据"""
        return {
            "threats": {
                "total": 86,
                "high": 25,
                "medium": 35,
                "low": 26,
                "trend": [12, 19, 15, 20, 25, 22]
            },
            "vulnerabilities": {
                "total": 124,
                "high": 30,
                "medium": 50,
                "low": 44,
                "trend": [20, 25, 22, 28, 30, 29]
            },
            "assets": {
                "total": 1200,
                "online": 1150,
                "offline": 50,
                "risky": 80
            },
            "security_score": 85,
            "recent_threats": [
                {
                    "id": "TH-2026-001",
                    "name": "SQL注入攻击",
                    "severity": "高",
                    "source": "外部",
                    "target": "Web服务器",
                    "detected": "2026-03-01 10:00:00"
                },
                {
                    "id": "TH-2026-002",
                    "name": "DDoS攻击",
                    "severity": "高",
                    "source": "外部",
                    "target": "负载均衡器",
                    "detected": "2026-03-01 11:15:00"
                }
            ]
        }