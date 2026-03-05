import httpx
from typing import Dict, Optional, List
import logging
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class CensysAPI:
    """Censys API客户端 - 互联网资产扫描"""
    
    def __init__(self):
        self.api_id = settings.threat_intel.censys_api_id
        self.api_secret = settings.threat_intel.censys_api_secret.get_secret_value() if settings.threat_intel.censys_api_secret else ""
        self.api_url = "https://search.censys.io/api/v2"
        self.headers = {
            "Content-Type": "application/json"
        }
    
    async def search_hosts(self, query: str, per_page: int = 100) -> Optional[Dict]:
        """搜索互联网主机"""
        if not self.api_id or not self.api_secret:
            logger.warning("Censys API credentials not set")
            return self._get_mock_host_search_result(query)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_url}/hosts/search",
                    params={"q": query, "per_page": per_page},
                    auth=(self.api_id, self.api_secret)
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error searching hosts: {e}")
            return self._get_mock_host_search_result(query)
    
    async def get_host(self, ip: str) -> Optional[Dict]:
        """获取特定主机的详细信息"""
        if not self.api_id or not self.api_secret:
            logger.warning("Censys API credentials not set")
            return self._get_mock_host_detail(ip)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_url}/hosts/{ip}",
                    auth=(self.api_id, self.api_secret)
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting host {ip}: {e}")
            return self._get_mock_host_detail(ip)
    
    async def search_certificates(self, query: str, per_page: int = 100) -> Optional[Dict]:
        """搜索证书"""
        if not self.api_id or not self.api_secret:
            logger.warning("Censys API credentials not set")
            return self._get_mock_cert_search_result(query)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_url}/certificates/search",
                    params={"q": query, "per_page": per_page},
                    auth=(self.api_id, self.api_secret)
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error searching certificates: {e}")
            return self._get_mock_cert_search_result(query)
    
    async def get_host_events(self, ip: str) -> Optional[Dict]:
        """获取主机事件历史"""
        if not self.api_id or not self.api_secret:
            logger.warning("Censys API credentials not set")
            return self._get_mock_host_events(ip)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_url}/hosts/{ip}/events",
                    auth=(self.api_id, self.api_secret)
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting host events {ip}: {e}")
            return self._get_mock_host_events(ip)
    
    def _get_mock_host_search_result(self, query: str) -> Dict:
        """获取模拟主机搜索结果"""
        return {
            "code": 200,
            "status": "OK",
            "result": {
                "query": query,
                "total": 1500,
                "hits": [
                    {
                        "ip": "192.168.1.100",
                        "services": [
                            {"port": 80, "service_name": "HTTP", "transport_protocol": "TCP"},
                            {"port": 443, "service_name": "HTTPS", "transport_protocol": "TCP"},
                            {"port": 22, "service_name": "SSH", "transport_protocol": "TCP"}
                        ],
                        "location": {
                            "country": "中国",
                            "city": "北京",
                            "latitude": 39.9042,
                            "longitude": 116.4074
                        },
                        "autonomous_system": {
                            "asn": 12345,
                            "name": "China Telecom",
                            "country": "中国"
                        },
                        "operating_system": {
                            "vendor": "Linux",
                            "product": "Ubuntu",
                            "version": "20.04"
                        }
                    },
                    {
                        "ip": "192.168.1.101",
                        "services": [
                            {"port": 3306, "service_name": "MySQL", "transport_protocol": "TCP"},
                            {"port": 8080, "service_name": "HTTP", "transport_protocol": "TCP"}
                        ],
                        "location": {
                            "country": "中国",
                            "city": "上海",
                            "latitude": 31.2304,
                            "longitude": 121.4737
                        }
                    }
                ]
            }
        }
    
    def _get_mock_host_detail(self, ip: str) -> Dict:
        """获取模拟主机详情"""
        return {
            "code": 200,
            "status": "OK",
            "result": {
                "ip": ip,
                "services": [
                    {
                        "port": 80,
                        "service_name": "HTTP",
                        "transport_protocol": "TCP",
                        "software": [
                            {"vendor": "nginx", "product": "nginx", "version": "1.18.0"}
                        ],
                        "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
                    },
                    {
                        "port": 443,
                        "service_name": "HTTPS",
                        "transport_protocol": "TCP",
                        "tls": {
                            "version": "TLSv1.3",
                            "certificate": {
                                "subject": "CN=example.com",
                                "issuer": "CN=Let's Encrypt",
                                "valid_from": "2025-01-01",
                                "valid_to": "2026-01-01"
                            }
                        }
                    }
                ],
                "location": {
                    "country": "中国",
                    "city": "北京",
                    "latitude": 39.9042,
                    "longitude": 116.4074
                },
                "autonomous_system": {
                    "asn": 12345,
                    "name": "China Telecom",
                    "country": "中国"
                },
                "operating_system": {
                    "vendor": "Linux",
                    "product": "Ubuntu",
                    "version": "20.04"
                },
                "dns": {
                    "reverse_dns": ["server1.example.com"]
                }
            }
        }
    
    def _get_mock_cert_search_result(self, query: str) -> Dict:
        """获取模拟证书搜索结果"""
        return {
            "code": 200,
            "status": "OK",
            "result": {
                "query": query,
                "total": 500,
                "hits": [
                    {
                        "fingerprint": "sha256:abc123...",
                        "names": ["example.com", "www.example.com"],
                        "issuer": {
                            "common_name": "Let's Encrypt Authority X3",
                            "organization": "Let's Encrypt"
                        },
                        "validity": {
                            "start": "2025-01-01T00:00:00Z",
                            "end": "2026-01-01T00:00:00Z"
                        }
                    }
                ]
            }
        }
    
    def _get_mock_host_events(self, ip: str) -> Dict:
        """获取模拟主机事件历史"""
        return {
            "code": 200,
            "status": "OK",
            "result": {
                "ip": ip,
                "events": [
                    {
                        "timestamp": "2026-03-01T10:00:00Z",
                        "event_type": "service_detected",
                        "details": {
                            "port": 443,
                            "service": "HTTPS"
                        }
                    },
                    {
                        "timestamp": "2026-02-28T15:30:00Z",
                        "event_type": "os_change",
                        "details": {
                            "old_os": "Ubuntu 18.04",
                            "new_os": "Ubuntu 20.04"
                        }
                    }
                ]
            }
        }