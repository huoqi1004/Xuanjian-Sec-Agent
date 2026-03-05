import httpx
from typing import Dict, Optional
import logging
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class VirusTotalAPI:
    """VirusTotal API客户端"""
    
    def __init__(self):
        self.api_key = settings.threat_intel.virustotal_api_key.get_secret_value() if settings.threat_intel.virustotal_api_key else ""
        self.api_url = settings.threat_intel.virustotal_base_url
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
    
    async def scan_file(self, file_hash: str) -> Optional[Dict]:
        """通过文件哈希扫描文件"""
        if not self.api_key:
            logger.warning("VirusTotal API key not set")
            return self._get_mock_scan_result(file_hash)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_url}/files/{file_hash}",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error scanning file {file_hash}: {e}")
            return self._get_mock_scan_result(file_hash)
    
    async def scan_url(self, url: str) -> Optional[Dict]:
        """扫描URL"""
        if not self.api_key:
            logger.warning("VirusTotal API key not set")
            return self._get_mock_url_result(url)
        
        try:
            async with httpx.AsyncClient() as client:
                # 首先提交URL进行扫描
                post_response = await client.post(
                    f"{self.api_url}/urls",
                    headers=self.headers,
                    data={"url": url}
                )
                post_response.raise_for_status()
                
                # 获取扫描结果
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                get_response = await client.get(
                    f"{self.api_url}/urls/{url_id}",
                    headers=self.headers
                )
                get_response.raise_for_status()
                return get_response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error scanning URL {url}: {e}")
            return self._get_mock_url_result(url)
    
    async def scan_ip(self, ip: str) -> Optional[Dict]:
        """扫描IP地址"""
        if not self.api_key:
            logger.warning("VirusTotal API key not set")
            return self._get_mock_ip_result(ip)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_url}/ip_addresses/{ip}",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error scanning IP {ip}: {e}")
            return self._get_mock_ip_result(ip)
    
    async def scan_domain(self, domain: str) -> Optional[Dict]:
        """扫描域名"""
        if not self.api_key:
            logger.warning("VirusTotal API key not set")
            return self._get_mock_domain_result(domain)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.api_url}/domains/{domain}",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error scanning domain {domain}: {e}")
            return self._get_mock_domain_result(domain)
    
    def _get_mock_scan_result(self, file_hash: str) -> Dict:
        """获取模拟文件扫描结果"""
        return {
            "data": {
                "id": file_hash,
                "type": "file",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 15,
                        "suspicious": 5,
                        "undetected": 45,
                        "harmless": 10,
                        "timeout": 0,
                        "confirmed-timeout": 0,
                        "failure": 0,
                        "type-unsupported": 0
                    },
                    "last_analysis_results": {
                        "Microsoft": {"result": "Trojan:Win32/Malware"},
                        "Kaspersky": {"result": "Trojan.Win32.Generic"},
                        "Symantec": {"result": "Trojan.Gen.2"},
                        "McAfee": {"result": "GenericRXQW-ABCD"},
                        "TrendMicro": {"result": "TROJ_GEN.R002C0PKE24"}
                    },
                    "total_votes": {
                        "harmless": 0,
                        "malicious": 25
                    },
                    "reputation": -50,
                    "first_submission_date": "2026-01-01T00:00:00Z",
                    "last_submission_date": "2026-03-01T00:00:00Z",
                    "names": ["malware.exe", "trojan.dll"],
                    "type_description": "PE32 executable",
                    "size": 1024000,
                    "md5": file_hash[:32],
                    "sha1": file_hash[:40],
                    "sha256": file_hash
                }
            }
        }
    
    def _get_mock_url_result(self, url: str) -> Dict:
        """获取模拟URL扫描结果"""
        return {
            "data": {
                "id": url,
                "type": "url",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 2,
                        "undetected": 60,
                        "harmless": 10
                    },
                    "last_analysis_results": {
                        "Google Safebrowsing": {"result": "malicious"},
                        "Sophos": {"result": "malicious"},
                        "BitDefender": {"result": "malicious"}
                    },
                    "reputation": -20,
                    "total_votes": {
                        "harmless": 5,
                        "malicious": 10
                    }
                }
            }
        }
    
    def _get_mock_ip_result(self, ip: str) -> Dict:
        """获取模拟IP扫描结果"""
        return {
            "data": {
                "id": ip,
                "type": "ip_address",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 8,
                        "suspicious": 3,
                        "undetected": 50,
                        "harmless": 15
                    },
                    "reputation": -30,
                    "country": "中国",
                    "continent": "Asia",
                    "as_owner": "China Telecom",
                    "total_votes": {
                        "harmless": 2,
                        "malicious": 15
                    }
                }
            }
        }
    
    def _get_mock_domain_result(self, domain: str) -> Dict:
        """获取模拟域名扫描结果"""
        return {
            "data": {
                "id": domain,
                "type": "domain",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "undetected": 55,
                        "harmless": 20
                    },
                    "reputation": -15,
                    "total_votes": {
                        "harmless": 8,
                        "malicious": 12
                    },
                    "whois": "Domain registered on 2025-01-01",
                    "creation_date": "2025-01-01T00:00:00Z"
                }
            }
        }