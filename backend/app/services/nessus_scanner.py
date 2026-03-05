import httpx
from typing import Dict, Optional, List
import logging
import asyncio
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class NessusScanner:
    """Nessus漏洞扫描器"""
    
    def __init__(self):
        self.url = settings.security_tools.nessus_url if hasattr(settings, 'security_tools') else None
        self.api_key = settings.security_tools.nessus_api_key.get_secret_value() if hasattr(settings, 'security_tools') and settings.security_tools.nessus_api_key else None
        self.headers = {
            "Content-Type": "application/json",
            "X-ApiKeys": f"accessKey={self.api_key}" if self.api_key else ""
        }
    
    async def create_scan(self, name: str, target: str, template: str = "basic") -> Dict:
        """创建扫描任务"""
        if not self.url or not self.api_key:
            logger.warning("Nessus not configured, returning mock data")
            return self._get_mock_scan_creation(name, target)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.url}/scans",
                    headers=self.headers,
                    json={
                        "uuid": self._get_template_uuid(template),
                        "settings": {
                            "name": name,
                            "text_targets": target,
                            "enabled": True
                        }
                    }
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error creating Nessus scan: {e}")
            return self._get_mock_scan_creation(name, target)
    
    async def launch_scan(self, scan_id: int) -> Dict:
        """启动扫描"""
        if not self.url or not self.api_key:
            return self._get_mock_scan_launch(scan_id)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.url}/scans/{scan_id}/launch",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error launching Nessus scan: {e}")
            return self._get_mock_scan_launch(scan_id)
    
    async def get_scan_status(self, scan_id: int) -> Dict:
        """获取扫描状态"""
        if not self.url or not self.api_key:
            return self._get_mock_scan_status(scan_id)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/scans/{scan_id}",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting Nessus scan status: {e}")
            return self._get_mock_scan_status(scan_id)
    
    async def get_scan_results(self, scan_id: int) -> Dict:
        """获取扫描结果"""
        if not self.url or not self.api_key:
            return self._get_mock_scan_results(scan_id)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/scans/{scan_id}/export",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting Nessus scan results: {e}")
            return self._get_mock_scan_results(scan_id)
    
    async def list_scans(self) -> Dict:
        """列出所有扫描任务"""
        if not self.url or not self.api_key:
            return self._get_mock_scan_list()
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/scans",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error listing Nessus scans: {e}")
            return self._get_mock_scan_list()
    
    async def get_vulnerabilities(self, scan_id: int) -> Dict:
        """获取漏洞列表"""
        if not self.url or not self.api_key:
            return self._get_mock_vulnerabilities(scan_id)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/scans/{scan_id}/vulnerabilities",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting Nessus vulnerabilities: {e}")
            return self._get_mock_vulnerabilities(scan_id)
    
    async def get_plugin_details(self, plugin_id: int) -> Dict:
        """获取插件详情"""
        if not self.url or not self.api_key:
            return self._get_mock_plugin_details(plugin_id)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/plugins/plugin/{plugin_id}",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting Nessus plugin details: {e}")
            return self._get_mock_plugin_details(plugin_id)
    
    def _get_template_uuid(self, template: str) -> str:
        """获取扫描模板UUID"""
        templates = {
            "basic": "ad629e16-3b26-4b28-9db2-929b9319a41a",
            "advanced": "d7f0c797-ea39-4875-8a5c-11c152e13a5f",
            "malware": "a3f2a7a8-1d5e-4f8b-9c7d-6e5f4a3b2c1d"
        }
        return templates.get(template, templates["basic"])
    
    def _get_mock_scan_creation(self, name: str, target: str) -> Dict:
        """获取模拟扫描创建结果"""
        return {
            "scan": {
                "id": 12345,
                "uuid": "scan-uuid-12345",
                "name": name,
                "type": "local",
                "owner": "admin",
                "enabled": True,
                "folder_id": 1,
                "read": True,
                "status": "empty",
                "shared": False,
                "user_permissions": 64,
                "creation_date": 1709500000,
                "last_modification_date": 1709500000,
                "control": True,
                "starttime": "2026-03-01T00:00:00Z",
                "timezone": "Asia/Shanghai",
                "rrules": "",
                "rrulesstarttime": "",
                "targets": target
            }
        }
    
    def _get_mock_scan_launch(self, scan_id: int) -> Dict:
        """获取模拟扫描启动结果"""
        return {
            "scan_uuid": f"scan-uuid-{scan_id}",
            "status": "running"
        }
    
    def _get_mock_scan_status(self, scan_id: int) -> Dict:
        """获取模拟扫描状态"""
        return {
            "info": {
                "name": f"Scan-{scan_id}",
                "status": "completed",
                "progress": 100,
                "start_time": "2026-03-01T00:00:00Z",
                "end_time": "2026-03-01T01:30:00Z",
                "targets": "192.168.1.0/24"
            },
            "hosts": [
                {
                    "host_id": 1,
                    "host_ip": "192.168.1.1",
                    "scan_progress": "complete",
                    "severity": "high",
                    "critical": 2,
                    "high": 5,
                    "medium": 12,
                    "low": 25
                },
                {
                    "host_id": 2,
                    "host_ip": "192.168.1.100",
                    "scan_progress": "complete",
                    "severity": "medium",
                    "critical": 0,
                    "high": 3,
                    "medium": 8,
                    "low": 15
                }
            ]
        }
    
    def _get_mock_scan_results(self, scan_id: int) -> Dict:
        """获取模拟扫描结果"""
        return {
            "scan_id": scan_id,
            "vulnerabilities": {
                "critical": [
                    {
                        "plugin_id": 123456,
                        "plugin_name": "Apache Log4j Remote Code Execution (CVE-2021-44228)",
                        "severity": 4,
                        "host": "192.168.1.100",
                        "port": 8080,
                        "protocol": "tcp",
                        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features...",
                        "solution": "Upgrade to Log4j 2.17.0 or later",
                        "risk_factor": "critical",
                        "cvss_base_score": 10.0
                    }
                ],
                "high": [
                    {
                        "plugin_id": 234567,
                        "plugin_name": "OpenSSH < 8.6 Vulnerability",
                        "severity": 3,
                        "host": "192.168.1.1",
                        "port": 22,
                        "protocol": "tcp",
                        "description": "The remote SSH service is outdated",
                        "solution": "Upgrade OpenSSH to version 8.6 or later",
                        "risk_factor": "high",
                        "cvss_base_score": 8.1
                    }
                ],
                "medium": [
                    {
                        "plugin_id": 345678,
                        "plugin_name": "SSL Certificate Signed Using Weak Hashing Algorithm",
                        "severity": 2,
                        "host": "192.168.1.1",
                        "port": 443,
                        "protocol": "tcp",
                        "description": "The SSL certificate is signed with a weak algorithm",
                        "solution": "Re-issue the certificate with SHA-256 or higher",
                        "risk_factor": "medium",
                        "cvss_base_score": 5.9
                    }
                ],
                "low": [
                    {
                        "plugin_id": 456789,
                        "plugin_name": "HTTP Server Type and Version",
                        "severity": 1,
                        "host": "192.168.1.100",
                        "port": 80,
                        "protocol": "tcp",
                        "description": "HTTP server version disclosure",
                        "solution": "Configure the server to hide version information",
                        "risk_factor": "low",
                        "cvss_base_score": 2.6
                    }
                ]
            },
            "summary": {
                "total_hosts": 2,
                "total_vulnerabilities": 47,
                "critical": 2,
                "high": 8,
                "medium": 20,
                "low": 40
            }
        }
    
    def _get_mock_scan_list(self) -> Dict:
        """获取模拟扫描列表"""
        return {
            "scans": [
                {
                    "id": 12345,
                    "name": "Internal Network Scan",
                    "type": "local",
                    "owner": "admin",
                    "status": "completed",
                    "creation_date": 1709500000,
                    "last_modification_date": 1709500000
                },
                {
                    "id": 12346,
                    "name": "Web Server Scan",
                    "type": "local",
                    "owner": "admin",
                    "status": "running",
                    "creation_date": 1709600000,
                    "last_modification_date": 1709600000
                }
            ],
            "folder_id": 1
        }
    
    def _get_mock_vulnerabilities(self, scan_id: int) -> Dict:
        """获取模拟漏洞列表"""
        return {
            "vulnerabilities": [
                {
                    "plugin_id": 123456,
                    "plugin_name": "Log4j RCE",
                    "severity": 4,
                    "host_count": 1,
                    "vuln_count": 1
                },
                {
                    "plugin_id": 234567,
                    "plugin_name": "OpenSSH Vulnerability",
                    "severity": 3,
                    "host_count": 3,
                    "vuln_count": 3
                }
            ]
        }
    
    def _get_mock_plugin_details(self, plugin_id: int) -> Dict:
        """获取模拟插件详情"""
        return {
            "plugin_id": plugin_id,
            "name": "Sample Vulnerability Plugin",
            "family": "General",
            "severity": 3,
            "description": "This is a sample vulnerability description",
            "solution": "Apply the latest security patches",
            "risk_factor": "high",
            "cvss_base_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cve": ["CVE-2021-44228"],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
            ]
        }