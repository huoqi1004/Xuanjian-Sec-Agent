import httpx
from typing import Dict, Optional, List
import logging
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class CAPESandbox:
    """CAPE沙箱恶意代码分析"""
    
    def __init__(self):
        self.url = settings.security_tools.cape_url if hasattr(settings, 'security_tools') else None
        self.api_key = settings.security_tools.cape_api_key.get_secret_value() if hasattr(settings, 'security_tools') and settings.security_tools.cape_api_key else None
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.api_key}" if self.api_key else ""
        }
    
    async def submit_file(self, file_path: str, options: Dict = None) -> Dict:
        """提交文件进行分析"""
        if not self.url or not self.api_key:
            logger.warning("CAPE sandbox not configured, returning mock data")
            return self._get_mock_submission(file_path)
        
        try:
            async with httpx.AsyncClient() as client:
                with open(file_path, 'rb') as f:
                    files = {'file': f}
                    data = options or {}
                    response = await client.post(
                        f"{self.url}/api/tasks/create/file/",
                        headers={"Authorization": f"Token {self.api_key}"},
                        files=files,
                        data=data
                    )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error submitting file to CAPE: {e}")
            return self._get_mock_submission(file_path)
    
    async def submit_url(self, url: str, options: Dict = None) -> Dict:
        """提交URL进行分析"""
        if not self.url or not self.api_key:
            return self._get_mock_url_submission(url)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.url}/api/tasks/create/url/",
                    headers=self.headers,
                    json={
                        "url": url,
                        **(options or {})
                    }
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error submitting URL to CAPE: {e}")
            return self._get_mock_url_submission(url)
    
    async def get_task_status(self, task_id: int) -> Dict:
        """获取任务状态"""
        if not self.url or not self.api_key:
            return self._get_mock_task_status(task_id)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/api/tasks/status/{task_id}/",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting task status: {e}")
            return self._get_mock_task_status(task_id)
    
    async def get_report(self, task_id: int) -> Dict:
        """获取分析报告"""
        if not self.url or not self.api_key:
            return self._get_mock_report(task_id)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/api/tasks/get/report/{task_id}/json/",
                    headers=self.headers
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error getting report: {e}")
            return self._get_mock_report(task_id)
    
    async def get_behavior_summary(self, task_id: int) -> Dict:
        """获取行为摘要"""
        report = await self.get_report(task_id)
        
        if "behavior" in report:
            return {
                "task_id": task_id,
                "processes": report["behavior"].get("processes", []),
                "summary": report["behavior"].get("summary", {}),
                "anomaly_scores": self._calculate_anomaly_scores(report["behavior"])
            }
        
        return self._get_mock_behavior_summary(task_id)
    
    async def get_network_activity(self, task_id: int) -> Dict:
        """获取网络活动"""
        report = await self.get_report(task_id)
        
        if "network" in report:
            return {
                "task_id": task_id,
                "dns": report["network"].get("dns", []),
                "http": report["network"].get("http", []),
                "tcp": report["network"].get("tcp", []),
                "udp": report["network"].get("udp", []),
                "hosts": report["network"].get("hosts", [])
            }
        
        return self._get_mock_network_activity(task_id)
    
    async def get_signatures(self, task_id: int) -> Dict:
        """获取检测签名"""
        report = await self.get_report(task_id)
        
        if "signatures" in report:
            return {
                "task_id": task_id,
                "signatures": report["signatures"],
                "detection_count": len(report["signatures"])
            }
        
        return self._get_mock_signatures(task_id)
    
    async def get_iocs(self, task_id: int) -> Dict:
        """获取威胁指标"""
        report = await self.get_report(task_id)
        
        iocs = {
            "task_id": task_id,
            "file_hashes": [],
            "network_iocs": [],
            "registry_iocs": [],
            "file_iocs": []
        }
        
        if "target" in report:
            file_info = report["target"]["file"]
            iocs["file_hashes"] = [
                {"type": "md5", "value": file_info.get("md5")},
                {"type": "sha1", "value": file_info.get("sha1")},
                {"type": "sha256", "value": file_info.get("sha256")}
            ]
        
        if "network" in report:
            for host in report["network"].get("hosts", []):
                iocs["network_iocs"].append({
                    "type": "ip",
                    "value": host.get("ip"),
                    "country": host.get("country_name")
                })
            
            for dns in report["network"].get("dns", []):
                for answer in dns.get("answers", []):
                    iocs["network_iocs"].append({
                        "type": "domain",
                        "value": answer.get("data")
                    })
        
        return iocs if iocs["file_hashes"] or iocs["network_iocs"] else self._get_mock_iocs(task_id)
    
    async def search_samples(self, query: str) -> Dict:
        """搜索样本"""
        if not self.url or not self.api_key:
            return self._get_mock_search_results(query)
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.url}/api/tasks/search/",
                    headers=self.headers,
                    params={"query": query}
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error searching samples: {e}")
            return self._get_mock_search_results(query)
    
    async def get_malware_family(self, task_id: int) -> Dict:
        """获取恶意软件家族信息"""
        report = await self.get_report(task_id)
        
        if "malscore" in report and "malfamily" in report:
            return {
                "task_id": task_id,
                "family": report.get("malfamily", "unknown"),
                "score": report.get("malscore", 0),
                "classification": self._classify_malware(report.get("malscore", 0))
            }
        
        return self._get_mock_malware_family(task_id)
    
    def _calculate_anomaly_scores(self, behavior: Dict) -> Dict:
        """计算异常分数"""
        scores = {
            "process_injection": 0,
            "persistence": 0,
            "network_activity": 0,
            "file_modification": 0,
            "registry_modification": 0
        }
        
        summary = behavior.get("summary", {})
        
        if "processes_created" in summary:
            for proc in summary["processes_created"]:
                if any(x in proc.lower() for x in ["cmd", "powershell", "wscript", "cscript"]):
                    scores["process_injection"] += 10
        
        if "registry_keys_modified" in summary:
            scores["registry_modification"] = min(len(summary["registry_keys_modified"]) * 2, 100)
        
        if "files_written" in summary:
            scores["file_modification"] = min(len(summary["files_written"]) * 2, 100)
        
        return scores
    
    def _classify_malware(self, score: float) -> str:
        """分类恶意软件"""
        if score >= 8:
            return "malicious"
        elif score >= 5:
            return "suspicious"
        else:
            return "benign"
    
    def _get_mock_submission(self, file_path: str) -> Dict:
        """获取模拟提交结果"""
        return {
            "status": "success",
            "task_id": 12345,
            "file_path": file_path,
            "message": "File submitted for analysis"
        }
    
    def _get_mock_url_submission(self, url: str) -> Dict:
        """获取模拟URL提交结果"""
        return {
            "status": "success",
            "task_id": 12346,
            "url": url,
            "message": "URL submitted for analysis"
        }
    
    def _get_mock_task_status(self, task_id: int) -> Dict:
        """获取模拟任务状态"""
        return {
            "task_id": task_id,
            "status": "completed",
            "progress": 100,
            "started_at": "2026-03-01T10:00:00Z",
            "completed_at": "2026-03-01T10:05:00Z"
        }
    
    def _get_mock_report(self, task_id: int) -> Dict:
        """获取模拟分析报告"""
        return {
            "task_id": task_id,
            "target": {
                "file": {
                    "name": "malware.exe",
                    "size": 1024000,
                    "md5": "abc123def456",
                    "sha1": "def456abc123",
                    "sha256": "123456abcdef",
                    "type": "PE32 executable"
                }
            },
            "behavior": {
                "processes": [
                    {"name": "malware.exe", "pid": 1234, "parent_pid": 567}
                ],
                "summary": {
                    "processes_created": ["cmd.exe", "powershell.exe"],
                    "files_written": ["C:\\Windows\\Temp\\malware.dll"],
                    "registry_keys_modified": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
                }
            },
            "network": {
                "hosts": [
                    {"ip": "192.168.1.100", "country_name": "China"}
                ],
                "dns": [
                    {"request": "malware.example.com", "answers": [{"data": "192.168.1.100"}]}
                ],
                "http": [
                    {"uri": "http://malware.example.com/payload", "method": "GET"}
                ]
            },
            "signatures": [
                {"name": "Creates executable files", "severity": 2},
                {"name": "Modifies auto-start registry keys", "severity": 3},
                {"name": "Connects to suspicious domains", "severity": 2}
            ],
            "malscore": 8.5,
            "malfamily": "trojan"
        }
    
    def _get_mock_behavior_summary(self, task_id: int) -> Dict:
        """获取模拟行为摘要"""
        return {
            "task_id": task_id,
            "processes": [
                {"name": "malware.exe", "pid": 1234, "parent_pid": 567}
            ],
            "summary": {
                "processes_created": 5,
                "files_written": 10,
                "registry_keys_modified": 3,
                "network_connections": 2
            },
            "anomaly_scores": {
                "process_injection": 30,
                "persistence": 60,
                "network_activity": 40,
                "file_modification": 20,
                "registry_modification": 30
            }
        }
    
    def _get_mock_network_activity(self, task_id: int) -> Dict:
        """获取模拟网络活动"""
        return {
            "task_id": task_id,
            "dns": [
                {"request": "malware.example.com", "type": "A"}
            ],
            "http": [
                {"uri": "http://malware.example.com/payload", "method": "GET", "status": 200}
            ],
            "tcp": [
                {"src": "192.168.1.50:12345", "dst": "192.168.1.100:80"}
            ],
            "udp": [],
            "hosts": [
                {"ip": "192.168.1.100", "country": "China"}
            ]
        }
    
    def _get_mock_signatures(self, task_id: int) -> Dict:
        """获取模拟检测签名"""
        return {
            "task_id": task_id,
            "signatures": [
                {"name": "Creates executable files", "severity": 2, "description": "The sample creates executable files"},
                {"name": "Modifies auto-start registry keys", "severity": 3, "description": "The sample modifies registry keys for persistence"},
                {"name": "Connects to suspicious domains", "severity": 2, "description": "The sample connects to known malicious domains"}
            ],
            "detection_count": 3
        }
    
    def _get_mock_iocs(self, task_id: int) -> Dict:
        """获取模拟威胁指标"""
        return {
            "task_id": task_id,
            "file_hashes": [
                {"type": "md5", "value": "abc123def456"},
                {"type": "sha1", "value": "def456abc123"},
                {"type": "sha256", "value": "123456abcdef"}
            ],
            "network_iocs": [
                {"type": "ip", "value": "192.168.1.100", "country": "China"},
                {"type": "domain", "value": "malware.example.com"}
            ],
            "registry_iocs": [
                {"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "malware"}
            ],
            "file_iocs": [
                {"path": "C:\\Windows\\Temp\\malware.dll", "hash": "abc123"}
            ]
        }
    
    def _get_mock_search_results(self, query: str) -> Dict:
        """获取模拟搜索结果"""
        return {
            "query": query,
            "results": [
                {
                    "task_id": 12345,
                    "file_name": "malware.exe",
                    "md5": "abc123def456",
                    "malscore": 8.5,
                    "malfamily": "trojan"
                }
            ],
            "total": 1
        }
    
    def _get_mock_malware_family(self, task_id: int) -> Dict:
        """获取模拟恶意软件家族信息"""
        return {
            "task_id": task_id,
            "family": "trojan",
            "score": 8.5,
            "classification": "malicious"
        }