"""
玄鉴安全智能体 - VirusTotal病毒查杀工具
集成VirusTotal API进行文件威胁检测和IP/域名威胁情报查询
"""

import asyncio
import logging
import base64
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

from ..base_tool import BaseTool, ToolCategory, ToolMetadata, ToolResult

logger = logging.getLogger(__name__)


class VirusTotalFileScan(BaseModel):
    """文件扫描参数"""
    file_path: Optional[str] = Field(default=None, description="文件路径(本地文件)")
    file_data: Optional[str] = Field(default=None, description="Base64编码的文件数据")
    file_hash: Optional[str] = Field(default=None, description="文件Hash(MD5/SHA1/SHA256)")


class VirusTotalUrlScan(BaseModel):
    """URL扫描参数"""
    url: str = Field(..., description="待扫描的URL")


class VirusTotalIPQuery(BaseModel):
    """IP查询参数"""
    ip: str = Field(..., description="IP地址")


class VirusTotalDomainQuery(BaseModel):
    """域名查询参数"""
    domain: str = Field(..., description="域名")


class VirusTotalTool(BaseTool):
    """VirusTotal病毒检测工具"""
    
    metadata = ToolMetadata(
        name="virustotal",
        category=ToolCategory.THREAT_INTEL,
        description="VirusTotal病毒查杀和威胁情报查询，支持文件扫描、URL检测、IP和域名查询",
        version="1.0.0",
        author="玄鉴安全团队",
        tags=["antivirus", "malware", "scan"]
    )
    
    def __init__(self, api_key: str, base_url: str = "https://www.virustotal.com/api/v3"):
        """
        初始化VirusTotal工具
        
        Args:
            api_key: VirusTotal API Key
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
                timeout=60.0,
                headers={
                    "x-apikey": self.api_key,
                    "accept": "application/json"
                }
            )
        return self._client
    
    async def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        扫描本地文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            扫描结果
        """
        client = await self._get_client()
        url = f"{self.base_url}/files"
        
        try:
            with open(file_path, "rb") as f:
                files = {"file": f}
                response = await client.post(url, files=files)
                response.raise_for_status()
                
                # 获取分析ID
                data = response.json()
                analysis_id = data.get("data", {}).get("id")
                
                if analysis_id:
                    # 等待分析完成
                    return await self._wait_for_analysis(analysis_id)
                
                return data
                
        except Exception as e:
            logger.error(f"Scan file failed: {e}")
            raise
    
    async def upload_file_data(self, file_data: bytes, filename: str = "unknown") -> Dict[str, Any]:
        """
        上传文件数据进行扫描
        
        Args:
            file_data: 文件二进制数据
            filename: 文件名
            
        Returns:
            扫描结果
        """
        client = await self._get_client()
        url = f"{self.base_url}/files"
        
        try:
            files = {"file": (filename, file_data)}
            response = await client.post(url, files=files)
            response.raise_for_status()
            
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            
            if analysis_id:
                return await self._wait_for_analysis(analysis_id)
            
            return data
            
        except Exception as e:
            logger.error(f"Upload file data failed: {e}")
            raise
    
    async def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        获取文件分析报告（通过Hash）
        
        Args:
            file_hash: 文件Hash
            
        Returns:
            分析报告
        """
        client = await self._get_client()
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Get file report failed: {e}")
            return {}
    
    async def scan_url(self, url: str) -> Dict[str, Any]:
        """
        扫描URL
        
        Args:
            url: 待扫描的URL
            
        Returns:
            扫描结果
        """
        client = await self._get_client()
        
        # 先提交URL
        submit_url = f"{self.base_url}/urls"
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        try:
            # 提交URL
            response = await client.post(submit_url, data={"url": url})
            response.raise_for_status()
            
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            
            if analysis_id:
                return await self._wait_for_analysis(analysis_id)
            
            return data
            
        except Exception as e:
            logger.error(f"Scan URL failed: {e}")
            raise
    
    async def get_ip_report(self, ip: str) -> Dict[str, Any]:
        """
        获取IP地址威胁情报
        
        Args:
            ip: IP地址
            
        Returns:
            威胁情报
        """
        client = await self._get_client()
        url = f"{self.base_url}/ip_addresses/{ip}"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Get IP report failed: {e}")
            return {}
    
    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """
        获取域名威胁情报
        
        Args:
            domain: 域名
            
        Returns:
            威胁情报
        """
        client = await self._get_client()
        url = f"{self.base_url}/domains/{domain}"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Get domain report failed: {e}")
            return {}
    
    async def _wait_for_analysis(
        self,
        analysis_id: str,
        max_wait: int = 300,
        interval: int = 10
    ) -> Dict[str, Any]:
        """
        等待分析完成
        
        Args:
            analysis_id: 分析ID
            max_wait: 最大等待时间(秒)
            interval: 检查间隔(秒)
            
        Returns:
            分析结果
        """
        client = await self._get_client()
        url = f"{self.base_url}/analyses/{analysis_id}"
        
        waited = 0
        while waited < max_wait:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                
                status = data.get("data", {}).get("attributes", {}).get("status")
                
                if status == "completed":
                    # 获取文件报告
                    meta = data.get("meta", {})
                    file_info = meta.get("file_info", {})
                    file_id = file_info.get("sha256")
                    
                    if file_id:
                        return await self.get_file_report(file_id)
                    
                    return data
                elif status in ["queued", "in-progress"]:
                    await asyncio.sleep(interval)
                    waited += interval
                else:
                    logger.warning(f"Analysis status: {status}")
                    return data
                    
            except Exception as e:
                logger.error(f"Wait for analysis failed: {e}")
                break
        
        return {}
    
    async def execute(self, **kwargs) -> ToolResult:
        """
        执行病毒检测
        
        Args:
            **kwargs: 查询/扫描参数
            
        Returns:
            检测结果
        """
        try:
            # 判断操作类型
            file_scan = VirusTotalFileScan(**kwargs)
            start_time = datetime.now()
            
            result_data = {}
            
            # 优先根据Hash查询（最快）
            if file_scan.file_hash:
                result_data = await self.get_file_report(file_scan.file_hash)
                
                # 提取关键信息
                stats = result_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = stats.get("total", 0)
                
                # 构造结果
                result = {
                    "type": "file_report",
                    "hash_analysis": {
                        "hash": file_scan.file_hash,
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "total_engines": total,
                        "is_malicious": malicious > 0 or suspicious > 0,
                        "threat_ratio": (malicious + suspicious) / total if total > 0 else 0
                    },
                    "raw_data": result_data
                }
            
            # 本地文件扫描
            elif file_scan.file_path:
                result_data = await self.scan_file(file_scan.file_path)
                
                stats = result_data.get("data", {}).get("attributes", {}).get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = stats.get("confirmed-timeout", 0) + stats.get("failure", 0) + stats.get("harmless", 0) + stats.get("malicious", 0) + stats.get("suspicious", 0) + stats.get("timeout", 0) + stats.get("type-unsupported", 0)
                
                result = {
                    "type": "file_scan",
                    "file_path": file_scan.file_path,
                    "scan_result": {
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "total_engines": total,
                        "is_malicious": malicious > 0 or suspicious > 0
                    },
                    "raw_data": result_data
                }
            
            # Base64文件数据扫描
            elif file_scan.file_data:
                try:
                    file_bytes = base64.b64decode(file_scan.file_data)
                    result_data = await self.upload_file_data(file_bytes)
                    
                    stats = result_data.get("data", {}).get("attributes", {}).get("stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = stats.get("confirmed-timeout", 0) + stats.get("failure", 0) + stats.get("harmless", 0) + stats.get("malicious", 0) + stats.get("suspicious", 0)
                    
                    result = {
                        "type": "file_scan",
                        "scan_result": {
                            "malicious_count": malicious,
                            "suspicious_count": suspicious,
                            "total_engines": total,
                            "is_malicious": malicious > 0 or suspicious > 0
                        },
                        "raw_data": result_data
                    }
                except Exception as e:
                    return ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="INVALID_FILE_DATA",
                        error_message=f"文件数据解码失败: {e}"
                    )
            else:
                return ToolResult.error_result(
                    tool_name=self.metadata.name,
                    error_code="MISSING_PARAM",
                    error_message="必须提供file_path、file_data或file_hash之一"
                )
            
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ToolResult.success_result(
                tool_name=self.metadata.name,
                data=result,
                metadata={
                    "scan_type": result.get("type"),
                    "is_malicious": result.get("scan_result", {}).get("is_malicious", False),
                    "threat_engines": result.get("scan_result", {}).get("malicious_count", 0)
                }
            )
            
        except Exception as e:
            logger.error(f"Execute VirusTotal scan failed: {e}", exc_info=True)
            return ToolResult.error_result(
                tool_name=self.metadata.name,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                details={"kwargs": kwargs}
            )
    
    async def execute_url_scan(self, **kwargs) -> ToolResult:
        """
        执行URL扫描
        
        Args:
            **kwargs: URL扫描参数
            
        Returns:
            扫描结果
        """
        try:
            params = VirusTotalUrlScan(**kwargs)
            start_time = datetime.now()
            
            result_data = await self.scan_url(params.url)
            
            stats = result_data.get("data", {}).get("attributes", {}).get("stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = stats.get("confirmed-timeout", 0) + stats.get("harmless", 0) + stats.get("malicious", 0) + stats.get("suspicious", 0)
            
            result = {
                "type": "url_scan",
                "url": params.url,
                "scan_result": {
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "total_engines": total,
                    "is_malicious": malicious > 0 or suspicious > 0
                },
                "raw_data": result_data
            }
            
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ToolResult.success_result(
                tool_name=self.metadata.name,
                data=result,
                metadata={
                    "scan_type": "url_scan",
                    "is_malicious": result.get("scan_result", {}).get("is_malicious", False)
                }
            )
            
        except Exception as e:
            logger.error(f"Execute URL scan failed: {e}", exc_info=True)
            return ToolResult.error_result(
                tool_name=self.metadata.name,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                details={"kwargs": kwargs}
            )
    
    async def execute_ip_query(self, **kwargs) -> ToolResult:
        """
        执行IP威胁情报查询
        
        Args:
            **kwargs: IP查询参数
            
        Returns:
            查询结果
        """
        try:
            params = VirusTotalIPQuery(**kwargs)
            start_time = datetime.now()
            
            result_data = await self.get_ip_report(params.ip)
            
            stats = result_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            result = {
                "type": "ip_intelligence",
                "ip": params.ip,
                "threat_intel": {
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "is_malicious": malicious > 0 or suspicious > 0
                },
                "raw_data": result_data
            }
            
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ToolResult.success_result(
                tool_name=self.metadata.name,
                data=result,
                metadata={
                    "query_type": "ip_intelligence",
                    "is_malicious": result.get("threat_intel", {}).get("is_malicious", False)
                }
            )
            
        except Exception as e:
            logger.error(f"Execute IP query failed: {e}", exc_info=True)
            return ToolResult.error_result(
                tool_name=self.metadata.name,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                details={"kwargs": kwargs}
            )
    
    async def execute_domain_query(self, **kwargs) -> ToolResult:
        """
        执行域名威胁情报查询
        
        Args:
            **kwargs: 域名查询参数
            
        Returns:
            查询结果
        """
        try:
            params = VirusTotalDomainQuery(**kwargs)
            start_time = datetime.now()
            
            result_data = await self.get_domain_report(params.domain)
            
            stats = result_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            result = {
                "type": "domain_intelligence",
                "domain": params.domain,
                "threat_intel": {
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "is_malicious": malicious > 0 or suspicious > 0
                },
                "raw_data": result_data
            }
            
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return ToolResult.success_result(
                tool_name=self.metadata.name,
                data=result,
                metadata={
                    "query_type": "domain_intelligence",
                    "is_malicious": result.get("threat_intel", {}).get("is_malicious", False)
                }
            )
            
        except Exception as e:
            logger.error(f"Execute domain query failed: {e}", exc_info=True)
            return ToolResult.error_result(
                tool_name=self.metadata.name,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                details={"kwargs": kwargs}
            )
    
    async def close(self):
        """关闭HTTP客户端"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
