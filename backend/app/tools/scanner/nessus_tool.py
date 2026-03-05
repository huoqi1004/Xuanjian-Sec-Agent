"""
玄鉴安全智能体 - Nessus漏洞扫描工具
集成Nessus API进行企业级漏洞扫描
"""

import asyncio
import logging
import base64
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

from ..base_tool import BaseTool, ToolCategory, ToolMetadata, ToolResult, RiskLevel

logger = logging.getLogger(__name__)


class NessusScanParams(BaseModel):
    """Nessus扫描参数"""
    policy_id: Optional[int] = Field(default=None, description="扫描策略ID")
    scanner_id: Optional[int] = Field(default=None, description="扫描器ID")
    targets: List[str] = Field(..., description="扫描目标列表(IP/域名)")
    scan_name: str = Field(default="XuanJian Scan", description="扫描名称")
    description: Optional[str] = Field(default=None, description="扫描描述")


class NessusLaunchParams(BaseModel):
    """Nessus启动参数"""
    scan_id: int = Field(..., description="扫描ID")


class NessusTool(BaseTool):
    """Nessus漏洞扫描工具"""
    
    metadata = ToolMetadata(
        name="nessus",
        category=ToolCategory.SCANNER,
        description="Nessus企业级漏洞扫描工具，支持漏洞发现和风险评估",
        version="1.0.0",
        author="玄鉴安全团队",
        tags=["vulnerability-scan", "security-audit"],
        risk_level=RiskLevel.HIGH,
        requires_approval=True
    )
    
    def __init__(self, url: str, access_key: str, secret_key: str):
        """
        初始化Nessus工具
        
        Args:
            url: Nessus服务器地址
            access_key: 访问密钥
            secret_key: 秘密密钥
        """
        super().__init__()
        self.url = url.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self._session: Optional[Dict[str, str]] = None
        self._client: Optional[httpx.AsyncClient] = None
    
    def _get_headers(self) -> Dict[str, str]:
        """获取请求头"""
        headers = {
            "Content-Type": "application/json",
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}"
        }
        
        if self._session:
            headers["X-Cookie"] = f"token={self._session['token']}"
        
        return headers
    
    async def _get_client(self) -> httpx.AsyncClient:
        """获取HTTP客户端"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=120.0,
                headers=self._get_headers()
            )
        return self._client
    
    async def login(self) -> bool:
        """
        登录Nessus
        
        Returns:
            是否成功
        """
        client = await self._get_client()
        url = f"{self.url}/session"
        
        try:
            # 对于API key，直接建立会话
            response = await client.post(url, json={
                "username": self.access_key,
                "password": self.secret_key
            })
            
            if response.status_code == 200:
                token = response.cookies.get("token")
                if token:
                    self._session = {"token": str(token)}
                    return True
            
            # API Key方式不需要登录
            return True
            
        except Exception as e:
            logger.error(f"Login failed: {e}")
            return False
    
    async def create_scan(self, params: NessusScanParams) -> Optional[int]:
        """
        创建扫描任务
        
        Args:
            params: 扫描参数
            
        Returns:
            扫描ID
        """
        client = await self._get_client()
        url = f"{self.url}/scans"
        
        scan_data = {
            "uuid": "adinab701eafa6bd48e29375796390e5e1f47295b5085d7710",  # 基础网络扫描模板UUID
            "settings": {
                "name": params.scan_name,
                "text_targets": ",".join(params.targets),
                "launch_now": False
            }
        }
        
        if params.description:
            scan_data["settings"]["description"] = params.description
        
        try:
            response = await client.post(url, json=scan_data)
            response.raise_for_status()
            
            data = response.json()
            scanner_id = data.get("scan", {}).get("id")
            
            if scanner_id:
                logger.info(f"Created scan {scanner_id}")
                return scanner_id
            
            return None
            
        except Exception as e:
            logger.error(f"Create scan failed: {e}")
            raise
    
    async def launch_scan(self, scan_id: int) -> bool:
        """
        启动扫描
        
        Args:
            scan_id: 扫描ID
            
        Returns:
            是否成功
        """
        client = await self._get_client()
        url = f"{self.url}/scans/{scan_id}/launch"
        
        try:
            response = await client.post(url)
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Launch scan failed: {e}")
            return False
    
    async def get_scan_status(self, scan_id: int) -> Dict[str, Any]:
        """
        获取扫描状态
        
        Args:
            scan_id: 扫描ID
            
        Returns:
            扫描状态
        """
        client = await self._get_client()
        url = f"{self.url}/scans/{scan_id}"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Get scan status failed: {e}")
            raise
    
    async def get_scan_results(self, scan_id: int) -> Dict[str, Any]:
        """
        获取扫描结果
        
        Args:
            scan_id: 扫描ID
            
        Returns:
            扫描结果
        """
        client = await self._get_client()
        url = f"{self.url}/scans/{scan_id}"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Get scan results failed: {e}")
            raise
    
    async def delete_scan(self, scan_id: int) -> bool:
        """
        删除扫描
        
        Args:
            scan_id: 扫描ID
            
        Returns:
            是否成功
        """
        client = await self._get_client()
        url = f"{self.url}/scans/{scan_id}"
        
        try:
            response = await client.delete(url)
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Delete scan failed: {e}")
            return False
    
    async def execute(self, **kwargs) -> ToolResult:
        """
        执行扫描
        
        Args:
            **kwargs: 扫描参数
            
        Returns:
            扫描结果
        """
        try:
            params = NessusScanParams(**kwargs)
            start_time = datetime.now()
            
            # 创建扫描
            scan_id = await self.create_scan(params)
            
            if not scan_id:
                return ToolResult.error_result(
                    tool_name=self.metadata.name,
                    error_code="CREATE_SCAN_FAILED",
                    error_message="创建扫描任务失败"
                )
            
            # 启动扫描
            if not await self.launch_scan(scan_id):
                return ToolResult.error_result(
                    tool_name=self.metadata.name,
                    error_code="LAUNCH_SCAN_FAILED",
                    error_message="启动扫描任务失败"
                )
            
            # 等待扫描完成
            logger.info(f"Waiting for scan {scan_id} to complete...")
            
            max_wait = 3600  # 1小时超时
            wait_interval = 30
            waited = 0
            
            while waited < max_wait:
                await asyncio.sleep(wait_interval)
                waited += wait_interval
                
                status_data = await self.get_scan_status(scan_id)
                scan_info = status_data.get("scan", {})
                status = scan_info.get("status", "").lower()
                
                if status == "completed":
                    logger.info(f"Scan {scan_id} completed")
                    break
                elif status in ["processing", "running"]:
                    logger.info(f"Scan {scan_id} is {status} ({waited}s)")
                else:
                    logger.warning(f"Scan {scan_id} status: {status}")
            
            # 获取结果
            result_data = await self.get_scan_results(scan_id)
            
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            # 整理结果
            scan_info = result_data.get("scan", {})
            vulnerabilities = scan_info.get("vulnerabilities", [])
            
            # 统计漏洞
            vuln_stats = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
            
            for vuln in vulnerabilities:
                severity = vuln.get("severity", 0)
                if severity == 4:
                    vuln_stats["critical"] += 1
                elif severity == 3:
                    vuln_stats["high"] += 1
                elif severity == 2:
                    vuln_stats["medium"] += 1
                elif severity == 1:
                    vuln_stats["low"] += 1
                else:
                    vuln_stats["info"] += 1
            
            result = {
                "scan_id": scan_id,
                "scan_name": scan_info.get("name"),
                "status": scan_info.get("status"),
                "targets": params.targets,
                "vulnerability_summary": vuln_stats,
                "total_vulnerabilities": len(vulnerabilities),
                "scan_details": scan_info
            }
            
            return ToolResult.success_result(
                tool_name=self.metadata.name,
                data=result,
                duration_ms=duration_ms,
                metadata={
                    "scan_id": scan_id,
                    "total_vulns": len(vulnerabilities),
                    "critical_vulns": vuln_stats["critical"]
                }
            )
            
        except Exception as e:
            logger.error(f"Execute Nessus scan failed: {e}", exc_info=True)
            return ToolResult.error_result(
                tool_name=self.metadata.name,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                details={"kwargs": kwargs}
            )
    
    async def list_scans(self) -> List[Dict[str, Any]]:
        """
        列出所有扫描
        
        Returns:
            扫描列表
        """
        client = await self._get_client()
        url = f"{self.url}/scans"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("scans", [])
        except Exception as e:
            logger.error(f"List scans failed: {e}")
            return []
    
    async def close(self):
        """关闭HTTP客户端"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
