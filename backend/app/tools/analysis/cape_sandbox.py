"""
玄鉴安全智能体 - CAPE沙箱恶意代码分析工具
集成CAPE沙箱进行恶意代码动态分析
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


class CAPESubmitParams(BaseModel):
    """CAPE提交参数"""
    file_path: Optional[str] = Field(default=None, description="文件路径")
    file_data: Optional[str] = Field(default=None, description="Base64编码的文件数据")
    url: Optional[str] = Field(default=None, description="URL")
    timeout: int = Field(default=120, description="分析超时时间(秒)")
    priority: int = Field(default=1, description="任务优先级(1-3)")
    options: Optional[str] = Field(default=None, description="分析选项")
    machine: Optional[str] = Field(default=None, description="指定机器标签")


class CAPEResultParams(BaseModel):
    """CAPE结果参数"""
    task_id: int = Field(..., description="任务ID")
    details: bool = Field(default=True, description="是否获取详细信息")


class CAPETaskInfo(BaseModel):
    """CAPE任务信息"""
    task_id: int = Field(..., description="任务ID")
    status: str = Field(default="pending", description="任务状态")
    completed: bool = Field(default=False, description="是否完成")
    score: Optional[int] = Field(default=None, description="恶意分数")
    target: Optional[str] = Field(default=None, description="目标文件/URL")


class CAPESandboxTool(BaseTool):
    """CAPE沙箱恶意代码分析工具"""
    
    metadata = ToolMetadata(
        name="cape_sandbox",
        category=ToolCategory.ANALYSIS,
        description="CAPE沙箱恶意代码分析工具，支持恶意软件动态分析",
        version="1.0.0",
        author="玄鉴安全团队",
        tags=["malware", "sandbox", "dynamic-analysis"],
        risk_level=RiskLevel.CRITICAL,
        requires_approval=True
    )
    
    def __init__(self, api_url: str, api_key: str):
        """
        初始化CAPE沙箱工具
        
        Args:
            api_url: CAPE API地址
            api_key: API密钥
        """
        super().__init__()
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None
    
    def _get_client(self) -> httpx.AsyncClient:
        """获取HTTP客户端"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=300.0,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
            )
        return self._client
    
    async def submit(self, params: CAPESubmitParams) -> Optional[int]:
        """
        提交分析任务
        
        Args:
            params: 提交参数
            
        Returns:
            任务ID
        """
        client = self._get_client()
        url = f"{self.api_url}/api/tasks/create"
        
        try:
            # 上传文件
            if params.file_path or params.file_data:
                if params.file_data:
                    file_bytes = base64.b64decode(params.file_data)
                elif params.file_path:
                    with open(params.file_path, "rb") as f:
                        file_bytes = f.read()
                else:
                    logger.error("No file path or data provided")
                    return None
                
                files = {"file": ("unknown", file_bytes)}
                data: Dict[str, Any] = {
                    "timeout": params.timeout,
                    "priority": params.priority
                }
                
                if params.options:
                    data["options"] = params.options
                if params.machine:
                    data["machine"] = params.machine
                
                response = await client.post(url, files=files, data=data)
            
            # 提交URL
            elif params.url:
                response = await client.post(url, json={
                    "url": params.url,
                    "timeout": params.timeout,
                    "priority": params.priority
                })
            
            else:
                logger.error("No file or URL provided")
                return None
            
            response.raise_for_status()
            result = response.json()
            
            task_id = result.get("task_id")
            if task_id:
                logger.info(f"Created CAPE task {task_id}")
                return task_id
            
            return None
            
        except Exception as e:
            logger.error(f"Submit CAP task failed: {e}")
            raise
    
    async def get_task_info(self, task_id: int) -> Dict[str, Any]:
        """
        获取任务信息
        
        Args:
            task_id: 任务ID
            
        Returns:
            任务信息
        """
        client = self._get_client()
        url = f"{self.api_url}/api/tasks/{task_id}"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Get task info failed: {e}")
            raise
    
    async def wait_for_completion(
        self,
        task_id: int,
        max_wait: int = 600,
        check_interval: int = 10
    ) -> Dict[str, Any]:
        """
        等待任务完成
        
        Args:
            task_id: 任务ID
            max_wait: 最大等待时间(秒)
            check_interval: 检查间隔(秒)
            
        Returns:
            任务结果
        """
        waited = 0
        while waited < max_wait:
            try:
                task_info = await self.get_task_info(task_id)
                status = task_info.get("status", "").lower()
                
                if status == "completed" or status == "reported":
                    return task_info
                elif status == "failed" or status == "error":
                    logger.error(f"Task {task_id} failed")
                    return task_info
                else:
                    await asyncio.sleep(check_interval)
                    waited += check_interval
                    
            except Exception as e:
                logger.error(f"Wait for task {task_id} failed: {e}")
                break
        
        return {"task_id": task_id, "status": "timeout", "error": "Task timed out"}
    
    async def get_result(self, params: CAPEResultParams) -> Dict[str, Any]:
        """
        获取分析结果
        
        Args:
            params: 结果参数
            
        Returns:
            分析结果
        """
        client = self._get_client()
        
        endpoint = "info" if params.details else "simple"
        url = f"{self.api_url}/api/tasks/{params.task_id}/{endpoint}"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Get result failed: {e}")
            raise
    
    async def get_report(self, task_id: int, report_type: str = "summary") -> Dict[str, Any]:
        """
        获取分析报告
        
        Args:
            task_id: 任务ID
            report_type: 报告类型(summary/json/html/pdf)
            
        Returns:
            分析报告
        """
        client = self._get_client()
        url = f"{self.api_url}/api/tasks/{task_id}/report/{report_type}"
        
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Get report failed: {e}")
            raise
    
    async def execute(self, **kwargs) -> ToolResult:
        """
        执行沙箱分析
        
        Args:
            **kwargs: 分析参数
            
        Returns:
            分析结果
        """
        try:
            params = CAPESubmitParams(**kwargs)
            action = kwargs.get("action", "submit")
            start_time = datetime.now()
            
            result_data = {}
            
            if action == "submit":
                # 提交任务
                task_id = await self.submit(params)
                
                if not task_id:
                    return ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="SUBMIT_FAILED",
                        error_message="提交分析任务失败"
                    )
                
                # 等待完成
                logger.info(f"Waiting for CAPE task {task_id} to complete...")
                task_info = await self.wait_for_completion(task_id)
                
                # 获取结果
                result_params = CAPEResultParams(task_id=task_id, details=True)
                result_data = await self.get_result(result_params)
                
                # 提取关键信息
                malware_info = result_data.get("malscore", {})
                score = malware_info.get("score", -1)
                
                result = {
                    "task_id": task_id,
                    "status": task_info.get("status"),
                    "score": score,
                    "is_malicious": score >= 5,
                    "target": task_info.get("target", ""),
                    "analysis": result_data
                }
                
            elif action == "get_info":
                task_id = kwargs.get("task_id")
                if not task_id:
                    return ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="MISSING_PARAM",
                        error_message="task_id参数缺失"
                    )
                result_data = await self.get_task_info(task_id)
                
            elif action == "get_report":
                task_id = kwargs.get("task_id")
                if not task_id:
                    return ToolResult.error_result(
                        tool_name=self.metadata.name,
                        error_code="MISSING_PARAM",
                        error_message="task_id参数缺失"
                    )
                report_type = kwargs.get("report_type", "summary")
                result_data = await self.get_report(task_id, report_type)
                
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
                    "action": action,
                    "task_id": kwargs.get("task_id")
                }
            )
            
        except Exception as e:
            logger.error(f"Execute CAPE analysis failed: {e}", exc_info=True)
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
