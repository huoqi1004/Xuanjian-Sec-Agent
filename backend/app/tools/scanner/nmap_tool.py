"""
玄鉴安全智能体 - Nmap内网扫描工具
集成Nmap进行内网主机发现、端口扫描和服务枚举
"""

import asyncio
import logging
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional, cast

from pydantic import BaseModel, Field

from ..base_tool import BaseTool, ToolCategory, ToolMetadata, ToolResult, RiskLevel

logger = logging.getLogger(__name__)


class NmapScanType:
    """Nmap扫描类型"""
    PING_SCAN = "-sn"  # Ping扫描
    FAST_SCAN = "-F"  # 快速扫描
    VERSION_DETECT = "-sV"  # 版本检测
    OS_DETECT = "-O"  # 操作系统检测
    AGGRESSIVE = "-A"  # 激进扫描
    UDP_SCAN = "-sU"  # UDP扫描
    SCRIPT_SCAN = "--script"  # 脚本扫描


class NmapScanParams(BaseModel):
    """Nmap扫描参数"""
    target: str = Field(..., description="扫描目标(IP/主机名/网段)")
    scan_type: str = Field(default="-sV", description="扫描类型")
    ports: Optional[str] = Field(default=None, description="指定端口(如: 22,80,443 或 1-1000)")
    max_retries: int = Field(default=3, description="最大重试次数")
    timing: int = Field(default=4, description="时间模板(0-5, 5最快)")
    output_format: str = Field(default="xml", description="输出格式(xml/grepable/normal)")


class NmapTarget(BaseModel):
    """扫描目标"""
    ip: str = Field(..., description="IP地址")
    hostname: Optional[str] = Field(default=None, description="主机名")
    state: str = Field(default="", description="状态(up/down)")
    open_ports: List[str] = Field(default_factory=list, description="开放的端口")
    services: Dict[str, str] = Field(default_factory=dict, description="服务信息")
    os_guess: Optional[str] = Field(default=None, description="操作系统推测")


class NmapTool(BaseTool):
    """Nmap内网扫描工具"""
    
    metadata = ToolMetadata(
        name="nmap",
        category=ToolCategory.SCANNER,
        description="Nmap内网扫描工具，支持主机发现、端口扫描、服务枚举和OS检测",
        version="1.0.0",
        author="玄鉴安全团队",
        tags=["scanner", "network", "port-scan"],
        risk_level=RiskLevel.MEDIUM
    )
    
    def __init__(self, nmap_path: str = "nmap"):
        """
        初始化Nmap工具
        
        Args:
            nmap_path: Nmap可执行文件路径
        """
        super().__init__()
        self.nmap_path = nmap_path
    
    def _build_nmap_command(self, params: NmapScanParams) -> List[str]:
        """
        构建Nmap命令
        
        Args:
            params: 扫描参数
            
        Returns:
            命令列表
        """
        cmd = [self.nmap_path]
        
        # 添加扫描类型
        if params.scan_type:
            cmd.extend(params.scan_type.split())
        
        # 添加端口范围
        if params.ports:
            cmd.extend(["-p", params.ports])
        
        # 添加时间模板
        if 0 <= params.timing <= 5:
            cmd.extend([f"-T{params.timing}"])
        
        # 添加重试次数
        cmd.extend([f"--max-retries={params.max_retries}"])
        
        # 添加输出格式
        if params.output_format == "xml":
            cmd.extend(["-oX", "-"])  # 输出到stdout
        elif params.output_format == "grepable":
            cmd.extend(["-oG", "-"])
        
        # 添加目标
        cmd.append(params.target)
        
        return cmd
    
    def _parse_nmap_xml_output(self, xml_output: str) -> Dict[str, Any]:
        """
        解析Nmap XML输出
        
        Args:
            xml_output: Nmap XML输出
            
        Returns:
            解析结果
        """
        try:
            import xml.etree.ElementTree as ET
            
            root = ET.fromstring(xml_output)
            hosts = []
            
            for host in root.findall(".//host"):
                host_data = {}
                
                # 获取IP地址
                address = host.find(".//address[@addrtype='ipv4']")
                if address is not None:
                    host_data["ip"] = address.get("addr")
                
                # 获取主机名
                hostname = host.find(".//hostname")
                if hostname is not None:
                    host_data["hostname"] = hostname.get("name")
                
                # 获取状态
                status = host.find(".//status")
                if status is not None:
                    host_data["state"] = status.get("state")
                
                # 如果主机是up状态，解析端口
                if host_data.get("state") == "up":
                    ports = host.find(".//ports")
                    if ports is not None:
                        open_ports = []
                        services = {}
                        
                        for port in ports.findall(".//port"):
                            if port.get("protocol") == "tcp":
                                state = port.find(".//state")
                                if state is not None and state.get("state") == "open":
                                    port_id = port.get("portid")
                                    protocol = port.get("protocol")
                                    port_str = f"{port_id}/{protocol}"
                                    open_ports.append(port_str)
                                    
                                    # 获取服务信息
                                    service = port.find(".//service")
                                    if service is not None:
                                        service_name = service.get("name", "")
                                        service_version = service.get("version", "")
                                        service_product = service.get("product", "")
                                        service_info = f"{service_name}"
                                        if service_product:
                                            service_info += f" {service_product}"
                                        if service_version:
                                            service_info += f" {service_version}"
                                        services[port_str] = service_info
                        
                        host_data["open_ports"] = open_ports
                        host_data["services"] = services
                
                # 获取操作系统信息
                os_elem = host.find(".//os")
                if os_elem is not None:
                    osmatch = os_elem.find(".//osmatch[@accuracy]")
                    if osmatch is not None:
                        host_data["os_guess"] = osmatch.get("name")
                
                if host_data:
                    hosts.append(host_data)
            
            return {"hosts": hosts}
            
        except Exception as e:
            logger.error(f"Parse Nmap XML failed: {e}")
            return {"hosts": [], "parse_error": str(e)}
    
    def _parse_nmap_output(self, output: str, format_type: str) -> Dict[str, Any]:
        """
        解析Nmap输出
        
        Args:
            output: Nmap输出
            format_type: 输出格式类型
            
        Returns:
            解析结果
        """
        if format_type == "xml":
            return self._parse_nmap_xml_output(output)
        else:
            # 简单解析非XML输出
            lines = output.split('\n')
            hosts: List[Dict[str, Any]] = []
            current_host: Optional[Dict[str, Any]] = None
            
            for line in lines:
                if "Nmap scan report for" in line:
                    if current_host is not None:
                        hosts.append(current_host)
                    current_host = {"services": {}}
                    # 提取IP
                    parts = line.split()
                    if len(parts) > 5:
                        current_host["ip"] = parts[-1].strip("()")
                elif current_host and "PORT" in line and "STATE" in line and "SERVICE" in line:
                    continue
                elif current_host and ("/tcp" in line or "/udp" in line):
                    parts = line.split()
                    if len(parts) >= 3:
                        port = parts[0]
                        state = parts[1]
                        service = " ".join(parts[2:])
                        if state == "open":
                            if current_host and "open_ports" not in current_host:
                                current_host["open_ports"] = []
                            if current_host and "open_ports" in current_host:
                                current_host["open_ports"].append(port)
                            if current_host and "services" in current_host:
                                current_host["services"][port] = service
            
            if current_host is not None:
                hosts.append(current_host)
            
            return {"hosts": hosts}
    
    async def scan(self, params: NmapScanParams) -> Dict[str, Any]:
        """
        执行扫描
        
        Args:
            params: 扫描参数
            
        Returns:
            扫描结果
        """
        cmd = self._build_nmap_command(params)
        logger.info(f"Executing Nmap scan: {' '.join(cmd)}")
        
        try:
            # 使用subprocess执行Nmap
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=600  # 10分钟超时
            )
            
            if process.returncode != 0:
                error_msg = stderr.decode('utf-8', errors='ignore')
                logger.error(f"Nmap scan failed: {error_msg}")
                return {
                    "success": False,
                    "error": error_msg,
                    "returncode": process.returncode
                }
            
            output = stdout.decode('utf-8', errors='ignore')
            
            # 解析输出
            parsed = self._parse_nmap_output(output, params.output_format)
            
            return {
                "success": True,
                "command": " ".join(cmd),
                "hosts": parsed.get("hosts", []),
                "raw_output": output
            }
            
        except asyncio.TimeoutError:
            logger.error("Nmap scan timed out")
            return {
                "success": False,
                "error": "Scan timed out"
            }
        except FileNotFoundError:
            logger.error(f"Nmap not found at {self.nmap_path}")
            return {
                "success": False,
                "error": f"Nmap executable not found at {self.nmap_path}"
            }
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }
    
    async def execute(self, **kwargs) -> ToolResult:
        """
        执行扫描
        
        Args:
            **kwargs: 扫描参数
            
        Returns:
            扫描结果
        """
        try:
            params = NmapScanParams(**kwargs)
            start_time = datetime.now()
            
            result_data = await self.scan(params)
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            
            if not result_data.get("success"):
                return ToolResult.error_result(
                    tool_name=self.metadata.name,
                    error_code="SCAN_FAILED",
                    error_message=result_data.get("error", "扫描失败"),
                    details={"target": params.target, "scan_type": params.scan_type}
                )
            
            # 统计信息
            hosts = result_data.get("hosts", [])
            total_hosts = len(hosts)
            total_open_ports = sum(len(h.get("open_ports", [])) for h in hosts)
            online_hosts = len([h for h in hosts if h.get("state") == "up"])
            
            result = {
                "target": params.target,
                "scan_type": params.scan_type,
                "summary": {
                    "total_hosts": total_hosts,
                    "online_hosts": online_hosts,
                    "total_open_ports": total_open_ports
                },
                "hosts": hosts,
                "command": result_data.get("command", "")
            }
            
            return ToolResult.success_result(
                tool_name=self.metadata.name,
                data=result,
                duration_ms=duration_ms,
                metadata={
                    "target": params.target,
                    "online_hosts": online_hosts,
                    "open_ports": total_open_ports
                }
            )
            
        except Exception as e:
            logger.error(f"Execute Nmap scan failed: {e}", exc_info=True)
            return ToolResult.error_result(
                tool_name=self.metadata.name,
                error_code="EXECUTION_ERROR",
                error_message=str(e),
                details={"kwargs": kwargs}
            )
    
    async def ping_sweep(self, network: str) -> ToolResult:
        """
        Ping扫描（主机发现）
        
        Args:
            network: 网络段(如: 192.168.1.0/24)
            
        Returns:
            扫描结果
        """
        return await self.execute(
            target=network,
            scan_type="-sn",
            output_format="xml"
        )
    
    async def port_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        detect_version: bool = True
    ) -> ToolResult:
        """
        端口扫描
        
        Args:
            target: 目标
            ports: 指定端口
            detect_version: 是否检测版本
            
        Returns:
            扫描结果
        """
        scan_type = "-sV" if detect_version else "-sS"
        
        return await self.execute(
            target=target,
            scan_type=scan_type,
            ports=ports,
            output_format="xml"
        )
    
    async def os_detection(self, target: str) -> ToolResult:
        """
        操作系统检测
        
        Args:
            target: 目标
            
        Returns:
            检测结果
        """
        return await self.execute(
            target=target,
            scan_type="-O",
            output_format="xml"
        )
    
    async def aggressive_scan(self, target: str) -> ToolResult:
        """
        激进扫描（包含版本检测、OS检测、脚本扫描等）
        
        Args:
            target: 目标
            
        Returns:
            扫描结果
        """
        return await self.execute(
            target=target,
            scan_type="-A",
            output_format="xml"
        )
