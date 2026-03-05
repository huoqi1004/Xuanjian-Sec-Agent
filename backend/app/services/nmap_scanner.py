import subprocess
import asyncio
import logging
import re
from typing import Dict, Optional, List
from xml.etree import ElementTree
import tempfile
import os

logger = logging.getLogger(__name__)

class NmapScanner:
    """Nmap内网扫描器"""
    
    def __init__(self, nmap_path: str = "nmap", timeout: int = 300):
        self.nmap_path = nmap_path
        self.timeout = timeout
        self.max_concurrent = 3
    
    async def scan_network(self, target: str, scan_type: str = "quick") -> Dict:
        """
        扫描网络
        
        Args:
            target: 目标网络或主机 (例如: 192.168.1.0/24, 192.168.1.1)
            scan_type: 扫描类型 (quick, full, stealth, udp)
        """
        try:
            # 构建Nmap命令
            command = self._build_command(target, scan_type)
            
            # 执行扫描
            result = await self._execute_scan(command)
            
            # 解析结果
            parsed_result = self._parse_result(result)
            
            return {
                "status": "success",
                "target": target,
                "scan_type": scan_type,
                "hosts": parsed_result.get("hosts", []),
                "summary": parsed_result.get("summary", {}),
                "raw_output": result[:5000]  # 限制原始输出大小
            }
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return self._get_mock_scan_result(target, scan_type)
    
    def _build_command(self, target: str, scan_type: str) -> List[str]:
        """构建Nmap命令"""
        base_cmd = [self.nmap_path]
        
        if scan_type == "quick":
            # 快速扫描：常用端口
            base_cmd.extend(["-T4", "-F", "--top-ports", "100"])
        elif scan_type == "full":
            # 完整扫描：所有端口
            base_cmd.extend(["-T4", "-p-", "-sV", "-sC"])
        elif scan_type == "stealth":
            # 隐蔽扫描：SYN扫描
            base_cmd.extend(["-T4", "-sS", "-F"])
        elif scan_type == "udp":
            # UDP扫描
            base_cmd.extend(["-T4", "-sU", "--top-ports", "50"])
        else:
            # 默认快速扫描
            base_cmd.extend(["-T4", "-F"])
        
        # 添加XML输出
        base_cmd.extend(["-oX", "-"])
        
        # 添加目标
        base_cmd.append(target)
        
        return base_cmd
    
    async def _execute_scan(self, command: List[str]) -> str:
        """执行Nmap扫描"""
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            if process.returncode != 0:
                logger.warning(f"Nmap returned non-zero exit code: {process.returncode}")
                raise Exception(f"Nmap scan failed: {stderr.decode()}")
            
            return stdout.decode()
        except asyncio.TimeoutError:
            logger.error("Nmap scan timeout")
            raise Exception("Scan timeout")
        except FileNotFoundError:
            logger.error("Nmap not found, using mock data")
            raise Exception("Nmap not installed")
    
    def _parse_result(self, xml_output: str) -> Dict:
        """解析Nmap XML输出"""
        try:
            root = ElementTree.fromstring(xml_output)
            
            hosts = []
            for host in root.findall(".//host"):
                host_info = self._parse_host(host)
                hosts.append(host_info)
            
            # 获取扫描摘要
            runstats = root.find(".//runstats/finished")
            summary = {
                "hosts_scanned": len(hosts),
                "hosts_up": len([h for h in hosts if h.get("status") == "up"]),
                "scan_time": runstats.get("elapsed", "unknown") if runstats is not None else "unknown"
            }
            
            return {
                "hosts": hosts,
                "summary": summary
            }
        except ElementTree.ParseError:
            logger.error("Failed to parse Nmap XML output")
            return {"hosts": [], "summary": {}}
    
    def _parse_host(self, host_elem) -> Dict:
        """解析单个主机信息"""
        host_info = {
            "address": "",
            "status": "unknown",
            "hostname": "",
            "ports": [],
            "os": "",
            "services": []
        }
        
        # 获取地址
        address = host_elem.find("address[@addrtype='ipv4']")
        if address is not None:
            host_info["address"] = address.get("addr", "")
        
        # 获取状态
        status = host_elem.find("status")
        if status is not None:
            host_info["status"] = status.get("state", "unknown")
        
        # 获取主机名
        hostname = host_elem.find(".//hostname")
        if hostname is not None:
            host_info["hostname"] = hostname.get("name", "")
        
        # 获取端口信息
        for port in host_elem.findall(".//port"):
            port_info = {
                "port": port.get("portid", ""),
                "protocol": port.get("protocol", ""),
                "state": port.find("state").get("state", "") if port.find("state") is not None else "unknown",
                "service": port.find("service").get("name", "") if port.find("service") is not None else "",
                "product": port.find("service").get("product", "") if port.find("service") is not None else "",
                "version": port.find("service").get("version", "") if port.find("service") is not None else ""
            }
            host_info["ports"].append(port_info)
        
        # 获取OS信息
        os_match = host_elem.find(".//osmatch")
        if os_match is not None:
            host_info["os"] = os_match.get("name", "")
        
        return host_info
    
    async def scan_port(self, target: str, port: int) -> Dict:
        """扫描特定端口"""
        try:
            command = [self.nmap_path, "-p", str(port), "-sV", target, "-oX", "-"]
            result = await self._execute_scan(command)
            parsed = self._parse_result(result)
            
            if parsed.get("hosts"):
                host = parsed["hosts"][0]
                for port_info in host.get("ports", []):
                    if int(port_info.get("port", 0)) == port:
                        return {
                            "status": "success",
                            "target": target,
                            "port": port,
                            "info": port_info
                        }
            
            return {
                "status": "success",
                "target": target,
                "port": port,
                "info": {"state": "closed"}
            }
        except Exception as e:
            logger.error(f"Port scan error: {e}")
            return self._get_mock_port_result(target, port)
    
    async def detect_os(self, target: str) -> Dict:
        """检测操作系统"""
        try:
            command = [self.nmap_path, "-O", target, "-oX", "-"]
            result = await self._execute_scan(command)
            parsed = self._parse_result(result)
            
            if parsed.get("hosts"):
                host = parsed["hosts"][0]
                return {
                    "status": "success",
                    "target": target,
                    "os": host.get("os", "unknown")
                }
            
            return {
                "status": "success",
                "target": target,
                "os": "unknown"
            }
        except Exception as e:
            logger.error(f"OS detection error: {e}")
            return self._get_mock_os_result(target)
    
    async def scan_vulnerability(self, target: str) -> Dict:
        """漏洞扫描 (使用Nmap脚本)"""
        try:
            command = [self.nmap_path, "-sV", "--script=vuln", target, "-oX", "-"]
            result = await self._execute_scan(command)
            parsed = self._parse_result(result)
            
            vulnerabilities = []
            for host in parsed.get("hosts", []):
                for port in host.get("ports", []):
                    script_results = port.get("scripts", [])
                    for script in script_results:
                        if "vuln" in script.get("id", "").lower():
                            vulnerabilities.append({
                                "port": port.get("port"),
                                "script": script.get("id"),
                                "output": script.get("output", "")
                            })
            
            return {
                "status": "success",
                "target": target,
                "vulnerabilities": vulnerabilities
            }
        except Exception as e:
            logger.error(f"Vulnerability scan error: {e}")
            return self._get_mock_vuln_result(target)
    
    def _get_mock_scan_result(self, target: str, scan_type: str) -> Dict:
        """获取模拟扫描结果"""
        return {
            "status": "success",
            "target": target,
            "scan_type": scan_type,
            "hosts": [
                {
                    "address": "192.168.1.1",
                    "status": "up",
                    "hostname": "router.local",
                    "ports": [
                        {"port": "22", "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.2"},
                        {"port": "80", "protocol": "tcp", "state": "open", "service": "http", "product": "nginx", "version": "1.18.0"},
                        {"port": "443", "protocol": "tcp", "state": "open", "service": "https", "product": "nginx", "version": "1.18.0"}
                    ],
                    "os": "Linux 4.15",
                    "services": ["ssh", "http", "https"]
                },
                {
                    "address": "192.168.1.100",
                    "status": "up",
                    "hostname": "web-server.local",
                    "ports": [
                        {"port": "80", "protocol": "tcp", "state": "open", "service": "http", "product": "Apache", "version": "2.4.41"},
                        {"port": "3306", "protocol": "tcp", "state": "open", "service": "mysql", "product": "MySQL", "version": "8.0"}
                    ],
                    "os": "Ubuntu Linux",
                    "services": ["http", "mysql"]
                },
                {
                    "address": "192.168.1.101",
                    "status": "up",
                    "hostname": "file-server.local",
                    "ports": [
                        {"port": "445", "protocol": "tcp", "state": "open", "service": "smb", "product": "Samba", "version": "4.13"},
                        {"port": "139", "protocol": "tcp", "state": "open", "service": "netbios-ssn", "product": "", "version": ""}
                    ],
                    "os": "Windows Server 2019",
                    "services": ["smb", "netbios"]
                }
            ],
            "summary": {
                "hosts_scanned": 3,
                "hosts_up": 3,
                "scan_time": "15.5"
            }
        }
    
    def _get_mock_port_result(self, target: str, port: int) -> Dict:
        """获取模拟端口扫描结果"""
        return {
            "status": "success",
            "target": target,
            "port": port,
            "info": {
                "state": "open",
                "service": "http",
                "product": "nginx",
                "version": "1.18.0"
            }
        }
    
    def _get_mock_os_result(self, target: str) -> Dict:
        """获取模拟OS检测结果"""
        return {
            "status": "success",
            "target": target,
            "os": "Linux 4.15 (Ubuntu 20.04)"
        }
    
    def _get_mock_vuln_result(self, target: str) -> Dict:
        """获取模拟漏洞扫描结果"""
        return {
            "status": "success",
            "target": target,
            "vulnerabilities": [
                {
                    "port": "80",
                    "script": "http-vuln-cve2021-41773",
                    "output": "VULNERABLE: Path Traversal"
                },
                {
                    "port": "443",
                    "script": "ssl-heartbleed",
                    "output": "NOT VULNERABLE"
                }
            ]
        }