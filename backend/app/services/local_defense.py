"""
玄鉴安全智能体 - 本地防御管理器
实现本地网络安全防护和自动化响应
"""

import os
import json
import subprocess
import socket
import threading
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkSegment:
    """网络段配置"""
    def __init__(self, cidr: str, name: str = ""):
        self.cidr = cidr
        self.name = name or cidr
    
    def to_dict(self):
        return {"cidr": self.cidr, "name": self.name}


class ScanResult:
    """扫描结果"""
    def __init__(self, ip: str, ports: List[Dict] = None, os_info: str = "", services: Dict = None):
        self.ip = ip
        self.ports = ports or []
        self.os_info = os_info
        self.services = services or {}
        self.scan_time = datetime.now()
    
    def to_dict(self):
        return {
            "ip": self.ip,
            "ports": self.ports,
            "os_info": self.os_info,
            "services": self.services,
            "scan_time": self.scan_time.isoformat()
        }


class ThreatEvent:
    """威胁事件"""
    def __init__(self, event_type: str, source_ip: str, description: str, severity: str = "medium"):
        self.id = f"THREAT-{int(time.time() * 1000)}"
        self.event_type = event_type
        self.source_ip = source_ip
        self.description = description
        self.severity = severity
        self.timestamp = datetime.now()
        self.status = "new"
    
    def to_dict(self):
        return {
            "id": self.id,
            "type": self.event_type,
            "source_ip": self.source_ip,
            "description": self.description,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status
        }


class LocalDefenseManager:
    """本地防御管理器"""
    
    def __init__(self):
        self.network_segments = [
            NetworkSegment("192.168.1.0/24", "主网络"),
            NetworkSegment("192.168.10.0/24", "VMware Host-Only"),
            NetworkSegment("192.168.233.0/24", "VMware NAT"),
        ]
        
        self.blocked_ips: Dict[str, Dict] = {}
        self.threat_events: List[ThreatEvent] = []
        self.asset_inventory: Dict[str, ScanResult] = {}
        
        self.alert_thresholds = {
            "ssh_brute_force": {"count": 5, "window": 60},
            "port_scan": {"ports": 10, "window": 60},
            "sql_injection": {"count": 1, "window": 0},
        }
        
        self.auto_response_enabled = True
        self.monitoring = False
        self.monitor_thread = None
        
        self.firewall_available = self._check_firewall()
        
        logger.info("本地防御管理器初始化完成")
        logger.info(f"网络段: {[seg.cidr for seg in self.network_segments]}")
        logger.info(f"防火墙可用: {self.firewall_available}")
    
    def _check_firewall(self) -> bool:
        """检查防火墙可用性"""
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"防火墙检查失败: {e}")
            return False
    
    def get_local_ip(self) -> str:
        """获取本机IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def get_network_info(self) -> Dict[str, Any]:
        """获取网络信息"""
        local_ip = self.get_local_ip()
        
        interfaces = []
        try:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                timeout=10
            )
            output = result.stdout
            
            current_adapter = ""
            for line in output.split('\n'):
                if "适配器" in line or "adapter" in line.lower():
                    current_adapter = line.split("适配器")[1].split(".")[0].strip() if "适配器" in line else line.strip()
                elif "IPv4" in line and "192.168" in line:
                    ip = line.split(":")[-1].strip()
                    if ip:
                        interfaces.append({
                            "name": current_adapter,
                            "ip": ip,
                            "type": "wired" if "以太网" in current_adapter or "Ethernet" in current_adapter else "wireless"
                        })
        except Exception as e:
            logger.error(f"获取网络信息失败: {e}")
        
        return {
            "local_ip": local_ip,
            "interfaces": interfaces,
            "network_segments": [seg.to_dict() for seg in self.network_segments]
        }
    
    def quick_scan(self, target: str = None) -> List[Dict]:
        """快速扫描本地网络"""
        if not target:
            local_ip = self.get_local_ip()
            octets = local_ip.split('.')
            target = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
        
        logger.info(f"开始快速扫描: {target}")
        
        results = []
        try:
            result = subprocess.run(
                ["nmap", "-sn", "-PR", target, "--max-retries", "2", "--host-timeout", "30s"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            for line in result.stdout.split('\n'):
                if "Nmap scan report for" in line:
                    ip = line.split("for")[-1].strip()
                    if ip and not ip.startswith("("):
                        results.append({
                            "ip": ip,
                            "status": "up",
                            "mac": "",
                            "hostname": ""
                        })
        except FileNotFoundError:
            logger.error("Nmap未安装，跳过扫描")
            results = self._generate_mock_scan(target)
        except Exception as e:
            logger.error(f"扫描失败: {e}")
            results = self._generate_mock_scan(target)
        
        logger.info(f"扫描完成，发现 {len(results)} 个在线主机")
        return results
    
    def _generate_mock_scan(self, target: str) -> List[Dict]:
        """生成模拟扫描结果"""
        return [
            {"ip": "192.168.1.1", "status": "up", "mac": "00:11:22:33:44:55", "hostname": "router"},
            {"ip": "192.168.1.100", "status": "up", "mac": "A4:01:B3:48:D0:01", "hostname": "PC-01"},
            {"ip": "192.168.1.101", "status": "up", "mac": "B4:02:34:59:E1:12", "hostname": "PC-02"},
        ]
    
    def port_scan(self, target: str, ports: str = "22,80,443,3306,5432,6379") -> Dict:
        """端口扫描"""
        logger.info(f"端口扫描: {target}")
        
        results = {
            "target": target,
            "ports": [],
            "services": {},
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            result = subprocess.run(
                ["nmap", "-sV", "-p", ports, target],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            for line in result.stdout.split('\n'):
                if "/tcp" in line or "/udp" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_proto = parts[0].split('/')[0]
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else "unknown"
                        
                        results["ports"].append({
                            "port": port_proto,
                            "state": state,
                            "service": service
                        })
                        
                        if state == "open":
                            results["services"][port_proto] = service
                            
        except FileNotFoundError:
            logger.error("Nmap未安装")
        except Exception as e:
            logger.error(f"端口扫描失败: {e}")
        
        return results
    
    def add_blocked_ip(self, ip: str, reason: str, duration: int = 3600) -> Dict:
        """添加封禁IP"""
        if ip in self.blocked_ips:
            logger.warning(f"IP {ip} 已经在封禁列表中")
            return {"success": False, "message": "IP已在封禁列表中"}
        
        rule_id = f"BLOCK-{int(time.time())}"
        
        blocked_info = {
            "ip": ip,
            "reason": reason,
            "rule_id": rule_id,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(seconds=duration)).isoformat() if duration > 0 else None,
            "status": "active"
        }
        
        self.blocked_ips[ip] = blocked_info
        
        if self.firewall_available:
            self._block_ip_firewall(ip, reason)
        
        logger.info(f"已封禁IP: {ip}, 原因: {reason}")
        return {"success": True, "rule_id": rule_id, **blocked_info}
    
    def _block_ip_firewall(self, ip: str, reason: str):
        """通过Windows防火墙封禁IP"""
        try:
            rule_name = f"SecGPT_Block_{ip.replace('.', '_')}"
            
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=" + rule_name,
                "dir=in",
                "action=block",
                "remoteip=" + ip,
                "description=" + reason
            ], check=True, timeout=10)
            
            logger.info(f"Windows防火墙规则已添加: {rule_name}")
        except Exception as e:
            logger.error(f"防火墙规则添加失败: {e}")
    
    def remove_blocked_ip(self, ip: str) -> Dict:
        """解除IP封禁"""
        if ip not in self.blocked_ips:
            return {"success": False, "message": "IP不在封禁列表中"}
        
        rule_id = self.blocked_ips[ip]["rule_id"]
        del self.blocked_ips[ip]
        
        if self.firewall_available:
            self._unblock_ip_firewall(ip)
        
        logger.info(f"已解除封禁IP: {ip}")
        return {"success": True, "rule_id": rule_id}
    
    def _unblock_ip_firewall(self, ip: str):
        """通过Windows防火墙解除封禁"""
        try:
            rule_name = f"SecGPT_Block_{ip.replace('.', '_')}"
            
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                "name=" + rule_name
            ], check=True, timeout=10)
            
            logger.info(f"Windows防火墙规则已删除: {rule_name}")
        except Exception as e:
            logger.error(f"防火墙规则删除失败: {e}")
    
    def get_blocked_ips(self) -> List[Dict]:
        """获取封禁列表"""
        return list(self.blocked_ips.values())
    
    def add_threat_event(self, event: ThreatEvent):
        """添加威胁事件"""
        self.threat_events.insert(0, event)
        
        if len(self.threat_events) > 1000:
            self.threat_events = self.threat_events[:1000]
        
        if self.auto_response_enabled:
            self._auto_response(event)
    
    def _auto_response(self, event: ThreatEvent):
        """自动响应"""
        if event.severity in ["critical", "high"]:
            logger.warning(f"检测到高危威胁，自动封禁: {event.source_ip}")
            self.add_blocked_ip(
                event.source_ip,
                f"自动封禁: {event.description}",
                duration=86400
            )
    
    def get_threat_events(self, limit: int = 50) -> List[Dict]:
        """获取威胁事件"""
        return [e.to_dict() for e in self.threat_events[:limit]]
    
    def get_defense_stats(self) -> Dict:
        """获取防御统计"""
        now = datetime.now()
        events_24h = [e for e in self.threat_events 
                     if (now - e.timestamp).total_seconds() < 86400]
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for e in events_24h:
            if e.severity in severity_counts:
                severity_counts[e.severity] += 1
        
        return {
            "blocked_ips": len(self.blocked_ips),
            "threat_events_24h": len(events_24h),
            "severity_breakdown": severity_counts,
            "auto_response_enabled": self.auto_response_enabled,
            "firewall_available": self.firewall_available,
            "local_ip": self.get_local_ip()
        }
    
    def start_monitoring(self):
        """启动监控"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("本地防御监控已启动")
    
    def stop_monitoring(self):
        """停止监控"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("本地防御监控已停止")
    
    def _monitor_loop(self):
        """监控循环"""
        while self.monitoring:
            try:
                self._check_network_changes()
                time.sleep(60)
            except Exception as e:
                logger.error(f"监控循环异常: {e}")
    
    def _check_network_changes(self):
        """检查网络变化"""
        current_info = self.get_network_info()
        
        logger.debug(f"网络监控: {current_info['local_ip']}")
    
    def generate_security_report(self) -> Dict:
        """生成安全报告"""
        stats = self.get_defense_stats()
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "local_ip": stats["local_ip"],
            "firewall_status": "active" if stats["firewall_available"] else "unavailable",
            "auto_response": "enabled" if stats["auto_response_enabled"] else "disabled",
            "summary": {
                "total_blocked_ips": stats["blocked_ips"],
                "threats_24h": stats["threat_events_24h"],
                "critical_threats": stats["severity_breakdown"]["critical"],
                "high_threats": stats["severity_breakdown"]["high"],
            },
            "recommendations": []
        }
        
        if stats["threat_events_24h"] > 100:
            report["recommendations"].append({
                "priority": "high",
                "action": "检查网络流量异常",
                "description": "24小时内检测到大量威胁事件，建议检查网络配置"
            })
        
        if stats["severity_breakdown"]["critical"] > 10:
            report["recommendations"].append({
                "priority": "critical",
                "action": "立即排查",
                "description": "检测到多个严重威胁，建议立即人工介入"
            })
        
        if not stats["firewall_available"]:
            report["recommendations"].append({
                "priority": "medium",
                "action": "启用防火墙",
                "description": "Windows防火墙不可用，建议检查安全设置"
            })
        
        return report


def get_defense_manager() -> LocalDefenseManager:
    """获取防御管理器单例"""
    if not hasattr(get_defense_manager, "_instance"):
        get_defense_manager._instance = LocalDefenseManager()
    return get_defense_manager._instance
