"""
玄鉴安全智能体 - Wireshark流量分析工具
集成PyShark进行网络流量分析和检测
"""

import asyncio
import logging
import tempfile
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import pyshark
from pydantic import BaseModel, Field

from ..base_tool import BaseTool, ToolCategory, ToolMetadata, ToolResult, RiskLevel

logger = logging.getLogger(__name__)


class TrafficAnalysisParams(BaseModel):
    """流量分析参数"""
    pcap_file: str = Field(..., description="PCAP文件路径")
    display_filter: Optional[str] = Field(default=None, description="Wireshark显示过滤器")
    limit: Optional[int] = Field(default=None, description="分析包数量限制")
    protocol: Optional[str] = Field(default=None, description="协议过滤")


class ProtocolStats(BaseModel):
    """协议统计"""
    total_packets: int = Field(default=0)
    protocols: Dict[str, int] = Field(default_factory=dict)
    top_ips: List[Dict[str, Any]] = Field(default_factory=list)
    top_ports: List[Dict[str, Any]] = Field(default_factory=list)


class WiresharkTool(BaseTool):
    """Wireshark流量分析工具"""
    
    metadata = ToolMetadata(
        name="wireshark",
        category=ToolCategory.ANALYSIS,
        description="Wireshark流量分析工具，支持网络包解析和威胁检测",
        version="1.0.0",
        author="玄鉴安全团队",
        tags=["packet-analysis", "network", "traffic"],
        risk_level=RiskLevel.MEDIUM
    )
    
    def __init__(self, tshark_path: Optional[str] = None):
        """
        初始化Wireshark工具
        
        Args:
            tshark_path: tshark可执行文件路径
        """
        super().__init__()
        self.tshark_path = tshark_path
        logger.info(f"Wireshark tool initialized (tshark: {tshark_path})")
    
    async def analyze_packets(self, params: TrafficAnalysisParams) -> Dict[str, Any]:
        """
        分析数据包
        
        Args:
            params: 分析参数
            
        Returns:
            分析结果
        """
        try:
            # 构建捕获参数
            capture_kwargs = {
                "display_filter": params.display_filter,
                "eventloop": asyncio.get_event_loop()
            }
            
            # 如果指定了tshark路径
            if self.tshark_path:
                capture_kwargs["tshark_path"] = self.tshark_path
            
            # 如果限制了包数量，使用临时文件只读取部分
            limit = params.limit
            if limit:
                logger.info(f"Analyzing {limit} packets from {params.pcap_file}")
            
            # 打开PCAP文件
            capture = pyshark.FileCapture(params.pcap_file, **capture_kwargs)
            
            packets = []
            proto_stats = {}
            ip_stats = {}
            port_stats = {}
            
            count = 0
            for packet in capture:
                try:
                    # 解析包信息
                    packet_info = self._parse_packet(packet)
                    packets.append(packet_info)
                    
                    # 统计协议
                    if hasattr(packet, 'highest_layer'):
                        proto = packet.highest_layer
                        proto_stats[proto] = proto_stats.get(proto, 0) + 1
                    
                    # 统计IP
                    if hasattr(packet, 'ip'):
                        src_ip = packet.ip.src
                        dst_ip = packet.ip.dst
                        ip_stats[src_ip] = ip_stats.get(src_ip, 0) + 1
                        ip_stats[dst_ip] = ip_stats.get(dst_ip, 0) + 1
                    
                    # 统计端口
                    if hasattr(packet, 'tcp'):
                        dst_port = packet.tcp.dstport
                        port_stats[dst_port] = port_stats.get(dst_port, 0) + 1
                    
                    count += 1
                    if limit and count >= limit:
                        break
                        
                except Exception as e:
                    logger.warning(f"Error parsing packet: {e}")
                    continue
            
            capture.close()
            
            # 整理统计信息
            top_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]
            top_ports = sorted(port_stats.items(), key=lambda x: x[1], reverse=True)[:10]
            
            result = {
                "total_packets": count,
                "protocol_stats": proto_stats,
                "top_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
                "top_ports": [{"port": port, "count": cnt} for port, cnt in top_ports],
                "sample_packets": packets[:100] if len(packets) > 100 else packets
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Analyze packets failed: {e}")
            raise
    
    def _parse_packet(self, packet) -> Dict[str, Any]:
        """
        解析单个数据包
        
        Args:
            packet: pyshark数据包对象
            
        Returns:
            解析结果
        """
        packet_info = {
            "number": getattr(packet, 'number', None),
            "timestamp": getattr(packet, 'sniff_timestamp', None),
            "length": getattr(packet, 'length', None),
            "protocol": getattr(packet, 'highest_layer', None),
            "summary": str(packet)
        }
        
        # IP层信息
        if hasattr(packet, 'ip'):
            packet_info["src_ip"] = packet.ip.src
            packet_info["dst_ip"] = packet.ip.dst
        
        # TCP/UDP端口
        if hasattr(packet, 'tcp'):
            packet_info["src_port"] = packet.tcp.srcport
            packet_info["dst_port"] = packet.tcp.dstport
            packet_info["flags"] = packet.tcp.flags if hasattr(packet.tcp, 'flags') else None
        elif hasattr(packet, 'udp'):
            packet_info["src_port"] = packet.udp.srcport
            packet_info["dst_port"] = packet.udp.dstport
        
        # HTTP信息
        if hasattr(packet, 'http'):
            packet_info["http_method"] = getattr(packet.http, 'request_method', None)
            packet_info["http_host"] = getattr(packet.http, 'host', None)
            packet_info["http_uri"] = getattr(packet.http, 'request_uri', None)
        
        # DNS信息
        if hasattr(packet, 'dns'):
            packet_info["dns_query"] = getattr(packet.dns, 'qname', None)
            packet_info["dns_response"] = getattr(packet.dns, 'a', None)
        
        return packet_info
    
    async def detect_threats(self, params: TrafficAnalysisParams) -> List[Dict[str, Any]]:
        """
        检测网络威胁
        
        Args:
            params: 分析参数
            
        Returns:
            威胁列表
        """
        try:
            threats = []
            
            # 读取PCAP文件
            packet_file = pyshark.FileCapture(params.pcap_file, display_filter=params.display_filter)
            
            for i, packet in enumerate(packet_file):
                if params.limit and i >= params.limit:
                    break
                
                threat_info = {}
                
                # 检测端口扫描行为
                if hasattr(packet, 'tcp'):
                    threat_info['type'] = 'tcp_analysis'
                    threat_info['src_ip'] = packet.ip.src if hasattr(packet, 'ip') else 'unknown'
                    threat_info['dst_ip'] = packet.ip.dst if hasattr(packet, 'ip') else 'unknown'
                    threat_info['dst_port'] = packet.tcp.dstport
                
                # 检测恶意域名
                if hasattr(packet, 'dns'):
                    threat_info['type'] = 'dns_analysis'
                    threat_info['query'] = packet.dns.qry_name
                
                # 检测ICMP流量
                if hasattr(packet, 'icmp'):
                    threat_info['type'] = 'icmp_analysis'
                    threat_info['src_ip'] = packet.ip.src if hasattr(packet, 'ip') else 'unknown'
                    threat_info['dst_ip'] = packet.ip.dst if hasattr(packet, 'ip') else 'unknown'
                
                if threat_info:
                    threat_info['timestamp'] = packet.sniff_time.isoformat()
                    threat_info['severity'] = 'medium'
                    threats.append(threat_info)
            
            packet_file.close()
            return threats
            
        except Exception as e:
            logger.error(f"威胁检测失败: {e}")
            raise
