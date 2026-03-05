"""
Security Tool Implementations

Concrete implementations of security tools that integrate with
external services and local utilities.
"""

import asyncio
import aiohttp
import logging
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from datetime import datetime
from pathlib import Path

from ..tools.base_tool import (
    BaseTool,
    NetworkTool,
    ThreatIntelTool,
    FileScanTool,
    ToolResult,
    ToolConfig,
    ToolMetadata,
)
from ..tools.registry import register_tool

logger = logging.getLogger(__name__)


# ============================================================================
# Network Tools
# ============================================================================

@register_tool("nmap")
class NmapTool(NetworkTool):
    """Nmap network scanner integration"""
    
    def __init__(self, config: Optional[ToolConfig] = None):
        super().__init__(config)
        self.nmap_path = config.options.get("nmap_path", "nmap") if config else "nmap"
    
    @classmethod
    def get_metadata(cls) -> ToolMetadata:
        return ToolMetadata(
            name="nmap",
            display_name="Nmap Scanner",
            description="Network port scanner and service detector",
            version="1.0.0",
            category="network",
            risk_level="medium",
            requires_approval=False,
        )
    
    async def execute(self, **kwargs) -> ToolResult:
        target = kwargs.get("target")
        ports = kwargs.get("ports", "1-1000")
        scan_type = kwargs.get("scan_type", "syn")
        timing = kwargs.get("timing", "T3")
        service_detection = kwargs.get("service_detection", True)
        os_detection = kwargs.get("os_detection", False)
        
        if not target:
            return ToolResult.error("Target is required")
        
        # Build nmap command
        cmd = [self.nmap_path, "-oX", "-"]  # XML output to stdout
        
        # Scan type
        scan_flags = {
            "syn": "-sS",
            "tcp": "-sT",
            "udp": "-sU",
            "ack": "-sA",
            "fin": "-sF",
            "xmas": "-sX",
        }
        cmd.append(scan_flags.get(scan_type, "-sS"))
        
        # Timing
        cmd.append(f"-{timing}")
        
        # Ports
        cmd.extend(["-p", ports])
        
        # Service detection
        if service_detection:
            cmd.append("-sV")
        
        # OS detection
        if os_detection:
            cmd.append("-O")
        
        # Target
        cmd.append(target)
        
        try:
            # Execute nmap
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.config.timeout if self.config else 600
            )
            
            if process.returncode != 0:
                return ToolResult.error(f"Nmap failed: {stderr.decode()}")
            
            # Parse XML output
            result = self._parse_nmap_xml(stdout.decode())
            return ToolResult.success(result)
            
        except asyncio.TimeoutError:
            return ToolResult.error("Nmap scan timed out")
        except FileNotFoundError:
            return ToolResult.error(f"Nmap not found at {self.nmap_path}")
        except Exception as e:
            logger.exception("Nmap execution failed")
            return ToolResult.error(str(e))
    
    def _parse_nmap_xml(self, xml_content: str) -> Dict[str, Any]:
        """Parse nmap XML output"""
        try:
            root = ET.fromstring(xml_content)
            
            hosts = []
            for host in root.findall(".//host"):
                host_data = {
                    "status": host.find("status").get("state") if host.find("status") is not None else "unknown",
                    "addresses": [],
                    "hostnames": [],
                    "ports": [],
                }
                
                # Addresses
                for addr in host.findall("address"):
                    host_data["addresses"].append({
                        "type": addr.get("addrtype"),
                        "addr": addr.get("addr"),
                    })
                
                # Hostnames
                for hostname in host.findall(".//hostname"):
                    host_data["hostnames"].append({
                        "name": hostname.get("name"),
                        "type": hostname.get("type"),
                    })
                
                # Ports
                for port in host.findall(".//port"):
                    port_data = {
                        "protocol": port.get("protocol"),
                        "portid": port.get("portid"),
                        "state": port.find("state").get("state") if port.find("state") is not None else "unknown",
                    }
                    
                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = {
                            "name": service.get("name"),
                            "product": service.get("product"),
                            "version": service.get("version"),
                        }
                    
                    host_data["ports"].append(port_data)
                
                hosts.append(host_data)
            
            return {
                "hosts": hosts,
                "host_count": len(hosts),
                "scan_info": {
                    "scanner": root.get("scanner"),
                    "args": root.get("args"),
                    "start_time": root.get("startstr"),
                },
            }
            
        except ET.ParseError as e:
            return {"error": f"Failed to parse XML: {e}", "raw": xml_content[:1000]}


@register_tool("censys")
class CensysTool(NetworkTool):
    """Censys internet search integration"""
    
    def __init__(self, config: Optional[ToolConfig] = None):
        super().__init__(config)
        self.api_id = config.options.get("api_id", "") if config else ""
        self.api_secret = config.options.get("api_secret", "") if config else ""
        self.base_url = "https://search.censys.io/api/v2"
    
    @classmethod
    def get_metadata(cls) -> ToolMetadata:
        return ToolMetadata(
            name="censys",
            display_name="Censys Search",
            description="Internet-wide device and service search",
            version="1.0.0",
            category="network",
            risk_level="low",
            requires_approval=False,
        )
    
    async def execute(self, **kwargs) -> ToolResult:
        query = kwargs.get("query")
        index = kwargs.get("index", "hosts")
        limit = kwargs.get("limit", 25)
        
        if not query:
            return ToolResult.error("Query is required")
        
        if not self.api_id or not self.api_secret:
            return ToolResult.error("Censys API credentials not configured")
        
        url = f"{self.base_url}/{index}/search"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json={"q": query, "per_page": min(limit, 100)},
                    auth=aiohttp.BasicAuth(self.api_id, self.api_secret),
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return ToolResult.success({
                            "results": data.get("result", {}).get("hits", []),
                            "total": data.get("result", {}).get("total", 0),
                            "query": query,
                        })
                    else:
                        error_text = await response.text()
                        return ToolResult.error(f"Censys API error: {response.status} - {error_text}")
                        
        except asyncio.TimeoutError:
            return ToolResult.error("Censys API request timed out")
        except Exception as e:
            logger.exception("Censys query failed")
            return ToolResult.error(str(e))


# ============================================================================
# Threat Intelligence Tools
# ============================================================================

@register_tool("virustotal")
class VirusTotalTool(ThreatIntelTool):
    """VirusTotal threat intelligence integration"""
    
    def __init__(self, config: Optional[ToolConfig] = None):
        super().__init__(config)
        self.api_key = config.options.get("api_key", "") if config else ""
        self.base_url = "https://www.virustotal.com/api/v3"
    
    @classmethod
    def get_metadata(cls) -> ToolMetadata:
        return ToolMetadata(
            name="virustotal",
            display_name="VirusTotal",
            description="Multi-engine malware and URL scanning",
            version="1.0.0",
            category="threat_intel",
            risk_level="low",
            requires_approval=False,
        )
    
    async def execute(self, **kwargs) -> ToolResult:
        indicator = kwargs.get("indicator")
        indicator_type = kwargs.get("indicator_type")
        
        if not indicator:
            return ToolResult.error("Indicator is required")
        if not indicator_type:
            return ToolResult.error("Indicator type is required")
        if not self.api_key:
            return ToolResult.error("VirusTotal API key not configured")
        
        # Map indicator type to endpoint
        endpoints = {
            "file_hash": f"/files/{indicator}",
            "url": f"/urls/{self._url_id(indicator)}",
            "domain": f"/domains/{indicator}",
            "ip": f"/ip_addresses/{indicator}",
        }
        
        endpoint = endpoints.get(indicator_type)
        if not endpoint:
            return ToolResult.error(f"Unknown indicator type: {indicator_type}")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}{endpoint}",
                    headers={"x-apikey": self.api_key},
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return ToolResult.success(self._format_vt_response(data, indicator_type))
                    elif response.status == 404:
                        return ToolResult.success({
                            "found": False,
                            "indicator": indicator,
                            "type": indicator_type,
                        })
                    else:
                        error_text = await response.text()
                        return ToolResult.error(f"VirusTotal API error: {response.status}")
                        
        except asyncio.TimeoutError:
            return ToolResult.error("VirusTotal API request timed out")
        except Exception as e:
            logger.exception("VirusTotal query failed")
            return ToolResult.error(str(e))
    
    def _url_id(self, url: str) -> str:
        """Generate VirusTotal URL identifier"""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    
    def _format_vt_response(self, data: Dict[str, Any], indicator_type: str) -> Dict[str, Any]:
        """Format VirusTotal response"""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        return {
            "found": True,
            "type": indicator_type,
            "stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            },
            "reputation": attributes.get("reputation", 0),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "tags": attributes.get("tags", []),
        }


@register_tool("misp")
class MISPTool(ThreatIntelTool):
    """MISP threat intelligence platform integration"""
    
    def __init__(self, config: Optional[ToolConfig] = None):
        super().__init__(config)
        self.url = config.options.get("url", "") if config else ""
        self.api_key = config.options.get("api_key", "") if config else ""
    
    @classmethod
    def get_metadata(cls) -> ToolMetadata:
        return ToolMetadata(
            name="misp",
            display_name="MISP",
            description="Threat intelligence sharing platform",
            version="1.0.0",
            category="threat_intel",
            risk_level="low",
            requires_approval=False,
        )
    
    async def execute(self, **kwargs) -> ToolResult:
        value = kwargs.get("value")
        attribute_type = kwargs.get("attribute_type")
        include_correlations = kwargs.get("include_correlations", True)
        
        if not value:
            return ToolResult.error("Value is required")
        if not self.url or not self.api_key:
            return ToolResult.error("MISP URL and API key required")
        
        search_body = {
            "returnFormat": "json",
            "value": value,
            "includeCorrelations": include_correlations,
        }
        
        if attribute_type:
            search_body["type"] = attribute_type
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.url}/attributes/restSearch",
                    json=search_body,
                    headers={
                        "Authorization": self.api_key,
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                    ssl=False,  # Many MISP instances use self-signed certs
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return ToolResult.success(self._format_misp_response(data))
                    else:
                        return ToolResult.error(f"MISP API error: {response.status}")
                        
        except Exception as e:
            logger.exception("MISP query failed")
            return ToolResult.error(str(e))
    
    def _format_misp_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format MISP response"""
        attributes = data.get("response", {}).get("Attribute", [])
        
        results = []
        for attr in attributes:
            results.append({
                "id": attr.get("id"),
                "type": attr.get("type"),
                "value": attr.get("value"),
                "category": attr.get("category"),
                "event_id": attr.get("event_id"),
                "timestamp": attr.get("timestamp"),
                "comment": attr.get("comment"),
                "tags": [t.get("name") for t in attr.get("Tag", [])],
            })
        
        return {
            "found": len(results) > 0,
            "count": len(results),
            "attributes": results,
        }


@register_tool("threatbook")
class ThreatBookTool(ThreatIntelTool):
    """ThreatBook (微步在线) threat intelligence integration"""
    
    def __init__(self, config: Optional[ToolConfig] = None):
        super().__init__(config)
        self.api_key = config.options.get("api_key", "") if config else ""
        self.base_url = "https://api.threatbook.cn/v3"
    
    @classmethod
    def get_metadata(cls) -> ToolMetadata:
        return ToolMetadata(
            name="threatbook",
            display_name="ThreatBook (微步在线)",
            description="Chinese threat intelligence platform",
            version="1.0.0",
            category="threat_intel",
            risk_level="low",
            requires_approval=False,
        )
    
    async def execute(self, **kwargs) -> ToolResult:
        indicator = kwargs.get("indicator")
        indicator_type = kwargs.get("indicator_type")
        
        if not indicator:
            return ToolResult.error("Indicator is required")
        if not indicator_type:
            return ToolResult.error("Indicator type is required")
        if not self.api_key:
            return ToolResult.error("ThreatBook API key not configured")
        
        # Map indicator type to endpoint
        endpoints = {
            "ip": "/scene/ip_reputation",
            "domain": "/scene/domain_reputation",
            "hash": "/scene/file_reputation",
        }
        
        endpoint = endpoints.get(indicator_type)
        if not endpoint:
            return ToolResult.error(f"Unknown indicator type: {indicator_type}")
        
        params = {
            "apikey": self.api_key,
            "resource": indicator,
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}{endpoint}",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return ToolResult.success(data.get("data", {}))
                    else:
                        return ToolResult.error(f"ThreatBook API error: {response.status}")
                        
        except Exception as e:
            logger.exception("ThreatBook query failed")
            return ToolResult.error(str(e))


# ============================================================================
# Forensics Tools
# ============================================================================

@register_tool("elk_query")
class ELKQueryTool(BaseTool):
    """Elasticsearch log query tool"""
    
    def __init__(self, config: Optional[ToolConfig] = None):
        super().__init__(config)
        self.es_url = config.options.get("es_url", "http://localhost:9200") if config else "http://localhost:9200"
        self.username = config.options.get("username", "") if config else ""
        self.password = config.options.get("password", "") if config else ""
    
    @classmethod
    def get_metadata(cls) -> ToolMetadata:
        return ToolMetadata(
            name="elk_query",
            display_name="ELK Query",
            description="Query Elasticsearch for log analysis",
            version="1.0.0",
            category="forensics",
            risk_level="low",
            requires_approval=False,
        )
    
    async def execute(self, **kwargs) -> ToolResult:
        query = kwargs.get("query")
        index = kwargs.get("index", "logs-*")
        time_range = kwargs.get("time_range", "now-24h")
        size = kwargs.get("size", 100)
        
        if not query:
            return ToolResult.error("Query is required")
        
        # Build Elasticsearch query
        es_query = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": query}},
                    ],
                    "filter": [
                        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    ],
                },
            },
            "size": min(size, 10000),
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        
        auth = None
        if self.username and self.password:
            auth = aiohttp.BasicAuth(self.username, self.password)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.es_url}/{index}/_search",
                    json=es_query,
                    auth=auth,
                    timeout=aiohttp.ClientTimeout(total=120),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        hits = data.get("hits", {})
                        return ToolResult.success({
                            "total": hits.get("total", {}).get("value", 0),
                            "hits": [h.get("_source", {}) for h in hits.get("hits", [])],
                            "took_ms": data.get("took", 0),
                        })
                    else:
                        error_text = await response.text()
                        return ToolResult.error(f"Elasticsearch error: {response.status}")
                        
        except Exception as e:
            logger.exception("Elasticsearch query failed")
            return ToolResult.error(str(e))


# ============================================================================
# CVE Lookup Tool
# ============================================================================

@register_tool("cve_lookup")
class CVELookupTool(BaseTool):
    """CVE vulnerability lookup from NVD"""
    
    def __init__(self, config: Optional[ToolConfig] = None):
        super().__init__(config)
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = config.options.get("api_key", "") if config else ""
    
    @classmethod
    def get_metadata(cls) -> ToolMetadata:
        return ToolMetadata(
            name="cve_lookup",
            display_name="CVE Lookup",
            description="Look up CVE details from NVD",
            version="1.0.0",
            category="vulnerability",
            risk_level="low",
            requires_approval=False,
        )
    
    async def execute(self, **kwargs) -> ToolResult:
        cve_id = kwargs.get("cve_id")
        
        if not cve_id:
            return ToolResult.error("CVE ID is required")
        
        # Validate CVE format
        if not cve_id.upper().startswith("CVE-"):
            return ToolResult.error("Invalid CVE format. Expected: CVE-YYYY-NNNNN")
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.base_url,
                    params={"cveId": cve_id.upper()},
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data.get("vulnerabilities", [])
                        
                        if not vulnerabilities:
                            return ToolResult.success({
                                "found": False,
                                "cve_id": cve_id,
                            })
                        
                        cve_data = vulnerabilities[0].get("cve", {})
                        return ToolResult.success(self._format_cve(cve_data))
                    else:
                        return ToolResult.error(f"NVD API error: {response.status}")
                        
        except Exception as e:
            logger.exception("CVE lookup failed")
            return ToolResult.error(str(e))
    
    def _format_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format CVE data"""
        # Get CVSS scores
        metrics = cve_data.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
        cvss_v2 = metrics.get("cvssMetricV2", [{}])[0] if metrics.get("cvssMetricV2") else {}
        
        # Get descriptions
        descriptions = cve_data.get("descriptions", [])
        description_en = next(
            (d.get("value") for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )
        
        return {
            "found": True,
            "cve_id": cve_data.get("id"),
            "description": description_en,
            "published": cve_data.get("published"),
            "last_modified": cve_data.get("lastModified"),
            "cvss_v3": {
                "score": cvss_v3.get("cvssData", {}).get("baseScore"),
                "severity": cvss_v3.get("cvssData", {}).get("baseSeverity"),
                "vector": cvss_v3.get("cvssData", {}).get("vectorString"),
            } if cvss_v3 else None,
            "cvss_v2": {
                "score": cvss_v2.get("cvssData", {}).get("baseScore"),
                "severity": cvss_v2.get("baseSeverity"),
                "vector": cvss_v2.get("cvssData", {}).get("vectorString"),
            } if cvss_v2 else None,
            "references": [
                {"url": r.get("url"), "source": r.get("source")}
                for r in cve_data.get("references", [])
            ],
            "weaknesses": [
                w.get("description", [{}])[0].get("value")
                for w in cve_data.get("weaknesses", [])
            ],
        }
