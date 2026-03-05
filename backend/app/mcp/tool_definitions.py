"""
MCP Tool Definitions for Security Tools

Provides pre-defined MCP tool specifications for common security operations.
These definitions follow the MCP protocol spec and can be registered with MCPServer.
"""

from typing import Dict, List, Optional, Any, Callable, Coroutine
from enum import Enum
from pydantic import BaseModel, Field
from dataclasses import dataclass, field
from datetime import datetime

from .mcp_server import MCPToolDefinition, MCPToolParameter


# ============================================================================
# Tool Categories
# ============================================================================

class ToolCategory(str, Enum):
    """Security tool categories"""
    NETWORK = "network"           # Network scanning and analysis
    VULNERABILITY = "vulnerability"  # Vulnerability assessment
    THREAT_INTEL = "threat_intel"   # Threat intelligence
    FORENSICS = "forensics"         # Digital forensics
    DEFENSE = "defense"             # Active defense
    ANALYSIS = "analysis"           # General analysis
    REPORTING = "reporting"         # Report generation


class RiskLevel(str, Enum):
    """Tool risk levels"""
    LOW = "low"           # Read-only, passive operations
    MEDIUM = "medium"     # Active scanning, may be detected
    HIGH = "high"         # May affect target systems
    CRITICAL = "critical" # Potentially destructive, requires approval


# ============================================================================
# Pre-defined Tool Definitions
# ============================================================================

# Network Tools
NMAP_SCAN = MCPToolDefinition(
    name="nmap_scan",
    description="Perform network port scanning using Nmap. Discovers open ports and services on target hosts.",
    parameters=[
        MCPToolParameter(
            name="target",
            type="string",
            description="Target IP address, hostname, or CIDR range (e.g., '192.168.1.1', 'example.com', '10.0.0.0/24')",
            required=True,
        ),
        MCPToolParameter(
            name="ports",
            type="string",
            description="Port specification. Can be: single port (80), range (1-1000), list (22,80,443), or 'all' for 1-65535",
            required=False,
            default="1-1000",
        ),
        MCPToolParameter(
            name="scan_type",
            type="string",
            description="Type of scan to perform",
            required=False,
            default="syn",
            enum=["syn", "tcp", "udp", "ack", "fin", "xmas"],
        ),
        MCPToolParameter(
            name="timing",
            type="string",
            description="Timing template (affects speed vs stealth)",
            required=False,
            default="T3",
            enum=["T0", "T1", "T2", "T3", "T4", "T5"],
        ),
        MCPToolParameter(
            name="service_detection",
            type="boolean",
            description="Enable service/version detection (-sV)",
            required=False,
            default=True,
        ),
        MCPToolParameter(
            name="os_detection",
            type="boolean",
            description="Enable OS detection (-O)",
            required=False,
            default=False,
        ),
    ],
    risk_level=RiskLevel.MEDIUM,
    requires_approval=False,
    timeout_seconds=600,
    category=ToolCategory.NETWORK,
)

CENSYS_SEARCH = MCPToolDefinition(
    name="censys_search",
    description="Search Censys for internet-connected devices and services. Passive reconnaissance without direct target contact.",
    parameters=[
        MCPToolParameter(
            name="query",
            type="string",
            description="Censys search query (e.g., 'services.port: 22 AND location.country: CN')",
            required=True,
        ),
        MCPToolParameter(
            name="index",
            type="string",
            description="Search index type",
            required=False,
            default="hosts",
            enum=["hosts", "certificates"],
        ),
        MCPToolParameter(
            name="limit",
            type="number",
            description="Maximum number of results (1-100)",
            required=False,
            default=25,
        ),
    ],
    risk_level=RiskLevel.LOW,
    requires_approval=False,
    timeout_seconds=60,
    category=ToolCategory.NETWORK,
)

SHODAN_SEARCH = MCPToolDefinition(
    name="shodan_search",
    description="Search Shodan for exposed services and vulnerabilities. Passive internet-wide reconnaissance.",
    parameters=[
        MCPToolParameter(
            name="query",
            type="string",
            description="Shodan search query (e.g., 'port:3389 country:CN')",
            required=True,
        ),
        MCPToolParameter(
            name="limit",
            type="number",
            description="Maximum results to return",
            required=False,
            default=25,
        ),
    ],
    risk_level=RiskLevel.LOW,
    requires_approval=False,
    timeout_seconds=60,
    category=ToolCategory.NETWORK,
)

# Vulnerability Tools
NESSUS_SCAN = MCPToolDefinition(
    name="nessus_scan",
    description="Run Nessus vulnerability scan against target systems. Identifies security vulnerabilities and misconfigurations.",
    parameters=[
        MCPToolParameter(
            name="targets",
            type="string",
            description="Comma-separated list of target IPs or hostnames",
            required=True,
        ),
        MCPToolParameter(
            name="template",
            type="string",
            description="Scan template to use",
            required=False,
            default="basic_network",
            enum=["basic_network", "advanced_scan", "web_app", "compliance", "malware"],
        ),
        MCPToolParameter(
            name="credentials",
            type="object",
            description="Optional credentials for authenticated scanning",
            required=False,
        ),
    ],
    risk_level=RiskLevel.MEDIUM,
    requires_approval=True,
    timeout_seconds=3600,
    category=ToolCategory.VULNERABILITY,
)

CVE_LOOKUP = MCPToolDefinition(
    name="cve_lookup",
    description="Look up CVE details from NVD database. Retrieves vulnerability information, CVSS scores, and references.",
    parameters=[
        MCPToolParameter(
            name="cve_id",
            type="string",
            description="CVE identifier (e.g., 'CVE-2024-12345')",
            required=True,
        ),
    ],
    risk_level=RiskLevel.LOW,
    requires_approval=False,
    timeout_seconds=30,
    category=ToolCategory.VULNERABILITY,
)

# Threat Intelligence Tools
VIRUSTOTAL_LOOKUP = MCPToolDefinition(
    name="virustotal_lookup",
    description="Query VirusTotal for file, URL, domain, or IP reputation. Returns multi-engine scan results.",
    parameters=[
        MCPToolParameter(
            name="indicator",
            type="string",
            description="The indicator to look up (hash, URL, domain, or IP)",
            required=True,
        ),
        MCPToolParameter(
            name="indicator_type",
            type="string",
            description="Type of indicator",
            required=True,
            enum=["file_hash", "url", "domain", "ip"],
        ),
    ],
    risk_level=RiskLevel.LOW,
    requires_approval=False,
    timeout_seconds=60,
    category=ToolCategory.THREAT_INTEL,
)

MISP_QUERY = MCPToolDefinition(
    name="misp_query",
    description="Query MISP threat intelligence platform for IOCs and threat information.",
    parameters=[
        MCPToolParameter(
            name="value",
            type="string",
            description="Indicator value to search (IP, domain, hash, etc.)",
            required=True,
        ),
        MCPToolParameter(
            name="attribute_type",
            type="string",
            description="MISP attribute type",
            required=False,
            enum=["ip-src", "ip-dst", "domain", "md5", "sha256", "url", "email-src"],
        ),
        MCPToolParameter(
            name="include_correlations",
            type="boolean",
            description="Include related events and correlations",
            required=False,
            default=True,
        ),
    ],
    risk_level=RiskLevel.LOW,
    requires_approval=False,
    timeout_seconds=60,
    category=ToolCategory.THREAT_INTEL,
)

THREATBOOK_QUERY = MCPToolDefinition(
    name="threatbook_query",
    description="Query ThreatBook (微步在线) for threat intelligence on Chinese APT groups and regional threats.",
    parameters=[
        MCPToolParameter(
            name="indicator",
            type="string",
            description="Indicator to query (IP, domain, hash)",
            required=True,
        ),
        MCPToolParameter(
            name="indicator_type",
            type="string",
            description="Type of indicator",
            required=True,
            enum=["ip", "domain", "hash"],
        ),
    ],
    risk_level=RiskLevel.LOW,
    requires_approval=False,
    timeout_seconds=60,
    category=ToolCategory.THREAT_INTEL,
)

# Forensics Tools
PCAP_ANALYZE = MCPToolDefinition(
    name="pcap_analyze",
    description="Analyze PCAP network capture files. Extracts sessions, identifies protocols, and detects anomalies.",
    parameters=[
        MCPToolParameter(
            name="file_path",
            type="string",
            description="Path to PCAP file",
            required=True,
        ),
        MCPToolParameter(
            name="analysis_type",
            type="string",
            description="Type of analysis to perform",
            required=False,
            default="overview",
            enum=["overview", "sessions", "dns", "http", "tls", "anomalies"],
        ),
        MCPToolParameter(
            name="filter",
            type="string",
            description="BPF filter expression",
            required=False,
        ),
    ],
    risk_level=RiskLevel.LOW,
    requires_approval=False,
    timeout_seconds=300,
    category=ToolCategory.FORENSICS,
)

MALWARE_ANALYZE = MCPToolDefinition(
    name="malware_analyze",
    description="Analyze potential malware samples in isolated sandbox environment.",
    parameters=[
        MCPToolParameter(
            name="file_path",
            type="string",
            description="Path to suspicious file",
            required=True,
        ),
        MCPToolParameter(
            name="sandbox",
            type="string",
            description="Sandbox environment to use",
            required=False,
            default="cape",
            enum=["cape", "cuckoo", "any_run"],
        ),
        MCPToolParameter(
            name="timeout",
            type="number",
            description="Analysis timeout in seconds",
            required=False,
            default=300,
        ),
    ],
    risk_level=RiskLevel.MEDIUM,
    requires_approval=True,
    timeout_seconds=600,
    category=ToolCategory.FORENSICS,
)

ELK_QUERY = MCPToolDefinition(
    name="elk_query",
    description="Query ELK Stack (Elasticsearch) for log analysis and SIEM data.",
    parameters=[
        MCPToolParameter(
            name="query",
            type="string",
            description="Elasticsearch DSL query or Lucene query string",
            required=True,
        ),
        MCPToolParameter(
            name="index",
            type="string",
            description="Index pattern to search (e.g., 'logs-*', 'filebeat-*')",
            required=False,
            default="logs-*",
        ),
        MCPToolParameter(
            name="time_range",
            type="string",
            description="Time range (e.g., 'now-24h', 'now-7d')",
            required=False,
            default="now-24h",
        ),
        MCPToolParameter(
            name="size",
            type="number",
            description="Number of results to return",
            required=False,
            default=100,
        ),
    ],
    risk_level=RiskLevel.LOW,
    requires_approval=False,
    timeout_seconds=120,
    category=ToolCategory.FORENSICS,
)

# Defense Tools
FIREWALL_BLOCK = MCPToolDefinition(
    name="firewall_block",
    description="Block IP address at firewall level. CRITICAL: This action affects network connectivity.",
    parameters=[
        MCPToolParameter(
            name="ip_address",
            type="string",
            description="IP address to block",
            required=True,
        ),
        MCPToolParameter(
            name="duration",
            type="number",
            description="Block duration in hours (0 for permanent)",
            required=False,
            default=24,
        ),
        MCPToolParameter(
            name="reason",
            type="string",
            description="Reason for blocking",
            required=True,
        ),
        MCPToolParameter(
            name="direction",
            type="string",
            description="Traffic direction to block",
            required=False,
            default="both",
            enum=["inbound", "outbound", "both"],
        ),
    ],
    risk_level=RiskLevel.CRITICAL,
    requires_approval=True,
    timeout_seconds=30,
    category=ToolCategory.DEFENSE,
)

WAF_RULE = MCPToolDefinition(
    name="waf_rule",
    description="Create or modify WAF (雷池) rule. Affects web application traffic filtering.",
    parameters=[
        MCPToolParameter(
            name="action",
            type="string",
            description="Rule action",
            required=True,
            enum=["create", "update", "delete", "enable", "disable"],
        ),
        MCPToolParameter(
            name="rule_type",
            type="string",
            description="Type of WAF rule",
            required=True,
            enum=["ip_block", "rate_limit", "custom_rule", "virtual_patch"],
        ),
        MCPToolParameter(
            name="rule_config",
            type="object",
            description="Rule configuration object",
            required=True,
        ),
    ],
    risk_level=RiskLevel.HIGH,
    requires_approval=True,
    timeout_seconds=60,
    category=ToolCategory.DEFENSE,
)

# Analysis Tools
MITRE_MAPPING = MCPToolDefinition(
    name="mitre_mapping",
    description="Map attack indicators to MITRE ATT&CK techniques and tactics.",
    parameters=[
        MCPToolParameter(
            name="indicators",
            type="array",
            description="List of attack indicators or behaviors",
            required=True,
        ),
        MCPToolParameter(
            name="include_mitigations",
            type="boolean",
            description="Include recommended mitigations",
            required=False,
            default=True,
        ),
    ],
    risk_level=RiskLevel.LOW,
    requires_approval=False,
    timeout_seconds=60,
    category=ToolCategory.ANALYSIS,
)

ATTACK_CHAIN_ANALYZE = MCPToolDefinition(
    name="attack_chain_analyze",
    description="Analyze and reconstruct attack chain from security events.",
    parameters=[
        MCPToolParameter(
            name="events",
            type="array",
            description="List of security events to analyze",
            required=True,
        ),
        MCPToolParameter(
            name="time_window",
            type="string",
            description="Time window for correlation",
            required=False,
            default="24h",
        ),
    ],
    risk_level=RiskLevel.LOW,
    requires_approval=False,
    timeout_seconds=300,
    category=ToolCategory.ANALYSIS,
)

# Reporting Tools
GENERATE_REPORT = MCPToolDefinition(
    name="generate_report",
    description="Generate security assessment or incident report.",
    parameters=[
        MCPToolParameter(
            name="report_type",
            type="string",
            description="Type of report to generate",
            required=True,
            enum=["vulnerability", "incident", "threat_intel", "compliance", "executive_summary"],
        ),
        MCPToolParameter(
            name="data",
            type="object",
            description="Report data and findings",
            required=True,
        ),
        MCPToolParameter(
            name="format",
            type="string",
            description="Output format",
            required=False,
            default="pdf",
            enum=["pdf", "html", "markdown", "json"],
        ),
        MCPToolParameter(
            name="classification",
            type="string",
            description="Report classification level",
            required=False,
            default="internal",
            enum=["public", "internal", "confidential", "restricted"],
        ),
    ],
    risk_level=RiskLevel.LOW,
    requires_approval=False,
    timeout_seconds=120,
    category=ToolCategory.REPORTING,
)


# ============================================================================
# Tool Registry
# ============================================================================

class MCPToolRegistry:
    """
    Registry of all available MCP tool definitions.
    
    Provides methods to look up tools by name, category, or risk level.
    """

    # All pre-defined tools
    ALL_TOOLS: List[MCPToolDefinition] = [
        # Network
        NMAP_SCAN,
        CENSYS_SEARCH,
        SHODAN_SEARCH,
        # Vulnerability
        NESSUS_SCAN,
        CVE_LOOKUP,
        # Threat Intel
        VIRUSTOTAL_LOOKUP,
        MISP_QUERY,
        THREATBOOK_QUERY,
        # Forensics
        PCAP_ANALYZE,
        MALWARE_ANALYZE,
        ELK_QUERY,
        # Defense
        FIREWALL_BLOCK,
        WAF_RULE,
        # Analysis
        MITRE_MAPPING,
        ATTACK_CHAIN_ANALYZE,
        # Reporting
        GENERATE_REPORT,
    ]

    def __init__(self):
        self._tools: Dict[str, MCPToolDefinition] = {
            t.name: t for t in self.ALL_TOOLS
        }

    def get(self, name: str) -> Optional[MCPToolDefinition]:
        """Get tool definition by name"""
        return self._tools.get(name)

    def list_all(self) -> List[MCPToolDefinition]:
        """List all tool definitions"""
        return list(self._tools.values())

    def list_by_category(self, category: str) -> List[MCPToolDefinition]:
        """List tools by category"""
        return [t for t in self._tools.values() if t.category == category]

    def list_by_risk_level(self, risk_level: str) -> List[MCPToolDefinition]:
        """List tools by risk level"""
        return [t for t in self._tools.values() if t.risk_level == risk_level]

    def list_requiring_approval(self) -> List[MCPToolDefinition]:
        """List tools that require approval"""
        return [t for t in self._tools.values() if t.requires_approval]

    def get_categories(self) -> List[str]:
        """Get all unique categories"""
        return list(set(t.category for t in self._tools.values()))

    def to_json_schema(self) -> Dict[str, Any]:
        """Export all tools as JSON Schema for AI consumption"""
        return {
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "parameters": {
                        "type": "object",
                        "properties": {
                            p.name: {
                                "type": p.type,
                                "description": p.description,
                                **({"enum": p.enum} if p.enum else {}),
                                **({"default": p.default} if p.default is not None else {}),
                            }
                            for p in t.parameters
                        },
                        "required": [p.name for p in t.parameters if p.required],
                    },
                    "metadata": {
                        "risk_level": t.risk_level,
                        "requires_approval": t.requires_approval,
                        "category": t.category,
                    }
                }
                for t in self._tools.values()
            ]
        }
