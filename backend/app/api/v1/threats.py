"""
玄鉴安全智能体 - 威胁分析API
提供威胁情报查询、分析功能
"""

from typing import List, Optional
from datetime import datetime
from enum import Enum
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()


# ============ 枚举定义 ============

class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class IntelSource(str, Enum):
    THREATBOOK = "threatbook"
    VIRUSTOTAL = "virustotal"
    MISP = "misp"
    OTX = "otx"
    LOCAL = "local"


# ============ Schema定义 ============

class MitreAttack(BaseModel):
    """MITRE ATT&CK技术"""
    technique_id: str = Field(..., description="技术ID")
    technique_name: str = Field(..., description="技术名称")
    tactic: str = Field(..., description="战术")
    sub_techniques: List[str] = Field(default=[], description="子技术")


class ThreatSource(BaseModel):
    """威胁情报来源"""
    name: IntelSource = Field(..., description="来源名称")
    confidence: float = Field(..., ge=0, le=100, description="置信度")
    last_updated: datetime = Field(..., description="最后更新时间")
    raw_data: Optional[dict] = Field(default=None, description="原始数据")


class ThreatIntelRequest(BaseModel):
    """威胁情报查询请求"""
    indicator: str = Field(..., description="IOC值")
    indicator_type: Optional[IndicatorType] = Field(default=None, description="IOC类型(可自动推断)")
    sources: List[IntelSource] = Field(
        default=[IntelSource.THREATBOOK, IntelSource.VIRUSTOTAL],
        description="查询来源"
    )
    enrich_mitre: bool = Field(default=True, description="是否关联MITRE ATT&CK")
    use_cache: bool = Field(default=True, description="是否使用缓存")


class ThreatIntelResponse(BaseModel):
    """威胁情报查询响应"""
    indicator: str = Field(..., description="IOC值")
    indicator_type: IndicatorType = Field(..., description="IOC类型")
    is_malicious: bool = Field(..., description="是否恶意")
    threat_score: float = Field(..., ge=0, le=100, description="威胁评分")
    threat_level: ThreatLevel = Field(..., description="威胁等级")
    tags: List[str] = Field(default=[], description="标签")
    mitre_techniques: List[MitreAttack] = Field(default=[], description="关联ATT&CK技术")
    sources: List[ThreatSource] = Field(default=[], description="情报来源详情")
    first_seen: Optional[datetime] = Field(default=None, description="首次发现时间")
    last_seen: Optional[datetime] = Field(default=None, description="最后活跃时间")
    related_iocs: List[str] = Field(default=[], description="关联IOC")
    cached: bool = Field(default=False, description="是否来自缓存")
    query_time_ms: int = Field(..., description="查询耗时(毫秒)")


class ThreatEvent(BaseModel):
    """威胁事件"""
    id: str = Field(..., description="事件ID")
    title: str = Field(..., description="事件标题")
    description: str = Field(..., description="事件描述")
    severity: ThreatLevel = Field(..., description="严重程度")
    source_ip: Optional[str] = Field(default=None, description="来源IP")
    target_ip: Optional[str] = Field(default=None, description="目标IP")
    indicators: List[str] = Field(default=[], description="相关IOC")
    mitre_techniques: List[str] = Field(default=[], description="ATT&CK技术ID")
    timestamp: datetime = Field(..., description="发生时间")
    status: str = Field(default="open", description="状态")


class ThreatEventListResponse(BaseModel):
    """威胁事件列表响应"""
    total: int
    items: List[ThreatEvent]
    page: int
    page_size: int


# ============ API端点 ============

@router.post("/intel/query", response_model=ThreatIntelResponse)
async def query_threat_intel(request: ThreatIntelRequest):
    """
    查询威胁情报
    
    支持IP、域名、URL、文件哈希、CVE等IOC类型的查询
    自动从多个情报源聚合数据
    """
    import time
    start_time = time.time()
    
    # 自动推断IOC类型
    indicator_type = request.indicator_type
    if not indicator_type:
        indicator_type = _detect_indicator_type(request.indicator)
    
    # TODO: 实际调用情报API
    # - 微步在线
    # - VirusTotal
    # - MISP
    # - 本地威胁库
    
    query_time = int((time.time() - start_time) * 1000)
    
    return ThreatIntelResponse(
        indicator=request.indicator,
        indicator_type=indicator_type,
        is_malicious=True,
        threat_score=75.5,
        threat_level=ThreatLevel.HIGH,
        tags=["malware", "botnet", "c2"],
        mitre_techniques=[
            MitreAttack(
                technique_id="T1071",
                technique_name="Application Layer Protocol",
                tactic="Command and Control",
                sub_techniques=["T1071.001"]
            )
        ],
        sources=[
            ThreatSource(
                name=IntelSource.THREATBOOK,
                confidence=85.0,
                last_updated=datetime.now()
            ),
            ThreatSource(
                name=IntelSource.VIRUSTOTAL,
                confidence=78.0,
                last_updated=datetime.now()
            )
        ],
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        related_iocs=["evil.com", "192.168.1.100"],
        cached=False,
        query_time_ms=query_time
    )


def _detect_indicator_type(indicator: str) -> IndicatorType:
    """自动检测IOC类型"""
    import re
    
    # IP地址
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', indicator):
        return IndicatorType.IP
    
    # MD5
    if re.match(r'^[a-fA-F0-9]{32}$', indicator):
        return IndicatorType.MD5
    
    # SHA1
    if re.match(r'^[a-fA-F0-9]{40}$', indicator):
        return IndicatorType.SHA1
    
    # SHA256
    if re.match(r'^[a-fA-F0-9]{64}$', indicator):
        return IndicatorType.SHA256
    
    # CVE
    if re.match(r'^CVE-\d{4}-\d+$', indicator, re.IGNORECASE):
        return IndicatorType.CVE
    
    # URL
    if indicator.startswith(('http://', 'https://')):
        return IndicatorType.URL
    
    # 默认域名
    return IndicatorType.DOMAIN


@router.get("/intel/batch")
async def batch_query_intel(indicators: str = Query(..., description="IOC列表,逗号分隔")):
    """批量查询威胁情报"""
    ioc_list = [i.strip() for i in indicators.split(',') if i.strip()]
    
    if len(ioc_list) > 100:
        raise HTTPException(status_code=400, detail="单次最多查询100个IOC")
    
    # TODO: 并行查询多个IOC
    results = []
    for ioc in ioc_list:
        results.append({
            "indicator": ioc,
            "is_malicious": False,
            "threat_score": 0.0,
            "threat_level": "safe"
        })
    
    return {"total": len(results), "results": results}


@router.get("/events", response_model=ThreatEventListResponse)
async def list_threat_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    severity: Optional[ThreatLevel] = None,
    status: Optional[str] = None,
    from_time: Optional[datetime] = None,
    to_time: Optional[datetime] = None
):
    """获取威胁事件列表"""
    # TODO: 从数据库查询事件
    return ThreatEventListResponse(
        total=1,
        items=[
            ThreatEvent(
                id="EVT-001",
                title="检测到C2通信行为",
                description="主机192.168.1.50与已知C2服务器建立连接",
                severity=ThreatLevel.HIGH,
                source_ip="192.168.1.50",
                target_ip="203.0.113.50",
                indicators=["203.0.113.50", "evil-c2.com"],
                mitre_techniques=["T1071", "T1105"],
                timestamp=datetime.now(),
                status="open"
            )
        ],
        page=page,
        page_size=page_size
    )


@router.get("/events/{event_id}", response_model=ThreatEvent)
async def get_threat_event(event_id: str):
    """获取威胁事件详情"""
    return ThreatEvent(
        id=event_id,
        title="检测到C2通信行为",
        description="主机192.168.1.50与已知C2服务器建立连接",
        severity=ThreatLevel.HIGH,
        source_ip="192.168.1.50",
        target_ip="203.0.113.50",
        indicators=["203.0.113.50", "evil-c2.com"],
        mitre_techniques=["T1071", "T1105"],
        timestamp=datetime.now(),
        status="open"
    )


@router.post("/events/{event_id}/acknowledge")
async def acknowledge_event(event_id: str):
    """确认威胁事件"""
    return {"message": "事件已确认", "event_id": event_id, "status": "acknowledged"}


@router.post("/events/{event_id}/resolve")
async def resolve_event(event_id: str, comment: str = ""):
    """解决威胁事件"""
    return {"message": "事件已解决", "event_id": event_id, "status": "resolved", "comment": comment}


@router.get("/mitre/matrix")
async def get_mitre_matrix():
    """获取MITRE ATT&CK矩阵热力图数据"""
    # TODO: 聚合统计各技术使用频率
    return {
        "tactics": [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact"
        ],
        "techniques": [
            {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "count": 45},
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "count": 32},
            {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "count": 28}
        ]
    }
