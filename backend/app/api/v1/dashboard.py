"""
玄鉴安全智能体 - 仪表盘API
提供安全态势总览数据
"""

from typing import List, Optional, Dict
from datetime import datetime, timedelta
from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.services.microstep_api import MicroStepAPI

router = APIRouter()
microstep_api = MicroStepAPI()


# ============ Schema定义 ============

class RiskScoreResponse(BaseModel):
    """风险评分响应"""
    score: float = Field(..., description="当前风险评分(0-100)")
    level: str = Field(..., description="风险等级")
    trend: str = Field(..., description="趋势(up/down/stable)")
    change_percent: float = Field(..., description="相比昨日变化百分比")


class AssetSummary(BaseModel):
    """资产摘要"""
    total: int = Field(..., description="资产总数")
    online: int = Field(..., description="在线资产数")
    at_risk: int = Field(..., description="存在风险的资产数")
    new_discovered: int = Field(..., description="新发现资产数")


class ThreatSummary(BaseModel):
    """威胁摘要"""
    active_threats: int = Field(..., description="活跃威胁数")
    blocked_attacks: int = Field(..., description="已拦截攻击数")
    pending_alerts: int = Field(..., description="待处理告警数")
    mitre_techniques: int = Field(..., description="涉及ATT&CK技术数")


class VulnSummary(BaseModel):
    """漏洞摘要"""
    total: int = Field(..., description="漏洞总数")
    critical: int = Field(..., description="严重漏洞数")
    high: int = Field(..., description="高危漏洞数")
    medium: int = Field(..., description="中危漏洞数")
    low: int = Field(..., description="低危漏洞数")
    patched_today: int = Field(..., description="今日修复数")


class AlertItem(BaseModel):
    """告警项"""
    id: str = Field(..., description="告警ID")
    title: str = Field(..., description="告警标题")
    severity: str = Field(..., description="严重程度")
    source: str = Field(..., description="来源")
    timestamp: datetime = Field(..., description="发生时间")
    status: str = Field(..., description="状态")


class DashboardOverview(BaseModel):
    """仪表盘总览"""
    risk_score: RiskScoreResponse
    assets: AssetSummary
    threats: ThreatSummary
    vulnerabilities: VulnSummary
    recent_alerts: List[AlertItem]
    last_updated: datetime


class ThreatLocation(BaseModel):
    """威胁地理位置"""
    country: str
    city: Optional[str] = None
    lat: float
    lng: float
    threat_count: int
    threat_score: float


class TimeSeriesPoint(BaseModel):
    """时序数据点"""
    timestamp: datetime
    value: float


# ============ API端点 ============

@router.get("/overview", response_model=DashboardOverview)
async def get_overview():
    """
    获取仪表盘总览数据
    
    返回包含风险评分、资产摘要、威胁摘要、漏洞摘要、近期告警的完整概览
    """
    # 从微步API获取安全态势数据
    security_data = await microstep_api.get_security态势()
    
    # 转换为响应模型
    return DashboardOverview(
        risk_score=RiskScoreResponse(
            score=security_data.get("security_score", 85),
            level="medium" if 40 <= security_data.get("security_score", 85) < 70 else "low" if security_data.get("security_score", 85) < 40 else "high",
            trend="up",
            change_percent=2.5
        ),
        assets=AssetSummary(
            total=security_data.get("assets", {}).get("total", 1200),
            online=security_data.get("assets", {}).get("online", 1150),
            at_risk=security_data.get("assets", {}).get("risky", 80),
            new_discovered=5
        ),
        threats=ThreatSummary(
            active_threats=security_data.get("threats", {}).get("total", 86),
            blocked_attacks=847,
            pending_alerts=8,
            mitre_techniques=15
        ),
        vulnerabilities=VulnSummary(
            total=security_data.get("vulnerabilities", {}).get("total", 124),
            critical=security_data.get("vulnerabilities", {}).get("high", 30),
            high=security_data.get("vulnerabilities", {}).get("high", 30),
            medium=security_data.get("vulnerabilities", {}).get("medium", 50),
            low=security_data.get("vulnerabilities", {}).get("low", 44),
            patched_today=7
        ),
        recent_alerts=[
            AlertItem(
                id=alert.get("id", ""),
                title=alert.get("name", ""),
                severity=alert.get("severity", "medium"),
                source=alert.get("source", ""),
                timestamp=datetime.now() - timedelta(minutes=5 * i),
                status="pending"
            ) for i, alert in enumerate(security_data.get("recent_threats", []))
        ],
        last_updated=datetime.now()
    )


@router.get("/risk-score", response_model=RiskScoreResponse)
async def get_risk_score():
    """获取当前风险评分"""
    return RiskScoreResponse(
        score=45.2,
        level="medium",
        trend="down",
        change_percent=-5.3
    )


@router.get("/threat-map", response_model=List[ThreatLocation])
async def get_threat_map(
    time_range: str = Query(default="24h", description="时间范围: 1h/24h/7d/30d")
):
    """
    获取威胁地理分布数据
    
    用于在地图上展示威胁来源分布
    """
    # TODO: 从威胁情报和日志中聚合地理数据
    return [
        ThreatLocation(
            country="中国",
            city="北京",
            lat=39.9042,
            lng=116.4074,
            threat_count=45,
            threat_score=65.0
        ),
        ThreatLocation(
            country="美国",
            city="纽约",
            lat=40.7128,
            lng=-74.0060,
            threat_count=23,
            threat_score=78.5
        ),
        ThreatLocation(
            country="俄罗斯",
            city="莫斯科",
            lat=55.7558,
            lng=37.6173,
            threat_count=67,
            threat_score=85.2
        )
    ]


@router.get("/alerts/timeline", response_model=List[TimeSeriesPoint])
async def get_alerts_timeline(
    time_range: str = Query(default="24h", description="时间范围"),
    interval: str = Query(default="1h", description="聚合间隔")
):
    """获取告警时序数据"""
    # TODO: 从ES聚合告警数据
    now = datetime.now()
    return [
        TimeSeriesPoint(timestamp=now - timedelta(hours=i), value=float(10 + i * 2))
        for i in range(24)
    ]


@router.get("/traffic/timeline", response_model=List[TimeSeriesPoint])
async def get_traffic_timeline(
    time_range: str = Query(default="24h", description="时间范围"),
    metric: str = Query(default="bytes", description="指标: bytes/packets/connections")
):
    """获取流量时序数据"""
    # TODO: 从ES聚合流量数据
    now = datetime.now()
    return [
        TimeSeriesPoint(timestamp=now - timedelta(hours=i), value=float(1000000 + i * 50000))
        for i in range(24)
    ]


@router.get("/quick-stats")
async def get_quick_stats():
    """获取快速统计数据"""
    return {
        "scans_today": 15,
        "blocked_ips": 234,
        "active_workflows": 3,
        "ai_queries": 127,
        "uptime_hours": 720,
        "last_scan": datetime.now() - timedelta(hours=2)
    }


@router.get("/security-posture")
async def get_security_posture():
    """
    获取安全态势数据
    
    返回包含威胁趋势、漏洞趋势、资产分布等数据
    """
    # 从微步API获取安全态势数据
    security_data = await microstep_api.get_security态势()
    
    return {
        "threats": {
            "total": security_data.get("threats", {}).get("total", 86),
            "high": security_data.get("threats", {}).get("high", 25),
            "medium": security_data.get("threats", {}).get("medium", 35),
            "low": security_data.get("threats", {}).get("low", 26),
            "trend": security_data.get("threats", {}).get("trend", [12, 19, 15, 20, 25, 22])
        },
        "vulnerabilities": {
            "total": security_data.get("vulnerabilities", {}).get("total", 124),
            "high": security_data.get("vulnerabilities", {}).get("high", 30),
            "medium": security_data.get("vulnerabilities", {}).get("medium", 50),
            "low": security_data.get("vulnerabilities", {}).get("low", 44),
            "trend": security_data.get("vulnerabilities", {}).get("trend", [20, 25, 22, 28, 30, 29])
        },
        "assets": {
            "total": security_data.get("assets", {}).get("total", 1200),
            "online": security_data.get("assets", {}).get("online", 1150),
            "offline": security_data.get("assets", {}).get("offline", 50),
            "risky": security_data.get("assets", {}).get("risky", 80),
            "distribution": [
                {"name": "服务器", "value": 30},
                {"name": "网络设备", "value": 25},
                {"name": "安全设备", "value": 20},
                {"name": "应用系统", "value": 15},
                {"name": "其他", "value": 10}
            ]
        },
        "security_score": security_data.get("security_score", 85),
        "recent_threats": security_data.get("recent_threats", []),
        "security_status": [
            {"name": "系统安全", "value": 85},
            {"name": "网络安全", "value": 78},
            {"name": "应用安全", "value": 90},
            {"name": "数据安全", "value": 82},
            {"name": "合规性", "value": 88}
        ]
    }


@router.get("/threat-intel/query")
async def query_threat_intel(
    indicator: str = Query(..., description="查询指标，如IP、域名、哈希或URL"),
    indicator_type: str = Query(..., description="指标类型: ip, domain, hash, url")
):
    """
    查询威胁情报
    
    根据指标类型查询对应的威胁情报数据
    """
    if indicator_type == "ip":
        result = await microstep_api.query_ip(indicator)
    elif indicator_type == "domain":
        result = await microstep_api.query_domain(indicator)
    elif indicator_type == "hash":
        result = await microstep_api.query_hash(indicator)
    elif indicator_type == "url":
        result = await microstep_api.query_url(indicator)
    else:
        return {"error": "Invalid indicator type"}
    
    if result:
        return result
    else:
        return {"error": "No data found or API key not set"}


@router.get("/threat-intel/local")
async def get_local_threat_intel(
    skip: int = Query(default=0, description="跳过记录数"),
    limit: int = Query(default=10, description="返回记录数"),
    indicator_type: str = Query(default=None, description="指标类型筛选")
):
    """
    获取本地威胁情报数据
    
    从本地数据库获取威胁情报记录
    """
    from app.database import SessionLocal
    from app.database.models import ThreatIntelligence
    
    db = SessionLocal()
    try:
        query = db.query(ThreatIntelligence)
        
        if indicator_type:
            query = query.filter(ThreatIntelligence.indicator_type == indicator_type)
        
        total = query.count()
        records = query.offset(skip).limit(limit).all()
        
        return {
            "total": total,
            "records": [
                {
                    "id": record.id,
                    "indicator": record.indicator,
                    "indicator_type": record.indicator_type,
                    "threat_type": record.threat_type,
                    "severity": record.severity,
                    "description": record.description,
                    "source": record.source,
                    "confidence": record.confidence,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                    "reference": record.reference,
                    "created_at": record.created_at,
                    "updated_at": record.updated_at
                }
                for record in records
            ]
        }
    finally:
        db.close()
