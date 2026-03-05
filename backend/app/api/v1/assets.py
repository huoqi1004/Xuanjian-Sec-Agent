"""
玄鉴安全智能体 - 资产管理API
提供资产扫描、发现、管理功能
"""

from typing import List, Optional
from datetime import datetime
from enum import Enum
from fastapi import APIRouter, Query, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field, field_validator
import re

router = APIRouter()


# ============ 枚举定义 ============

class ScanType(str, Enum):
    NMAP = "nmap"
    CENSYS = "censys"
    PASSIVE = "passive"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============ Schema定义 ============

class Port(BaseModel):
    """端口信息"""
    port: int = Field(..., ge=1, le=65535, description="端口号")
    protocol: str = Field(default="tcp", description="协议")
    state: str = Field(default="open", description="状态")
    service: Optional[str] = Field(default=None, description="服务名称")
    version: Optional[str] = Field(default=None, description="服务版本")
    risk_level: Optional[RiskLevel] = Field(default=None, description="风险等级")


class Asset(BaseModel):
    """资产信息"""
    id: str = Field(..., description="资产ID")
    ip: str = Field(..., description="IP地址")
    hostname: Optional[str] = Field(default=None, description="主机名")
    mac: Optional[str] = Field(default=None, description="MAC地址")
    os: Optional[str] = Field(default=None, description="操作系统")
    os_confidence: Optional[int] = Field(default=None, ge=0, le=100, description="OS识别置信度")
    ports: List[Port] = Field(default=[], description="开放端口列表")
    tags: List[str] = Field(default=[], description="标签")
    risk_score: float = Field(default=0.0, ge=0, le=100, description="风险评分")
    first_seen: datetime = Field(..., description="首次发现时间")
    last_seen: datetime = Field(..., description="最后发现时间")
    location: Optional[dict] = Field(default=None, description="地理位置")


class AssetScanRequest(BaseModel):
    """资产扫描请求"""
    scope: str = Field(..., description="扫描范围(IP/CIDR/域名)")
    scan_type: ScanType = Field(default=ScanType.NMAP, description="扫描类型")
    ports: Optional[str] = Field(default="1-1000", description="端口范围")
    include_os: bool = Field(default=True, description="是否识别OS")
    rate: int = Field(default=1000, ge=100, le=10000, description="扫描速率")
    
    @field_validator('scope')
    @classmethod
    def validate_scope(cls, v):
        """验证扫描范围格式"""
        # IP地址
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # CIDR
        cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        # 域名
        domain_pattern = r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$'
        
        if not (re.match(ip_pattern, v) or re.match(cidr_pattern, v) or re.match(domain_pattern, v)):
            raise ValueError('无效的扫描范围格式，请输入IP、CIDR或域名')
        return v


class AssetScanResponse(BaseModel):
    """资产扫描响应"""
    scan_id: str = Field(..., description="扫描任务ID")
    status: ScanStatus = Field(..., description="扫描状态")
    scope: str = Field(..., description="扫描范围")
    scan_type: ScanType = Field(..., description="扫描类型")
    created_at: datetime = Field(..., description="创建时间")
    estimated_duration: Optional[int] = Field(default=None, description="预计耗时(秒)")


class ScanResult(BaseModel):
    """扫描结果"""
    scan_id: str
    status: ScanStatus
    assets: List[Asset] = []
    summary: dict = {}
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


class AssetListResponse(BaseModel):
    """资产列表响应"""
    total: int
    items: List[Asset]
    page: int
    page_size: int


# ============ API端点 ============

@router.post("/scan", response_model=AssetScanResponse)
async def start_asset_scan(
    request: AssetScanRequest,
    background_tasks: BackgroundTasks
):
    """
    发起资产扫描任务
    
    支持Nmap主动扫描、Censys被动扫描和流量分析被动发现
    """
    import uuid
    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
    
    # TODO: 将扫描任务加入后台队列
    # background_tasks.add_task(run_asset_scan, scan_id, request)
    
    return AssetScanResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        scope=request.scope,
        scan_type=request.scan_type,
        created_at=datetime.now(),
        estimated_duration=300 if request.scan_type == ScanType.NMAP else 60
    )


@router.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan_status(scan_id: str):
    """获取扫描任务状态和结果"""
    # TODO: 从数据库获取扫描状态
    return ScanResult(
        scan_id=scan_id,
        status=ScanStatus.COMPLETED,
        assets=[
            Asset(
                id="ASSET-001",
                ip="192.168.1.1",
                hostname="gateway",
                os="Linux 5.x",
                os_confidence=95,
                ports=[
                    Port(port=22, service="ssh", version="OpenSSH 8.2"),
                    Port(port=80, service="http", version="nginx 1.18")
                ],
                tags=["gateway", "linux"],
                risk_score=25.0,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
        ],
        summary={
            "total_assets": 1,
            "total_ports": 2,
            "services": {"ssh": 1, "http": 1}
        },
        started_at=datetime.now(),
        completed_at=datetime.now()
    )


@router.get("/inventory", response_model=AssetListResponse)
async def list_assets(
    page: int = Query(default=1, ge=1, description="页码"),
    page_size: int = Query(default=20, ge=1, le=100, description="每页数量"),
    ip: Optional[str] = Query(default=None, description="IP过滤"),
    os: Optional[str] = Query(default=None, description="OS过滤"),
    tag: Optional[str] = Query(default=None, description="标签过滤"),
    risk_level: Optional[RiskLevel] = Query(default=None, description="风险等级过滤"),
    sort_by: str = Query(default="last_seen", description="排序字段"),
    sort_order: str = Query(default="desc", description="排序方向")
):
    """
    获取资产清单列表
    
    支持分页、过滤和排序
    """
    # TODO: 从数据库查询资产
    return AssetListResponse(
        total=1,
        items=[
            Asset(
                id="ASSET-001",
                ip="192.168.1.1",
                hostname="gateway",
                os="Linux 5.x",
                os_confidence=95,
                ports=[
                    Port(port=22, service="ssh"),
                    Port(port=80, service="http")
                ],
                tags=["gateway"],
                risk_score=25.0,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
        ],
        page=page,
        page_size=page_size
    )


@router.get("/{asset_id}", response_model=Asset)
async def get_asset(asset_id: str):
    """获取单个资产详情"""
    # TODO: 从数据库查询资产
    return Asset(
        id=asset_id,
        ip="192.168.1.1",
        hostname="gateway",
        os="Linux 5.x",
        os_confidence=95,
        ports=[
            Port(port=22, service="ssh", version="OpenSSH 8.2"),
            Port(port=80, service="http", version="nginx 1.18")
        ],
        tags=["gateway", "linux"],
        risk_score=25.0,
        first_seen=datetime.now(),
        last_seen=datetime.now()
    )


@router.put("/{asset_id}/tags")
async def update_asset_tags(asset_id: str, tags: List[str]):
    """更新资产标签"""
    # TODO: 更新数据库
    return {"message": "标签更新成功", "asset_id": asset_id, "tags": tags}


@router.delete("/{asset_id}")
async def delete_asset(asset_id: str):
    """删除资产"""
    # TODO: 从数据库删除
    return {"message": "资产删除成功", "asset_id": asset_id}


@router.get("/topology/graph")
async def get_network_topology():
    """获取网络拓扑图数据"""
    # TODO: 构建网络拓扑
    return {
        "nodes": [
            {"id": "1", "label": "Gateway", "type": "router"},
            {"id": "2", "label": "Web Server", "type": "server"},
            {"id": "3", "label": "Database", "type": "database"}
        ],
        "edges": [
            {"source": "1", "target": "2"},
            {"source": "2", "target": "3"}
        ]
    }
