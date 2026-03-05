"""
玄鉴安全智能体 - 防御拦截API
提供WAF规则管理、IP封堵、联动防御功能
"""

from typing import List, Optional
from datetime import datetime, timedelta
from enum import Enum
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()


# ============ 枚举定义 ============

class BlockDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BOTH = "both"


class BlockStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    MANUALLY_REMOVED = "manually_removed"


class RuleAction(str, Enum):
    BLOCK = "block"
    ALLOW = "allow"
    LOG = "log"
    CHALLENGE = "challenge"


# ============ Schema定义 ============

class BlockIPRequest(BaseModel):
    """IP封堵请求"""
    ip: str = Field(..., description="要封堵的IP地址")
    direction: BlockDirection = Field(default=BlockDirection.BOTH, description="封堵方向")
    duration: int = Field(default=3600, ge=0, description="封堵时长(秒), 0为永久")
    reason: str = Field(..., description="封堵原因")
    notify_soc: bool = Field(default=True, description="是否通知SOC")


class BlockIPResponse(BaseModel):
    """IP封堵响应"""
    rule_id: str
    ip: str
    direction: BlockDirection
    status: BlockStatus
    created_at: datetime
    expires_at: Optional[datetime]
    reason: str
    created_by: str


class BlockedIP(BaseModel):
    """已封堵的IP"""
    rule_id: str
    ip: str
    direction: BlockDirection
    status: BlockStatus
    reason: str
    created_at: datetime
    expires_at: Optional[datetime]
    created_by: str
    hit_count: int = 0


class WAFRule(BaseModel):
    """WAF规则"""
    rule_id: str
    name: str
    description: str
    action: RuleAction
    condition: str
    enabled: bool
    priority: int
    hit_count: int
    created_at: datetime
    updated_at: datetime


class WAFRuleRequest(BaseModel):
    """WAF规则创建/更新请求"""
    name: str = Field(..., description="规则名称")
    description: str = Field(default="", description="规则描述")
    action: RuleAction = Field(..., description="匹配动作")
    condition: str = Field(..., description="匹配条件")
    enabled: bool = Field(default=True, description="是否启用")
    priority: int = Field(default=100, description="优先级")


class DefenseStats(BaseModel):
    """防御统计"""
    blocked_requests_24h: int
    blocked_ips_24h: int
    active_block_rules: int
    active_waf_rules: int
    top_attack_types: List[dict]
    top_blocked_ips: List[dict]


# ============ API端点 ============

@router.post("/block-ip", response_model=BlockIPResponse)
async def block_ip(request: BlockIPRequest):
    """
    封堵IP地址
    
    高危操作，需要人工审批确认
    支持设置封堵方向和时长
    """
    import uuid
    
    # 验证IP格式
    import re
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', request.ip):
        raise HTTPException(status_code=400, detail="无效的IP地址格式")
    
    # 检查是否在白名单中
    whitelist = ["127.0.0.1", "10.0.0.1", "192.168.1.1"]  # TODO: 从配置读取
    if request.ip in whitelist:
        raise HTTPException(status_code=400, detail="该IP在白名单中，无法封堵")
    
    rule_id = f"BLOCK-{uuid.uuid4().hex[:8].upper()}"
    expires_at = None
    if request.duration > 0:
        expires_at = datetime.now() + timedelta(seconds=request.duration)
    
    # TODO: 
    # 1. 创建审批请求
    # 2. 等待审批通过
    # 3. 执行封堵操作（iptables/WAF）
    # 4. 记录审计日志
    
    return BlockIPResponse(
        rule_id=rule_id,
        ip=request.ip,
        direction=request.direction,
        status=BlockStatus.ACTIVE,
        created_at=datetime.now(),
        expires_at=expires_at,
        reason=request.reason,
        created_by="system"
    )


@router.delete("/block-ip/{rule_id}")
async def unblock_ip(rule_id: str, comment: str = ""):
    """解除IP封堵"""
    return {
        "message": "IP封堵已解除",
        "rule_id": rule_id,
        "status": "removed",
        "comment": comment
    }


@router.get("/blocked-ips", response_model=List[BlockedIP])
async def list_blocked_ips(
    status: Optional[BlockStatus] = None,
    direction: Optional[BlockDirection] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100)
):
    """获取已封堵IP列表"""
    return [
        BlockedIP(
            rule_id="BLOCK-001",
            ip="203.0.113.50",
            direction=BlockDirection.BOTH,
            status=BlockStatus.ACTIVE,
            reason="检测到暴力破解行为",
            created_at=datetime.now() - timedelta(hours=2),
            expires_at=datetime.now() + timedelta(hours=22),
            created_by="auto",
            hit_count=1523
        )
    ]


@router.get("/waf/rules", response_model=List[WAFRule])
async def list_waf_rules(
    enabled: Optional[bool] = None,
    action: Optional[RuleAction] = None
):
    """获取WAF规则列表"""
    return [
        WAFRule(
            rule_id="WAF-001",
            name="SQL注入防护",
            description="检测并阻止SQL注入攻击",
            action=RuleAction.BLOCK,
            condition="request.body contains 'union select'",
            enabled=True,
            priority=10,
            hit_count=2341,
            created_at=datetime.now() - timedelta(days=30),
            updated_at=datetime.now()
        ),
        WAFRule(
            rule_id="WAF-002",
            name="XSS防护",
            description="检测并阻止XSS攻击",
            action=RuleAction.BLOCK,
            condition="request.body contains '<script>'",
            enabled=True,
            priority=20,
            hit_count=1892,
            created_at=datetime.now() - timedelta(days=30),
            updated_at=datetime.now()
        )
    ]


@router.post("/waf/rules", response_model=WAFRule)
async def create_waf_rule(request: WAFRuleRequest):
    """创建WAF规则"""
    import uuid
    rule_id = f"WAF-{uuid.uuid4().hex[:8].upper()}"
    
    return WAFRule(
        rule_id=rule_id,
        name=request.name,
        description=request.description,
        action=request.action,
        condition=request.condition,
        enabled=request.enabled,
        priority=request.priority,
        hit_count=0,
        created_at=datetime.now(),
        updated_at=datetime.now()
    )


@router.put("/waf/rules/{rule_id}")
async def update_waf_rule(rule_id: str, request: WAFRuleRequest):
    """更新WAF规则"""
    return {
        "message": "规则更新成功",
        "rule_id": rule_id,
        "updated_at": datetime.now()
    }


@router.delete("/waf/rules/{rule_id}")
async def delete_waf_rule(rule_id: str):
    """删除WAF规则"""
    return {"message": "规则删除成功", "rule_id": rule_id}


@router.put("/waf/rules/{rule_id}/toggle")
async def toggle_waf_rule(rule_id: str, enabled: bool):
    """启用/禁用WAF规则"""
    return {
        "message": f"规则已{'启用' if enabled else '禁用'}",
        "rule_id": rule_id,
        "enabled": enabled
    }


@router.get("/stats", response_model=DefenseStats)
async def get_defense_stats():
    """获取防御统计数据"""
    return DefenseStats(
        blocked_requests_24h=15234,
        blocked_ips_24h=89,
        active_block_rules=234,
        active_waf_rules=45,
        top_attack_types=[
            {"type": "SQL Injection", "count": 5234},
            {"type": "XSS", "count": 3421},
            {"type": "Path Traversal", "count": 2134},
            {"type": "Brute Force", "count": 1893}
        ],
        top_blocked_ips=[
            {"ip": "203.0.113.50", "count": 2341},
            {"ip": "198.51.100.23", "count": 1892},
            {"ip": "192.0.2.100", "count": 1234}
        ]
    )


@router.post("/isolate/{asset_id}")
async def isolate_asset(asset_id: str, reason: str):
    """
    隔离资产
    
    将资产从网络中隔离，阻止其与其他系统通信
    高危操作，需要人工审批
    """
    return {
        "message": "资产隔离请求已提交",
        "asset_id": asset_id,
        "reason": reason,
        "status": "pending_approval"
    }


@router.post("/restore/{asset_id}")
async def restore_asset(asset_id: str, comment: str = ""):
    """恢复被隔离的资产"""
    return {
        "message": "资产已恢复网络连接",
        "asset_id": asset_id,
        "comment": comment
    }
