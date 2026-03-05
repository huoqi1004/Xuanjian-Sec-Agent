"""
玄鉴安全智能体 - 本地防御API
提供本地网络安全防护功能
"""

import re
from typing import Optional, List
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel, Field
from datetime import datetime

router = APIRouter()


def get_defense_manager():
    """获取防御管理器"""
    from app.services.local_defense import get_defense_manager as _get_manager
    return _get_manager()


class ScanRequest(BaseModel):
    target: Optional[str] = Field(default=None, description="扫描目标IP或网段")


class BlockIPRequest(BaseModel):
    ip: str = Field(..., description="要封禁的IP地址")
    reason: str = Field(..., description="封禁原因")
    duration: int = Field(default=3600, description="封禁时长(秒)")


class DefenseConfigRequest(BaseModel):
    auto_response: Optional[bool] = Field(default=None, description="启用/禁用自动响应")


@router.get("/network/info")
async def get_network_info():
    """获取本地网络信息"""
    manager = get_defense_manager()
    return manager.get_network_info()


@router.get("/network/scan")
async def quick_scan(target: Optional[str] = Query(default=None, description="扫描目标")):
    """快速扫描网络"""
    manager = get_defense_manager()
    return {
        "status": "completed",
        "target": target or "local_network",
        "results": manager.quick_scan(target)
    }


@router.post("/network/scan")
async def port_scan(request: ScanRequest):
    """端口扫描"""
    manager = get_defense_manager()
    return manager.port_scan(request.target or "127.0.0.1")


@router.get("/blocked-ips")
async def get_blocked_ips():
    """获取封禁IP列表"""
    manager = get_defense_manager()
    return {"blocked_ips": manager.get_blocked_ips()}


@router.post("/block-ip")
async def block_ip(request: BlockIPRequest):
    """封禁IP"""
    import re
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', request.ip):
        raise HTTPException(status_code=400, detail="无效的IP地址")
    
    manager = get_defense_manager()
    result = manager.add_blocked_ip(request.ip, request.reason, request.duration)
    
    return {
        "success": result["success"],
        "message": f"IP {request.ip} 已封禁" if result["success"] else result.get("message"),
        "rule_id": result.get("rule_id")
    }


@router.delete("/block-ip/{ip}")
async def unblock_ip(ip: str):
    """解除IP封禁"""
    manager = get_defense_manager()
    result = manager.remove_blocked_ip(ip)
    
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result.get("message"))
    
    return {"success": True, "message": f"IP {ip} 已解除封禁"}


@router.get("/threats")
async def get_threats(limit: int = Query(default=50, ge=1, le=100)):
    """获取威胁事件"""
    manager = get_defense_manager()
    return {"threats": manager.get_threat_events(limit)}


@router.post("/threats")
async def add_threat(event_type: str, source_ip: str, description: str, severity: str = "medium"):
    """手动添加威胁事件"""
    from app.services.local_defense import ThreatEvent
    manager = get_defense_manager()
    
    event = ThreatEvent(event_type, source_ip, description, severity)
    manager.add_threat_event(event)
    
    return {"success": True, "event_id": event.id}


@router.get("/stats")
async def get_defense_stats():
    """获取防御统计"""
    manager = get_defense_manager()
    return manager.get_defense_stats()


@router.get("/report")
async def get_security_report():
    """获取安全报告"""
    manager = get_defense_manager()
    return manager.generate_security_report()


@router.get("/config")
async def get_config():
    """获取防御配置"""
    manager = get_defense_manager()
    return {
        "auto_response_enabled": manager.auto_response_enabled,
        "alert_thresholds": manager.alert_thresholds,
        "network_segments": [seg.to_dict() for seg in manager.network_segments]
    }


@router.post("/config")
async def update_config(request: DefenseConfigRequest):
    """更新防御配置"""
    manager = get_defense_manager()
    
    if request.auto_response is not None:
        manager.auto_response_enabled = request.auto_response
    
    return {
        "success": True,
        "auto_response_enabled": manager.auto_response_enabled
    }


@router.post("/monitoring/start")
async def start_monitoring():
    """启动监控"""
    manager = get_defense_manager()
    manager.start_monitoring()
    return {"success": True, "message": "监控已启动"}


@router.post("/monitoring/stop")
async def stop_monitoring():
    """停止监控"""
    manager = get_defense_manager()
    manager.stop_monitoring()
    return {"success": True, "message": "监控已停止"}


@router.get("/status")
async def get_status():
    """获取防御系统状态"""
    manager = get_defense_manager()
    return {
        "status": "running",
        "monitoring": manager.monitoring,
        "firewall_available": manager.firewall_available,
        "local_ip": manager.get_local_ip(),
        "blocked_ips_count": len(manager.blocked_ips),
        "threats_count": len(manager.threat_events)
    }
