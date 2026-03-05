"""
Self-Improving Security API - 自改进安全系统接口
"""

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime

router = APIRouter()


class SecurityEventRequest(BaseModel):
    """安全事件请求"""
    type: str = Field(..., description="事件类型")
    source: str = Field(..., description="事件来源")
    severity: str = Field(default="medium", description="严重程度")
    details: Dict = Field(default={}, description="详细信息")
    indicators: List[str] = Field(default=[], description="威胁指标")


class ThreatIntelRequest(BaseModel):
    """威胁情报请求"""
    name: str = Field(..., description="威胁名称")
    category: str = Field(default="unknown", description="威胁类别")
    severity: str = Field(default="medium", description="严重程度")
    description: str = Field(default="", description="描述")
    attack_patterns: List[str] = Field(default=[], description="攻击模式")
    indicators: List[str] = Field(default=[], description="IOC指标")
    mitigations: List[str] = Field(default=[], description="缓解措施")
    first_seen: Optional[str] = Field(default=None, description="首次发现时间")
    last_seen: Optional[str] = Field(default=None, description="最后发现时间")


class VulnerabilityRequest(BaseModel):
    """漏洞信息请求"""
    name: str = Field(..., description="漏洞名称")
    cve_id: Optional[str] = Field(default=None, description="CVE ID")
    severity: str = Field(default="medium", description="严重程度")
    cvss_score: Optional[float] = Field(default=None, description="CVSS评分")
    description: str = Field(default="", description="描述")
    affected_products: List[str] = Field(default=[], description="受影响产品")
    exploit_available: bool = Field(default=False, description="是否有利用代码")


class ReflectionRequest(BaseModel):
    """反思请求"""
    task_description: str = Field(..., description="任务描述")
    outcome: str = Field(..., description="任务结果")
    challenges: List[str] = Field(default=[], description="遇到的挑战")
    category: str = Field(default="task_execution", description="类别")


class InitiativeRequest(BaseModel):
    """改进计划请求"""
    area: str = Field(..., description="改进领域")
    description: str = Field(..., description="描述")
    goals: List[str] = Field(..., description="目标")
    priority: str = Field(default="medium", description="优先级")


class KnowledgeQueryRequest(BaseModel):
    """知识查询请求"""
    query: str = Field(..., description="查询内容")
    knowledge_types: List[str] = Field(default=[], description="知识类型")


def get_security_system():
    """获取自改进安全系统"""
    from ..services.self_improving_security import get_self_improving_security_system
    return get_self_improving_security_system()


@router.post("/security-event")
async def process_security_event(request: SecurityEventRequest):
    """处理安全事件"""
    try:
        system = get_security_system()
        result = system.process_security_event({
            "type": request.type,
            "source": request.source,
            "severity": request.severity,
            "details": request.details,
            "indicators": request.indicators
        })
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threat-intelligence")
async def add_threat_intelligence(request: ThreatIntelRequest):
    """添加威胁情报"""
    try:
        system = get_security_system()
        threat_id = system.update_threat_intelligence({
            "name": request.name,
            "category": request.category,
            "severity": request.severity,
            "description": request.description,
            "attack_patterns": request.attack_patterns,
            "indicators": request.indicators,
            "mitigations": request.mitigations,
            "first_seen": request.first_seen,
            "last_seen": request.last_seen
        })
        return {"success": True, "threat_id": threat_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/vulnerability")
async def add_vulnerability(request: VulnerabilityRequest):
    """添加漏洞信息"""
    try:
        system = get_security_system()
        vuln_id = system.update_vulnerability({
            "name": request.name,
            "cve_id": request.cve_id,
            "severity": request.severity,
            "cvss_score": request.cvss_score,
            "description": request.description,
            "affected_products": request.affected_products,
            "exploit_available": request.exploit_available
        })
        return {"success": True, "vulnerability_id": vuln_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reflect")
async def create_reflection(request: ReflectionRequest):
    """创建反思"""
    try:
        system = get_security_system()
        reflection = system.self_improving_agent.reflect_on_task(
            task_description=request.task_description,
            outcome=request.outcome,
            challenges=request.challenges,
            category=request.category
        )
        return {"success": True, "data": reflection}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/initiative")
async def create_initiative(request: InitiativeRequest):
    """创建改进计划"""
    try:
        system = get_security_system()
        initiative_id = system.self_improving_agent.create_initiative(
            area=request.area,
            description=request.description,
            goals=request.goals,
            priority=request.priority
        )
        return {"success": True, "initiative_id": initiative_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/initiative")
async def get_initiatives():
    """获取改进计划列表"""
    try:
        system = get_security_system()
        initiatives = system.self_improving_agent.get_active_initiatives()
        return {"success": True, "data": initiatives}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/initiative/{initiative_id}/start")
async def start_initiative(initiative_id: str):
    """开始改进计划"""
    try:
        system = get_security_system()
        result = system.self_improving_agent.start_initiative(initiative_id)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/initiative/{initiative_id}/complete")
async def complete_initiative(initiative_id: str, success: bool = True, impact_score: int = 0):
    """完成改进计划"""
    try:
        system = get_security_system()
        result = system.self_improving_agent.complete_initiative(initiative_id, success, impact_score)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_defense_status():
    """获取防御状态"""
    try:
        system = get_security_system()
        status = system.get_defense_status()
        return {"success": True, "data": status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/recommendations")
async def get_optimization_recommendations():
    """获取优化建议"""
    try:
        system = get_security_system()
        recommendations = system.get_optimization_recommendations()
        return {"success": True, "data": recommendations}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/report")
async def get_comprehensive_report(period_days: int = 30):
    """获取综合报告"""
    try:
        system = get_security_system()
        report = system.generate_comprehensive_report(period_days)
        return {"success": True, "data": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics")
async def get_metrics():
    """获取性能指标"""
    try:
        system = get_security_system()
        metrics = system.self_improving_agent.get_metrics()
        return {"success": True, "data": metrics}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/knowledge-graph/stats")
async def get_knowledge_graph_stats():
    """获取知识图谱统计"""
    try:
        system = get_security_system()
        stats = system.knowledge_graph.get_statistics()
        return {"success": True, "data": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/knowledge-graph/search")
async def search_knowledge(query: str, entity_type: str = None, limit: int = 10):
    """搜索知识图谱"""
    try:
        system = get_security_system()
        
        entity_type_enum = None
        if entity_type:
            from ..services.knowledge_graph import EntityType
            try:
                entity_type_enum = EntityType(entity_type)
            except:
                pass
        
        results = system.knowledge_graph.search_entities(
            query, 
            entity_type=entity_type_enum,
            limit=limit
        )
        return {"success": True, "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents")
async def get_registered_agents():
    """获取注册的Agent列表"""
    try:
        system = get_security_system()
        agents = system.multi_agent_learning.get_registered_agents()
        return {"success": True, "data": agents}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/{agent_id}/stats")
async def get_agent_statistics(agent_id: str):
    """获取Agent统计信息"""
    try:
        system = get_security_system()
        stats = system.multi_agent_learning.get_agent_statistics(agent_id)
        return {"success": True, "data": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/learning/cycle")
async def run_collaborative_cycle():
    """运行协作学习周期"""
    try:
        system = get_security_system()
        result = system.run_collaborative_cycle()
        return {"success": True, "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/learning/start")
async def start_continuous_learning():
    """启动持续学习"""
    try:
        system = get_security_system()
        system.start_continuous_learning()
        return {"success": True, "message": "Continuous learning started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/learning/stop")
async def stop_continuous_learning():
    """停止持续学习"""
    try:
        system = get_security_system()
        system.stop_continuous_learning()
        return {"success": True, "message": "Continuous learning stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/defense/threats")
async def get_threat_statistics(days: int = 7):
    """获取威胁统计"""
    try:
        system = get_security_system()
        stats = system.adaptive_defense.get_threat_statistics(days)
        return {"success": True, "data": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/defense/status")
async def get_defense_system_status():
    """获取防御系统状态"""
    try:
        system = get_security_system()
        status = system.adaptive_defense.get_current_defense_status()
        return {"success": True, "data": status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/defense/rule")
async def add_defense_rule(rule: Dict):
    """添加防御规则"""
    try:
        system = get_security_system()
        rule_id = system.adaptive_defense.add_custom_rule(rule)
        return {"success": True, "rule_id": rule_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/defense/adaptations")
async def get_adaptation_history(limit: int = 20):
    """获取适应调整历史"""
    try:
        system = get_security_system()
        history = system.adaptive_defense.get_adaptation_history(limit)
        return {"success": True, "data": history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/improvement/report")
async def get_improvement_report(period_days: int = 30):
    """获取改进报告"""
    try:
        system = get_security_system()
        report = system.self_improving_agent.generate_improvement_report(period_days)
        return {"success": True, "data": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/improvement/reflections")
async def get_recent_reflections(days: int = 7):
    """获取近期反思"""
    try:
        system = get_security_system()
        reflections = system.self_improving_agent.get_recent_reflections(days)
        return {"success": True, "data": reflections}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
