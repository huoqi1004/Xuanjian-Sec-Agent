"""
玄鉴安全智能体 - 高级防御API
提供AI攻击检测、勒索软件防护、多Agent协同防御功能
"""

import time
from typing import Optional, List
from fastapi import APIRouter, Query, HTTPException, Body
from pydantic import BaseModel, Field
from datetime import datetime

router = APIRouter()


def get_defense_system():
    """获取防御系统"""
    from app.services.advanced_defense import get_defense_system as _get_defense
    return _get_defense()


class ThreatAnalysisRequest(BaseModel):
    content: str = Field(..., description="待分析的内容")
    context: Optional[dict] = Field(default=None, description="上下文信息")


class DefenseTestRequest(BaseModel):
    scenario_name: str = Field(..., description="测试场景名称")
    scenario_type: str = Field(..., description="场景类型: ai_attack, ransomware")
    expected_detection: bool = Field(default=True, description="预期检测结果")
    expected_block: bool = Field(default=True, description="预期阻断结果")


@router.get("/status")
async def get_defense_status():
    """获取防御系统状态"""
    system = get_defense_system()
    return system.get_defense_status()


@router.post("/analyze")
async def analyze_threat(request: ThreatAnalysisRequest):
    """综合威胁分析"""
    system = get_defense_system()
    return system.analyze_threat(request.content, request.context)


@router.post("/analyze/ai")
async def analyze_ai_attack(content: str = Body(..., description="待分析的内容")):
    """AI攻击检测分析"""
    system = get_defense_system()
    result = system.ai_detector.analyze_content(content)
    return result


@router.post("/analyze/ransomware")
async def analyze_ransomware(
    file_path: str = Body(..., description="文件路径"),
    process_info: Optional[dict] = Body(default=None, description="进程信息")
):
    """勒索软件检测分析"""
    system = get_defense_system()
    
    result = {"timestamp": datetime.now().isoformat()}
    
    file_result = system.ransomware_detector.detect_file_encryption(file_path, process_info or {})
    if file_result:
        result["detection"] = file_result
        return result
    
    if process_info:
        process_result = system.ransomware_detector.detect_ransomware_process(process_info)
        if process_result:
            result["detection"] = process_result
            return result
    
    result["detection"] = None
    result["message"] = "未检测到勒索软件行为"
    return result


@router.get("/ransomware/iocs")
async def get_ransomware_iocs():
    """获取勒索软件IOC库"""
    system = get_defense_system()
    return {"iocs": system.ransomware_detector.threat_intel.ransomware_iocs}


@router.get("/ransomware/sequences")
async def get_attack_sequences():
    """获取攻击序列模式"""
    system = get_defense_system()
    return {"sequences": system.ransomware_detector.threat_intel.attack_sequences}


@router.post("/ransomware/baseline")
async def establish_baseline(duration: int = Body(default=60, description="基线建立时长(秒)")):
    """建立正常行为基线"""
    system = get_defense_system()
    system.ransomware_detector.establish_baseline(duration)
    return {"success": True, "message": f"基线建立完成，监测时长: {duration}秒"}


@router.post("/test")
async def run_defense_test(request: DefenseTestRequest):
    """运行防御测试"""
    system = get_defense_system()
    
    scenario = {
        "name": request.scenario_name,
        "type": request.scenario_type,
        "expected_detection": request.expected_detection,
        "expected_block": request.expected_block
    }
    
    return system.run_defense_test(scenario)


@router.get("/test/results")
async def get_test_results(limit: int = Query(default=10, ge=1, le=100)):
    """获取测试结果"""
    system = get_defense_system()
    results = system.evaluator.test_results
    return {
        "total": len(results),
        "results": results[-limit:]
    }


@router.get("/test/report")
async def get_test_report():
    """获取防御评估报告"""
    system = get_defense_system()
    return system.evaluator.generate_report()


@router.get("/agents/status")
async def get_agents_status():
    """获取Agent状态"""
    system = get_defense_system()
    return system.coordinator.get_agent_status()


@router.post("/agents/register")
async def register_agent(agent_id: str = Body(...), agent_type: str = Body(...)):
    """注册新的Agent"""
    system = get_defense_system()
    system.coordinator.register_agent(agent_id, agent_type)
    return {"success": True, "message": f"Agent {agent_id} 注册成功"}


@router.post("/intel/share")
async def share_intelligence(agent_id: str = Body(...), intel: dict = Body(...)):
    """Agent间共享情报"""
    system = get_defense_system()
    system.coordinator.share_intelligence(agent_id, intel)
    return {"success": True, "message": "情报已共享"}


@router.post("/response/coordinate")
async def coordinate_response(threat_event: dict = Body(...)):
    """协调响应"""
    system = get_defense_system()
    return system.coordinator.coordinate_response(threat_event)


@router.get("/threat-intel/signatures")
async def get_threat_signatures():
    """获取威胁特征库"""
    system = get_defense_system()
    return {
        "ai_attack_signatures": [
            {"id": s["id"], "name": s["name"], "type": s["type"].value, "severity": s["severity"].value}
            for s in system.ai_detector.threat_intel.ai_attack_signatures
        ]
    }


@router.get("/simulation/scenarios")
async def get_simulation_scenarios():
    """获取模拟攻击场景"""
    return {
        "scenarios": [
            {
                "id": "ai-prompt-injection-01",
                "name": "AI Prompt注入攻击",
                "type": "ai_attack",
                "description": "模拟通过Prompt注入绕过AI安全限制",
                "expected_detection": True
            },
            {
                "id": "ai-jailbreak-01",
                "name": "AI越狱攻击",
                "type": "ai_attack",
                "description": "模拟尝试绕过AI模型的越狱攻击",
                "expected_detection": True
            },
            {
                "id": "ransomware-encryption-01",
                "name": "勒索软件文件加密",
                "type": "ransomware",
                "description": "模拟勒索软件加密文件行为",
                "expected_detection": True
            },
            {
                "id": "ransomware-lateral-01",
                "name": "勒索软件横向移动",
                "type": "ransomware",
                "description": "模拟勒索软件内网横向传播",
                "expected_detection": True
            },
            {
                "id": "ransomware-exfil-01",
                "name": "数据外泄",
                "type": "ransomware",
                "description": "模拟数据外发到外部服务器",
                "expected_detection": True
            }
        ]
    }


@router.post("/simulation/run/{scenario_id}")
async def run_simulation(scenario_id: str):
    """运行指定模拟场景"""
    scenarios = {
        "ai-prompt-injection-01": {
            "name": "AI Prompt注入攻击",
            "type": "ai_attack",
            "expected_detection": True,
            "expected_block": True
        },
        "ai-jailbreak-01": {
            "name": "AI越狱攻击",
            "type": "ai_attack", 
            "expected_detection": True,
            "expected_block": True
        },
        "ransomware-encryption-01": {
            "name": "勒索软件文件加密",
            "type": "ransomware",
            "expected_detection": True,
            "expected_block": True
        },
        "ransomware-lateral-01": {
            "name": "勒索软件横向移动",
            "type": "ransomware",
            "expected_detection": True,
            "expected_block": True
        },
        "ransomware-exfil-01": {
            "name": "数据外泄",
            "type": "ransomware",
            "expected_detection": True,
            "expected_block": True
        }
    }
    
    if scenario_id not in scenarios:
        raise HTTPException(status_code=404, detail="场景不存在")
    
    system = get_defense_system()
    return system.run_defense_test(scenarios[scenario_id])
