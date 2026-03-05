"""
玄鉴安全智能体 - 安全工具API路由
整合所有安全工具和AI服务
"""

from fastapi import APIRouter, Query, HTTPException, BackgroundTasks
from typing import Optional, Dict, List
from pydantic import BaseModel, Field

from app.services.microstep_api import MicroStepAPI
from app.services.virustotal_api import VirusTotalAPI
from app.services.censys_api import CensysAPI
from app.services.deepseek_api import DeepSeekAPI
from app.services.local_model_api import LocalModelAPI
from app.services.ai_supervisor import AISupervisor
from app.services.nmap_scanner import NmapScanner
from app.services.nessus_scanner import NessusScanner
from app.services.safeline_waf import SafeLineWAF
from app.services.cape_sandbox import CAPESandbox
from app.services.elk_stack import ELKStack
from app.services.tool_manager import ToolManager

router = APIRouter()

# 初始化服务
microstep_api = MicroStepAPI()
virustotal_api = VirusTotalAPI()
censys_api = CensysAPI()
deepseek_api = DeepSeekAPI()
local_model_api = LocalModelAPI()
ai_supervisor = AISupervisor()
nmap_scanner = NmapScanner()
nessus_scanner = NessusScanner()
safeline_waf = SafeLineWAF()
cape_sandbox = CAPESandbox()
elk_stack = ELKStack()
tool_manager = ToolManager()


# ============ 威胁情报查询 ============

class ThreatIntelQuery(BaseModel):
    """威胁情报查询请求"""
    indicator: str = Field(..., description="查询指标")
    indicator_type: str = Field(..., description="指标类型: ip, domain, hash, url")


@router.post("/threat-intel/query")
async def query_threat_intel(query: ThreatIntelQuery):
    """查询威胁情报"""
    results = {}
    
    # 微步在线查询
    if query.indicator_type == "ip":
        results["microstep"] = await microstep_api.query_ip(query.indicator)
        results["virustotal"] = await virustotal_api.scan_ip(query.indicator)
    elif query.indicator_type == "domain":
        results["microstep"] = await microstep_api.query_domain(query.indicator)
        results["virustotal"] = await virustotal_api.scan_domain(query.indicator)
    elif query.indicator_type == "hash":
        results["microstep"] = await microstep_api.query_hash(query.indicator)
        results["virustotal"] = await virustotal_api.scan_file(query.indicator)
    elif query.indicator_type == "url":
        results["microstep"] = await microstep_api.query_url(query.indicator)
        results["virustotal"] = await virustotal_api.scan_url(query.indicator)
    else:
        raise HTTPException(status_code=400, detail="Invalid indicator type")
    
    return {
        "indicator": query.indicator,
        "type": query.indicator_type,
        "results": results
    }


# ============ Nmap扫描 ============

class NmapScanRequest(BaseModel):
    """Nmap扫描请求"""
    target: str = Field(..., description="目标网络或主机")
    scan_type: str = Field(default="quick", description="扫描类型: quick, full, stealth, udp")


@router.post("/nmap/scan")
async def nmap_scan(request: NmapScanRequest):
    """执行Nmap网络扫描"""
    result = await nmap_scanner.scan_network(request.target, request.scan_type)
    return result


@router.get("/nmap/port/{target}/{port}")
async def nmap_port_scan(target: str, port: int):
    """扫描特定端口"""
    result = await nmap_scanner.scan_port(target, port)
    return result


@router.get("/nmap/os/{target}")
async def nmap_os_detect(target: str):
    """检测操作系统"""
    result = await nmap_scanner.detect_os(target)
    return result


@router.get("/nmap/vuln/{target}")
async def nmap_vuln_scan(target: str):
    """漏洞扫描"""
    result = await nmap_scanner.scan_vulnerability(target)
    return result


# ============ Nessus扫描 ============

class NessusScanRequest(BaseModel):
    """Nessus扫描请求"""
    name: str = Field(..., description="扫描名称")
    target: str = Field(..., description="目标")
    template: str = Field(default="basic", description="扫描模板")


@router.post("/nessus/scan")
async def nessus_create_scan(request: NessusScanRequest):
    """创建Nessus扫描任务"""
    result = await nessus_scanner.create_scan(request.name, request.target, request.template)
    return result


@router.post("/nessus/scan/{scan_id}/launch")
async def nessus_launch_scan(scan_id: int):
    """启动扫描"""
    result = await nessus_scanner.launch_scan(scan_id)
    return result


@router.get("/nessus/scan/{scan_id}/status")
async def nessus_get_status(scan_id: int):
    """获取扫描状态"""
    result = await nessus_scanner.get_scan_status(scan_id)
    return result


@router.get("/nessus/scan/{scan_id}/results")
async def nessus_get_results(scan_id: int):
    """获取扫描结果"""
    result = await nessus_scanner.get_scan_results(scan_id)
    return result


@router.get("/nessus/scans")
async def nessus_list_scans():
    """获取扫描列表"""
    result = await nessus_scanner.list_scans()
    return result


# ============ 雷池WAF ============

@router.get("/waf/status")
async def waf_get_status():
    """获取WAF状态"""
    result = await safeline_waf.get_status()
    return result


@router.get("/waf/sites")
async def waf_get_sites():
    """获取保护的网站列表"""
    result = await safeline_waf.get_sites()
    return result


@router.get("/waf/rules")
async def waf_get_rules():
    """获取防护规则"""
    result = await safeline_waf.get_rules()
    return result


@router.post("/waf/block-ip")
async def waf_block_ip(ip: str, duration: int = 3600):
    """封禁IP"""
    result = await safeline_waf.block_ip(ip, duration)
    return result


@router.delete("/waf/block-ip/{ip}")
async def waf_unblock_ip(ip: str):
    """解封IP"""
    result = await safeline_waf.unblock_ip(ip)
    return result


@router.get("/waf/blocked-ips")
async def waf_get_blocked_ips():
    """获取被封禁的IP列表"""
    result = await safeline_waf.get_blocked_ips()
    return result


@router.get("/waf/attack-logs")
async def waf_get_attack_logs(page: int = 1, size: int = 100):
    """获取攻击日志"""
    result = await safeline_waf.get_attack_logs(page, size)
    return result


@router.get("/waf/statistics")
async def waf_get_statistics(time_range: str = "24h"):
    """获取统计数据"""
    result = await safeline_waf.get_statistics(time_range)
    return result


# ============ CAPE沙箱 ============

@router.post("/cape/submit/file")
async def cape_submit_file(file_path: str, options: Dict = None):
    """提交文件进行分析"""
    result = await cape_sandbox.submit_file(file_path, options)
    return result


@router.post("/cape/submit/url")
async def cape_submit_url(url: str, options: Dict = None):
    """提交URL进行分析"""
    result = await cape_sandbox.submit_url(url, options)
    return result


@router.get("/cape/task/{task_id}/status")
async def cape_get_task_status(task_id: int):
    """获取任务状态"""
    result = await cape_sandbox.get_task_status(task_id)
    return result


@router.get("/cape/task/{task_id}/report")
async def cape_get_report(task_id: int):
    """获取分析报告"""
    result = await cape_sandbox.get_report(task_id)
    return result


@router.get("/cape/task/{task_id}/behavior")
async def cape_get_behavior(task_id: int):
    """获取行为摘要"""
    result = await cape_sandbox.get_behavior_summary(task_id)
    return result


@router.get("/cape/task/{task_id}/network")
async def cape_get_network(task_id: int):
    """获取网络活动"""
    result = await cape_sandbox.get_network_activity(task_id)
    return result


@router.get("/cape/task/{task_id}/signatures")
async def cape_get_signatures(task_id: int):
    """获取检测签名"""
    result = await cape_sandbox.get_signatures(task_id)
    return result


@router.get("/cape/task/{task_id}/iocs")
async def cape_get_iocs(task_id: int):
    """获取威胁指标"""
    result = await cape_sandbox.get_iocs(task_id)
    return result


# ============ ELK Stack日志分析 ============

class LogSearchRequest(BaseModel):
    """日志搜索请求"""
    index: str = Field(..., description="索引名称")
    query: Dict = Field(..., description="查询条件")
    size: int = Field(default=100, description="返回结果数量")


@router.post("/elk/search")
async def elk_search_logs(request: LogSearchRequest):
    """搜索日志"""
    result = await elk_stack.search_logs(request.index, request.query, request.size)
    return result


@router.get("/elk/security-events")
async def elk_get_security_events(time_range: str = "24h", severity: str = None):
    """获取安全事件"""
    result = await elk_stack.get_security_events(time_range, severity)
    return result


@router.get("/elk/attack-patterns")
async def elk_get_attack_patterns(time_range: str = "24h"):
    """获取攻击模式分析"""
    result = await elk_stack.get_attack_patterns(time_range)
    return result


@router.get("/elk/threat-intel")
async def elk_get_threat_intel(time_range: str = "7d"):
    """获取威胁情报分析"""
    result = await elk_stack.get_threat_intelligence(time_range)
    return result


@router.get("/elk/asset-activity/{asset_ip}")
async def elk_get_asset_activity(asset_ip: str, time_range: str = "24h"):
    """获取资产活动日志"""
    result = await elk_stack.get_asset_activity(asset_ip, time_range)
    return result


@router.get("/elk/statistics")
async def elk_get_statistics(time_range: str = "24h"):
    """获取日志统计"""
    result = await elk_stack.get_log_statistics(time_range)
    return result


# ============ Skill+MCP工作流 ============

class SkillExecutionRequest(BaseModel):
    """技能执行请求"""
    skill_name: str = Field(..., description="技能名称")
    params: Dict = Field(default={}, description="技能参数")
    supervision: bool = Field(default=True, description="是否需要监督")


class WorkflowExecutionRequest(BaseModel):
    """工作流执行请求"""
    workflow: List[Dict] = Field(..., description="工作流步骤")


@router.get("/skills")
async def get_available_skills():
    """获取可用技能列表"""
    return tool_manager.get_available_skills()


@router.post("/skills/execute")
async def execute_skill(request: SkillExecutionRequest):
    """执行技能"""
    result = await tool_manager.execute_skill(request.skill_name, request.params, request.supervision)
    return result


@router.post("/workflow/execute")
async def execute_workflow(request: WorkflowExecutionRequest):
    """执行工作流"""
    result = await tool_manager.execute_workflow(request.workflow)
    return result


@router.get("/workflow/history")
async def get_workflow_history(limit: int = 100):
    """获取工作流历史"""
    return tool_manager.get_workflow_history(limit)


# ============ AI安全分析 ============

class SecurityEventRequest(BaseModel):
    """安全事件请求"""
    event_type: str = Field(..., description="事件类型")
    event_data: Dict = Field(..., description="事件数据")
    severity: str = Field(default="medium", description="严重程度")


@router.post("/ai/analyze")
async def analyze_security_event(request: SecurityEventRequest):
    """AI分析安全事件"""
    result = await ai_supervisor.process_security_event({
        "type": request.event_type,
        "data": request.event_data,
        "severity": request.severity
    })
    return result


@router.post("/ai/respond")
async def respond_to_incident(request: SecurityEventRequest):
    """AI响应安全事件"""
    result = await ai_supervisor.respond_to_incident({
        "type": request.event_type,
        "data": request.event_data,
        "severity": request.severity
    })
    return result


@router.get("/ai/pending-approvals")
async def get_pending_approvals():
    """获取待审批的操作"""
    return ai_supervisor.get_pending_approvals()


@router.post("/ai/approve/{operation_id}")
async def approve_operation(operation_id: int, approved: bool, notes: str = ""):
    """审批操作"""
    result = await ai_supervisor.approve_operation(operation_id, approved, notes)
    return result


@router.get("/ai/execution-history")
async def get_execution_history(limit: int = 100):
    """获取执行历史"""
    return ai_supervisor.get_execution_history(limit)


@router.get("/ai/health")
async def ai_health_check():
    """AI服务健康检查"""
    return await ai_supervisor.health_check()


# ============ 资产扫描 ============

class AssetScanRequest(BaseModel):
    """资产扫描请求"""
    query: str = Field(..., description="搜索查询")
    scan_type: str = Field(default="hosts", description="扫描类型: hosts, certificates")


@router.post("/assets/scan")
async def scan_assets(request: AssetScanRequest):
    """扫描互联网资产"""
    if request.scan_type == "hosts":
        result = await censys_api.search_hosts(request.query)
    elif request.scan_type == "certificates":
        result = await censys_api.search_certificates(request.query)
    else:
        raise HTTPException(status_code=400, detail="Invalid scan type")
    
    return result


@router.get("/assets/{ip}")
async def get_asset_detail(ip: str):
    """获取资产详情"""
    result = await censys_api.get_host(ip)
    return result


# ============ 病毒查杀 ============

class VirusScanRequest(BaseModel):
    """病毒扫描请求"""
    scan_type: str = Field(..., description="扫描类型: file, url, ip, domain")
    target: str = Field(..., description="扫描目标")


@router.post("/virus/scan")
async def scan_virus(request: VirusScanRequest):
    """病毒扫描"""
    if request.scan_type == "file":
        result = await virustotal_api.scan_file(request.target)
    elif request.scan_type == "url":
        result = await virustotal_api.scan_url(request.target)
    elif request.scan_type == "ip":
        result = await virustotal_api.scan_ip(request.target)
    elif request.scan_type == "domain":
        result = await virustotal_api.scan_domain(request.target)
    else:
        raise HTTPException(status_code=400, detail="Invalid scan type")
    
    return result


# ============ 安全态势 ============

@router.get("/security-posture")
async def get_security_posture():
    """获取安全态势数据"""
    result = await microstep_api.get_security态势()
    return result


# ============ 批量查询 ============

class BatchQueryRequest(BaseModel):
    """批量查询请求"""
    indicators: List[str] = Field(..., description="指标列表")
    indicator_type: str = Field(..., description="指标类型")


@router.post("/batch/query")
async def batch_query(request: BatchQueryRequest):
    """批量查询威胁情报"""
    results = []
    
    for indicator in request.indicators:
        query = ThreatIntelQuery(indicator=indicator, indicator_type=request.indicator_type)
        result = await query_threat_intel(query)
        results.append(result)
    
    return {
        "total": len(results),
        "results": results
    }