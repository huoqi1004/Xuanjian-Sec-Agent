"""
玄鉴安全智能体 - Skill+MCP工具调用工作流管理器
整合所有安全工具的调用，提供统一的接口
"""

from typing import Dict, Optional, List, Callable, Any
import logging
import asyncio
from enum import Enum
from dataclasses import dataclass
import json

from app.services.nmap_scanner import NmapScanner
from app.services.nessus_scanner import NessusScanner
from app.services.safeline_waf import SafeLineWAF
from app.services.cape_sandbox import CAPESandbox
from app.services.elk_stack import ELKStack
from app.services.microstep_api import MicroStepAPI
from app.services.virustotal_api import VirusTotalAPI
from app.services.censys_api import CensysAPI
from app.services.deepseek_api import DeepSeekAPI
from app.services.local_model_api import LocalModelAPI
from app.services.ai_supervisor import AISupervisor

logger = logging.getLogger(__name__)

class ToolType(Enum):
    """工具类型枚举"""
    SCANNER = "scanner"
    WAF = "waf"
    SANDBOX = "sandbox"
    LOG_ANALYZER = "log_analyzer"
    THREAT_INTEL = "threat_intel"
    AI_MODEL = "ai_model"

class SkillPriority(Enum):
    """技能优先级"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4

@dataclass
class Skill:
    """技能定义"""
    name: str
    description: str
    tool_type: ToolType
    priority: SkillPriority
    required_params: List[str]
    optional_params: List[str]
    execution_func: Callable
    
class MCPProtocol:
    """MCP协议实现"""
    
    @staticmethod
    def create_request(tool_name: str, action: str, params: Dict) -> Dict:
        """创建MCP请求"""
        return {
            "protocol": "mcp/1.0",
            "tool": tool_name,
            "action": action,
            "params": params,
            "metadata": {
                "timestamp": "2026-03-01T00:00:00Z",
                "request_id": f"req-{tool_name}-{action}"
            }
        }
    
    @staticmethod
    def parse_response(response: Dict) -> Dict:
        """解析MCP响应"""
        return {
            "status": response.get("status", "unknown"),
            "data": response.get("data", {}),
            "error": response.get("error", None),
            "metadata": response.get("metadata", {})
        }

class ToolManager:
    """工具管理器"""
    
    def __init__(self):
        # 初始化所有工具
        self.tools = {
            "nmap": NmapScanner(),
            "nessus": NessusScanner(),
            "safeline_waf": SafeLineWAF(),
            "cape_sandbox": CAPESandbox(),
            "elk_stack": ELKStack(),
            "microstep": MicroStepAPI(),
            "virustotal": VirusTotalAPI(),
            "censys": CensysAPI(),
            "deepseek": DeepSeekAPI(),
            "local_model": LocalModelAPI(),
            "ai_supervisor": AISupervisor()
        }
        
        # 注册技能
        self.skills = self._register_skills()
        
        # 工作流历史
        self.workflow_history = []
    
    def _register_skills(self) -> Dict[str, Skill]:
        """注册所有技能"""
        skills = {}
        
        # 网络扫描技能
        skills["network_scan"] = Skill(
            name="network_scan",
            description="执行网络扫描，发现主机和服务",
            tool_type=ToolType.SCANNER,
            priority=SkillPriority.HIGH,
            required_params=["target"],
            optional_params=["scan_type"],
            execution_func=self._execute_network_scan
        )
        
        # 漏洞扫描技能
        skills["vulnerability_scan"] = Skill(
            name="vulnerability_scan",
            description="执行漏洞扫描，识别安全漏洞",
            tool_type=ToolType.SCANNER,
            priority=SkillPriority.HIGH,
            required_params=["target"],
            optional_params=["scan_profile"],
            execution_func=self._execute_vulnerability_scan
        )
        
        # 威胁情报查询技能
        skills["threat_intel_query"] = Skill(
            name="threat_intel_query",
            description="查询威胁情报信息",
            tool_type=ToolType.THREAT_INTEL,
            priority=SkillPriority.HIGH,
            required_params=["indicator", "indicator_type"],
            optional_params=["sources"],
            execution_func=self._execute_threat_intel_query
        )
        
        # 恶意代码分析技能
        skills["malware_analysis"] = Skill(
            name="malware_analysis",
            description="分析恶意代码样本",
            tool_type=ToolType.SANDBOX,
            priority=SkillPriority.CRITICAL,
            required_params=["sample"],
            optional_params=["timeout"],
            execution_func=self._execute_malware_analysis
        )
        
        # WAF防御技能
        skills["waf_defense"] = Skill(
            name="waf_defense",
            description="配置WAF防御规则",
            tool_type=ToolType.WAF,
            priority=SkillPriority.HIGH,
            required_params=["action"],
            optional_params=["rule", "ip"],
            execution_func=self._execute_waf_defense
        )
        
        # 日志分析技能
        skills["log_analysis"] = Skill(
            name="log_analysis",
            description="分析安全日志",
            tool_type=ToolType.LOG_ANALYZER,
            priority=SkillPriority.MEDIUM,
            required_params=["query"],
            optional_params=["time_range", "index"],
            execution_func=self._execute_log_analysis
        )
        
        # AI分析技能
        skills["ai_analysis"] = Skill(
            name="ai_analysis",
            description="使用AI分析安全事件",
            tool_type=ToolType.AI_MODEL,
            priority=SkillPriority.HIGH,
            required_params=["event_data"],
            optional_params=["analysis_type"],
            execution_func=self._execute_ai_analysis
        )
        
        # 资产扫描技能
        skills["asset_scan"] = Skill(
            name="asset_scan",
            description="扫描互联网资产",
            tool_type=ToolType.SCANNER,
            priority=SkillPriority.MEDIUM,
            required_params=["query"],
            optional_params=["scan_type"],
            execution_func=self._execute_asset_scan
        )
        
        # 病毒扫描技能
        skills["virus_scan"] = Skill(
            name="virus_scan",
            description="扫描病毒和恶意软件",
            tool_type=ToolType.THREAT_INTEL,
            priority=SkillPriority.CRITICAL,
            required_params=["target", "scan_type"],
            optional_params=[],
            execution_func=self._execute_virus_scan
        )
        
        return skills
    
    async def execute_skill(self, skill_name: str, params: Dict, supervision: bool = True) -> Dict:
        """执行技能"""
        if skill_name not in self.skills:
            return {"error": f"Skill {skill_name} not found"}
        
        skill = self.skills[skill_name]
        
        # 验证必需参数
        missing_params = [p for p in skill.required_params if p not in params]
        if missing_params:
            return {"error": f"Missing required parameters: {missing_params}"}
        
        # 如果需要监督，先进行安全审查
        if supervision and skill.priority in [SkillPriority.CRITICAL, SkillPriority.HIGH]:
            review = await self._review_execution(skill_name, params)
            if not review.get("approved", False):
                return {
                    "error": "Execution not approved by supervisor",
                    "reason": review.get("reason", "Unknown")
                }
        
        # 执行技能
        try:
            result = await skill.execution_func(params)
            
            # 记录工作流历史
            self.workflow_history.append({
                "skill": skill_name,
                "params": params,
                "result": result,
                "timestamp": "2026-03-01T00:00:00Z"
            })
            
            return result
        except Exception as e:
            logger.error(f"Error executing skill {skill_name}: {e}")
            return {"error": str(e)}
    
    async def execute_workflow(self, workflow: List[Dict]) -> Dict:
        """执行工作流"""
        results = []
        
        for step in workflow:
            skill_name = step.get("skill")
            params = step.get("params", {})
            supervision = step.get("supervision", True)
            
            result = await self.execute_skill(skill_name, params, supervision)
            results.append({
                "step": skill_name,
                "result": result
            })
            
            # 如果某一步失败，可以选择终止工作流
            if result.get("error") and step.get("critical", False):
                break
        
        return {
            "workflow": workflow,
            "results": results,
            "status": "completed" if all(not r["result"].get("error") for r in results) else "partial"
        }
    
    async def _review_execution(self, skill_name: str, params: Dict) -> Dict:
        """审查执行操作"""
        ai_supervisor = self.tools["ai_supervisor"]
        
        return await ai_supervisor.review_execution(
            {"skill": skill_name, "params": params},
            {"tool_type": self.skills[skill_name].tool_type.value}
        )
    
    async def _execute_network_scan(self, params: Dict) -> Dict:
        """执行网络扫描"""
        nmap = self.tools["nmap"]
        target = params["target"]
        scan_type = params.get("scan_type", "quick")
        
        return await nmap.scan_network(target, scan_type)
    
    async def _execute_vulnerability_scan(self, params: Dict) -> Dict:
        """执行漏洞扫描"""
        nessus = self.tools["nessus"]
        target = params["target"]
        
        # 创建扫描
        scan = await nessus.create_scan(f"Vuln Scan {target}", target)
        scan_id = scan.get("scan_id", 12345)
        
        # 启动扫描
        await nessus.launch_scan(scan_id)
        
        # 返回扫描ID，实际结果需要轮询获取
        return {
            "status": "started",
            "scan_id": scan_id,
            "target": target
        }
    
    async def _execute_threat_intel_query(self, params: Dict) -> Dict:
        """执行威胁情报查询"""
        indicator = params["indicator"]
        indicator_type = params["indicator_type"]
        
        results = {}
        
        # 查询微步在线
        microstep = self.tools["microstep"]
        if indicator_type == "ip":
            results["microstep"] = await microstep.query_ip(indicator)
        elif indicator_type == "domain":
            results["microstep"] = await microstep.query_domain(indicator)
        elif indicator_type == "hash":
            results["microstep"] = await microstep.query_hash(indicator)
        elif indicator_type == "url":
            results["microstep"] = await microstep.query_url(indicator)
        
        # 查询VirusTotal
        virustotal = self.tools["virustotal"]
        if indicator_type == "ip":
            results["virustotal"] = await virustotal.scan_ip(indicator)
        elif indicator_type == "domain":
            results["virustotal"] = await virustotal.scan_domain(indicator)
        elif indicator_type == "hash":
            results["virustotal"] = await virustotal.scan_file(indicator)
        elif indicator_type == "url":
            results["virustotal"] = await virustotal.scan_url(indicator)
        
        return {
            "indicator": indicator,
            "type": indicator_type,
            "results": results
        }
    
    async def _execute_malware_analysis(self, params: Dict) -> Dict:
        """执行恶意代码分析"""
        cape = self.tools["cape_sandbox"]
        sample = params["sample"]
        
        # 提交样本
        if sample.startswith("http"):
            result = await cape.submit_url(sample)
        else:
            result = await cape.submit_file(sample)
        
        task_id = result.get("task_id", 12345)
        
        # 获取报告
        report = await cape.get_report(task_id)
        
        return report
    
    async def _execute_waf_defense(self, params: Dict) -> Dict:
        """执行WAF防御"""
        waf = self.tools["safeline_waf"]
        action = params["action"]
        
        if action == "block_ip":
            return await waf.block_ip(params["ip"], params.get("duration", 3600))
        elif action == "unblock_ip":
            return await waf.unblock_ip(params["ip"])
        elif action == "add_rule":
            return await waf.add_rule(params["rule"]["name"], params["rule"]["pattern"])
        elif action == "get_status":
            return await waf.get_status()
        elif action == "get_blocked_ips":
            return await waf.get_blocked_ips()
        else:
            return {"error": f"Unknown WAF action: {action}"}
    
    async def _execute_log_analysis(self, params: Dict) -> Dict:
        """执行日志分析"""
        elk = self.tools["elk_stack"]
        query = params["query"]
        time_range = params.get("time_range", "24h")
        index = params.get("index", "security-events")
        
        return await elk.search_logs(index, query)
    
    async def _execute_ai_analysis(self, params: Dict) -> Dict:
        """执行AI分析"""
        ai_supervisor = self.tools["ai_supervisor"]
        event_data = params["event_data"]
        
        return await ai_supervisor.process_security_event(event_data)
    
    async def _execute_asset_scan(self, params: Dict) -> Dict:
        """执行资产扫描"""
        censys = self.tools["censys"]
        query = params["query"]
        scan_type = params.get("scan_type", "hosts")
        
        if scan_type == "hosts":
            return await censys.search_hosts(query)
        elif scan_type == "certificates":
            return await censys.search_certificates(query)
        else:
            return {"error": f"Unknown scan type: {scan_type}"}
    
    async def _execute_virus_scan(self, params: Dict) -> Dict:
        """执行病毒扫描"""
        virustotal = self.tools["virustotal"]
        target = params["target"]
        scan_type = params["scan_type"]
        
        if scan_type == "file":
            return await virustotal.scan_file(target)
        elif scan_type == "url":
            return await virustotal.scan_url(target)
        elif scan_type == "ip":
            return await virustotal.scan_ip(target)
        elif scan_type == "domain":
            return await virustotal.scan_domain(target)
        else:
            return {"error": f"Unknown scan type: {scan_type}"}
    
    def get_available_skills(self) -> List[Dict]:
        """获取可用技能列表"""
        return [
            {
                "name": skill.name,
                "description": skill.description,
                "tool_type": skill.tool_type.value,
                "priority": skill.priority.name,
                "required_params": skill.required_params,
                "optional_params": skill.optional_params
            }
            for skill in self.skills.values()
        ]
    
    def get_workflow_history(self, limit: int = 100) -> List[Dict]:
        """获取工作流历史"""
        return self.workflow_history[-limit:]

# 全局工具管理器实例
tool_manager = ToolManager()