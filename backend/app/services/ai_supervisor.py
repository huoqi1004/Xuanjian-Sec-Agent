import logging
from typing import Dict, Optional, List
from app.services.deepseek_api import DeepSeekAPI
from app.services.local_model_api import LocalModelAPI
import asyncio

logger = logging.getLogger(__name__)

class AISupervisor:
    """AI协同监督机制"""
    
    def __init__(self):
        self.supervisor = DeepSeekAPI()  # 监督模型
        self.executor = LocalModelAPI()  # 执行模型
        self.approval_queue = []  # 需要人工审批的操作队列
        self.execution_history = []  # 执行历史
    
    async def process_security_event(self, event: Dict) -> Dict:
        """处理安全事件"""
        # 1. 监督模型分析事件
        analysis = await self.supervisor.analyze_security_event(event)
        
        # 2. 根据分析结果决定是否需要执行操作
        if analysis.get("severity") in ["high", "critical"]:
            # 生成响应计划
            plan = await self.supervisor.generate_response_plan(event)
            
            # 执行模型执行计划
            execution_result = await self.execute_with_supervision(plan, event)
            
            return {
                "analysis": analysis,
                "plan": plan,
                "execution": execution_result,
                "status": "completed"
            }
        
        return {
            "analysis": analysis,
            "status": "monitoring"
        }
    
    async def execute_with_supervision(self, plan: Dict, context: Dict) -> Dict:
        """在监督下执行操作"""
        results = []
        steps = plan.get("steps", [])
        
        for step in steps:
            # 1. 执行模型规划具体操作
            operation_plan = await self.executor.plan_security_operation(step, context)
            
            # 2. 监督模型审查操作
            review = await self.supervisor.review_execution(
                {"step": step, "plan": operation_plan},
                context
            )
            
            # 3. 根据审查结果决定是否执行
            if review.get("approved"):
                if review.get("requires_human_approval"):
                    # 添加到人工审批队列
                    self.approval_queue.append({
                        "step": step,
                        "plan": operation_plan,
                        "review": review,
                        "context": context
                    })
                    results.append({
                        "step": step,
                        "status": "pending_approval",
                        "review": review
                    })
                else:
                    # 直接执行
                    execution_result = await self.executor.execute_security_tool(
                        step,
                        operation_plan.get("params", {})
                    )
                    
                    # 记录执行历史
                    self.execution_history.append({
                        "step": step,
                        "result": execution_result,
                        "review": review
                    })
                    
                    results.append({
                        "step": step,
                        "status": "executed",
                        "result": execution_result
                    })
            else:
                results.append({
                    "step": step,
                    "status": "rejected",
                    "reason": review.get("review_notes", "未通过安全审查")
                })
        
        return {
            "results": results,
            "total_steps": len(steps),
            "executed": len([r for r in results if r["status"] == "executed"]),
            "pending": len([r for r in results if r["status"] == "pending_approval"]),
            "rejected": len([r for r in results if r["status"] == "rejected"])
        }
    
    async def analyze_threat(self, threat_data: Dict) -> Dict:
        """分析威胁"""
        # 监督模型分析威胁
        analysis = await self.supervisor.analyze_security_event(threat_data)
        
        # 执行模型进行详细分析
        if threat_data.get("type") == "network":
            detailed_analysis = await self.executor.analyze_network_traffic(threat_data)
        elif threat_data.get("type") == "vulnerability":
            detailed_analysis = await self.executor.analyze_vulnerability(threat_data)
        elif threat_data.get("type") == "malware":
            detailed_analysis = await self.executor.generate_malware_report(threat_data)
        else:
            detailed_analysis = {"analysis": "未知威胁类型"}
        
        return {
            "supervisor_analysis": analysis,
            "executor_analysis": detailed_analysis,
            "combined_assessment": self._combine_assessments(analysis, detailed_analysis)
        }
    
    async def scan_asset(self, asset_info: Dict) -> Dict:
        """扫描资产"""
        # 执行模型执行扫描
        scan_result = await self.executor.execute_security_tool("asset_scan", asset_info)
        
        # 监督模型审查扫描结果
        review = await self.supervisor.review_execution(
            {"tool": "asset_scan", "result": scan_result},
            asset_info
        )
        
        return {
            "scan_result": scan_result,
            "review": review,
            "approved": review.get("approved", False)
        }
    
    async def respond_to_incident(self, incident: Dict) -> Dict:
        """响应安全事件"""
        # 1. 监督模型生成响应计划
        response_plan = await self.supervisor.generate_response_plan(incident)
        
        # 2. 执行模型执行响应操作
        execution_results = await self.execute_with_supervision(response_plan, incident)
        
        # 3. 监督模型评估响应效果
        evaluation = await self.supervisor.analyze_security_event({
            "type": "response_evaluation",
            "incident": incident,
            "execution_results": execution_results
        })
        
        return {
            "plan": response_plan,
            "execution": execution_results,
            "evaluation": evaluation,
            "status": "completed"
        }
    
    def get_pending_approvals(self) -> List[Dict]:
        """获取待审批的操作"""
        return self.approval_queue
    
    async def approve_operation(self, operation_id: int, approved: bool, notes: str = "") -> Dict:
        """审批操作"""
        if operation_id >= len(self.approval_queue):
            return {"error": "操作不存在"}
        
        operation = self.approval_queue[operation_id]
        
        if approved:
            # 执行已批准的操作
            execution_result = await self.executor.execute_security_tool(
                operation["step"],
                operation["plan"].get("params", {})
            )
            
            # 记录执行历史
            self.execution_history.append({
                "step": operation["step"],
                "result": execution_result,
                "review": operation["review"],
                "approval_notes": notes
            })
            
            # 从审批队列中移除
            self.approval_queue.pop(operation_id)
            
            return {
                "status": "executed",
                "result": execution_result
            }
        else:
            # 拒绝操作
            self.approval_queue.pop(operation_id)
            return {
                "status": "rejected",
                "reason": notes
            }
    
    def get_execution_history(self, limit: int = 100) -> List[Dict]:
        """获取执行历史"""
        return self.execution_history[-limit:]
    
    def _combine_assessments(self, supervisor_analysis: Dict, executor_analysis: Dict) -> Dict:
        """合并评估结果"""
        supervisor_severity = supervisor_analysis.get("severity", "low")
        executor_confidence = executor_analysis.get("confidence", 0.5)
        
        # 根据监督模型的严重程度和执行模型的置信度计算综合风险
        severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        severity_score = severity_scores.get(supervisor_severity, 1)
        
        combined_risk = severity_score * executor_confidence
        
        if combined_risk >= 3:
            risk_level = "critical"
        elif combined_risk >= 2:
            risk_level = "high"
        elif combined_risk >= 1:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_level": risk_level,
            "combined_score": combined_risk,
            "supervisor_severity": supervisor_severity,
            "executor_confidence": executor_confidence,
            "recommendations": supervisor_analysis.get("recommendations", [])
        }
    
    async def health_check(self) -> Dict:
        """健康检查"""
        supervisor_status = "ok" if self.supervisor.api_key else "not_configured"
        executor_status = "ok"  # 本地模型总是可用
        
        return {
            "supervisor_model": {
                "status": supervisor_status,
                "model": self.supervisor.model
            },
            "executor_model": {
                "status": executor_status,
                "model": self.executor.model
            },
            "pending_approvals": len(self.approval_queue),
            "execution_history": len(self.execution_history)
        }