"""
玄鉴安全智能体 - 双模型协调器
实现监督模型与执行模型的协作编排
"""

import asyncio
import logging
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, Field

from .supervisor import DeepSeekSupervisor, SupervisorRole
from .executor import OllamaExecutor

logger = logging.getLogger(__name__)


# ============ 枚举定义 ============

class TaskType(str, Enum):
    """任务类型"""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOIT_ANALYSIS = "exploit_analysis"
    REPORT_GENERATION = "report_generation"
    LOG_ANALYSIS = "log_analysis"
    THREAT_HUNT = "threat_hunt"
    INCIDENT_RESPONSE = "incident_response"


class TaskStatus(str, Enum):
    """任务状态"""
    PENDING = "pending"
    PLANNING = "planning"
    EXECUTING = "executing"
    REVIEWING = "reviewing"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"


class ExecutionMode(str, Enum):
    """执行模式"""
    SUPERVISOR_ONLY = "supervisor_only"
    EXECUTOR_ONLY = "executor_only"
    COLLABORATIVE = "collaborative"
    SEQUENTIAL = "sequential"


# ============ 数据结构 ============

class CoordinationTask(BaseModel):
    """协调任务"""
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_type: TaskType = Field(..., description="任务类型")
    description: str = Field(..., description="任务描述")
    target: Optional[str] = Field(default=None, description="目标")
    constraints: Dict[str, Any] = Field(default_factory=dict, description="约束条件")
    priority: int = Field(default=5, ge=1, le=10, description="优先级")
    created_at: datetime = Field(default_factory=datetime.now)
    deadline: Optional[datetime] = Field(default=None)


class ExecutionPlan(BaseModel):
    """执行计划"""
    steps: List[Dict[str, Any]] = Field(default_factory=list, description="执行步骤")
    estimated_duration: int = Field(default=0, description="预计耗时(秒)")
    risk_assessment: Dict[str, Any] = Field(default_factory=dict)
    required_tools: List[str] = Field(default_factory=list)


class SupervisorVerdict(BaseModel):
    """监督审查意见"""
    approved: bool = Field(..., description="是否批准")
    confidence: float = Field(default=0.0, ge=0, le=1, description="置信度")
    issues: List[str] = Field(default_factory=list, description="发现的问题")
    suggestions: List[str] = Field(default_factory=list, description="建议")


class CoordinationResult(BaseModel):
    """协调结果"""
    task_id: str
    status: TaskStatus
    plan: Optional[ExecutionPlan] = None
    execution_logs: List[Dict[str, Any]] = Field(default_factory=list)
    supervisor_verdict: Optional[SupervisorVerdict] = None
    final_output: Optional[Any] = None
    confidence_score: float = Field(default=0.0)
    total_duration_ms: int = 0
    error: Optional[str] = None


# ============ 双模型协调器 ============

class DualModelCoordinator:
    """
    双模型协调器
    
    实现监督模型与执行模型的协作：
    - 任务分发
    - 计划生成与审核
    - 执行监控
    - 结果审查
    - 冲突仲裁
    """
    
    def __init__(
        self,
        supervisor: Optional[DeepSeekSupervisor] = None,
        executor: Optional[OllamaExecutor] = None,
        max_retries: int = 2
    ):
        self.supervisor = supervisor or DeepSeekSupervisor()
        self.executor = executor or OllamaExecutor()
        self.max_retries = max_retries
        
        self._progress_callback: Optional[Callable] = None
        self._task_semaphore = asyncio.Semaphore(3)
        self._active_tasks: Dict[str, CoordinationTask] = {}
    
    def set_progress_callback(self, callback: Callable):
        """设置进度回调"""
        self._progress_callback = callback
    
    async def coordinate(self, task: CoordinationTask) -> CoordinationResult:
        """
        协调执行任务
        
        流程：规划 -> 执行 -> 审查
        """
        start_time = datetime.now()
        result = CoordinationResult(
            task_id=task.task_id,
            status=TaskStatus.PENDING
        )
        
        async with self._task_semaphore:
            self._active_tasks[task.task_id] = task
            
            try:
                # 1. 规划阶段
                result.status = TaskStatus.PLANNING
                self._notify_progress(task.task_id, "planning", 10)
                
                plan = await self._planning_phase(task)
                result.plan = plan
                
                if not plan or not plan.steps:
                    result.status = TaskStatus.REJECTED
                    result.error = "无法生成有效的执行计划"
                    return result
                
                # 2. 执行阶段
                result.status = TaskStatus.EXECUTING
                self._notify_progress(task.task_id, "executing", 30)
                
                execution_logs = await self._execution_phase(plan, task)
                result.execution_logs = execution_logs
                
                # 3. 审查阶段
                result.status = TaskStatus.REVIEWING
                self._notify_progress(task.task_id, "reviewing", 80)
                
                verdict = await self._review_phase(task, plan, execution_logs)
                result.supervisor_verdict = verdict
                
                # 4. 合并结果
                if verdict.approved:
                    result.status = TaskStatus.COMPLETED
                    result.final_output = self._merge_results(execution_logs, verdict)
                    result.confidence_score = verdict.confidence
                else:
                    # 审查不通过，可以重试
                    if self.max_retries > 0:
                        logger.warning(f"Task {task.task_id} review failed, retrying...")
                        # TODO: 实现重试逻辑
                    result.status = TaskStatus.FAILED
                    result.error = "执行结果未通过审查"
                
                self._notify_progress(task.task_id, "completed", 100)
                
            except Exception as e:
                result.status = TaskStatus.FAILED
                result.error = str(e)
                logger.exception(f"Coordination failed: {e}")
            finally:
                del self._active_tasks[task.task_id]
                result.total_duration_ms = int(
                    (datetime.now() - start_time).total_seconds() * 1000
                )
        
        return result
    
    async def _planning_phase(self, task: CoordinationTask) -> Optional[ExecutionPlan]:
        """规划阶段"""
        try:
            # 获取可用工具列表
            available_tools = self.executor.tool_registry.list_tools()
            
            # 调用监督模型生成计划
            response = await self.supervisor.plan_task(
                task_description=task.description,
                available_tools=available_tools,
                constraints=task.constraints
            )
            
            # 解析计划
            plan = self._parse_execution_plan(response.content)
            
            # 风险评估
            if plan and plan.risk_assessment.get("level") == "critical":
                logger.warning(f"Task {task.task_id} has critical risk")
                # TODO: 请求人工审批
            
            return plan
            
        except Exception as e:
            logger.error(f"Planning phase failed: {e}")
            return None
    
    async def _execution_phase(
        self,
        plan: ExecutionPlan,
        task: CoordinationTask
    ) -> List[Dict[str, Any]]:
        """执行阶段"""
        execution_logs = []
        
        for i, step in enumerate(plan.steps):
            step_id = step.get("step_id", f"step_{i}")
            tool_name = step.get("tool_name")
            params = step.get("params", {})
            
            self._notify_progress(
                task.task_id,
                f"executing_step_{step_id}",
                30 + int(50 * (i / len(plan.steps)))
            )
            
            try:
                # 使用执行模型执行步骤
                result = await self.executor.execute(
                    prompt=f"执行工具 {tool_name}，参数：{params}",
                    system_prompt="你是一个安全工具执行助手，请按要求调用工具并返回结果。",
                    tools_enabled=True
                )
                
                execution_logs.append({
                    "step_id": step_id,
                    "tool_name": tool_name,
                    "params": params,
                    "success": True,
                    "output": result.output,
                    "tool_calls": result.tool_calls_log,
                    "duration_ms": result.total_time_ms
                })
                
            except Exception as e:
                execution_logs.append({
                    "step_id": step_id,
                    "tool_name": tool_name,
                    "params": params,
                    "success": False,
                    "error": str(e)
                })
                
                # 检查是否应该停止
                if step.get("on_error") == "stop":
                    break
        
        return execution_logs
    
    async def _review_phase(
        self,
        task: CoordinationTask,
        plan: ExecutionPlan,
        execution_logs: List[Dict[str, Any]]
    ) -> SupervisorVerdict:
        """审查阶段"""
        try:
            # 调用监督模型审查结果
            response = await self.supervisor.review_result(
                plan=plan.model_dump() if plan else {},
                execution_log=execution_logs,
                output=self._extract_outputs(execution_logs)
            )
            
            # 解析审查意见
            verdict = self._parse_verdict(response.content)
            return verdict
            
        except Exception as e:
            logger.error(f"Review phase failed: {e}")
            return SupervisorVerdict(
                approved=False,
                confidence=0.0,
                issues=[f"审查失败: {str(e)}"]
            )
    
    def _parse_execution_plan(self, content: str) -> Optional[ExecutionPlan]:
        """解析执行计划"""
        import json
        
        try:
            # 尝试解析JSON
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0]
            else:
                json_str = content
            
            data = json.loads(json_str)
            
            return ExecutionPlan(
                steps=data.get("steps", []),
                estimated_duration=data.get("estimated_duration", 0),
                risk_assessment=data.get("risk_assessment", {}),
                required_tools=data.get("required_tools", [])
            )
        except Exception as e:
            logger.warning(f"Failed to parse execution plan: {e}")
            return None
    
    def _parse_verdict(self, content: str) -> SupervisorVerdict:
        """解析审查意见"""
        import json
        
        try:
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                json_str = content.split("```")[1].split("```")[0]
            else:
                json_str = content
            
            data = json.loads(json_str)
            
            return SupervisorVerdict(
                approved=data.get("approved", False),
                confidence=data.get("confidence", 0.0),
                issues=data.get("issues", []),
                suggestions=data.get("suggestions", [])
            )
        except:
            # 如果解析失败，使用默认值
            return SupervisorVerdict(
                approved=True,
                confidence=0.5,
                issues=["无法解析审查结果"]
            )
    
    def _extract_outputs(self, execution_logs: List[Dict[str, Any]]) -> List[Any]:
        """提取执行输出"""
        return [
            log.get("output")
            for log in execution_logs
            if log.get("success") and log.get("output")
        ]
    
    def _merge_results(
        self,
        execution_logs: List[Dict[str, Any]],
        verdict: SupervisorVerdict
    ) -> Dict[str, Any]:
        """合并结果"""
        outputs = self._extract_outputs(execution_logs)
        
        success_count = sum(1 for log in execution_logs if log.get("success"))
        total_count = len(execution_logs)
        
        return {
            "outputs": outputs,
            "success_rate": success_count / total_count if total_count > 0 else 0,
            "verdict": verdict.model_dump(),
            "step_count": total_count
        }
    
    def _notify_progress(self, task_id: str, stage: str, progress: int):
        """通知进度"""
        if self._progress_callback:
            try:
                self._progress_callback({
                    "task_id": task_id,
                    "stage": stage,
                    "progress": progress
                })
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")
    
    async def get_active_tasks(self) -> List[CoordinationTask]:
        """获取活动任务"""
        return list(self._active_tasks.values())
