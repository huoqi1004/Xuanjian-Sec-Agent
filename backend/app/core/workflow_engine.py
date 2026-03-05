"""
玄鉴安全智能体 - 工作流编排引擎
实现安全流程的自动化编排和执行
"""

import asyncio
import logging
import uuid
from collections import defaultdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ============ 枚举定义 ============

class WorkflowState(str, Enum):
    """工作流状态"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepState(str, Enum):
    """步骤状态"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING_APPROVAL = "waiting_approval"


class StepType(str, Enum):
    """步骤类型"""
    TOOL_CALL = "tool_call"
    LLM_QUERY = "llm_query"
    CONDITION = "condition"
    PARALLEL = "parallel"
    NOTIFICATION = "notification"
    HUMAN_APPROVAL = "human_approval"
    DELAY = "delay"


class ErrorPolicy(str, Enum):
    """错误处理策略"""
    STOP = "stop"
    CONTINUE = "continue"
    RETRY = "retry"


# ============ 数据模型 ============

class RetryConfig(BaseModel):
    """重试配置"""
    max_retries: int = Field(default=3, description="最大重试次数")
    delay_seconds: float = Field(default=1.0, description="重试延迟")
    backoff_factor: float = Field(default=2.0, description="退避因子")


class StepDefinition(BaseModel):
    """步骤定义"""
    step_id: str = Field(..., description="步骤ID")
    name: str = Field(..., description="步骤名称")
    step_type: StepType = Field(..., description="步骤类型")
    tool_name: Optional[str] = Field(default=None, description="工具名称(tool_call类型)")
    params: Dict[str, Any] = Field(default_factory=dict, description="参数(支持模板变量)")
    depends_on: List[str] = Field(default_factory=list, description="依赖的步骤ID")
    condition: Optional[str] = Field(default=None, description="执行条件表达式")
    output_key: Optional[str] = Field(default=None, description="输出存储键名")
    retry_config: RetryConfig = Field(default_factory=RetryConfig, description="重试配置")
    timeout_seconds: int = Field(default=300, description="超时时间")
    on_error: ErrorPolicy = Field(default=ErrorPolicy.STOP, description="错误处理策略")


class WorkflowDefinition(BaseModel):
    """工作流定义"""
    workflow_id: str = Field(..., description="工作流ID")
    name: str = Field(..., description="工作流名称")
    description: str = Field(default="", description="描述")
    version: str = Field(default="1.0.0", description="版本")
    steps: List[StepDefinition] = Field(..., description="步骤列表")
    inputs: Dict[str, Any] = Field(default_factory=dict, description="输入参数定义")
    outputs: Dict[str, Any] = Field(default_factory=dict, description="输出参数定义")
    error_policy: ErrorPolicy = Field(default=ErrorPolicy.STOP, description="全局错误策略")
    timeout_seconds: int = Field(default=3600, description="总超时时间")
    
    def validate_dag(self) -> bool:
        """验证步骤DAG是否有效（无环）"""
        # 构建邻接表
        graph = defaultdict(list)
        in_degree = defaultdict(int)
        all_steps = set()
        
        for step in self.steps:
            all_steps.add(step.step_id)
            for dep in step.depends_on:
                graph[dep].append(step.step_id)
                in_degree[step.step_id] += 1
        
        # 拓扑排序检测环
        queue = [s for s in all_steps if in_degree[s] == 0]
        visited = 0
        
        while queue:
            node = queue.pop(0)
            visited += 1
            for neighbor in graph[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
        
        return visited == len(all_steps)


class StepResult(BaseModel):
    """步骤执行结果"""
    step_id: str
    state: StepState
    output: Optional[Any] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    retry_count: int = 0


class WorkflowInstance(BaseModel):
    """工作流执行实例"""
    instance_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workflow_id: str
    state: WorkflowState = Field(default=WorkflowState.PENDING)
    current_step: Optional[str] = None
    step_results: Dict[str, StepResult] = Field(default_factory=dict)
    context: Dict[str, Any] = Field(default_factory=dict)
    inputs: Dict[str, Any] = Field(default_factory=dict)
    outputs: Dict[str, Any] = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    
    @property
    def progress(self) -> float:
        """计算执行进度"""
        if not self.step_results:
            return 0.0
        
        completed = sum(
            1 for r in self.step_results.values()
            if r.state in (StepState.SUCCESS, StepState.SKIPPED, StepState.FAILED)
        )
        return (completed / len(self.step_results)) * 100


# ============ 工作流引擎 ============

class WorkflowEngine:
    """
    工作流编排引擎
    
    负责解析工作流定义、调度步骤执行、管理状态
    """
    
    def __init__(self):
        self._workflows: Dict[str, WorkflowDefinition] = {}
        self._instances: Dict[str, WorkflowInstance] = {}
        self._tool_executor: Optional[Callable] = None
        self._llm_executor: Optional[Callable] = None
        self._progress_callback: Optional[Callable] = None
        self._running_tasks: Dict[str, asyncio.Task] = {}
    
    def set_tool_executor(self, executor: Callable):
        """设置工具执行器"""
        self._tool_executor = executor
    
    def set_llm_executor(self, executor: Callable):
        """设置LLM执行器"""
        self._llm_executor = executor
    
    def set_progress_callback(self, callback: Callable):
        """设置进度回调"""
        self._progress_callback = callback
    
    def register_workflow(self, definition: WorkflowDefinition):
        """注册工作流定义"""
        if not definition.validate_dag():
            raise ValueError(f"Workflow {definition.workflow_id} has circular dependencies")
        
        self._workflows[definition.workflow_id] = definition
        logger.info(f"Registered workflow: {definition.workflow_id}")
    
    def get_workflow(self, workflow_id: str) -> Optional[WorkflowDefinition]:
        """获取工作流定义"""
        return self._workflows.get(workflow_id)
    
    def get_instance(self, instance_id: str) -> Optional[WorkflowInstance]:
        """获取工作流实例"""
        return self._instances.get(instance_id)
    
    async def execute(
        self,
        workflow_id: str,
        inputs: Dict[str, Any] = None
    ) -> WorkflowInstance:
        """
        执行工作流
        
        Args:
            workflow_id: 工作流ID
            inputs: 输入参数
        
        Returns:
            工作流实例
        """
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        # 创建实例
        instance = WorkflowInstance(
            workflow_id=workflow_id,
            inputs=inputs or {},
            context={"inputs": inputs or {}}
        )
        
        # 初始化步骤结果
        for step in workflow.steps:
            instance.step_results[step.step_id] = StepResult(
                step_id=step.step_id,
                state=StepState.PENDING
            )
        
        self._instances[instance.instance_id] = instance
        
        # 启动执行
        instance.state = WorkflowState.RUNNING
        instance.started_at = datetime.now()
        
        try:
            await self._execute_dag(workflow, instance)
            
            if instance.state == WorkflowState.RUNNING:
                instance.state = WorkflowState.COMPLETED
        except asyncio.CancelledError:
            instance.state = WorkflowState.CANCELLED
        except Exception as e:
            instance.state = WorkflowState.FAILED
            instance.error = str(e)
            logger.exception(f"Workflow {workflow_id} failed: {e}")
        finally:
            instance.finished_at = datetime.now()
        
        return instance
    
    async def _execute_dag(
        self,
        workflow: WorkflowDefinition,
        instance: WorkflowInstance
    ):
        """
        执行DAG（拓扑排序 + 并行执行）
        """
        # 构建依赖图
        step_map = {s.step_id: s for s in workflow.steps}
        in_degree = {s.step_id: len(s.depends_on) for s in workflow.steps}
        dependents = defaultdict(list)
        
        for step in workflow.steps:
            for dep in step.depends_on:
                dependents[dep].append(step.step_id)
        
        # 找出初始可执行步骤
        ready = [sid for sid, deg in in_degree.items() if deg == 0]
        pending_tasks: Dict[str, asyncio.Task] = {}
        
        while ready or pending_tasks:
            # 启动所有就绪的步骤
            for step_id in ready:
                if instance.state != WorkflowState.RUNNING:
                    break
                
                step = step_map[step_id]
                
                # 检查条件
                if step.condition and not self._evaluate_condition(step.condition, instance.context):
                    instance.step_results[step_id].state = StepState.SKIPPED
                    self._notify_step_complete(instance, step_id)
                    continue
                
                # 启动异步任务
                task = asyncio.create_task(
                    self._execute_step(step, instance)
                )
                pending_tasks[step_id] = task
            
            ready.clear()
            
            if not pending_tasks:
                break
            
            # 等待任一任务完成
            done, _ = await asyncio.wait(
                pending_tasks.values(),
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # 处理完成的任务
            for task in done:
                # 找到对应的step_id
                completed_step_id = None
                for sid, t in pending_tasks.items():
                    if t == task:
                        completed_step_id = sid
                        break
                
                if completed_step_id:
                    del pending_tasks[completed_step_id]
                    
                    # 检查是否失败
                    result = instance.step_results[completed_step_id]
                    if result.state == StepState.FAILED:
                        if workflow.error_policy == ErrorPolicy.STOP:
                            instance.state = WorkflowState.FAILED
                            instance.error = f"Step {completed_step_id} failed"
                            # 取消所有运行中的任务
                            for t in pending_tasks.values():
                                t.cancel()
                            return
                    
                    # 更新依赖计数，找出新的可执行步骤
                    for dep_id in dependents[completed_step_id]:
                        in_degree[dep_id] -= 1
                        if in_degree[dep_id] == 0:
                            ready.append(dep_id)
    
    async def _execute_step(
        self,
        step: StepDefinition,
        instance: WorkflowInstance
    ):
        """执行单个步骤"""
        result = instance.step_results[step.step_id]
        result.state = StepState.RUNNING
        result.started_at = datetime.now()
        instance.current_step = step.step_id
        
        self._notify_step_start(instance, step.step_id)
        
        try:
            # 解析参数（替换模板变量）
            params = self._resolve_params(step.params, instance.context)
            
            # 根据步骤类型执行
            output = None
            
            if step.step_type == StepType.TOOL_CALL:
                output = await self._execute_tool(step.tool_name, params)
            
            elif step.step_type == StepType.LLM_QUERY:
                output = await self._execute_llm(params)
            
            elif step.step_type == StepType.CONDITION:
                output = self._evaluate_condition(step.condition, instance.context)
            
            elif step.step_type == StepType.DELAY:
                delay = params.get("seconds", 1)
                await asyncio.sleep(delay)
                output = {"delayed": delay}
            
            elif step.step_type == StepType.NOTIFICATION:
                output = await self._send_notification(params)
            
            elif step.step_type == StepType.HUMAN_APPROVAL:
                result.state = StepState.WAITING_APPROVAL
                self._notify_step_update(instance, step.step_id)
                # TODO: 等待人工审批
                output = {"approved": True}
            
            # 保存输出到上下文
            if step.output_key:
                instance.context[step.output_key] = output
            
            result.output = output
            result.state = StepState.SUCCESS
            
        except asyncio.TimeoutError:
            result.state = StepState.FAILED
            result.error = f"Step timeout after {step.timeout_seconds}s"
            
        except Exception as e:
            result.state = StepState.FAILED
            result.error = str(e)
            logger.exception(f"Step {step.step_id} failed: {e}")
        
        finally:
            result.finished_at = datetime.now()
            if result.started_at:
                result.duration_ms = int(
                    (result.finished_at - result.started_at).total_seconds() * 1000
                )
            
            self._notify_step_complete(instance, step.step_id)
    
    async def _execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Any:
        """执行工具调用"""
        if not self._tool_executor:
            raise RuntimeError("Tool executor not configured")
        
        return await self._tool_executor(tool_name, params)
    
    async def _execute_llm(self, params: Dict[str, Any]) -> Any:
        """执行LLM查询"""
        if not self._llm_executor:
            raise RuntimeError("LLM executor not configured")
        
        return await self._llm_executor(params)
    
    async def _send_notification(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """发送通知"""
        # TODO: 实现通知发送逻辑
        logger.info(f"Notification: {params}")
        return {"sent": True, "params": params}
    
    def _resolve_params(
        self,
        params: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """解析参数模板"""
        import re
        
        resolved = {}
        pattern = r'\{\{([^}]+)\}\}'
        
        for key, value in params.items():
            if isinstance(value, str):
                # 替换模板变量 {{variable}}
                def replace(match):
                    var_path = match.group(1).strip()
                    return str(self._get_context_value(var_path, context))
                
                resolved[key] = re.sub(pattern, replace, value)
            elif isinstance(value, dict):
                resolved[key] = self._resolve_params(value, context)
            else:
                resolved[key] = value
        
        return resolved
    
    def _get_context_value(self, path: str, context: Dict[str, Any]) -> Any:
        """从上下文获取值（支持点号路径）"""
        parts = path.split('.')
        value = context
        
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            elif hasattr(value, part):
                value = getattr(value, part)
            else:
                return None
        
        return value
    
    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """评估条件表达式"""
        # 简单实现：只支持基本比较
        # TODO: 使用更安全的表达式解析器
        try:
            # 替换变量
            import re
            pattern = r'\{\{([^}]+)\}\}'
            
            def replace(match):
                var_path = match.group(1).strip()
                value = self._get_context_value(var_path, context)
                if isinstance(value, str):
                    return f'"{value}"'
                return str(value)
            
            expr = re.sub(pattern, replace, condition)
            
            # 安全评估（仅允许比较运算）
            allowed = {'True', 'False', 'None', 'and', 'or', 'not', 'in', '==', '!=', '<', '>', '<=', '>='}
            # 简化处理，实际应使用AST解析
            return eval(expr, {"__builtins__": {}}, {})
        except Exception as e:
            logger.warning(f"Failed to evaluate condition '{condition}': {e}")
            return False
    
    def _notify_step_start(self, instance: WorkflowInstance, step_id: str):
        """通知步骤开始"""
        if self._progress_callback:
            try:
                self._progress_callback({
                    "type": "step_start",
                    "instance_id": instance.instance_id,
                    "step_id": step_id,
                    "progress": instance.progress
                })
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")
    
    def _notify_step_update(self, instance: WorkflowInstance, step_id: str):
        """通知步骤更新"""
        if self._progress_callback:
            try:
                self._progress_callback({
                    "type": "step_update",
                    "instance_id": instance.instance_id,
                    "step_id": step_id,
                    "state": instance.step_results[step_id].state,
                    "progress": instance.progress
                })
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")
    
    def _notify_step_complete(self, instance: WorkflowInstance, step_id: str):
        """通知步骤完成"""
        if self._progress_callback:
            try:
                result = instance.step_results[step_id]
                self._progress_callback({
                    "type": "step_complete",
                    "instance_id": instance.instance_id,
                    "step_id": step_id,
                    "state": result.state,
                    "duration_ms": result.duration_ms,
                    "progress": instance.progress
                })
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")
    
    async def pause(self, instance_id: str) -> bool:
        """暂停工作流"""
        instance = self._instances.get(instance_id)
        if instance and instance.state == WorkflowState.RUNNING:
            instance.state = WorkflowState.PAUSED
            return True
        return False
    
    async def resume(self, instance_id: str) -> bool:
        """恢复工作流"""
        instance = self._instances.get(instance_id)
        if instance and instance.state == WorkflowState.PAUSED:
            instance.state = WorkflowState.RUNNING
            # TODO: 从暂停点继续执行
            return True
        return False
    
    async def cancel(self, instance_id: str) -> bool:
        """取消工作流"""
        instance = self._instances.get(instance_id)
        if instance and instance.state in (WorkflowState.RUNNING, WorkflowState.PAUSED):
            instance.state = WorkflowState.CANCELLED
            
            # 取消运行中的任务
            if instance_id in self._running_tasks:
                self._running_tasks[instance_id].cancel()
            
            return True
        return False
