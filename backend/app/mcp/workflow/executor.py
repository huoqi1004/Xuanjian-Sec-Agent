"""
Skill Workflow Executor

Executes parsed skill workflows with support for:
- Parallel and sequential step execution
- Variable resolution with template expressions
- Conditional branching
- Loop execution
- Approval gates
- Error handling and retry
- Progress tracking and events
"""

import re
import asyncio
import logging
import uuid
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set
from enum import Enum
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from pydantic import BaseModel, Field

from .dsl_parser import (
    SkillDefinition,
    StepDefinition,
    StepType,
    ErrorPolicy,
    ApprovalLevel,
    LoopConfig,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Execution State Models
# ============================================================================

class ExecutionStatus(str, Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class StepStatus(str, Enum):
    """Step execution status"""
    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


@dataclass
class StepResult:
    """Result of a step execution"""
    step_id: str
    status: StepStatus
    output: Optional[Any] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: int = 0
    
    @property
    def execution_time_ms(self) -> int:
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds() * 1000)
        return 0


@dataclass
class ExecutionContext:
    """Context for workflow execution"""
    execution_id: str
    skill_name: str
    inputs: Dict[str, Any]
    variables: Dict[str, Any] = field(default_factory=dict)
    step_results: Dict[str, StepResult] = field(default_factory=dict)
    status: ExecutionStatus = ExecutionStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    
    def get_step_output(self, step_id: str) -> Optional[Any]:
        """Get output from a completed step"""
        if step_id in self.step_results:
            return self.step_results[step_id].output
        return None


class ApprovalRequest(BaseModel):
    """Approval request for high-risk operations"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    execution_id: str
    step_id: str
    step_name: str
    approval_level: ApprovalLevel
    tool_name: Optional[str] = None
    tool_params: Dict[str, Any] = Field(default_factory=dict)
    requested_at: datetime = Field(default_factory=datetime.now)
    expires_at: datetime = Field(default_factory=lambda: datetime.now() + timedelta(hours=1))
    approvers: List[str] = Field(default_factory=list)
    approved_by: List[str] = Field(default_factory=list)
    rejected_by: Optional[str] = None
    status: str = "pending"  # pending, approved, rejected, expired


# ============================================================================
# Progress and Events
# ============================================================================

class ExecutionEvent(BaseModel):
    """Event emitted during execution"""
    event_type: str
    execution_id: str
    step_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    data: Dict[str, Any] = Field(default_factory=dict)


ProgressCallback = Callable[[ExecutionEvent], Coroutine[Any, Any, None]]


# ============================================================================
# Tool Executor Interface
# ============================================================================

ToolExecutor = Callable[[str, Dict[str, Any]], Coroutine[Any, Any, Any]]


# ============================================================================
# Variable Resolution
# ============================================================================

class VariableResolver:
    """
    Resolves template variables in step parameters.
    
    Supports:
    - ${inputs.name} - Skill input values
    - ${step_id.output} - Step output
    - ${step_id.output.field} - Nested field access
    - ${env.VAR_NAME} - Environment variables
    - Ternary expressions: ${condition ? true_value : false_value}
    """
    
    # Pattern for variable references: ${path.to.value}
    VAR_PATTERN = re.compile(r'\$\{([^}]+)\}')
    
    # Pattern for ternary expressions
    TERNARY_PATTERN = re.compile(r'(.+?)\s*\?\s*(.+?)\s*:\s*(.+)')

    def __init__(self, context: ExecutionContext):
        self.context = context

    def resolve(self, value: Any) -> Any:
        """Resolve variables in a value (recursively for dicts/lists)"""
        if isinstance(value, str):
            return self._resolve_string(value)
        elif isinstance(value, dict):
            return {k: self.resolve(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self.resolve(v) for v in value]
        return value

    def _resolve_string(self, value: str) -> Any:
        """Resolve variables in a string"""
        # Check if entire string is a variable reference
        match = self.VAR_PATTERN.fullmatch(value)
        if match:
            # Return the actual value (may not be string)
            return self._resolve_reference(match.group(1))
        
        # Replace all variable references in string
        def replacer(m):
            resolved = self._resolve_reference(m.group(1))
            return str(resolved) if resolved is not None else ""
        
        return self.VAR_PATTERN.sub(replacer, value)

    def _resolve_reference(self, ref: str) -> Any:
        """Resolve a single variable reference"""
        ref = ref.strip()
        
        # Check for ternary expression
        ternary_match = self.TERNARY_PATTERN.match(ref)
        if ternary_match:
            condition = self._resolve_reference(ternary_match.group(1))
            true_val = ternary_match.group(2).strip().strip("'\"")
            false_val = ternary_match.group(3).strip().strip("'\"")
            return true_val if self._is_truthy(condition) else false_val
        
        # Split path
        parts = ref.split('.')
        if not parts:
            return None
        
        root = parts[0]
        path = parts[1:] if len(parts) > 1 else []
        
        # Resolve root
        if root == 'inputs':
            value = self.context.inputs
        elif root == 'env':
            import os
            if path:
                return os.environ.get(path[0], '')
            return {}
        elif root in self.context.step_results:
            result = self.context.step_results[root]
            if result.status == StepStatus.COMPLETED:
                value = result.output
            else:
                value = None
        elif root in self.context.variables:
            value = self.context.variables[root]
        else:
            return None
        
        # Navigate path
        for part in path:
            if value is None:
                return None
            if isinstance(value, dict):
                value = value.get(part)
            elif hasattr(value, part):
                value = getattr(value, part)
            elif hasattr(value, '__getitem__'):
                try:
                    value = value[part]
                except (KeyError, IndexError, TypeError):
                    return None
            else:
                return None
        
        return value

    def _is_truthy(self, value: Any) -> bool:
        """Check if a value is truthy"""
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() not in ('', 'false', 'no', '0', 'none')
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, (list, dict)):
            return len(value) > 0
        return bool(value)


# ============================================================================
# Skill Executor Implementation
# ============================================================================

class SkillExecutor:
    """
    Executes skill workflows.
    
    Features:
    - DAG-based parallel execution
    - Variable resolution
    - Approval gates
    - Error handling and retry
    - Progress tracking
    """

    def __init__(
        self,
        tool_executor: ToolExecutor,
        max_concurrent_steps: int = 5,
        default_timeout: int = 3600,
    ):
        self.tool_executor = tool_executor
        self.max_concurrent_steps = max_concurrent_steps
        self.default_timeout = default_timeout
        
        # Active executions
        self._executions: Dict[str, ExecutionContext] = {}
        
        # Pending approvals
        self._approvals: Dict[str, ApprovalRequest] = {}
        
        # Approval handlers
        self._approval_handlers: Dict[ApprovalLevel, Callable] = {}
        
        # Progress callbacks
        self._progress_callbacks: List[ProgressCallback] = []
        
        # Semaphore for concurrency control
        self._semaphore = asyncio.Semaphore(max_concurrent_steps)

    def register_progress_callback(self, callback: ProgressCallback) -> None:
        """Register a callback for execution progress events"""
        self._progress_callbacks.append(callback)

    def register_approval_handler(
        self,
        level: ApprovalLevel,
        handler: Callable[[ApprovalRequest], Coroutine[Any, Any, bool]]
    ) -> None:
        """Register an approval handler for a specific level"""
        self._approval_handlers[level] = handler

    async def execute(
        self,
        skill: SkillDefinition,
        inputs: Dict[str, Any],
        execution_id: Optional[str] = None,
    ) -> ExecutionContext:
        """
        Execute a skill workflow.
        
        Args:
            skill: Parsed skill definition
            inputs: Input parameter values
            execution_id: Optional execution ID (generated if not provided)
            
        Returns:
            ExecutionContext with results
        """
        execution_id = execution_id or str(uuid.uuid4())
        
        # Create context
        context = ExecutionContext(
            execution_id=execution_id,
            skill_name=skill.metadata.name,
            inputs=inputs,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(),
        )
        
        self._executions[execution_id] = context
        
        # Emit start event
        await self._emit_event(ExecutionEvent(
            event_type="execution_started",
            execution_id=execution_id,
            data={
                "skill_name": skill.metadata.name,
                "inputs": inputs,
            }
        ))
        
        try:
            # Execute workflow
            await self._execute_workflow(skill, context)
            
            # Set completion status
            if context.status == ExecutionStatus.RUNNING:
                context.status = ExecutionStatus.COMPLETED
            context.completed_at = datetime.now()
            
            # Emit completion event
            await self._emit_event(ExecutionEvent(
                event_type="execution_completed",
                execution_id=execution_id,
                data={
                    "status": context.status.value,
                    "duration_ms": int(
                        (context.completed_at - context.started_at).total_seconds() * 1000
                    ),
                }
            ))
            
        except asyncio.CancelledError:
            context.status = ExecutionStatus.CANCELLED
            context.completed_at = datetime.now()
            raise
            
        except asyncio.TimeoutError:
            context.status = ExecutionStatus.TIMEOUT
            context.error = "Execution timed out"
            context.completed_at = datetime.now()
            
        except Exception as e:
            context.status = ExecutionStatus.FAILED
            context.error = str(e)
            context.completed_at = datetime.now()
            logger.exception(f"Skill execution failed: {execution_id}")
            
            # Emit error event
            await self._emit_event(ExecutionEvent(
                event_type="execution_failed",
                execution_id=execution_id,
                data={"error": str(e)}
            ))
        
        return context

    async def _execute_workflow(
        self,
        skill: SkillDefinition,
        context: ExecutionContext,
    ) -> None:
        """Execute workflow steps in DAG order"""
        # Build dependency graph
        pending_steps: Set[str] = {s.id for s in skill.steps}
        completed_steps: Set[str] = set()
        
        while pending_steps:
            # Find steps ready to execute (all dependencies satisfied)
            ready_steps = []
            for step_id in pending_steps:
                step = skill.get_step(step_id)
                if step and all(d in completed_steps for d in step.depends_on):
                    ready_steps.append(step)
            
            if not ready_steps:
                # No progress possible - check for errors
                if pending_steps:
                    raise RuntimeError(
                        f"Workflow stuck: steps {pending_steps} cannot execute"
                    )
                break
            
            # Execute ready steps (in parallel if possible)
            tasks = []
            for step in ready_steps:
                task = asyncio.create_task(
                    self._execute_step(step, skill, context)
                )
                tasks.append((step.id, task))
            
            # Wait for all tasks
            for step_id, task in tasks:
                try:
                    result = await task
                    context.step_results[step_id] = result
                    
                    if result.status == StepStatus.COMPLETED:
                        completed_steps.add(step_id)
                        pending_steps.discard(step_id)
                    elif result.status == StepStatus.SKIPPED:
                        completed_steps.add(step_id)
                        pending_steps.discard(step_id)
                    elif result.status == StepStatus.FAILED:
                        step = skill.get_step(step_id)
                        if step and step.error_policy == ErrorPolicy.STOP:
                            context.status = ExecutionStatus.FAILED
                            context.error = f"Step '{step_id}' failed: {result.error}"
                            return
                        elif step and step.error_policy == ErrorPolicy.CONTINUE:
                            completed_steps.add(step_id)
                            pending_steps.discard(step_id)
                        # RETRY is handled within _execute_step
                except Exception as e:
                    logger.exception(f"Step {step_id} failed")
                    pending_steps.discard(step_id)
                    context.step_results[step_id] = StepResult(
                        step_id=step_id,
                        status=StepStatus.FAILED,
                        error=str(e),
                    )
                    
                    step = skill.get_step(step_id)
                    if step and step.error_policy == ErrorPolicy.STOP:
                        context.status = ExecutionStatus.FAILED
                        context.error = f"Step '{step_id}' failed: {e}"
                        return

    async def _execute_step(
        self,
        step: StepDefinition,
        skill: SkillDefinition,
        context: ExecutionContext,
    ) -> StepResult:
        """Execute a single step"""
        result = StepResult(
            step_id=step.id,
            status=StepStatus.RUNNING,
            started_at=datetime.now(),
        )
        
        # Emit step started event
        await self._emit_event(ExecutionEvent(
            event_type="step_started",
            execution_id=context.execution_id,
            step_id=step.id,
            data={"step_name": step.name, "step_type": step.type.value}
        ))
        
        try:
            # Check condition
            if step.condition:
                resolver = VariableResolver(context)
                condition_result = resolver.resolve(step.condition.expression)
                if not resolver._is_truthy(condition_result):
                    # Skip step or go to false branch
                    result.status = StepStatus.SKIPPED
                    result.completed_at = datetime.now()
                    return result
            
            # Check approval requirement
            if step.approval_level != ApprovalLevel.NONE:
                approved = await self._request_approval(step, context)
                if not approved:
                    result.status = StepStatus.FAILED
                    result.error = "Approval denied or timed out"
                    result.completed_at = datetime.now()
                    return result
            
            # Execute based on step type
            async with self._semaphore:
                if step.type == StepType.TOOL:
                    output = await self._execute_tool_step(step, context)
                elif step.type == StepType.LOOP:
                    output = await self._execute_loop_step(step, context)
                elif step.type == StepType.PARALLEL:
                    output = await self._execute_parallel_step(step, skill, context)
                elif step.type == StepType.CONDITION:
                    output = await self._execute_condition_step(step, skill, context)
                elif step.type == StepType.WAIT:
                    output = await self._execute_wait_step(step, context)
                elif step.type == StepType.TRANSFORM:
                    output = await self._execute_transform_step(step, context)
                elif step.type == StepType.NOTIFY:
                    output = await self._execute_notify_step(step, context)
                else:
                    raise ValueError(f"Unknown step type: {step.type}")
            
            result.status = StepStatus.COMPLETED
            result.output = output
            result.completed_at = datetime.now()
            
            # Emit step completed event
            await self._emit_event(ExecutionEvent(
                event_type="step_completed",
                execution_id=context.execution_id,
                step_id=step.id,
                data={
                    "duration_ms": result.execution_time_ms,
                    "output_preview": str(output)[:200] if output else None,
                }
            ))
            
        except Exception as e:
            logger.exception(f"Step {step.id} execution failed")
            result.status = StepStatus.FAILED
            result.error = str(e)
            result.completed_at = datetime.now()
            
            # Handle retry
            if step.retry and result.retry_count < step.retry.max_attempts:
                result.retry_count += 1
                delay = min(
                    step.retry.delay_seconds * (step.retry.backoff_multiplier ** (result.retry_count - 1)),
                    step.retry.max_delay_seconds
                )
                logger.info(f"Retrying step {step.id} in {delay}s (attempt {result.retry_count})")
                await asyncio.sleep(delay)
                return await self._execute_step(step, skill, context)
            
            # Emit step failed event
            await self._emit_event(ExecutionEvent(
                event_type="step_failed",
                execution_id=context.execution_id,
                step_id=step.id,
                data={"error": str(e)}
            ))
        
        return result

    async def _execute_tool_step(
        self,
        step: StepDefinition,
        context: ExecutionContext,
    ) -> Any:
        """Execute a tool step"""
        if not step.tool:
            raise ValueError(f"Step {step.id} has no tool specified")
        
        # Resolve parameters
        resolver = VariableResolver(context)
        params = resolver.resolve(step.tool_params)
        
        # Execute tool
        result = await asyncio.wait_for(
            self.tool_executor(step.tool, params),
            timeout=step.timeout_seconds,
        )
        
        return result

    async def _execute_loop_step(
        self,
        step: StepDefinition,
        context: ExecutionContext,
    ) -> List[Any]:
        """Execute a loop step"""
        if not step.loop:
            raise ValueError(f"Step {step.id} has no loop configuration")
        
        # Resolve items
        resolver = VariableResolver(context)
        items = resolver.resolve(step.loop.items)
        
        if not isinstance(items, (list, tuple)):
            raise ValueError(f"Loop items must be a list, got {type(items)}")
        
        results = []
        
        if step.loop.parallel:
            # Parallel execution
            semaphore = asyncio.Semaphore(step.loop.max_parallel)
            
            async def execute_item(item: Any, index: int) -> Any:
                async with semaphore:
                    # Create item context
                    item_context = ExecutionContext(
                        execution_id=f"{context.execution_id}_loop_{index}",
                        skill_name=context.skill_name,
                        inputs=context.inputs,
                        variables={
                            **context.variables,
                            step.loop.item_var: item,
                            "index": index,
                        },
                        step_results=context.step_results.copy(),
                    )
                    
                    # Resolve params with item context
                    item_resolver = VariableResolver(item_context)
                    params = item_resolver.resolve(step.tool_params)
                    
                    return await self.tool_executor(step.tool, params)
            
            tasks = [execute_item(item, i) for i, item in enumerate(items)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
        else:
            # Sequential execution
            for i, item in enumerate(items):
                context.variables[step.loop.item_var] = item
                context.variables["index"] = i
                
                resolver = VariableResolver(context)
                params = resolver.resolve(step.tool_params)
                
                result = await self.tool_executor(step.tool, params)
                results.append(result)
        
        return results

    async def _execute_parallel_step(
        self,
        step: StepDefinition,
        skill: SkillDefinition,
        context: ExecutionContext,
    ) -> Dict[str, Any]:
        """Execute parallel steps"""
        results = {}
        
        async def execute_substep(substep_id: str) -> tuple:
            substep = skill.get_step(substep_id)
            if not substep:
                raise ValueError(f"Unknown substep: {substep_id}")
            result = await self._execute_step(substep, skill, context)
            return substep_id, result
        
        tasks = [execute_substep(sid) for sid in step.parallel_steps]
        completed = await asyncio.gather(*tasks, return_exceptions=True)
        
        for item in completed:
            if isinstance(item, Exception):
                logger.error(f"Parallel substep failed: {item}")
            else:
                step_id, result = item
                results[step_id] = result.output if result.status == StepStatus.COMPLETED else None
        
        return results

    async def _execute_condition_step(
        self,
        step: StepDefinition,
        skill: SkillDefinition,
        context: ExecutionContext,
    ) -> Any:
        """Execute a condition step"""
        if not step.condition:
            raise ValueError(f"Step {step.id} has no condition")
        
        resolver = VariableResolver(context)
        condition_result = resolver.resolve(step.condition.expression)
        
        if resolver._is_truthy(condition_result):
            if step.condition.true_branch:
                branch_step = skill.get_step(step.condition.true_branch)
                if branch_step:
                    result = await self._execute_step(branch_step, skill, context)
                    return {"branch": "true", "result": result.output}
        else:
            if step.condition.false_branch:
                branch_step = skill.get_step(step.condition.false_branch)
                if branch_step:
                    result = await self._execute_step(branch_step, skill, context)
                    return {"branch": "false", "result": result.output}
        
        return {"branch": "true" if resolver._is_truthy(condition_result) else "false", "result": None}

    async def _execute_wait_step(
        self,
        step: StepDefinition,
        context: ExecutionContext,
    ) -> Dict[str, Any]:
        """Execute a wait step"""
        if not step.wait:
            raise ValueError(f"Step {step.id} has no wait configuration")
        
        start_time = datetime.now()
        timeout = step.wait.timeout_seconds
        
        if step.wait.duration_seconds:
            # Simple wait
            await asyncio.sleep(step.wait.duration_seconds)
            return {"waited_seconds": step.wait.duration_seconds}
        
        elif step.wait.until_condition:
            # Wait for condition
            resolver = VariableResolver(context)
            
            while (datetime.now() - start_time).total_seconds() < timeout:
                result = resolver.resolve(step.wait.until_condition)
                if resolver._is_truthy(result):
                    return {
                        "condition_met": True,
                        "waited_seconds": (datetime.now() - start_time).total_seconds(),
                    }
                await asyncio.sleep(step.wait.poll_interval_seconds)
            
            return {
                "condition_met": False,
                "waited_seconds": timeout,
                "timed_out": True,
            }
        
        return {"waited_seconds": 0}

    async def _execute_transform_step(
        self,
        step: StepDefinition,
        context: ExecutionContext,
    ) -> Any:
        """Execute a transform step"""
        resolver = VariableResolver(context)
        params = resolver.resolve(step.tool_params)
        
        operation = params.get("operation", "identity")
        
        if operation == "merge":
            sources = params.get("sources", [])
            result = {}
            for source in sources:
                if isinstance(source, dict):
                    result.update(source)
            return result
        
        elif operation == "filter":
            source = params.get("source", [])
            condition = params.get("condition", "true")
            return [item for item in source if resolver._is_truthy(
                resolver.resolve(condition.replace("$item", str(item)))
            )]
        
        elif operation == "map":
            source = params.get("source", [])
            transform = params.get("transform", "$item")
            return [resolver.resolve(transform.replace("$item", str(item))) for item in source]
        
        elif operation == "extract":
            source = params.get("source", {})
            fields = params.get("fields", [])
            return {f: source.get(f) for f in fields if f in source}
        
        else:
            return params.get("source")

    async def _execute_notify_step(
        self,
        step: StepDefinition,
        context: ExecutionContext,
    ) -> Dict[str, Any]:
        """Execute a notify step"""
        if not step.notify:
            raise ValueError(f"Step {step.id} has no notify configuration")
        
        resolver = VariableResolver(context)
        message = resolver.resolve(step.notify.template)
        
        # Emit notification event
        await self._emit_event(ExecutionEvent(
            event_type="notification",
            execution_id=context.execution_id,
            step_id=step.id,
            data={
                "channel": step.notify.channel,
                "recipients": step.notify.recipients,
                "message": message,
                "severity": step.notify.severity,
            }
        ))
        
        return {
            "sent": True,
            "channel": step.notify.channel,
            "recipients": step.notify.recipients,
        }

    async def _request_approval(
        self,
        step: StepDefinition,
        context: ExecutionContext,
    ) -> bool:
        """Request and wait for approval"""
        request = ApprovalRequest(
            execution_id=context.execution_id,
            step_id=step.id,
            step_name=step.name,
            approval_level=step.approval_level,
            tool_name=step.tool,
            tool_params=step.tool_params,
            expires_at=datetime.now() + timedelta(minutes=step.approval_timeout_minutes),
        )
        
        self._approvals[request.id] = request
        
        # Emit approval request event
        await self._emit_event(ExecutionEvent(
            event_type="approval_requested",
            execution_id=context.execution_id,
            step_id=step.id,
            data={
                "approval_id": request.id,
                "approval_level": step.approval_level.value,
                "expires_at": request.expires_at.isoformat(),
            }
        ))
        
        # Check for registered handler
        if step.approval_level in self._approval_handlers:
            handler = self._approval_handlers[step.approval_level]
            try:
                approved = await asyncio.wait_for(
                    handler(request),
                    timeout=step.approval_timeout_minutes * 60,
                )
                request.status = "approved" if approved else "rejected"
                return approved
            except asyncio.TimeoutError:
                request.status = "expired"
                return False
        
        # No handler - auto-approve for testing
        logger.warning(f"No approval handler for {step.approval_level}, auto-approving")
        request.status = "approved"
        return True

    async def approve(self, approval_id: str, approver: str) -> bool:
        """Approve a pending request"""
        if approval_id not in self._approvals:
            return False
        
        request = self._approvals[approval_id]
        
        if request.status != "pending":
            return False
        
        if datetime.now() > request.expires_at:
            request.status = "expired"
            return False
        
        request.approved_by.append(approver)
        
        # Check if enough approvers
        required = 2 if request.approval_level == ApprovalLevel.DUAL else 1
        if len(request.approved_by) >= required:
            request.status = "approved"
        
        return request.status == "approved"

    async def reject(self, approval_id: str, rejector: str) -> bool:
        """Reject a pending request"""
        if approval_id not in self._approvals:
            return False
        
        request = self._approvals[approval_id]
        
        if request.status != "pending":
            return False
        
        request.rejected_by = rejector
        request.status = "rejected"
        return True

    async def cancel(self, execution_id: str) -> bool:
        """Cancel a running execution"""
        if execution_id not in self._executions:
            return False
        
        context = self._executions[execution_id]
        context.status = ExecutionStatus.CANCELLED
        context.completed_at = datetime.now()
        
        await self._emit_event(ExecutionEvent(
            event_type="execution_cancelled",
            execution_id=execution_id,
        ))
        
        return True

    async def _emit_event(self, event: ExecutionEvent) -> None:
        """Emit an event to all registered callbacks"""
        for callback in self._progress_callbacks:
            try:
                await callback(event)
            except Exception as e:
                logger.exception(f"Progress callback failed: {e}")

    def get_execution(self, execution_id: str) -> Optional[ExecutionContext]:
        """Get execution context by ID"""
        return self._executions.get(execution_id)

    def get_approval(self, approval_id: str) -> Optional[ApprovalRequest]:
        """Get approval request by ID"""
        return self._approvals.get(approval_id)

    def list_pending_approvals(self) -> List[ApprovalRequest]:
        """List all pending approval requests"""
        return [r for r in self._approvals.values() if r.status == "pending"]
