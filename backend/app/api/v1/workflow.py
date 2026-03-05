"""
玄鉴安全智能体 - 工作流编排API
提供安全工作流管理和执行功能
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
from fastapi import APIRouter, Query, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

router = APIRouter()


# ============ 枚举定义 ============

class WorkflowStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING_APPROVAL = "waiting_approval"


class StepType(str, Enum):
    TOOL_CALL = "tool_call"
    LLM_QUERY = "llm_query"
    CONDITION = "condition"
    PARALLEL = "parallel"
    NOTIFICATION = "notification"
    HUMAN_APPROVAL = "human_approval"


class TriggerType(str, Enum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    EVENT = "event"
    API = "api"


# ============ Schema定义 ============

class WorkflowStep(BaseModel):
    """工作流步骤"""
    id: str = Field(..., description="步骤ID")
    name: str = Field(..., description="步骤名称")
    type: StepType = Field(..., description="步骤类型")
    status: StepStatus = Field(default=StepStatus.PENDING, description="步骤状态")
    tool: Optional[str] = Field(default=None, description="调用的工具")
    params: Dict[str, Any] = Field(default={}, description="参数")
    output: Optional[Any] = Field(default=None, description="输出结果")
    error: Optional[str] = Field(default=None, description="错误信息")
    started_at: Optional[datetime] = Field(default=None, description="开始时间")
    finished_at: Optional[datetime] = Field(default=None, description="结束时间")
    duration_ms: Optional[int] = Field(default=None, description="耗时(毫秒)")


class WorkflowDefinition(BaseModel):
    """工作流定义"""
    id: str = Field(..., description="工作流ID")
    name: str = Field(..., description="工作流名称")
    description: str = Field(default="", description="描述")
    trigger_type: TriggerType = Field(..., description="触发类型")
    steps: List[dict] = Field(..., description="步骤定义")
    inputs: Dict[str, Any] = Field(default={}, description="输入参数定义")
    outputs: Dict[str, Any] = Field(default={}, description="输出参数定义")
    timeout_sec: int = Field(default=1800, description="超时时间(秒)")
    created_at: datetime = Field(..., description="创建时间")
    updated_at: datetime = Field(..., description="更新时间")
    version: str = Field(default="1.0.0", description="版本")


class WorkflowExecution(BaseModel):
    """工作流执行实例"""
    execution_id: str = Field(..., description="执行ID")
    workflow_id: str = Field(..., description="工作流ID")
    workflow_name: str = Field(..., description="工作流名称")
    status: WorkflowStatus = Field(..., description="执行状态")
    steps: List[WorkflowStep] = Field(default=[], description="步骤列表")
    inputs: Dict[str, Any] = Field(default={}, description="输入参数")
    outputs: Optional[Dict[str, Any]] = Field(default=None, description="输出结果")
    context: Dict[str, Any] = Field(default={}, description="上下文")
    progress: int = Field(default=0, ge=0, le=100, description="进度")
    current_step: Optional[str] = Field(default=None, description="当前步骤")
    started_at: datetime = Field(..., description="开始时间")
    finished_at: Optional[datetime] = Field(default=None, description="结束时间")
    error: Optional[str] = Field(default=None, description="错误信息")
    triggered_by: str = Field(default="manual", description="触发方式")


class ExecuteWorkflowRequest(BaseModel):
    """执行工作流请求"""
    workflow_id: str = Field(..., description="工作流ID")
    inputs: Dict[str, Any] = Field(default={}, description="输入参数")
    async_mode: bool = Field(default=True, description="是否异步执行")


class SkillInfo(BaseModel):
    """Skill信息"""
    id: str
    name: str
    description: str
    category: str
    inputs: Dict[str, Any]
    outputs: Dict[str, Any]
    estimated_duration: Optional[int] = None
    requires_approval: bool = False


# ============ API端点 ============

@router.get("/definitions", response_model=List[WorkflowDefinition])
async def list_workflow_definitions(
    category: Optional[str] = None,
    trigger_type: Optional[TriggerType] = None
):
    """获取工作流定义列表"""
    return [
        WorkflowDefinition(
            id="wf-incident-response",
            name="安全事件自动响应",
            description="检测到安全告警时自动执行响应流程",
            trigger_type=TriggerType.EVENT,
            steps=[
                {"id": "s1", "name": "资产确认", "type": "tool_call", "tool": "scan_asset"},
                {"id": "s2", "name": "威胁情报查询", "type": "tool_call", "tool": "query_threat_intel"},
                {"id": "s3", "name": "AI分析", "type": "llm_query"},
                {"id": "s4", "name": "自动封堵", "type": "condition"}
            ],
            inputs={"alert_id": "string", "source_ip": "string"},
            outputs={"report": "string", "actions_taken": "list"},
            timeout_sec=1800,
            created_at=datetime.now(),
            updated_at=datetime.now()
        ),
        WorkflowDefinition(
            id="wf-full-scan",
            name="全量安全扫描",
            description="执行完整的资产发现和漏洞扫描",
            trigger_type=TriggerType.SCHEDULED,
            steps=[
                {"id": "s1", "name": "资产发现", "type": "tool_call", "tool": "scan_asset"},
                {"id": "s2", "name": "漏洞扫描", "type": "tool_call", "tool": "run_vuln_scan"},
                {"id": "s3", "name": "情报关联", "type": "tool_call", "tool": "query_threat_intel"},
                {"id": "s4", "name": "生成报告", "type": "llm_query"}
            ],
            inputs={"scope": "string"},
            outputs={"report": "string", "findings": "list"},
            timeout_sec=3600,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
    ]


@router.get("/definitions/{workflow_id}", response_model=WorkflowDefinition)
async def get_workflow_definition(workflow_id: str):
    """获取工作流定义详情"""
    return WorkflowDefinition(
        id=workflow_id,
        name="安全事件自动响应",
        description="检测到安全告警时自动执行响应流程",
        trigger_type=TriggerType.EVENT,
        steps=[],
        inputs={},
        outputs={},
        timeout_sec=1800,
        created_at=datetime.now(),
        updated_at=datetime.now()
    )


@router.post("/execute", response_model=WorkflowExecution)
async def execute_workflow(
    request: ExecuteWorkflowRequest,
    background_tasks: BackgroundTasks
):
    """
    执行工作流
    
    支持同步和异步两种执行模式
    """
    import uuid
    execution_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
    
    execution = WorkflowExecution(
        execution_id=execution_id,
        workflow_id=request.workflow_id,
        workflow_name="安全事件自动响应",
        status=WorkflowStatus.PENDING if request.async_mode else WorkflowStatus.RUNNING,
        steps=[
            WorkflowStep(id="s1", name="资产确认", type=StepType.TOOL_CALL, tool="scan_asset"),
            WorkflowStep(id="s2", name="威胁情报查询", type=StepType.TOOL_CALL, tool="query_threat_intel"),
            WorkflowStep(id="s3", name="AI分析", type=StepType.LLM_QUERY),
            WorkflowStep(id="s4", name="自动封堵", type=StepType.CONDITION)
        ],
        inputs=request.inputs,
        started_at=datetime.now(),
        triggered_by="api"
    )
    
    if request.async_mode:
        # TODO: 将执行任务加入后台队列
        # background_tasks.add_task(run_workflow, execution)
        pass
    
    return execution


@router.get("/executions", response_model=List[WorkflowExecution])
async def list_workflow_executions(
    workflow_id: Optional[str] = None,
    status: Optional[WorkflowStatus] = None,
    from_time: Optional[datetime] = None,
    to_time: Optional[datetime] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100)
):
    """获取工作流执行历史"""
    return [
        WorkflowExecution(
            execution_id="EXEC-001",
            workflow_id="wf-incident-response",
            workflow_name="安全事件自动响应",
            status=WorkflowStatus.COMPLETED,
            steps=[],
            inputs={"alert_id": "ALT-001"},
            outputs={"report": "事件已处理"},
            progress=100,
            started_at=datetime.now(),
            finished_at=datetime.now(),
            triggered_by="event"
        )
    ]


@router.get("/executions/{execution_id}", response_model=WorkflowExecution)
async def get_workflow_execution(execution_id: str):
    """获取工作流执行详情"""
    return WorkflowExecution(
        execution_id=execution_id,
        workflow_id="wf-incident-response",
        workflow_name="安全事件自动响应",
        status=WorkflowStatus.RUNNING,
        steps=[
            WorkflowStep(
                id="s1",
                name="资产确认",
                type=StepType.TOOL_CALL,
                tool="scan_asset",
                status=StepStatus.SUCCESS,
                started_at=datetime.now(),
                finished_at=datetime.now(),
                duration_ms=1234
            ),
            WorkflowStep(
                id="s2",
                name="威胁情报查询",
                type=StepType.TOOL_CALL,
                tool="query_threat_intel",
                status=StepStatus.RUNNING,
                started_at=datetime.now()
            ),
            WorkflowStep(
                id="s3",
                name="AI分析",
                type=StepType.LLM_QUERY,
                status=StepStatus.PENDING
            )
        ],
        inputs={"alert_id": "ALT-001"},
        progress=50,
        current_step="s2",
        started_at=datetime.now(),
        triggered_by="event"
    )


@router.post("/executions/{execution_id}/pause")
async def pause_workflow(execution_id: str):
    """暂停工作流执行"""
    return {"message": "工作流已暂停", "execution_id": execution_id, "status": "paused"}


@router.post("/executions/{execution_id}/resume")
async def resume_workflow(execution_id: str):
    """恢复工作流执行"""
    return {"message": "工作流已恢复", "execution_id": execution_id, "status": "running"}


@router.post("/executions/{execution_id}/cancel")
async def cancel_workflow(execution_id: str):
    """取消工作流执行"""
    return {"message": "工作流已取消", "execution_id": execution_id, "status": "cancelled"}


@router.get("/skills", response_model=List[SkillInfo])
async def list_skills():
    """获取可用的Skill列表"""
    return [
        SkillInfo(
            id="incident_response",
            name="安全事件自动响应",
            description="检测到告警时自动执行响应流程",
            category="response",
            inputs={"alert_id": "string", "source_ip": "string"},
            outputs={"report": "string"},
            estimated_duration=300,
            requires_approval=True
        ),
        SkillInfo(
            id="full_scan",
            name="全量安全扫描",
            description="资产发现+漏洞扫描+情报关联",
            category="scan",
            inputs={"scope": "string"},
            outputs={"findings": "list"},
            estimated_duration=1800,
            requires_approval=False
        ),
        SkillInfo(
            id="threat_hunt",
            name="威胁狩猎",
            description="基于IOC进行主动威胁发现",
            category="analysis",
            inputs={"indicator": "string"},
            outputs={"threats": "list"},
            estimated_duration=600,
            requires_approval=False
        )
    ]


@router.post("/skills/{skill_id}/run")
async def run_skill(skill_id: str, inputs: Dict[str, Any] = {}):
    """执行Skill"""
    import uuid
    execution_id = f"SKILL-{uuid.uuid4().hex[:8].upper()}"
    
    return {
        "execution_id": execution_id,
        "skill_id": skill_id,
        "status": "running",
        "inputs": inputs,
        "started_at": datetime.now()
    }


@router.get("/approvals/pending")
async def get_pending_approvals():
    """获取待审批的工作流步骤"""
    return [
        {
            "approval_id": "APR-001",
            "execution_id": "EXEC-001",
            "step_id": "s4",
            "step_name": "IP封堵",
            "operation": "block_ip",
            "details": {"ip": "203.0.113.50", "reason": "检测到攻击行为"},
            "requested_at": datetime.now(),
            "expires_at": datetime.now(),
            "status": "pending"
        }
    ]


@router.post("/approvals/{approval_id}/approve")
async def approve_step(approval_id: str, comment: str = ""):
    """审批通过"""
    return {
        "message": "已审批通过",
        "approval_id": approval_id,
        "status": "approved",
        "comment": comment
    }


@router.post("/approvals/{approval_id}/reject")
async def reject_step(approval_id: str, reason: str):
    """审批拒绝"""
    return {
        "message": "已审批拒绝",
        "approval_id": approval_id,
        "status": "rejected",
        "reason": reason
    }
