"""
玄鉴安全智能体 - 事件总线
实现发布订阅模式的异步事件系统
"""

import asyncio
import logging
import uuid
from collections import defaultdict, deque
from datetime import datetime
from enum import Enum
from functools import lru_cache
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ============ 枚举定义 ============

class EventType(str, Enum):
    """事件类型"""
    # 工具相关
    TOOL_EXECUTED = "tool.executed"
    TOOL_FAILED = "tool.failed"
    
    # 工作流相关
    WORKFLOW_STARTED = "workflow.started"
    WORKFLOW_COMPLETED = "workflow.completed"
    WORKFLOW_FAILED = "workflow.failed"
    WORKFLOW_PAUSED = "workflow.paused"
    WORKFLOW_RESUMED = "workflow.resumed"
    WORKFLOW_CANCELLED = "workflow.cancelled"
    
    STEP_STARTED = "step.started"
    STEP_COMPLETED = "step.completed"
    STEP_FAILED = "step.failed"
    
    # 安全事件
    THREAT_DETECTED = "threat.detected"
    VULNERABILITY_FOUND = "vulnerability.found"
    ATTACK_BLOCKED = "attack.blocked"
    ANOMALY_DETECTED = "anomaly.detected"
    
    # 告警相关
    ALERT_CREATED = "alert.created"
    ALERT_UPDATED = "alert.updated"
    ALERT_RESOLVED = "alert.resolved"
    ALERT_ESCALATED = "alert.escalated"
    
    # 资产相关
    ASSET_DISCOVERED = "asset.discovered"
    ASSET_UPDATED = "asset.updated"
    ASSET_OFFLINE = "asset.offline"
    
    # AI相关
    AI_QUERY_STARTED = "ai.query.started"
    AI_QUERY_COMPLETED = "ai.query.completed"
    AI_TOOL_CALLED = "ai.tool.called"
    
    # 系统相关
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"
    
    # 审批相关
    APPROVAL_REQUIRED = "approval.required"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_DENIED = "approval.denied"


class Severity(str, Enum):
    """事件严重程度"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# ============ 数据模型 ============

class SecurityEvent(BaseModel):
    """安全事件"""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType = Field(..., description="事件类型")
    timestamp: datetime = Field(default_factory=datetime.now, description="时间戳")
    source: str = Field(..., description="事件来源")
    severity: Severity = Field(default=Severity.INFO, description="严重程度")
    payload: Dict[str, Any] = Field(default_factory=dict, description="事件数据")
    correlation_id: Optional[str] = Field(default=None, description="关联ID")
    tags: List[str] = Field(default_factory=list, description="标签")
    
    class Config:
        use_enum_values = True


class Subscription(BaseModel):
    """订阅信息"""
    subscription_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_types: List[EventType] = Field(..., description="订阅的事件类型")
    filter_func: Optional[str] = Field(default=None, description="过滤函数名")
    created_at: datetime = Field(default_factory=datetime.now)
    
    class Config:
        arbitrary_types_allowed = True


# ============ 事件总线 ============

class EventBus:
    """
    事件总线
    
    实现发布订阅模式，支持：
    - 异步事件发布
    - 多订阅者
    - 事件过滤
    - 事件历史记录
    - 事件重放
    """
    
    _instance: Optional["EventBus"] = None
    
    def __new__(cls) -> "EventBus":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        # 订阅者：事件类型 -> 处理器列表
        self._subscribers: Dict[EventType, List[tuple]] = defaultdict(list)
        
        # 订阅ID映射
        self._subscription_map: Dict[str, tuple] = {}
        
        # 事件历史（环形缓冲区）
        self._event_history: deque = deque(maxlen=10000)
        
        # 待处理事件队列
        self._event_queue: asyncio.Queue = asyncio.Queue()
        
        # 是否正在运行
        self._running: bool = False
        self._processor_task: Optional[asyncio.Task] = None
        
        self._initialized = True
        logger.info("EventBus initialized")
    
    async def start(self):
        """启动事件处理器"""
        if self._running:
            return
        
        self._running = True
        self._processor_task = asyncio.create_task(self._process_events())
        logger.info("EventBus started")
    
    async def stop(self):
        """停止事件处理器"""
        self._running = False
        
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("EventBus stopped")
    
    async def publish(self, event: SecurityEvent):
        """
        发布事件
        
        Args:
            event: 安全事件
        """
        # 记录到历史
        self._event_history.append(event)
        
        # 加入队列
        await self._event_queue.put(event)
        
        logger.debug(f"Published event: {event.event_type} from {event.source}")
    
    def publish_sync(self, event: SecurityEvent):
        """
        同步发布事件（用于非异步上下文）
        """
        self._event_history.append(event)
        
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self._dispatch_event(event))
            else:
                loop.run_until_complete(self._dispatch_event(event))
        except RuntimeError:
            # 没有事件循环时，同步调用订阅者
            for event_type in [event.event_type, EventType.SYSTEM_ERROR]:
                for handler, filter_func, _ in self._subscribers.get(event_type, []):
                    if filter_func is None or filter_func(event):
                        try:
                            if asyncio.iscoroutinefunction(handler):
                                asyncio.run(handler(event))
                            else:
                                handler(event)
                        except Exception as e:
                            logger.error(f"Handler failed: {e}")
    
    def subscribe(
        self,
        event_types: List[EventType],
        handler: Callable[[SecurityEvent], Coroutine[Any, Any, None]],
        filter_func: Optional[Callable[[SecurityEvent], bool]] = None
    ) -> str:
        """
        订阅事件
        
        Args:
            event_types: 要订阅的事件类型列表
            handler: 事件处理器（异步函数）
            filter_func: 可选的过滤函数
        
        Returns:
            订阅ID
        """
        subscription_id = str(uuid.uuid4())
        
        for event_type in event_types:
            entry = (handler, filter_func, subscription_id)
            self._subscribers[event_type].append(entry)
            self._subscription_map[subscription_id] = (event_type, entry)
        
        logger.info(f"Subscribed to {event_types} with ID {subscription_id}")
        return subscription_id
    
    def unsubscribe(self, subscription_id: str) -> bool:
        """
        取消订阅
        
        Args:
            subscription_id: 订阅ID
        
        Returns:
            是否成功取消
        """
        if subscription_id not in self._subscription_map:
            return False
        
        # 从所有事件类型中移除
        for event_type, subscribers in self._subscribers.items():
            self._subscribers[event_type] = [
                s for s in subscribers if s[2] != subscription_id
            ]
        
        del self._subscription_map[subscription_id]
        logger.info(f"Unsubscribed: {subscription_id}")
        return True
    
    async def _process_events(self):
        """事件处理循环"""
        while self._running:
            try:
                # 获取事件（带超时）
                try:
                    event = await asyncio.wait_for(
                        self._event_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # 分发事件
                await self._dispatch_event(event)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Event processing error: {e}")
    
    async def _dispatch_event(self, event: SecurityEvent):
        """分发事件到订阅者"""
        handlers = self._subscribers.get(event.event_type, [])
        
        if not handlers:
            return
        
        # 并发调用所有处理器
        tasks = []
        for handler, filter_func, _ in handlers:
            # 检查过滤条件
            if filter_func is not None:
                try:
                    if not filter_func(event):
                        continue
                except Exception as e:
                    logger.warning(f"Filter function failed: {e}")
                    continue
            
            # 创建处理任务
            tasks.append(self._safe_call_handler(handler, event))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _safe_call_handler(
        self,
        handler: Callable,
        event: SecurityEvent
    ):
        """安全调用处理器"""
        try:
            if asyncio.iscoroutinefunction(handler):
                await handler(event)
            else:
                handler(event)
        except Exception as e:
            logger.exception(f"Event handler failed: {e}")
    
    def replay(
        self,
        since: Optional[datetime] = None,
        event_type: Optional[EventType] = None,
        limit: int = 100
    ) -> List[SecurityEvent]:
        """
        重放历史事件
        
        Args:
            since: 起始时间
            event_type: 事件类型过滤
            limit: 最大返回数量
        
        Returns:
            事件列表
        """
        events = []
        
        for event in reversed(self._event_history):
            if len(events) >= limit:
                break
            
            if since and event.timestamp < since:
                continue
            
            if event_type and event.event_type != event_type:
                continue
            
            events.append(event)
        
        return list(reversed(events))
    
    def get_history(self, limit: int = 100) -> List[SecurityEvent]:
        """获取最近的事件历史"""
        return list(self._event_history)[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        event_counts = defaultdict(int)
        for event in self._event_history:
            event_counts[event.event_type] += 1
        
        return {
            "total_events": len(self._event_history),
            "event_counts": dict(event_counts),
            "subscriber_counts": {
                str(et): len(handlers)
                for et, handlers in self._subscribers.items()
            },
            "queue_size": self._event_queue.qsize()
        }
    
    def clear_history(self):
        """清空事件历史"""
        self._event_history.clear()
        logger.info("Event history cleared")


# ============ 便捷函数 ============

@lru_cache()
def get_event_bus() -> EventBus:
    """获取事件总线单例"""
    return EventBus()


async def publish_event(
    event_type: EventType,
    source: str,
    payload: Dict[str, Any] = None,
    severity: Severity = Severity.INFO,
    correlation_id: Optional[str] = None,
    tags: List[str] = None
):
    """
    便捷的事件发布函数
    
    Args:
        event_type: 事件类型
        source: 事件来源
        payload: 事件数据
        severity: 严重程度
        correlation_id: 关联ID
        tags: 标签
    """
    event = SecurityEvent(
        event_type=event_type,
        source=source,
        payload=payload or {},
        severity=severity,
        correlation_id=correlation_id,
        tags=tags or []
    )
    
    bus = get_event_bus()
    await bus.publish(event)


def on_event(*event_types: EventType):
    """
    事件处理装饰器
    
    用法:
        @on_event(EventType.THREAT_DETECTED, EventType.ATTACK_BLOCKED)
        async def handle_threat(event: SecurityEvent):
            ...
    """
    def decorator(func):
        bus = get_event_bus()
        bus.subscribe(list(event_types), func)
        return func
    
    return decorator
