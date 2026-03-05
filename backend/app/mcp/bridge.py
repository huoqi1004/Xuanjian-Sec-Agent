"""
MCP Integration Bridge

Connects the MCP Server with the tool registry and AI coordinator.
Provides a unified interface for tool execution across the system.
"""

import asyncio
import logging
from typing import Any, Callable, Coroutine, Dict, List, Optional
from datetime import datetime

from .mcp_server import MCPServer, MCPToolDefinition, MCPToolParameter, MCPToolResult
from .tool_definitions import MCPToolRegistry
from .workflow.dsl_parser import SkillParser, SkillDefinition, get_builtin_skills
from .workflow.executor import SkillExecutor, ExecutionContext, ExecutionEvent
from ..tools.registry import ToolRegistry
from ..core.event_bus import EventBus, SecurityEvent, EventType

logger = logging.getLogger(__name__)


class MCPBridge:
    """
    Bridges MCP Server with internal tool registry and event bus.
    
    Responsibilities:
    - Auto-registers tools from ToolRegistry into MCPServer
    - Routes MCP tool calls to actual tool implementations
    - Publishes tool execution events to EventBus
    - Manages Skill workflow execution
    """

    def __init__(self):
        self.mcp_server = MCPServer(
            name="xuanjian-security-mcp",
            version="1.0.0",
        )
        self.tool_registry = ToolRegistry()
        self.event_bus = EventBus()
        self.skill_parser = SkillParser()
        self.skill_executor: Optional[SkillExecutor] = None
        
        # Loaded skills
        self._skills: Dict[str, SkillDefinition] = {}
    
    async def initialize(self) -> None:
        """Initialize the MCP bridge"""
        # Register tools from registry into MCP server
        await self._sync_tools()
        
        # Initialize skill executor
        self.skill_executor = SkillExecutor(
            tool_executor=self._execute_tool_via_mcp,
            max_concurrent_steps=5,
        )
        
        # Register progress callback
        self.skill_executor.register_progress_callback(self._on_skill_event)
        
        # Load built-in skills
        await self._load_builtin_skills()
        
        logger.info("MCP Bridge initialized")
    
    async def _sync_tools(self) -> None:
        """Sync tools from ToolRegistry to MCPServer"""
        # Discover tools
        self.tool_registry.discover_tools()
        
        tool_defs = MCPToolRegistry()
        
        for tool_def in tool_defs.list_all():
            # Create handler that routes to tool registry
            handler = self._create_tool_handler(tool_def.name)
            self.mcp_server.register_tool(tool_def, handler)
        
        logger.info(f"Synced {len(tool_defs.list_all())} tools to MCP Server")
    
    def _create_tool_handler(self, tool_name: str) -> Callable:
        """Create an async handler for a tool"""
        async def handler(**kwargs) -> Any:
            start_time = datetime.now()
            
            # Publish start event
            await self.event_bus.publish(SecurityEvent(
                event_type=EventType.TOOL_EXECUTED,
                source="mcp_bridge",
                data={
                    "tool_name": tool_name,
                    "action": "start",
                    "params": {k: str(v)[:100] for k, v in kwargs.items()},
                },
            ))
            
            try:
                # Try to find and execute tool from registry
                tool_class = self.tool_registry.get(tool_name)
                
                if tool_class:
                    tool_instance = self.tool_registry.get_instance(tool_name)
                    result = await tool_instance.execute(**kwargs)
                    
                    # Publish completion event
                    execution_time = int(
                        (datetime.now() - start_time).total_seconds() * 1000
                    )
                    
                    await self.event_bus.publish(SecurityEvent(
                        event_type=EventType.TOOL_EXECUTED,
                        source="mcp_bridge",
                        data={
                            "tool_name": tool_name,
                            "action": "complete",
                            "success": result.success,
                            "execution_time_ms": execution_time,
                        },
                    ))
                    
                    if result.success:
                        return result.data
                    else:
                        raise RuntimeError(result.error or "Tool execution failed")
                else:
                    raise ValueError(f"Tool '{tool_name}' not found in registry")
                    
            except Exception as e:
                # Publish error event
                await self.event_bus.publish(SecurityEvent(
                    event_type=EventType.TOOL_EXECUTED,
                    source="mcp_bridge",
                    data={
                        "tool_name": tool_name,
                        "action": "error",
                        "error": str(e),
                    },
                    severity="error",
                ))
                raise
        
        return handler
    
    async def _execute_tool_via_mcp(
        self,
        tool_name: str,
        params: Dict[str, Any],
    ) -> Any:
        """Execute a tool through the MCP server"""
        response = await self.mcp_server.process_message({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": params,
            },
            "id": f"skill_{tool_name}_{id(params)}",
        })
        
        if response.error:
            raise RuntimeError(f"MCP tool call failed: {response.error.message}")
        
        result = response.result
        if result and result.get("isError"):
            error_content = result.get("content", [{}])
            error_msg = error_content[0].get("text", "Unknown error") if error_content else "Unknown error"
            raise RuntimeError(error_msg)
        
        return result
    
    async def _on_skill_event(self, event: ExecutionEvent) -> None:
        """Handle skill execution events"""
        event_type_map = {
            "execution_started": EventType.WORKFLOW_STARTED,
            "execution_completed": EventType.WORKFLOW_COMPLETED,
            "execution_failed": EventType.WORKFLOW_FAILED,
            "step_started": EventType.STEP_STARTED,
            "step_completed": EventType.STEP_COMPLETED,
            "step_failed": EventType.STEP_FAILED,
            "approval_requested": EventType.APPROVAL_REQUESTED,
        }
        
        mapped_type = event_type_map.get(event.event_type)
        if mapped_type:
            await self.event_bus.publish(SecurityEvent(
                event_type=mapped_type,
                source="skill_executor",
                data={
                    "execution_id": event.execution_id,
                    "step_id": event.step_id,
                    **event.data,
                },
            ))
    
    async def _load_builtin_skills(self) -> None:
        """Load built-in skill templates"""
        for name, yaml_content in get_builtin_skills().items():
            try:
                skill = self.skill_parser.parse_string(yaml_content)
                self._skills[name] = skill
                logger.info(f"Loaded built-in skill: {name}")
            except Exception as e:
                logger.error(f"Failed to load skill '{name}': {e}")
    
    async def load_skill_file(self, file_path: str) -> SkillDefinition:
        """Load a skill from a YAML file"""
        skill = self.skill_parser.parse_file(file_path)
        self._skills[skill.metadata.name] = skill
        return skill
    
    async def execute_skill(
        self,
        skill_name: str,
        inputs: Dict[str, Any],
        execution_id: Optional[str] = None,
    ) -> ExecutionContext:
        """Execute a skill by name"""
        if skill_name not in self._skills:
            raise ValueError(f"Skill '{skill_name}' not found")
        
        if not self.skill_executor:
            raise RuntimeError("MCP Bridge not initialized")
        
        skill = self._skills[skill_name]
        
        # Validate inputs
        errors = self.skill_parser.validate_inputs(skill, inputs)
        if errors:
            raise ValueError(f"Invalid inputs: {', '.join(errors)}")
        
        return await self.skill_executor.execute(skill, inputs, execution_id)
    
    def list_skills(self) -> List[Dict[str, Any]]:
        """List all loaded skills"""
        return [
            {
                "name": s.metadata.name,
                "version": s.metadata.version,
                "description": s.metadata.description,
                "category": s.metadata.category,
                "risk_level": s.metadata.risk_level,
                "requires_approval": s.metadata.requires_approval,
                "input_count": len(s.inputs),
                "step_count": len(s.steps),
            }
            for s in self._skills.values()
        ]
    
    async def health_check(self) -> Dict[str, Any]:
        """Check health of MCP bridge"""
        mcp_health = await self.mcp_server.health_check()
        
        return {
            "status": "healthy",
            "mcp_server": mcp_health,
            "tools_registered": len(self.mcp_server.list_tools()),
            "skills_loaded": len(self._skills),
            "event_bus_subscribers": self.event_bus.subscriber_count,
        }
