"""
MCP (Model Context Protocol) Server Implementation

Implements JSON-RPC 2.0 protocol for standardized AI-to-tool communication.
Provides bidirectional streaming support for long-running security operations.
"""

import asyncio
import json
import uuid
import logging
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    Coroutine,
    Dict,
    List,
    Optional,
    Union,
)
from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ============================================================================
# JSON-RPC 2.0 Data Models
# ============================================================================

class JsonRpcErrorCode(int, Enum):
    """Standard JSON-RPC 2.0 error codes"""
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    # Custom error codes for MCP
    TOOL_EXECUTION_ERROR = -32000
    TOOL_TIMEOUT = -32001
    TOOL_NOT_FOUND = -32002
    PERMISSION_DENIED = -32003
    RATE_LIMITED = -32004


class JsonRpcError(BaseModel):
    """JSON-RPC 2.0 Error object"""
    code: int
    message: str
    data: Optional[Any] = None


class JsonRpcRequest(BaseModel):
    """JSON-RPC 2.0 Request object"""
    jsonrpc: str = "2.0"
    method: str
    params: Optional[Union[Dict[str, Any], List[Any]]] = None
    id: Optional[Union[str, int]] = None  # None for notifications


class JsonRpcResponse(BaseModel):
    """JSON-RPC 2.0 Response object"""
    jsonrpc: str = "2.0"
    result: Optional[Any] = None
    error: Optional[JsonRpcError] = None
    id: Optional[Union[str, int]] = None

    @classmethod
    def success(cls, result: Any, request_id: Union[str, int]) -> "JsonRpcResponse":
        return cls(result=result, id=request_id)

    @classmethod
    def error_response(
        cls,
        code: int,
        message: str,
        request_id: Optional[Union[str, int]] = None,
        data: Any = None
    ) -> "JsonRpcResponse":
        return cls(
            error=JsonRpcError(code=code, message=message, data=data),
            id=request_id
        )


# ============================================================================
# MCP Protocol Messages
# ============================================================================

class MCPCapability(str, Enum):
    """MCP server capabilities"""
    TOOLS = "tools"
    RESOURCES = "resources"
    PROMPTS = "prompts"
    SAMPLING = "sampling"
    STREAMING = "streaming"


class MCPToolParameter(BaseModel):
    """Tool parameter definition"""
    name: str
    type: str  # "string", "number", "boolean", "array", "object"
    description: str
    required: bool = True
    default: Optional[Any] = None
    enum: Optional[List[Any]] = None


class MCPToolDefinition(BaseModel):
    """MCP Tool definition following the protocol spec"""
    name: str
    description: str
    parameters: List[MCPToolParameter] = Field(default_factory=list)
    returns: str = "object"
    risk_level: str = "low"  # "low", "medium", "high", "critical"
    requires_approval: bool = False
    timeout_seconds: int = 300
    category: str = "general"


class MCPToolResult(BaseModel):
    """Result of tool execution"""
    tool_name: str
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time_ms: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Tool Handler Registry
# ============================================================================

ToolHandler = Callable[..., Coroutine[Any, Any, Any]]


@dataclass
class RegisteredTool:
    """Internal representation of a registered tool"""
    definition: MCPToolDefinition
    handler: ToolHandler
    registered_at: datetime = field(default_factory=datetime.now)
    call_count: int = 0
    total_execution_time_ms: int = 0
    last_called: Optional[datetime] = None


# ============================================================================
# MCP Server Implementation
# ============================================================================

class MCPServer:
    """
    MCP Server implementing JSON-RPC 2.0 protocol.
    
    Features:
    - Tool registration and discovery
    - Async tool execution with timeout
    - Streaming support for long-running operations
    - Rate limiting and concurrency control
    - Execution metrics and logging
    """

    def __init__(
        self,
        name: str = "xuanjian-security-mcp",
        version: str = "1.0.0",
        max_concurrent_calls: int = 10,
        default_timeout: int = 300,
    ):
        self.name = name
        self.version = version
        self.max_concurrent_calls = max_concurrent_calls
        self.default_timeout = default_timeout
        
        # Tool registry
        self._tools: Dict[str, RegisteredTool] = {}
        
        # Concurrency control
        self._semaphore = asyncio.Semaphore(max_concurrent_calls)
        
        # Pending streaming operations
        self._streaming_tasks: Dict[str, asyncio.Task] = {}
        
        # Capabilities
        self._capabilities: List[MCPCapability] = [
            MCPCapability.TOOLS,
            MCPCapability.STREAMING,
        ]
        
        # Built-in method handlers
        self._method_handlers: Dict[str, ToolHandler] = {
            "initialize": self._handle_initialize,
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
            "tools/cancel": self._handle_tools_cancel,
            "ping": self._handle_ping,
            "shutdown": self._handle_shutdown,
        }
        
        logger.info(f"MCP Server '{name}' v{version} initialized")

    # ------------------------------------------------------------------------
    # Tool Registration
    # ------------------------------------------------------------------------

    def register_tool(
        self,
        definition: MCPToolDefinition,
        handler: ToolHandler,
    ) -> None:
        """Register a tool with its handler"""
        if definition.name in self._tools:
            logger.warning(f"Tool '{definition.name}' already registered, overwriting")
        
        self._tools[definition.name] = RegisteredTool(
            definition=definition,
            handler=handler,
        )
        logger.info(f"Registered tool: {definition.name} ({definition.category})")

    def unregister_tool(self, name: str) -> bool:
        """Unregister a tool"""
        if name in self._tools:
            del self._tools[name]
            logger.info(f"Unregistered tool: {name}")
            return True
        return False

    def get_tool(self, name: str) -> Optional[MCPToolDefinition]:
        """Get tool definition by name"""
        if name in self._tools:
            return self._tools[name].definition
        return None

    def list_tools(
        self,
        category: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[MCPToolDefinition]:
        """List all registered tools with optional filtering"""
        tools = [t.definition for t in self._tools.values()]
        
        if category:
            tools = [t for t in tools if t.category == category]
        if risk_level:
            tools = [t for t in tools if t.risk_level == risk_level]
        
        return tools

    # ------------------------------------------------------------------------
    # JSON-RPC Message Processing
    # ------------------------------------------------------------------------

    async def process_message(
        self,
        message: Union[str, bytes, Dict[str, Any]]
    ) -> JsonRpcResponse:
        """
        Process a JSON-RPC 2.0 message.
        
        Args:
            message: Raw JSON string, bytes, or parsed dict
            
        Returns:
            JSON-RPC response object
        """
        # Parse message if needed
        if isinstance(message, (str, bytes)):
            try:
                data = json.loads(message)
            except json.JSONDecodeError as e:
                return JsonRpcResponse.error_response(
                    JsonRpcErrorCode.PARSE_ERROR,
                    f"Parse error: {str(e)}"
                )
        else:
            data = message

        # Validate request structure
        try:
            request = JsonRpcRequest(**data)
        except Exception as e:
            return JsonRpcResponse.error_response(
                JsonRpcErrorCode.INVALID_REQUEST,
                f"Invalid request: {str(e)}"
            )

        # Route to handler
        return await self._dispatch_request(request)

    async def _dispatch_request(self, request: JsonRpcRequest) -> JsonRpcResponse:
        """Dispatch request to appropriate handler"""
        method = request.method
        
        # Check built-in methods first
        if method in self._method_handlers:
            handler = self._method_handlers[method]
            try:
                result = await handler(request.params or {})
                return JsonRpcResponse.success(result, request.id)
            except Exception as e:
                logger.exception(f"Error handling method '{method}'")
                return JsonRpcResponse.error_response(
                    JsonRpcErrorCode.INTERNAL_ERROR,
                    str(e),
                    request.id
                )
        
        # Unknown method
        return JsonRpcResponse.error_response(
            JsonRpcErrorCode.METHOD_NOT_FOUND,
            f"Method not found: {method}",
            request.id
        )

    # ------------------------------------------------------------------------
    # Built-in Method Handlers
    # ------------------------------------------------------------------------

    async def _handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle initialize request"""
        return {
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": self.name,
                "version": self.version,
            },
            "capabilities": {
                "tools": {"listChanged": True},
                "streaming": True,
            }
        }

    async def _handle_tools_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/list request"""
        category = params.get("category")
        risk_level = params.get("risk_level")
        
        tools = self.list_tools(category, risk_level)
        
        return {
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            p.name: {
                                "type": p.type,
                                "description": p.description,
                                **({"enum": p.enum} if p.enum else {}),
                                **({"default": p.default} if p.default is not None else {}),
                            }
                            for p in t.parameters
                        },
                        "required": [p.name for p in t.parameters if p.required],
                    },
                    "metadata": {
                        "risk_level": t.risk_level,
                        "requires_approval": t.requires_approval,
                        "timeout_seconds": t.timeout_seconds,
                        "category": t.category,
                    }
                }
                for t in tools
            ]
        }

    async def _handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/call request"""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        if not tool_name:
            raise ValueError("Tool name is required")
        
        if tool_name not in self._tools:
            raise ValueError(f"Tool not found: {tool_name}")
        
        registered_tool = self._tools[tool_name]
        definition = registered_tool.definition
        
        # Check approval requirement
        if definition.requires_approval:
            approval_token = params.get("approval_token")
            if not approval_token:
                return {
                    "status": "pending_approval",
                    "message": f"Tool '{tool_name}' requires approval",
                    "approval_request_id": str(uuid.uuid4()),
                }
        
        # Execute with concurrency control
        result = await self._execute_tool(
            tool_name,
            arguments,
            timeout=definition.timeout_seconds,
        )
        
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result.result) if result.success else result.error,
                }
            ],
            "isError": not result.success,
            "metadata": {
                "execution_time_ms": result.execution_time_ms,
                **result.metadata,
            }
        }

    async def _handle_tools_cancel(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tools/cancel request"""
        task_id = params.get("task_id")
        
        if task_id in self._streaming_tasks:
            self._streaming_tasks[task_id].cancel()
            del self._streaming_tasks[task_id]
            return {"cancelled": True}
        
        return {"cancelled": False, "reason": "Task not found"}

    async def _handle_ping(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ping request"""
        return {"pong": True, "timestamp": datetime.now().isoformat()}

    async def _handle_shutdown(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle shutdown request"""
        # Cancel all streaming tasks
        for task_id, task in self._streaming_tasks.items():
            task.cancel()
        self._streaming_tasks.clear()
        
        return {"status": "shutting_down"}

    # ------------------------------------------------------------------------
    # Tool Execution
    # ------------------------------------------------------------------------

    async def _execute_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: Optional[int] = None,
    ) -> MCPToolResult:
        """Execute a tool with timeout and concurrency control"""
        registered_tool = self._tools[tool_name]
        handler = registered_tool.handler
        timeout = timeout or self.default_timeout
        
        start_time = datetime.now()
        
        async with self._semaphore:
            try:
                result = await asyncio.wait_for(
                    handler(**arguments),
                    timeout=timeout
                )
                
                execution_time_ms = int(
                    (datetime.now() - start_time).total_seconds() * 1000
                )
                
                # Update stats
                registered_tool.call_count += 1
                registered_tool.total_execution_time_ms += execution_time_ms
                registered_tool.last_called = datetime.now()
                
                return MCPToolResult(
                    tool_name=tool_name,
                    success=True,
                    result=result,
                    execution_time_ms=execution_time_ms,
                )
                
            except asyncio.TimeoutError:
                logger.error(f"Tool '{tool_name}' timed out after {timeout}s")
                return MCPToolResult(
                    tool_name=tool_name,
                    success=False,
                    error=f"Execution timed out after {timeout} seconds",
                    execution_time_ms=timeout * 1000,
                )
                
            except Exception as e:
                logger.exception(f"Tool '{tool_name}' execution failed")
                execution_time_ms = int(
                    (datetime.now() - start_time).total_seconds() * 1000
                )
                return MCPToolResult(
                    tool_name=tool_name,
                    success=False,
                    error=str(e),
                    execution_time_ms=execution_time_ms,
                )

    # ------------------------------------------------------------------------
    # Streaming Support
    # ------------------------------------------------------------------------

    async def execute_tool_stream(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Execute a tool with streaming results.
        
        Yields progress updates and partial results for long-running operations.
        """
        task_id = str(uuid.uuid4())
        
        if tool_name not in self._tools:
            yield {
                "type": "error",
                "task_id": task_id,
                "error": f"Tool not found: {tool_name}",
            }
            return
        
        registered_tool = self._tools[tool_name]
        
        # Emit start event
        yield {
            "type": "start",
            "task_id": task_id,
            "tool_name": tool_name,
            "timestamp": datetime.now().isoformat(),
        }
        
        try:
            # Execute tool
            result = await self._execute_tool(tool_name, arguments)
            
            # Emit completion event
            yield {
                "type": "complete",
                "task_id": task_id,
                "success": result.success,
                "result": result.result,
                "error": result.error,
                "execution_time_ms": result.execution_time_ms,
                "timestamp": datetime.now().isoformat(),
            }
            
        except asyncio.CancelledError:
            yield {
                "type": "cancelled",
                "task_id": task_id,
                "timestamp": datetime.now().isoformat(),
            }
            raise
            
        except Exception as e:
            yield {
                "type": "error",
                "task_id": task_id,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    # ------------------------------------------------------------------------
    # Statistics and Health
    # ------------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Get server statistics"""
        tool_stats = {}
        for name, tool in self._tools.items():
            avg_time = (
                tool.total_execution_time_ms / tool.call_count
                if tool.call_count > 0 else 0
            )
            tool_stats[name] = {
                "call_count": tool.call_count,
                "total_execution_time_ms": tool.total_execution_time_ms,
                "avg_execution_time_ms": avg_time,
                "last_called": tool.last_called.isoformat() if tool.last_called else None,
            }
        
        return {
            "server_name": self.name,
            "server_version": self.version,
            "total_tools": len(self._tools),
            "active_streaming_tasks": len(self._streaming_tasks),
            "tool_stats": tool_stats,
        }

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check"""
        return {
            "status": "healthy",
            "server": self.name,
            "version": self.version,
            "tools_registered": len(self._tools),
            "timestamp": datetime.now().isoformat(),
        }


# ============================================================================
# Decorator for Tool Registration
# ============================================================================

def mcp_tool(
    name: str,
    description: str,
    parameters: Optional[List[Dict[str, Any]]] = None,
    risk_level: str = "low",
    requires_approval: bool = False,
    timeout_seconds: int = 300,
    category: str = "general",
):
    """
    Decorator for registering MCP tools.
    
    Usage:
        @mcp_tool(
            name="nmap_scan",
            description="Perform network port scanning",
            parameters=[
                {"name": "target", "type": "string", "description": "Target IP or hostname"},
                {"name": "ports", "type": "string", "description": "Port range", "default": "1-1000"},
            ],
            risk_level="medium",
            category="network",
        )
        async def nmap_scan(target: str, ports: str = "1-1000"):
            ...
    """
    def decorator(func: ToolHandler) -> ToolHandler:
        # Build parameter definitions
        param_defs = []
        if parameters:
            for p in parameters:
                param_defs.append(MCPToolParameter(
                    name=p["name"],
                    type=p.get("type", "string"),
                    description=p.get("description", ""),
                    required=p.get("required", True),
                    default=p.get("default"),
                    enum=p.get("enum"),
                ))
        
        # Store definition on function for later registration
        func._mcp_definition = MCPToolDefinition(
            name=name,
            description=description,
            parameters=param_defs,
            risk_level=risk_level,
            requires_approval=requires_approval,
            timeout_seconds=timeout_seconds,
            category=category,
        )
        
        return func
    
    return decorator
