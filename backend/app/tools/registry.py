"""
玄鉴安全智能体 - 工具注册表
管理所有安全工具的注册、发现和调用
"""

import importlib
import logging
import pkgutil
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type

from .base_tool import BaseTool, ToolCategory, ToolMetadata, ToolResult

logger = logging.getLogger(__name__)


class ToolRegistry:
    """
    工具注册表
    
    单例模式，管理所有安全工具的注册和调用
    """
    
    _instance: Optional["ToolRegistry"] = None
    
    def __new__(cls) -> "ToolRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._tools: Dict[str, Type[BaseTool]] = {}
        self._instances: Dict[str, BaseTool] = {}
        self._initialized = True
        logger.info("ToolRegistry initialized")
    
    def register(self, tool_class: Type[BaseTool]) -> Type[BaseTool]:
        """
        注册工具类
        
        Args:
            tool_class: 工具类（必须继承BaseTool）
        
        Returns:
            原工具类（支持装饰器用法）
        """
        if not issubclass(tool_class, BaseTool):
            raise TypeError(f"{tool_class.__name__} must inherit from BaseTool")
        
        name = tool_class.metadata.name
        
        if name in self._tools:
            logger.warning(f"Tool {name} already registered, overwriting")
        
        self._tools[name] = tool_class
        logger.info(f"Registered tool: {name} ({tool_class.__name__})")
        
        return tool_class
    
    def unregister(self, name: str) -> bool:
        """
        注销工具
        
        Args:
            name: 工具名称
        
        Returns:
            是否成功注销
        """
        if name in self._tools:
            del self._tools[name]
            if name in self._instances:
                del self._instances[name]
            logger.info(f"Unregistered tool: {name}")
            return True
        return False
    
    def get(self, name: str) -> Optional[Type[BaseTool]]:
        """
        获取工具类
        
        Args:
            name: 工具名称
        
        Returns:
            工具类或None
        """
        return self._tools.get(name)
    
    def get_instance(self, name: str) -> Optional[BaseTool]:
        """
        获取工具实例（单例）
        
        Args:
            name: 工具名称
        
        Returns:
            工具实例或None
        """
        if name not in self._instances:
            tool_class = self.get(name)
            if tool_class:
                self._instances[name] = tool_class()
        return self._instances.get(name)
    
    async def call(self, name: str, **params) -> ToolResult:
        """
        调用工具
        
        Args:
            name: 工具名称
            **params: 工具参数
        
        Returns:
            工具执行结果
        """
        tool = self.get_instance(name)
        if not tool:
            return ToolResult.error_result(
                tool_name=name,
                error_code="TOOL_NOT_FOUND",
                error_message=f"工具 {name} 未注册",
                recoverable=False
            )
        
        return await tool.run(**params)
    
    def list_tools(self) -> List[str]:
        """获取所有已注册工具名称"""
        return list(self._tools.keys())
    
    def list_by_category(self, category: ToolCategory) -> List[str]:
        """
        按类别列出工具
        
        Args:
            category: 工具类别
        
        Returns:
            工具名称列表
        """
        return [
            name for name, tool_class in self._tools.items()
            if tool_class.metadata.category == category
        ]
    
    def get_metadata(self, name: str) -> Optional[ToolMetadata]:
        """
        获取工具元数据
        
        Args:
            name: 工具名称
        
        Returns:
            工具元数据或None
        """
        tool_class = self.get(name)
        if tool_class:
            return tool_class.metadata
        return None
    
    def get_all_metadata(self) -> Dict[str, ToolMetadata]:
        """获取所有工具的元数据"""
        return {
            name: tool_class.metadata
            for name, tool_class in self._tools.items()
        }
    
    def discover(self, package_path: str) -> int:
        """
        自动发现并注册工具
        
        扫描指定包路径下所有带@register_tool装饰器的工具类
        
        Args:
            package_path: 包路径
        
        Returns:
            发现的工具数量
        """
        count = 0
        
        try:
            package = importlib.import_module(package_path)
            package_dir = Path(package.__file__).parent
            
            for _, module_name, is_pkg in pkgutil.iter_modules([str(package_dir)]):
                if is_pkg:
                    # 递归扫描子包
                    count += self.discover(f"{package_path}.{module_name}")
                else:
                    try:
                        module = importlib.import_module(f"{package_path}.{module_name}")
                        # 检查模块中是否有已注册的工具
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if (
                                isinstance(attr, type) and
                                issubclass(attr, BaseTool) and
                                attr is not BaseTool and
                                hasattr(attr, 'metadata') and
                                attr.metadata.name in self._tools
                            ):
                                count += 1
                    except Exception as e:
                        logger.warning(f"Failed to load module {module_name}: {e}")
        
        except Exception as e:
            logger.error(f"Failed to discover tools in {package_path}: {e}")
        
        logger.info(f"Discovered {count} tools in {package_path}")
        return count
    
    def to_mcp_tools(self) -> List[Dict[str, Any]]:
        """
        将所有工具转换为MCP格式
        
        Returns:
            MCP工具定义列表
        """
        tools = []
        for name in self._tools:
            instance = self.get_instance(name)
            if instance:
                tools.append(instance.to_mcp_tool())
        return tools
    
    async def health_check_all(self) -> Dict[str, bool]:
        """
        对所有工具执行健康检查
        
        Returns:
            工具名称到健康状态的映射
        """
        results = {}
        for name in self._tools:
            instance = self.get_instance(name)
            if instance:
                try:
                    results[name] = await instance.health_check()
                except Exception as e:
                    logger.error(f"Health check failed for {name}: {e}")
                    results[name] = False
        return results
    
    def get_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        获取所有工具的统计信息
        
        Returns:
            工具名称到统计信息的映射
        """
        return {
            name: instance.stats
            for name, instance in self._instances.items()
        }
    
    def clear(self):
        """清空注册表（主要用于测试）"""
        self._tools.clear()
        self._instances.clear()
        logger.info("ToolRegistry cleared")
    
    def __len__(self) -> int:
        return len(self._tools)
    
    def __contains__(self, name: str) -> bool:
        return name in self._tools
    
    def __iter__(self):
        return iter(self._tools.items())


# ============ 装饰器 ============

def register_tool(
    category: Optional[ToolCategory] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
    risk_level: Optional[str] = None,
    requires_approval: bool = False
) -> Callable[[Type[BaseTool]], Type[BaseTool]]:
    """
    工具注册装饰器
    
    用法:
        @register_tool(category=ToolCategory.THREAT_INTEL)
        class MyTool(BaseTool):
            ...
    
    Args:
        category: 工具类别
        name: 工具名称（可选，默认使用类的metadata.name）
        description: 工具描述（可选）
        risk_level: 风险等级（可选）
        requires_approval: 是否需要审批
    
    Returns:
        装饰器函数
    """
    def decorator(tool_class: Type[BaseTool]) -> Type[BaseTool]:
        # 更新元数据
        if category:
            tool_class.metadata.category = category
        if name:
            tool_class.metadata.name = name
        if description:
            tool_class.metadata.description = description
        if risk_level:
            tool_class.metadata.risk_level = risk_level
        if requires_approval:
            tool_class.metadata.requires_approval = requires_approval
        
        # 注册到全局注册表
        registry = get_registry()
        registry.register(tool_class)
        
        return tool_class
    
    return decorator


# ============ 全局访问 ============

@lru_cache()
def get_registry() -> ToolRegistry:
    """
    获取全局工具注册表实例
    
    Returns:
        ToolRegistry单例
    """
    return ToolRegistry()
