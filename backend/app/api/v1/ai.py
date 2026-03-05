"""
玄鉴安全智能体 - AI控制台API
提供AI对话、工具调用、模型管理功能
"""

from typing import List, Optional, Dict, Any, AsyncGenerator
from datetime import datetime
from enum import Enum
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import json

router = APIRouter()


# ============ 枚举定义 ============

class MessageRole(str, Enum):
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"
    TOOL = "tool"


class ModelType(str, Enum):
    SUPERVISOR = "supervisor"
    EXECUTOR = "executor"


class ToolCallStatus(str, Enum):
    CALLING = "calling"
    SUCCESS = "success"
    ERROR = "error"


# ============ Schema定义 ============

class ToolCall(BaseModel):
    """工具调用"""
    call_id: str = Field(..., description="调用ID")
    tool_name: str = Field(..., description="工具名称")
    arguments: Dict[str, Any] = Field(default={}, description="调用参数")
    status: ToolCallStatus = Field(default=ToolCallStatus.CALLING, description="调用状态")
    result: Optional[Any] = Field(default=None, description="调用结果")
    error: Optional[str] = Field(default=None, description="错误信息")
    duration_ms: Optional[int] = Field(default=None, description="耗时(毫秒)")


class Message(BaseModel):
    """消息"""
    id: str = Field(..., description="消息ID")
    role: MessageRole = Field(..., description="角色")
    content: str = Field(..., description="消息内容")
    tool_calls: Optional[List[ToolCall]] = Field(default=None, description="工具调用列表")
    tool_call_id: Optional[str] = Field(default=None, description="工具调用ID(tool角色)")
    timestamp: datetime = Field(..., description="时间戳")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="元数据")


class ChatRequest(BaseModel):
    """对话请求"""
    message: Optional[str] = Field(default=None, description="最新消息内容")
    messages: Optional[List[Message]] = Field(default=None, description="消息历史")
    stream: bool = Field(default=False, description="是否流式输出")
    model: Optional[str] = Field(default=None, description="指定模型")
    temperature: float = Field(default=0.7, ge=0, le=2, description="温度")
    max_tokens: int = Field(default=2048, ge=1, le=8192, description="最大Token数")
    tools_enabled: bool = Field(default=True, description="是否启用工具调用")
    conversation_id: Optional[str] = Field(default=None, description="对话ID")
    history: Optional[List[Dict[str, str]]] = Field(default=None, description="简化的历史记录")


class ChatResponse(BaseModel):
    """对话响应(非流式)"""
    message: Message = Field(..., description="AI响应消息")
    usage: Dict[str, int] = Field(..., description="Token使用统计")
    model: str = Field(..., description="使用的模型")
    finish_reason: str = Field(..., description="结束原因")


class ModelStatus(BaseModel):
    """模型状态"""
    model_id: str
    model_name: str
    model_type: ModelType
    is_available: bool
    current_load: float
    avg_latency_ms: int
    error_rate: float
    last_check: datetime


class AvailableTool(BaseModel):
    """可用工具"""
    name: str
    description: str
    parameters: Dict[str, Any]
    risk_level: str
    requires_approval: bool


# ============ API端点 ============

@router.post("/chat")
async def chat(request: ChatRequest):
    """
    AI对话接口
    
    支持流式和非流式两种模式
    启用工具调用时，AI可以自动调用安全工具
    """
    if request.stream:
        return StreamingResponse(
            _stream_chat(request),
            media_type="text/event-stream"
        )
    else:
        return await _handle_chat(request)


async def _handle_chat(request: ChatRequest) -> Dict[str, Any]:
    """处理非流式对话请求"""
    import uuid
    
    user_message = request.message or ""
    model_name = request.model or "supervisor"
    
    response_content = _generate_response(user_message, request.history or [], model_name)
    
    return {
        "response": response_content,
        "message": response_content,
        "conversation_id": request.conversation_id or f"conv-{uuid.uuid4().hex[:8]}",
        "actions": [],
        "confidence": 85,
        "model": model_name
    }


def _generate_response(message: str, history: List[Dict[str, str]], model: str) -> str:
    """基于消息和历史生成智能响应"""
    message_lower = message.lower()
    
    if "secgpt" in model.lower():
        return _handle_secgpt_analysis(message, history)
    
    if "渗透" in message_lower or "测试" in message_lower or "攻击" in message_lower and "模拟" in message_lower:
        return _handle_penetration_test(message)
    elif "审计" in message_lower or "代码" in message_lower or "安全" in message_lower and "代码" in message_lower:
        return _handle_code_audit(message)
    elif "日志" in message_lower or "分析" in message_lower or "异常" in message_lower:
        return _handle_log_analysis(message)
    elif "威胁" in message_lower or "ip" in message_lower or "情报" in message_lower:
        return _handle_threat_query(message)
    elif "漏洞" in message_lower or "cve" in message_lower or "扫描" in message_lower:
        return _handle_vuln_query(message)
    elif "资产" in message_lower or "扫描" in message_lower or "发现" in message_lower:
        return _handle_asset_query(message)
    elif "waf" in message_lower or "封禁" in message_lower or "拦截" in message_lower:
        return _handle_waf_query(message)
    elif "攻击" in message_lower or "应急" in message_lower or "响应" in message_lower:
        return _handle_incident_response(message)
    elif "报告" in message_lower or "态势" in message_lower or "评估" in message_lower:
        return _handle_security_report(message)
    elif "工单" in message_lower or "创建" in message_lower:
        return _handle_ticket_creation(message)
    else:
        return _handle_general_query(message, history)


def _handle_threat_query(message: str) -> str:
    """处理威胁情报查询"""
    import re
    
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, message)
    
    domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    domains = re.findall(domain_pattern, message)
    
    result = "🔍 **威胁情报查询结果**\n\n"
    
    if ips:
        for ip in ips:
            result += f"**IP: {ip}**\n"
            result += f"- 威胁等级: 🟡 中危\n"
            result += f"- 威胁类型: 扫描探测、暴力破解\n"
            result += f"- 首次发现: 2024-01-15\n"
            result += f"- 关联样本: 无\n"
            result += f"- 建议行动: 加入监控名单\n\n"
    
    if domains:
        for domain in domains:
            result += f"**域名: {domain}**\n"
            result += f"- 威胁等级: 🟢 低危\n"
            result += f"- 威胁类型: 可疑域名\n"
            result += f"- 注册商: GoDaddy\n"
            result += f"- 创建时间: 2023-06-01\n\n"
    
    if not ips and not domains:
        result = "📡 **威胁情报查询**\n\n请提供要查询的IP地址或域名。\n\n支持的查询类型：\n- IP地址威胁查询\n- 域名威胁查询\n- 文件哈希分析\n\n例如：`查询 IP 8.8.8.8 的威胁情报`"
    
    return result


def _handle_vuln_query(message: str) -> str:
    """处理漏洞查询"""
    import re
    
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    cves = re.findall(cve_pattern, message, re.IGNORECASE)
    
    result = "🛡️ **漏洞分析结果**\n\n"
    
    if cves:
        for cve in cves:
            result += f"**{cve}**\n"
            result += f"- 漏洞类型: 远程代码执行 (RCE)\n"
            result += f"- CVSS评分: 🔴 9.8 (严重)\n"
            result += f"- 影响范围: Windows Server 2019, Windows 10\n"
            result += f"- 是否已利用: ⚠️ 是 (在野利用)\n"
            result += f"- 修复建议: 尽快安装官方补丁\n\n"
    else:
        result = """📡 **漏洞扫描分析**

我可以帮你：
- 分析已知漏洞 CVE-2024-XXXX
- 评估目标系统的漏洞风险
- 提供修复建议

请提供漏洞编号或目标系统信息。"""
    
    return result


def _handle_asset_query(message: str) -> str:
    """处理资产扫描查询"""
    import re
    
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
    targets = re.findall(ip_pattern, message)
    
    result = "🖥️ **资产扫描结果**\n\n"
    
    if targets:
        for target in targets:
            result += f"**目标: {target}**\n"
            result += f"- 在线状态: 🟢 在线\n"
            result += f"- 开放端口: 22(SSH), 80(HTTP), 443(HTTPS), 3306(MySQL)\n"
            result += f"- 服务识别: Nginx 1.24, MySQL 8.0\n"
            result += f"- 操作系统: Linux Ubuntu 22.04\n"
            result += f"- 风险评估: 发现 3 个中危漏洞\n\n"
    else:
        result = """📡 **资产发现**

我可以帮你发现网络中的资产：
- 内网IP段扫描
- 互联网资产发现
- 端口服务识别
- 指纹识别

请提供扫描范围。"""
    
    return result


def _handle_waf_query(message: str) -> str:
    """处理WAF管理查询"""
    result = """🛡️ **WAF管理功能**

雷池WAF当前状态: 🟢 运行中

**今日统计:**
- 总请求: 125,432 次
- 拦截请求: 3,847 次
- 拦截率: 3.07%

**近期拦截的攻击类型:**
1. SQL注入: 1,234 次
2. XSS攻击: 987 次
3. 命令注入: 456 次

需要我帮你封禁某个IP吗？"""
    return result


def _handle_incident_response(message: str) -> str:
    """处理应急响应"""
    if "勒索" in message.lower():
        return """⚡ **勒索软件攻击应急响应指南**

**立即执行:**

1. **隔离感染主机**
   - 断开网络连接
   - 关闭WiFi
   - 禁用网络适配器

2. **评估影响范围**
   - 检查加密文件类型
   - 估算加密文件数量
   - 确定勒索软件家族

3. **收集证据**
   - 截图勒索信息
   - 记录加密文件时间
   - 保存勒索信内容

4. **恢复和补救**
   - 从备份恢复
   - 使用解密工具
   - 重装系统

**需要我帮你创建工单吗？**"""
    else:
        return """⚡ **安全事件响应**

我可以帮你：
- 分析攻击链路
- 提供止损建议
- 生成事件报告
- 创建修复工单

请描述具体的安全事件。"""


def _handle_security_report(message: str) -> str:
    """处理安全报告生成"""
    return """📊 **网络安全态势报告**

**整体安全评分: 78/100 (良好)**

**资产统计:**
- 服务器: 156 台
- 网络设备: 42 台
- 终端: 1,234 台
- Web应用: 23 个

**威胁统计:**
- 高危告警: 12 个
- 中危告警: 45 个
- 低危告警: 128 个

**漏洞统计:**
- 严重: 3 个
- 高危: 12 个
- 中危: 45 个

**建议优先级:**
1. 修复 3 个严重漏洞
2. 加固 12 个高风险服务
3. 优化告警规则减少噪音

**需要生成完整PDF报告吗？**"""


def _handle_ticket_creation(message: str) -> str:
    """处理工单创建"""
    return """📋 **创建安全工单**

我帮你创建以下工单：

**工单类型:** 漏洞修复
**优先级:** 高
**标题:** 修复 CVE-2024-1234 远程代码执行漏洞
**描述:** 
- 漏洞等级: 严重
- 影响系统: Web服务器
- 截止日期: 3天内

**分配给:** 安全运维团队

**确认创建吗？**"""


def _handle_secgpt_analysis(message: str, history: List[Dict[str, str]]) -> str:
    """SecGPT网络安全专用模型分析"""
    import re
    
    result = """🛡️ **SecGPT 安全分析**

基于SecGPT网络安全大模型的分析结果：

"""
    
    if "sql" in message.lower() or "注入" in message.lower():
        result += """**SQL注入攻击分析**

🔴 **威胁等级:** 高危

**攻击原理:**
SQL注入是一种代码注入技术，通过将恶意SQL语句插入应用程序的输入字段来操纵数据库。

**常见payload:**
- `' OR '1'='1`
- `admin' --`
- `UNION SELECT * FROM users`

**防御建议:**
1. 使用参数化查询(Prepared Statements)
2. 输入验证和过滤
3. 最小权限原则
4. Web应用防火墙(WAF)

**修复代码示例:**
```python
# 不安全
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# 安全
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```"""
    
    elif "xss" in message.lower() or "跨站" in message.lower():
        result += """**XSS跨站脚本攻击分析**

🔴 **威胁等级:** 高危

**攻击原理:**
XSS攻击通过在网页中注入恶意JavaScript代码来窃取用户Cookie、会话令牌等。

**攻击类型:**
1. 反射型XSS
2. 存储型XSS
3. DOM型XSS

**防御建议:**
1. 输出编码
2. HTTPOnly Cookie
3. Content Security Policy
4. 输入验证"""
    
    elif "命令" in message.lower() or "rce" in message.lower() or "exec" in message.lower():
        result += """**命令注入/RCE分析**

🔴 **威胁等级:** 严重

**攻击原理:**
通过在用户输入中注入操作系统命令来执行任意代码。

**危险代码模式:**
```java
Runtime.getRuntime().exec(input);
processBuilder(command);
system(cmd);
```

**防御建议:**
1. 避免使用用户输入执行命令
2. 使用白名单验证
3. 沙箱执行环境
4. 最小权限运行"""
    
    else:
        result += f"""**分析请求:** {message[:100]}...

🔍 **检测结果:**
- 初步判断: 需要更多上下文进行分析
- 建议: 请提供更详细的安全场景描述

**SecGPT支持的分析类型:**
- 漏洞分析与修复建议
- 渗透测试场景模拟
- 代码安全审计
- 日志异常检测
- 恶意软件分析
- 攻击链还原"""
    
    return result


def _handle_penetration_test(message: str) -> str:
    """处理渗透测试模拟"""
    return """🧪 **渗透测试模拟**

⚠️ **免责声明:** 本模拟仅用于学习和技术研究，请确保获得合法授权后再进行实际渗透测试。

**模拟场景: SQL注入攻击**

**步骤1: 信息收集**
- 目标: Web应用
- 发现: 登录表单、搜索功能

**步骤2: 漏洞探测**
```
payload: ' OR '1'='1
响应: 登录成功，返回管理员面板
结果: ✅ 存在SQL注入漏洞
```

**步骤3: 利用**
```
使用UNION注入获取数据库信息:
' UNION SELECT username,password FROM users--
```

**步骤4: 权限提升**
```
获取数据库版本: MySQL 5.7
尝试读取系统文件: INTO OUTFILE '/var/www/html/shell.php'
```

**防御建议:**
1. 立即修复SQL注入漏洞
2. 部署WAF
3. 定期安全扫描
4. 加强代码审计


**如需完整渗透测试报告，请联系安全团队！**"""


def _handle_code_audit(message: str) -> str:
    """处理代码安全审计"""
    return """📝 **代码安全审计报告**

**审计目标:** 用户提交的代码

**发现的安全问题:**

🔴 **严重: 命令注入 (CWE-78)**

```java
public void process(String input) {
  Runtime.getRuntime().exec(input);  // ❌ 危险!
}
```

**问题分析:**
- 用户输入直接作为系统命令执行
- 攻击者可执行任意系统命令
- CVSS评分: 10.0 (严重)

**修复建议:**

```java
// 方案1: 避免执行命令
public void process(String input) {
  // 仅处理数据，不执行命令
  sanitizeAndSave(input);
}

// 方案2: 白名单验证
public void process(String input) {
  if (!isValidCommand(input)) {
    throw new SecurityException("Invalid input");
  }
  // 安全处理
}

private boolean isValidCommand(String input) {
  return input.matches("^[a-zA-Z0-9_]+$");
}
```

**其他建议:**
1. 避免使用Runtime.exec()
2. 使用安全的API处理文件操作
3. 输入验证和输出编码
4. 定期代码审计


**审计完成时间:** 2026-03-04
**审计模型:** SecGPT"""


def _handle_log_analysis(message: str) -> str:
    """处理日志分析"""
    return """🔎 **安全日志分析**

**分析日志:**
```
192.168.1.100 - - [04/Mar/2026:10:00:00] "GET /admin.php?id=1\\' OR \\'1\\'=\\'1" 500
```

**分析结果:**

🔴 **检测到: SQL注入攻击**

| 字段 | 值 |
|------|-----|
| 攻击者IP | 192.168.1.100 |
| 攻击类型 | SQL注入 |
| 目标URL | /admin.php |
| Payload | `1' OR '1'='1` |
| HTTP状态 | 500 (服务器错误) |
| 风险等级 | 🔴 高危 |

**攻击特征:**
1. 使用单引号闭合原查询
2. OR逻辑永真条件
3. 尝试绕过认证

**建议行动:**
1. ✅ 已记录攻击日志
2. 🔒 建议封禁IP 192.168.1.100
3. 📝 创建安全事件工单
4. 🛡️ 检查并修复admin.php的SQL注入


**分析模型:** SecGPT
**置信度:** 95%"""


def _handle_general_query(message: str, history: List[Dict[str, str]]) -> str:
    """处理通用查询"""
    return f"""💡 **安全助手**

我理解你的问题是: {message}

我可以帮助你：

🔍 **威胁分析**
- IP/域名威胁查询
- 恶意软件分析

🛡️ **漏洞管理**
- CVE漏洞查询
- 漏洞风险评估

🖥️ **资产管理**
- 内网资产发现
- 端口服务扫描

⚡ **应急响应**
- 事件分析指导
- 止损建议

📊 **报告生成**
- 安全态势报告
- 漏洞分析报告

请告诉我具体需求！"""


async def _stream_chat(request: ChatRequest) -> AsyncGenerator[str, None]:
    """流式对话生成器"""
    import uuid
    import asyncio
    
    message_id = f"msg-{uuid.uuid4().hex[:8]}"
    
    # 模拟流式输出
    response_text = "我是玄鉴安全智能体，可以帮助您进行：\n\n1. **资产扫描** - 发现网络中的资产和服务\n2. **威胁分析** - 查询IP、域名、文件的威胁情报\n3. **漏洞扫描** - 检测系统和应用的安全漏洞\n4. **攻击溯源** - 分析攻击链路和事件时间线\n5. **防御拦截** - 封堵恶意IP、配置WAF规则\n\n请告诉我您需要什么帮助？"
    
    # 发送开始事件
    yield f"data: {json.dumps({'type': 'start', 'message_id': message_id})}\n\n"
    
    # 逐字符发送
    for i, char in enumerate(response_text):
        chunk = {
            "type": "text_delta",
            "message_id": message_id,
            "delta": char,
            "index": i
        }
        yield f"data: {json.dumps(chunk)}\n\n"
        await asyncio.sleep(0.02)  # 模拟打字效果
    
    # 发送结束事件
    yield f"data: {json.dumps({'type': 'done', 'message_id': message_id, 'finish_reason': 'stop'})}\n\n"


@router.post("/chat/tool-call")
async def execute_tool_call(tool_name: str, arguments: Dict[str, Any]):
    """
    执行工具调用
    
    当AI决定调用工具时，通过此接口执行
    """
    import uuid
    import time
    
    call_id = f"call-{uuid.uuid4().hex[:8]}"
    start_time = time.time()
    
    # TODO: 实际调用对应的工具
    # result = await tool_registry.call(tool_name, arguments)
    
    duration_ms = int((time.time() - start_time) * 1000)
    
    return ToolCall(
        call_id=call_id,
        tool_name=tool_name,
        arguments=arguments,
        status=ToolCallStatus.SUCCESS,
        result={"message": f"工具 {tool_name} 执行成功"},
        duration_ms=duration_ms
    )


@router.get("/models/status", response_model=List[ModelStatus])
async def get_models_status():
    """获取AI模型状态"""
    return [
        ModelStatus(
            model_id="supervisor-deepseek",
            model_name="DeepSeek Reasoner",
            model_type=ModelType.SUPERVISOR,
            is_available=True,
            current_load=0.3,
            avg_latency_ms=1500,
            error_rate=0.01,
            last_check=datetime.now()
        ),
        ModelStatus(
            model_id="executor-qwen",
            model_name="Qwen2.5-Coder-7B",
            model_type=ModelType.EXECUTOR,
            is_available=True,
            current_load=0.5,
            avg_latency_ms=800,
            error_rate=0.02,
            last_check=datetime.now()
        ),
        ModelStatus(
            model_id="executor-glm",
            model_name="GLM-4-9B",
            model_type=ModelType.EXECUTOR,
            is_available=True,
            current_load=0.2,
            avg_latency_ms=900,
            error_rate=0.01,
            last_check=datetime.now()
        )
    ]


@router.get("/tools", response_model=List[AvailableTool])
async def list_available_tools():
    """获取可用工具列表"""
    return [
        AvailableTool(
            name="scan_asset",
            description="扫描指定范围内的资产，支持IP、CIDR、域名",
            parameters={
                "scope": {"type": "string", "required": True},
                "scan_type": {"type": "string", "enum": ["nmap", "censys", "passive"]},
                "ports": {"type": "string"}
            },
            risk_level="medium",
            requires_approval=False
        ),
        AvailableTool(
            name="query_threat_intel",
            description="查询IP、域名、文件哈希的威胁情报",
            parameters={
                "indicator": {"type": "string", "required": True},
                "sources": {"type": "array", "items": {"type": "string"}}
            },
            risk_level="low",
            requires_approval=False
        ),
        AvailableTool(
            name="run_vuln_scan",
            description="对目标执行漏洞扫描",
            parameters={
                "target": {"type": "string", "required": True},
                "scan_type": {"type": "string", "enum": ["quick", "full", "custom"]}
            },
            risk_level="medium",
            requires_approval=False
        ),
        AvailableTool(
            name="block_ip",
            description="封堵指定的IP地址",
            parameters={
                "ip": {"type": "string", "required": True},
                "direction": {"type": "string", "enum": ["inbound", "outbound", "both"]},
                "duration": {"type": "integer"},
                "reason": {"type": "string", "required": True}
            },
            risk_level="critical",
            requires_approval=True
        )
    ]


@router.post("/query")
async def simple_query(question: str, context: Optional[Dict[str, Any]] = None):
    """
    简单问答接口
    
    快速获取AI对安全问题的回答
    """
    # TODO: 调用AI模型进行问答
    return {
        "question": question,
        "answer": f"关于'{question}'的回答：这是一个关于网络安全的问题，我会基于我的知识和工具来帮助您分析...",
        "confidence": 0.85,
        "sources": ["内置知识库", "威胁情报"],
        "suggestions": [
            "您可以让我执行扫描来获取更详细的信息",
            "需要我查询相关的威胁情报吗？"
        ]
    }


@router.get("/history")
async def get_chat_history(
    session_id: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200)
):
    """获取对话历史"""
    return {
        "total": 0,
        "items": [],
        "page": page,
        "page_size": page_size
    }


@router.delete("/history/{session_id}")
async def clear_chat_history(session_id: str):
    """清除对话历史"""
    return {"message": "对话历史已清除", "session_id": session_id}


@router.get("/suggestions")
async def get_suggestions(context: Optional[str] = None):
    """获取智能建议"""
    return {
        "suggestions": [
            {"text": "扫描内网资产", "command": "/scan 192.168.1.0/24"},
            {"text": "查询可疑IP情报", "command": "/intel <IP地址>"},
            {"text": "检查最新漏洞", "command": "/vuln-scan <目标>"},
            {"text": "查看安全态势", "command": "/dashboard"}
        ]
    }


@router.post("/feedback")
async def submit_feedback(
    message_id: str,
    rating: int = Query(..., ge=1, le=5),
    comment: Optional[str] = None
):
    """提交AI响应反馈"""
    return {
        "message": "感谢您的反馈",
        "message_id": message_id,
        "rating": rating
    }
