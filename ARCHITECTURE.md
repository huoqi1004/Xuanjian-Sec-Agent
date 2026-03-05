# 玄鉴安全智能体 - 技术架构设计文档

## 项目概述

玄鉴安全智能体是一个AI驱动的企业级网络安全解决方案，通过集成多种安全工具和AI模型，实现自动化安全防护、威胁检测、漏洞扫描和响应处置。

## 核心架构

### 1. 分层架构

```
┌─────────────────────────────────────────────────────┐
│           数据可视化层 (Dashboard)             │
│         - 实时监控大屏                           │
│         - 安全态势感知                              │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│           API网关层 (FastAPI)                  │
│         - RESTful API                           │
│         - WebSocket推送                           │
│         - 认证授权                                │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│             协调编排层                            │
│  ┌──────────────┬──────────────┐            │
│  │   工作流引擎   │   事件总线      │            │
│  │  (Workflow)   │  (EventBus)  │            │
│  └──────────────┴──────────────┘            │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│             AI智能层                               │
│  ┌──────────────┬──────────────┐            │
│  │  监督模型      │  执行模型       │            │
│  │  (Supervisor) │  (Executor)  │            │
│  │  DeepSeek     │  Local LLM   │            │
│  └──────────────┴──────────────┘            │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│           安全工具层 (MCP Tools)              │
│  ┌────────┬────────┬────────┬────────┐  │
│  │威胁情报  │ 资产扫描 │ 漏洞扫描│ 防御   │  │
│  │ Intel  │ Scanner │ Vuln   │Defense │  │
│  └────────┴────────┴────────┴────────┘  │
└─────────────────────────────────────────┘
```

## 已实现的安全工具

### 1. 威胁情报工具

#### 1.1 微步在线威胁情报 ([`threatbook.py`](xuanjian-security/backend/app/tools/threat_intel/threatbook.py:1))
- **功能**: IP、域名、文件Hash威胁查询
- **API**: 微步在线API v3
- **特性**:
  - 支持批量查询
  - 威胁等级评估
  - 关联恶意软件识别
  - 子域名和兄弟域名查询

#### 1.2 VirusTotal病毒查杀 ([`virustotal.py`](xuanjian-security/backend/app/tools/threat_intel/virustotal.py:1))
- **功能**: 文件病毒检测、URL扫描、IP/域名威胁查询
- **API**: VirusTotal API v3
- **特性**:
  - 支持58+杀毒引擎
  - 实时威胁检测
  - 恶意软件家族识别
  - 支持Base64文件上传

### 2. 资产扫描工具

#### 2.1 Nmap内网扫描器 ([`nmap_tool.py`](xuanjian-security/backend/app/tools/scanner/nmap_tool.py:1))
- **功能**: 主机发现、端口扫描、服务枚举、OS检测
- **特性**:
  - Ping扫描(主机发现)
  - 端口扫描(TCP/UDP)
  - 版本检测
  - 操作系统识别
  - 脚本扫描(NSE)

#### 2.2 Censys互联网资产扫描 ([`censys_tool.py`](xuanjian-security/backend/app/tools/scanner/censys_tool.py:1))
- **功能**: 互联网资产发现、域名查询、IP查询
- **API**: Censys Search API v2
- **特性**:
  - 证书指纹查询
  - 域名资产发现
  - IP服务指纹识别
  - 批量搜索

#### 2.3 Nessus漏洞扫描 ([`nessus_tool.py`](xuanjian-security/backend/app/tools/scanner/nessus_tool.py:1))
- **功能**: 企业级漏洞扫描、风险评估
- **API**: Nessus API
- **特性**:
  - CVSS评分
  - 漏洞分级(Critical/High/Medium/Low)
  - 自定义扫描策略
  - 报告导出

### 3. 防御工具

#### 3.1 雷池WAF ([`safeline_waf.py`](xuanjian-security/backend/app/tools/defense/safeline_waf.py:1))
- **功能**: Web应用防火墙、规则管理、IP封禁
- **API**: 雷池WAF API
- **特性**:
  - 自定义规则创建
  - 实时IP封禁
  - 审计日志查询
  - 统计分析

#### 3.2 本地防御系统 ([`local_defense.py`](xuanjian-security/backend/app/services/local_defense.py:1))
- **功能**: 本地网络防御、IP封禁、威胁检测
- **特性**:
  - 网络扫描和监控
  - Windows防火墙集成
  - 实时威胁检测
  - 自动响应机制

#### 3.3 高级防御系统 ([`advanced_defense.py`](xuanjian-security/backend/app/services/advanced_defense.py:1))
- **功能**: AI驱动的高级防御、勒索软件检测、多Agent协同
- **特性**:
  - AI攻击检测和拦截
  - 勒索软件行为识别
  - 多Agent协同防御
  - 威胁情报和IOC库
  - 攻击序列分析

### 4. 恶意代码分析

#### 4.1 CAPE沙箱 ([`cape_sandbox.py`](xuanjian-security/backend/app/tools/analysis/cape_sandbox.py:1))
- **功能**: 恶意软件动态分析、行为监控
- **API**: CAPE Sandbox API
- **特性**:
  - 文件/URL提交
  - API调用监控
  - 网络行为分析
  - 文件系统监控
  - 恶意分数评分

## 核心框架组件

### 1. MCP (Model Context Protocol)

**作用**: 将AI模型与安全工具进行标准化连接

**组件**:
- [`mcp_server.py`](backend/app/mcp/mcp_server.py:1): MCP服务器实现
- [`bridge.py`](backend/app/mcp/bridge.py:1): AI与工具层桥接
- [`tool_definitions.py`](backend/app/mcp/tool_definitions.py:1): 工具定义和元数据
- `dsl_parser.py`: DSL工作流语言解析器
- `executor.py`: 工作流执行器

### 2. 工作流引擎 ([`workflow_engine.py`](xuanjian-security/backend/app/core/workflow_engine.py:1))

**功能**: 
- DAG工作流编排
- 步骤依赖管理
- 并行执行支持
- 错误处理和重试
- 条件分支和循环

**支持的步骤类型**:
- `TOOL_CALL`: 调用安全工具
- `LLM_QUERY`: 查询大模型
- `CONDITION`: 条件判断
- `PARALLEL`: 并行执行
- `NOTIFICATION`: 通知
- `HUMAN_APPROVAL`: 人工审批
- `DELAY`: 延迟等待

### 3. AI双模型架构

#### 3.1 监督模型 (Supervisor)
- **实现**: [`supervisor.py`](xuanjian-security/backend/app/ai/supervisor.py:1)
- **模型**: DeepSeek API
- **职责**:
  - 任务规划和分解
  - 结果审查和验证
  - 冲突仲裁
  - 安全合规检查

#### 3.2 执行模型 (Executor)
- **实现**: [`executor.py`](xuanjian-security/backend/app/ai/executor.py:1)
- **模型**: 本地模型(Ollama: Qwen/DeepSeek-Code/Claude/Kimi/GLM)
- **职责**:
  - 工具调用决策
  - 参数提取和构造
  - 实时响应生成
  - 工作流执行驱动

#### 3.3 安全守卫 (SafetyGuard)
- **实现**: [`safety_guard.py`](xuanjian-security/backend/app/ai/safety_guard.py:1)
- **职责**:
  - 模型投毒检测
  - 越狱攻击防御
  - 提权攻击阻止
  - 后门行为识别

### 4. 事件总线 ([`event_bus.py`](xuanjian-security/backend/app/core/event_bus.py:1))

**功能**: 
- 异步事件发布订阅
- 工具间解耦通信
- 实时通知推送
- 事件持久化和重放

## 安全工作流

### 典型安全流程

```
1. 资产发现阶段
   ├─ 使用Nmap扫描内网
   ├─ 使用Censys发现互联网资产
   └─ 整合资产清单

2. 威胁识别阶段
   ├─ 微步在线: IP/域名威胁查询
   ├─ VirusTotal: 文件病毒检测
   ├─ CAPE沙箱: 恶意代码分析
   └─ 威胁情报聚合

3. 漏洞扫描阶段
   ├─ Nessus: 深度漏洞扫描
   ├─ 风险等级评估
   └─ 优先级排序

4. 威胁处置阶段
   ├─ 雷池WAF: 攻击拦截
   ├─ IP封禁: 阻断恶意源
   └─ 规则调整: 防御策略优化

5. 取证溯源阶段
   ├─ 流量分析: 攻击路径
   ├─ 日志审计: 攻击时间线
   ├─ 攻击者画像
   └─ 威胁建模

6. 方案迭代阶段
   ├─ 监督模型: 审查执行结果
   ├─ 威胁建模: 更新知识库
   └─ 策略优化: 持续改进
```

## API接口设计

### 工具调用接口

所有工具继承自 [`BaseTool`](xuanjian-security/backend/app/tools/base_tool.py:1)，实现统一的接口:

```python
async def execute(self, **kwargs) -> ToolResult:
    """
    执行工具
    
    Args:
        **kwargs: 工具参数
        
    Returns:
        ToolResult包含:
        - success: 是否成功
        - data: 结果数据
        - error: 错误信息(如有)
        - metadata: 元数据
        - duration_ms: 执行耗时
    """
```

### 工具注册机制

使用装饰器自动注册工具:

```python
@ToolRegistry.register()
class MySecurityTool(BaseTool):
    metadata = ToolMetadata(
        name="my_tool",
        category=ToolCategory.SCANNER,
        description="..."
    )
```

## 配置管理

### API密钥配置 ([`settings.py`](xuanjian-security/backend/app/config/settings.py:1))

```python
# 微步在线
threatbook_api_key = "aeac41e7dae84fc4897b7ae258e27a8404f265dbc66a4a19a563aa8cb84ee2bc"

# VirusTotal
virustotal_api_key = "4e457d41fd687d44bfd97b7b11f54921482c437fce9a5e7def212a8bf6e590f3"

# Censys
censys_api_id = "censys_HCiSyV9H_GoDyfcpy66PT2DMJ2xGgbe1U"
censys_api_secret = "**SECRET**"

# DeepSeek (监督模型)
supervisor_api_key = "**SECRET**"

# Nessus
nessus_url = "https://nessus-server:8834"
nessus_access_key = "**ACCESS_KEY**"
nessus_secret_key = "**SECRET_KEY**"

# 雷池WAF
safeline_api_url = "https://safeline-instance/api"
safeline_api_key = "**API_KEY**"

# CAPE沙箱
cape_api_url = "https://cape-instance/api"
cape_api_key = "**API_KEY**"
```

## 扩展接口

### 集成新安全工具

1. 继承 `BaseTool`
2. 实现 `execute()` 方法
3. 定义 `ToolMetadata`
4. 使用 `@ToolRegistry.register()` 装饰器

### 集成新AI模型

1. 实现 `Executor` 接口
2. 支持 OpenAI Protocol
3. 实现流式输出
4. 支持函数调用(Function Calling)

### 集成新安全产品

支持标准协议:
- REST API
- SNMP
- Syslog
- CEF (Common Event Format)
- STIX/TAXII (威胁情报交换)

## 监控和日志

### ELK Stack集成

- **Elasticsearch**: 日志存储和索引
- **Logstash**: 日志收集和解析
- **Kibana**: 可视化 dashboard

### 指标监控

- 工具执行统计
- 成功率和耗时
- 威胁检测率
- 漏洞覆盖率
- 响应时间

## 安全保障

### AI内生安全

1. **模型投毒防护**
   - 输入验证和过滤
   - 异常行为检测
   - 结果一致性校验

2. **模型后门防护**
   - 行为监控
   - 输出审计
   - 异常模式识别

3. **越狱攻击防护**
   - Prompt注入检测
   - 敏感操作审批
   - 权限验证

4. **提权攻击防护**
   - 操作权限分级
   - 审计日志记录
   - 异常告警

### 数据安全

- API密钥加密存储
- 传输层TLS加密
- 敏感数据脱敏
- 访问控制和审计

## 性能优化

1. **并发执行**: 工作流支持并行步骤
2. **结果缓存**: 工具结果缓存(TTL配置)
3. **连接池**: HTTP客户端连接复用
4. **异步IO**: 全面使用async/await
5. **限流控制**: API调用速率限制

## 部署架构

### 容器化部署

```yaml
services:
  xuanjian-api:
    image: xuanjian/security-agent:latest
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://...
      - REDIS_URL=redis://...
  
  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ./models:/root/.ollama
  
  nessus:
    image: tenable/nessus:latest
    ports:
      - "8834:8834"
  
  elk:
    image: sebp/elk:latest
    ports:
      - "5601:5601"
      - "9200:9200"
      - "5044:5044"
```

## 未来扩展

### 计划中的工具集成

- [ ] MISP威胁情报平台
- [ ] Shodan搜索引擎
- [ ] Snort IDS
- [ ] Suricata IPS
- [ ] QRadar SIEM
- [ ] Splunk日志分析
- [ ] Cobalt Strike对抗
- [ ] Metasploit集成

### 计划中的AI能力

- [ ] 多模态威胁分析
- [ ] 零日学习异常检测
- [ ] 图神经网络威胁建模
- [ ] 强化学习防御策略优化
- [ ] 联邦学习隐私保护

## 技术栈总结

| 层级 | 技术选型 |
|--------|----------|
| Web框架 | FastAPI 0.109.2 |
| 数据库 | PostgreSQL + SQLAlchemy |
| 缓存 | Redis |
| 搜索 | Elasticsearch |
| AI/LLM | OpenAI SDK + Ollama |
| 工作流 | 自研Workflow Engine |
| 容器 | Docker + Docker Compose |
| 监控 | Prometheus + Grafana |
| 日志 | ELK Stack |

---

**文档版本**: v1.1.0  
**最后更新**: 2026-03-05  
**维护者**: 玄鉴安全团队
