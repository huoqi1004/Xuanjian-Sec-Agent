# 玄鉴安全智能体 (XuanJian Security Agent)

> AI驱动的企业级网络安全解决方案

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109.2-green)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

## 项目简介

玄鉴安全智能体是一个基于AI和MCP (Model Context Protocol) 架构的网络安全解决方案，通过集成多种主流安全工具和大语言模型，实现智能化的威胁检测、漏洞扫描、防御响应和取证分析。

### 核心特性

- 🤖 **AI双模型架构**
  - 监督模型 (DeepSeek): 战略规划、结果审查、安全合规
  - 执行模型 (本地Qwen/DeepSeek-Code/Claude等): 工具调用、实时响应

- 🛡️ **全栈安全工具集成**
  - 威胁情报: 微步在线、VirusTotal
  - 资产扫描: Nmap、Censys
  - 漏洞扫描: Nessus
  - Web防御: 雷池WAF
  - 恶意分析: CAPE沙箱
  - 流量分析: Wireshark
  - 日志分析: ELK Stack

- 🔄 **工作流编排引擎**
  - DAG工作流定义
  - 并行/串行执行
  - 条件分支和循环
  - 自动化安全流程

- 🔒 **AI内生安全防护**
  - 模型投毒检测
  - 越狱攻击防御
  - 提权攻击阻止
  - 后门行为识别

## 快速开始

### 环境要求

- Python 3.10+
- PostgreSQL 14+
- Redis 7+
- Elasticsearch 8+
- Docker & Docker Compose (可选)

### 安装

```bash
# 克隆仓库
git clone https://github.com/your-org/xuanjian-security.git
cd xuanjian-security

# 安装依赖
cd backend
pip install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env 文件，填写你的API密钥

# 初始化数据库
alembic upgrade head

# 启动服务
python -m app.main
```

### 使用Docker Compose (推荐)

```bash
# 启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

## 配置指南

### API密钥配置

在 `backend/app/config/.env` 中配置各安全工具的API密钥:

```env
# 威胁情报
XUANJIAN_THREATBOOK_API_KEY=aeac41e7dae84fc4897b7ae258e27a8404f265dbc66a4a19a563aa8cb84ee2bc
XUANJIAN_VIRUSTOTAL_API_KEY=4e457d41fd687d44bfd97b7b11f54921482c437fce9a5e7def212a8bf6e590f3
XUANJIAN_CENSYS_API_ID=censys_HCiSyV9H_GoDyfcpy66PT2DMJ2xGgbe1U
XUANJIAN_CENSYS_API_SECRET=your_censys_secret

# AI模型
XUANJIAN_LLM_SUPERVISOR_API_KEY=your_deepseek_key
XUANJIAN_LLM_EXECUTOR_BASE_URL=http://localhost:11434
XUANJIAN_LLM_EXECUTOR_MODEL=qwen2.5-coder:7b

# 漏洞扫描
XUANJIAN_NESSUS_URL=https://nessus-server:8834
XUANJIAN_NESSUS_ACCESS_KEY=your_access_key
XUANJIAN_NESSUS_SECRET_KEY=your_secret_key

# 防御
XUANJIAN_SAFEWAF_API_URL=https://safeline-instance/api
XUANJIAN_SAFEWAF_API_KEY=your_api_key

# 恶意分析
XUANJIAN_CAPE_API_URL=https://cape-instance/api
XUANJIAN_CAPE_API_KEY=your_api_key

# 数据库
XUANJIAN_DB_URL=postgresql+asyncpg://xuanjian:password@localhost:5432/xuanjian
XUANJIAN_REDIS_URL=redis://localhost:6379/0
XUANJIAN_ES_HOSTS=http://localhost:9200
```

## API文档

启动服务后，访问以下地址查看API文档:

- Swagger UI: http://localhost:8000/api/docs
- ReDoc: http://localhost:8000/api/redoc

## 使用示例

### 调用威胁情报工具

```python
from app.tools.virustotal import VirusTotalTool
from app.tools.base_tool import ToolResult

# 初始化工具
vt = VirusTotalTool(api_key="your_api_key")

# 查询文件Hash
result: ToolResult = await vt.execute(
    query_type="hash",
    file_hash="d41d8cd98f00b204e9800998ecf8427e"
)

if result.success:
    print(f"检测引擎: {result.data['scan_result']['total_engines']}")
    print(f"恶意检测: {result.data['scan_result']['malicious_count']}")
```

### 执行Nmap扫描

```python
from app.tools.scanner.nmap_tool import NmapTool

# 初始化工具
nmap = NmapTool(nmap_path="/usr/bin/nmap")

# Ping扫描
result = await nmap.ping_sweep("192.168.1.0/24")

if result.success:
    print(f"发现主机: {result.data['summary']['online_hosts']}")
```

### 创建自动化工作流

```python
from app.core.workflow_engine import WorkflowDefinition, StepDefinition

# 定义工作流
workflow = WorkflowDefinition(
    workflow_id="security_scan",
    name="自动化安全扫描流程",
    version="1.0.0",
    steps=[
        StepDefinition(
            step_id="discovery",
            name="资产发现",
            step_type="tool_call",
            tool_name="nmap",
            params={"target": "{{target}}", "scan_type": "-sn"}
        ),
        StepDefinition(
            step_id="threat_check",
            name="威胁情报查询",
            step_type="tool_call",
            tool_name="threatbook",
            params={"query_type": "ip", "query_value": "{{discovery.ip}}"},
            depends_on=["discovery"]
        ),
        StepDefinition(
            step_id="vuln_scan",
            name="漏洞扫描",
            step_type="tool_call",
            tool_name="nessus",
            params={"targets": ["{{discovery.ip}}"]},
            depends_on=["threat_check"]
        )
    ]
)
```

## 架构设计

详细架构设计请参考 [ARCHITECTURE.md](ARCHITECTURE.md)

### 六层架构

```
┌─────────────────────────────────────────────┐
│     数据可视化层 (Dashboard/SOC)   │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│       API网关层 (FastAPI/Fastify)    │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│      协调编排层 (Workflow Engine)      │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│       AI智能层 (Supervisor + Executor) │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│    安全工具层 (MCP Protocol Tools)    │
│  ThreatIntel | Scanner | Analysis | Defense│
└───────────────────────────────────────────┘
```

## 安全防护

### AI内生安全

玄鉴安全智能体实现了多层AI安全防护机制:

1. **输入验证层**
   - Prompt注入检测
   - SQL注入防护
   - XSS过滤

2. **行为监控层**
   - 模型输出审计
   - 异常操作检测
   - 敏感操作审批

3. **威胁防护层**
   - 模型投毒检测
   - 后门行为识别
   - 越狱攻击防御

4. **响应控制层**
   - 权限分级管理
   - 限流保护
   - 熔断机制

## 监控和日志

### 日志级别

- `INFO`: 正常操作日志
- `WARNING`: 非致命警告
- `ERROR`: 错误和异常
- `DEBUG`: 调试信息(开发环境)

### 指标监控

访问 Grafana dashboard: http://localhost:3000

主要指标:
- 工具执行成功率
- 平均响应时间
- 威胁检测率
- 漏洞覆盖率

## 扩展开发

### 集成新安全工具

1. 继承 `BaseTool` 类
2. 实现 `execute()` 方法
3. 使用 `@ToolRegistry.register()` 装饰器

示例:

```python
from app.tools.base_tool import BaseTool, ToolRegistry, ToolMetadata
from app.tools.base_tool import ToolCategory

@ToolRegistry.register()
class MyTool(BaseTool):
    metadata = ToolMetadata(
        name="my_tool",
        category=ToolCategory.SCANNER,
        description="我的安全工具"
    )
    
    async def execute(self, **kwargs) -> ToolResult:
        # 实现工具逻辑
        return ToolResult.success_result(
            tool_name=self.metadata.name,
            data={"result": "success"}
        )
```

### 开发自定义技能

参考 `app/mcp/skills/` 目录中的技能示例。

## 部署清单

### 生产环境部署

- [ ] 配置反向代理(Nginx/HAProxy)
- [ ] 启用HTTPS/TLS
- [ ] 配置数据库主从复制
- [ ] 设置Redis哨兵/集群
- [ ] Elasticsearch集群配置
- [ ] 配置日志收集(Logstash)
- [ ] 启用监控告警(Prometheus Alertmanager)
- [ ] 设置备份策略
- [ ] 配置防火墙规则
- [ ] 性能调优(workers/连接池)

## 性能基准

| 操作 | 平均耗时 | 吞吐量 |
|------|----------|----------|
| Nmap主机发现 | 5-30s | 100 hosts/min |
| VirusTotal扫描 | 10-60s | 4 queries/min |
| Nessus扫描 | 5-30min | 1 scan/5min |
| Censys搜索 | 1-5s | 20 queries/min |
| CAPE分析 | 1-5min | 12 tasks/hour |

## 故障排查

### 常见问题

**Q: Ollama模型加载失败**
```bash
# 拉取模型
ollama pull qwen2.5-coder:7b

# 验证服务
curl http://localhost:11434/api/tags
```

**Q: Nmap权限不足**
```bash
# 确保有CAP_NET_RAW权限
sudo setcap cap_net_raw=ep /usr/bin/nmap
```

**Q: Elasticsearch连接失败**
```bash
# 检查ES服务状态
curl -X GET "localhost:9200/_cluster/health"

# 检查索引
curl -X GET "localhost:9200/_cat/indices"
```

## 贡献指南

我们欢迎社区贡献! 请参考 [CONTRIBUTING.md](CONTRIBUTING.md)

### 代码规范

- 遵循PEP 8代码风格
- 使用类型注解(Type Hints)
- 编写单元测试(使用pytest)
- 更新文档字符串

### Pull Request流程

1. Fork本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启Pull Request

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 开发路线图

### v1.1.0 (计划中)
- [ ] MISP威胁情报平台集成
- [ ] Shodan搜索引擎集成
- [ ] 多模态威胁分析
- [ ] 图神经网络威胁建模

### v2.0.0 (规划中)
- [ ] 联邦学习隐私保护
- [ ] 零日学习异常检测
- [ ] 强化学习防御策略优化
- [ ] 边缘计算支持

## 联系我们

- 📧 邮箱: security@xuanjian.ai
- 💬 微信群: 玄鉴安全智能体
- 📊 监控: [Grafana Dashboard](http://localhost:3000)
- 📚 文档: [技术文档](https://docs.xuanjian.ai)

---

**玄鉴安全智能体** - AI守护企业网络安全

```
Made with ❤️ by XuanJian Security Team