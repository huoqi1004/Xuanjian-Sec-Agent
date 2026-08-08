# N-25 Multi-Agent + Tools 增强 + React 架构改造计划

> 版本：v1.0 ｜ 生成日期：2026-08-09
> 目标架构：**Multi-Agent 编排框架 + Tools 工具注册表 + React 18 前端全量迁移**
> 策略：后端内部重构兼容（现有 `/api/ai/agent/*` API 与 87 Jest 用例不回归）；前端新建 `frontend-react/`（Vue3 版 `frontend-app/` 保留并行，静态托管按构建产物切换）
> 关联文档：[ROADMAP.md](./ROADMAP.md) Phase 4（4.13/4.14/4.15）、[NEXT_ITERATIONS.md](./NEXT_ITERATIONS.md) N-17

---

## 一、现状基线（改造起点）

| 维度 | 现状 | 目标 |
|------|------|------|
| Agent 框架 | 单 Agent 多步循环（[agentService.js](file:///e:/迅雷下载/xuanjian-security-agent/server/services/agentService.js)：规划→执行→总结） | 多 Agent 编排（规划/执行/研判/情报/报告/扫描/防御 7 类角色，Orchestrator 调度 + 上下文传递） |
| Tools | [aiService.executeTool](file:///e:/迅雷下载/xuanjian-security-agent/server/services/aiService.js#L386) 一个巨型 switch（14 个 case） | 集中式工具注册表 `server/agents/tools/registry.js`（元数据驱动 + 校验 + 审计 + 测试） |
| 前端 | Vue3（[frontend-app/](file:///e:/迅雷下载/xuanjian-security-agent/frontend-app)） | React 18 + Vite + TS + shadcn/ui + Zustand（[frontend-react/](file:///e:/迅雷下载/xuanjian-security-agent)） |
| 静态托管 | [server.js#L86-L90](file:///e:/迅雷下载/xuanjian-security-agent/server/server.js#L86-L90) 优先 `frontend-app/dist`，回退 `frontend/` | 增加 `frontend-react/dist` 优先（env `FRONTEND_DIR` 可指定） |

### 约束
- **兼容红线**：`POST /api/ai/agent/run`、`POST /api/ai/agent/confirm`、`GET /api/ai/agent/pending` 三个接口签名不变；[agentService.test.js](file:///e:/迅雷下载/xuanjian-security-agent/server/test/agentService.test.js) 7 用例必须继续通过。
- 后端全部 `db.prepare()` 调用**不**在本计划改动（N-06 负责数据层）；Multi-Agent 只做服务编排层重构。
- React 前端只消费现有 REST API + WS `/ws/frontend`，不新增后端接口（除 Agent 编排过程接口外，见 Task A7）。

---

## 二、总体架构（目标态）

```
┌──────────────────────────────────────────────────────────────┐
│  React 18 前端（frontend-react/）                              │
│  Agent 工作台 / Dashboard / Scan / ... 14 页 + WS 订阅         │
└───────────────────────────┬──────────────────────────────────┘
                            │ REST /api/*  +  WS /ws/frontend
┌───────────────────────────▼──────────────────────────────────┐
│  Server                                                       │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ Orchestrator（server/agents/orchestrator.js）            │   │
│  │  任务解析 → 角色路由 → 上下文传递 → 结果聚合 → 总结       │   │
│  │  中间件：人工确认 / 审计 / 指标 / 超时 / 重试             │   │
│  └───────┬───────────────────────┬───────────────────────┘   │
│   ┌──────▼──────┐  ┌─────────────▼──────────────┐            │
│   │ Agent 注册表 │  │ 工具注册表                    │            │
│   │ Planner     │  │ tools/registry.js           │            │
│   │ Executor    │  │ ├─ 情报查询组（4）            │            │
│   │ Analyst     │  │ ├─ 扫描/告警/基线组（5）       │            │
│   │ Intel       │  │ ├─ 报告/分析组（3）            │            │
│   │ Reporter    │  │ └─ 防御动作组（2+2 新增）      │            │
│   │ Scan        │  └──────────────────────────────┘            │
│   │ Defense     │                                              │
│   └─────────────┘   agentService.js = 兼容壳（转调 Orchestrator）│
└──────────────────────────────────────────────────────────────┘
```

---

## 三、文件结构与职责

```
server/agents/                       # 新建：多 Agent 框架
├── baseAgent.js                     # Agent 基类契约 + 上下文工具
├── registry.js                      # Agent 注册中心（name → class）
├── orchestrator.js                  # 编排器：调度/上下文/确认/审计/指标
├── agents/
│   ├── plannerAgent.js              # 规划 Agent（LLM 计划 + 规则回退）
│   ├── executorAgent.js             # 执行 Agent（调工具注册表，重试）
│   ├── analystAgent.js              # 研判 Agent（告警聚合/根因/建议）
│   ├── intelAgent.js                # 情报 Agent（多源聚合）
│   ├── reporterAgent.js             # 报告 Agent（生成安全/扫描/基线报告）
│   ├── scanAgent.js                 # 扫描 Agent（创建/查询扫描任务）
│   └── defenseAgent.js              # 防御 Agent（高危动作 + 人工确认）
└── tools/
    ├── registry.js                  # 工具注册表（元数据/校验/审计/执行）
    ├── intelTools.js                # get_threat_intel/query_shodan/query_abuseipdb/query_virustotal/analyze_virus_hash
    ├── queryTools.js                # get_scan_results/get_alert_summary/get_baseline_results/analyze_alerts
    ├── actionTools.js               # start_scan/generate_security_report/scan_file_with_ai
    └── defenseTools.js              # block_ip/account_lock + 新增 search_knowledge/list_alerts/run_playbook

server/services/agentService.js      # 改为兼容壳：runAgent/confirmExecution/getPendingConfirmations 转调 orchestrator（保持导出不变）

server/test/
├── agent-framework.test.js          # 新建：基类/注册表/编排器单测
├── tools-registry.test.js           # 新建：工具注册表执行/校验/审计单测
├── agentService.test.js             # 保留：7 用例回归（必须全绿）

frontend-react/                      # 新建：React 18 工程
├── package.json / vite.config.ts / tsconfig*.json / tailwind.config.ts
├── index.html
├── src/
│   ├── main.tsx / App.tsx
│   ├── api/  http.ts / index.ts     # axios 封装 + 全部 API（对照 frontend-app/src/api）
│   ├── stores/ user.ts (Zustand) / ws.ts
│   ├── layouts/ MainLayout.tsx
│   ├── router/ index.tsx            # React Router 6（14 路由 + 登录守卫）
│   ├── components/ ui/ (shadcn) + chart/ + common/
│   └── pages/  Login/Dashboard/Scan/Baseline/Virus/Djpp/Assistant/Situational/
│               Defense/Device/Users/Playbook/Config/Reports/AgentWorkbench(新增)
└── .github 无（CI 复用根 workflow）

server/server.js                     # 修改：静态托管优先 frontend-react/dist（env FRONTEND_DIR）
.github/workflows/ci.yml             # 修改：新增 react-build job（构建 + 类型检查 + lint）
README.md / ROADMAP.md               # 修改：补充新架构说明（Phase 6 归档）
```

---

## 四、分阶段迭代任务（每批可独立验收/回滚）

### Phase A 多 Agent 框架（后端）

#### Task A1: Agent 基类 + 上下文工具

**Files:**
- Create: `server/agents/baseAgent.js`
- Create: `server/test/agent-framework.test.js`

**Step 1 — 写失败测试**（`server/test/agent-framework.test.js`）：

```js
const { createContext } = require('../agents/baseAgent');

describe('Agent 框架 - 基类', () => {
  test('createContext 提供任务/用户/元数据与 set/get', () => {
    const ctx = createContext('分析内网资产风险', { userId: 2, plan: null });
    expect(ctx.task).toBe('分析内网资产风险');
    expect(ctx.userId).toBe(2);
    ctx.set('task_id', 't1');
    expect(ctx.get('task_id')).toBe('t1');
    ctx.set('task_id', 't2'); // 覆盖
    expect(ctx.get('task_id')).toBe('t2');
  });
  test('createContext 记录开始时间与步骤列表', () => {
    const ctx = createContext('任务');
    expect(ctx.startedAt).toBeTruthy();
    expect(Array.isArray(ctx.steps)).toBe(true);
  });
});
```

**Step 2 — 运行确认失败**：`cd server && npx jest test/agent-framework.test.js` → FAIL（`Cannot find module '../agents/baseAgent'`）。

**Step 3 — 实现 `server/agents/baseAgent.js`**：

```js
/**
 * 玄鉴安全智能体 - 多 Agent 框架基类与上下文
 * 上下文（Context）是 Agent 间传递的共享工作区（黑板模式）：
 * 每个 Agent 读取前序产物，写入自己的产物，编排器负责调度顺序。
 */
const { randomUUID } = require('crypto');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

/** 创建共享上下文 */
function createContext(task, opts = {}) {
  const store = new Map();
  const ctx = {
    runId: `agent_${Date.now().toString(36)}_${randomUUID().slice(0, 4)}`,
    task: String(task || ''),
    userId: opts.userId || null,
    startedAt: new Date().toISOString(),
    steps: [], // { agent, tool?, status, duration_ms, at }
    set(key, value) { store.set(key, value); },
    get(key) { return store.get(key); },
    has(key) { return store.has(key); },
    appendStep(record) { ctx.steps.push({ at: new Date().toISOString(), ...record }); }
  };
  return ctx;
}

/**
 * Agent 基类
 * 子类必须实现 run(ctx)：读取 ctx 输入，返回 { success, data?, message?, error? }
 */
class BaseAgent {
  constructor(name, capability) {
    this.name = name;          // 唯一标识，如 'planner'
    this.capability = capability; // 能力描述，供编排器路由
  }

  /** 统一执行入口：计时 + 指标 + 日志 + 步骤记录 */
  async execute(ctx) {
    const start = Date.now();
    const step = { agent: this.name, status: 'running' };
    ctx.appendStep(step);
    metrics.inc('agent_calls_total', { agent: this.name }, 1, 'Agent 调用次数');
    try {
      const result = await this.run(ctx);
      const ok = result && result.success !== false;
      step.status = ok ? 'done' : 'failed';
      step.duration_ms = Date.now() - start;
      if (ok) logger.info(`[Agent:${this.name}] 执行成功（${step.duration_ms}ms）`);
      else logger.warn(`[Agent:${this.name}] 执行失败: ${result && result.error}`);
      return { success: ok, agent: this.name, data: result.data, message: result.message, error: result.error };
    } catch (err) {
      step.status = 'failed';
      step.duration_ms = Date.now() - start;
      logger.error(`[Agent:${this.name}] 异常:`, err.message);
      return { success: false, agent: this.name, error: err.message };
    }
  }
}

module.exports = { createContext, BaseAgent };
```

**Step 4 — 运行确认通过**：`npx jest test/agent-framework.test.js` → PASS（2 例）。

**Step 5 — 提交**：`git add server/agents/baseAgent.js server/test/agent-framework.test.js && git commit -m "feat(agents): Agent 基类与共享上下文"`。

---

#### Task A2: Agent 注册中心

**Files:**
- Create: `server/agents/registry.js`
- Modify: `server/test/agent-framework.test.js`（追加用例）

**Step 1 — 追加失败测试**（在 `agent-framework.test.js` 顶部 require registry）：

```js
const { createContext } = require('../agents/baseAgent');
const { registerAgent, getAgent, listAgents } = require('../agents/registry');

// 一个最小假 Agent 用于注册测试
const FakeAgent = require('../agents/baseAgent').BaseAgent;
class HelloAgent extends FakeAgent {
  constructor() { super('hello', '打招呼'); }
  async run(ctx) { ctx.set('hello', ctx.task); return { success: true, data: { echo: ctx.task } }; }
}

describe('Agent 框架 - 注册中心', () => {
  test('注册/获取/列表', () => {
    registerAgent(HelloAgent);
    expect(getAgent('hello').name).toBe('hello');
    const names = listAgents().map((a) => a.name);
    expect(names).toContain('hello');
  });
  test('重复注册抛错', () => {
    expect(() => registerAgent(HelloAgent)).toThrow(/已注册/);
  });
});
```

**Step 2 — 运行确认失败**：`npx jest test/agent-framework.test.js` → FAIL（module not found）。

**Step 3 — 实现 `server/agents/registry.js`**：

```js
/** Agent 注册中心：name → 构造类，供编排器路由 */
const agents = new Map();

function registerAgent(AgentClass, { override = false } = {}) {
  const name = new AgentClass().name;
  if (!override && agents.has(name)) throw new Error(`Agent 已注册: ${name}`);
  agents.set(name, AgentClass);
  return name;
}

function getAgent(name) {
  const Cls = agents.get(name);
  if (!Cls) throw new Error(`未知 Agent: ${name}`);
  return new Cls();
}

function listAgents() {
  return [...agents.entries()].map(([name, Cls]) => {
    const inst = new Cls();
    return { name, capability: inst.capability };
  });
}

module.exports = { registerAgent, getAgent, listAgents };
```

**Step 4 — 运行确认通过**：`npx jest test/agent-framework.test.js` → PASS（4 例）。

**Step 5 — 提交**：`git add server/agents/registry.js server/test/agent-framework.test.js && git commit -m "feat(agents): Agent 注册中心"`。

---

#### Task A3: 工具注册表（Tools 增强核心）

> 现有 `aiService.executeTool` 是巨型 switch（14 case）。本任务建立注册表，将工具迁移为"元数据 + handler"结构；`executeTool` 保留为转发壳（兼容红线），工具实现整体搬入 `server/agents/tools/`。

**Files:**
- Create: `server/agents/tools/registry.js`
- Create: `server/test/tools-registry.test.js`

**Step 1 — 写失败测试**（`server/test/tools-registry.test.js`）：

```js
const { registerTool, executeToolByName, listTools, resetTools } = require('../agents/tools/registry');

describe('工具注册表', () => {
  beforeEach(() => resetTools());

  test('注册/列表/按名执行', async () => {
    registerTool({
      name: 'echo',
      desc: '回显参数',
      params: ['text'],
      risk: 'low',
      handler: async (params) => ({ data: { text: params.text }, message: 'ok' })
    });
    const tools = listTools();
    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe('echo');
    const r = await executeToolByName('echo', { text: 'hi' });
    expect(r.success).toBe(true);
    expect(r.data.text).toBe('hi');
  });

  test('未知工具返回失败', async () => {
    const r = await executeToolByName('nope', {});
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/未知工具/);
  });

  test('重复注册抛错', () => {
    registerTool({ name: 'echo', handler: async () => ({}) });
    expect(() => registerTool({ name: 'echo', handler: async () => ({}) })).toThrow(/已注册/);
  });

  test('高危工具返回 risk 元数据（供前端展示）', () => {
    registerTool({ name: 'block_ip', risk: 'high', handler: async () => ({}) });
    expect(listTools().find((t) => t.name === 'block_ip').risk).toBe('high');
  });
});
```

**Step 2 — 运行确认失败**：`npx jest test/tools-registry.test.js` → FAIL。

**Step 3 — 实现 `server/agents/tools/registry.js`**：

```js
/**
 * 玄鉴安全智能体 - 工具注册表（Tools 增强核心）
 * 每个工具：{ name, desc, params[], risk: low|high, handler(params) }
 * handler 统一返回 { success?, data?, message? }；注册表负责异常兜底与审计。
 */
const logger = require('../../utils/logger');
const metrics = require('../../utils/metrics');

const tools = new Map();
const auditLogs = [];

function registerTool(spec, { override = false } = {}) {
  if (!spec || !spec.name || typeof spec.handler !== 'function') {
    throw new Error('工具注册失败：需要 name 与 handler');
  }
  if (!override && tools.has(spec.name)) throw new Error(`工具已注册: ${spec.name}`);
  tools.set(spec.name, {
    name: spec.name,
    desc: spec.desc || '',
    params: spec.params || [],
    risk: spec.risk || 'low',
    handler: spec.handler
  });
  return spec.name;
}

function listTools() {
  return [...tools.values()].map(({ handler, ...meta }) => meta);
}

function getTool(name) {
  return tools.get(name);
}

function resetTools() {
  tools.clear();
  auditLogs.length = 0;
}

/** 记录工具调用审计（含高危动作留痕） */
function recordAudit(tool, params, result) {
  auditLogs.push({
    tool: tool.name,
    params,
    success: result.success !== false,
    error: result.error || null,
    at: new Date().toISOString()
  });
  if (auditLogs.length > 200) auditLogs.shift();
}

function getAuditLogs() {
  return [...auditLogs];
}

/** 统一执行入口 */
async function executeToolByName(name, params = {}) {
  const tool = tools.get(name);
  if (!tool) {
    logger.warn(`[Tool] 未知工具: ${name}`);
    return { success: false, error: `未知工具: ${name}` };
  }
  metrics.inc('tool_calls_total', { tool: name }, 1, '工具调用次数');
  const start = Date.now();
  try {
    const result = await tool.handler(params || {});
    const normalized = { success: true, ...result };
    recordAudit(tool, params, normalized);
    metrics.observe('tool_execution_duration', { tool: name }, (Date.now() - start) / 1000, '工具执行耗时');
    return normalized;
  } catch (err) {
    logger.error(`[Tool:${name}] 执行异常:`, err.message);
    const failed = { success: false, error: err.message };
    recordAudit(tool, params, failed);
    return failed;
  }
}

module.exports = {
  registerTool,
  listTools,
  getTool,
  executeToolByName,
  resetTools,
  getAuditLogs
};
```

**Step 4 — 运行确认通过**：`npx jest test/tools-registry.test.js` → PASS（4 例）。

**Step 5 — 提交**：`git add server/agents/tools/registry.js server/test/tools-registry.test.js && git commit -m "feat(agents): 工具注册表（元数据+审计+指标）"`。

---

#### Task A4: 迁移现有 14 个工具到注册表

**Files:**
- Create: `server/agents/tools/intelTools.js`
- Create: `server/agents/tools/queryTools.js`
- Create: `server/agents/tools/actionTools.js`
- Create: `server/agents/tools/defenseTools.js`
- Create: `server/agents/tools/index.js`（一次性注册）
- Modify: `server/services/aiService.js`（executeTool 改为转发注册表）
- Modify: `server/test/tools-registry.test.js`（追加真实工具冒烟用例）

**Step 1 — 写失败测试**（追加到 `tools-registry.test.js`）：

```js
const { registerBuiltinTools } = require('../agents/tools');

describe('内置工具注册', () => {
  beforeAll(() => { resetTools(); registerBuiltinTools(); });

  test('注册 14+ 个内置工具', () => {
    const names = listTools().map((t) => t.name);
    expect(names).toContain('get_threat_intel');
    expect(names).toContain('get_alert_summary');
    expect(names).toContain('start_scan');
    expect(names).toContain('block_ip');
    expect(names.length).toBeGreaterThanOrEqual(14);
  });

  test('get_alert_summary 执行（shim 库）', async () => {
    const r = await executeToolByName('get_alert_summary', { limit: 3 });
    expect(r.success).toBe(true);
    expect(Array.isArray(r.data)).toBe(true);
  });
});
```

**Step 2 — 运行确认失败**：`npx jest test/tools-registry.test.js` → FAIL（module not found）。

**Step 3 — 实现工具文件**。从 [aiService.executeTool](file:///e:/迅雷下载/xuanjian-security-agent/server/services/aiService.js#L386) 逐 case 搬移，仅改 `db.all/run` 为通过 `getDb()` 获取（保持现有 shim 用法不变）。

`server/agents/tools/intelTools.js`（情报查询组，5 个工具）：

```js
/** 情报查询工具组：get_threat_intel / query_shodan / query_abuseipdb / query_virustotal / analyze_virus_hash */
const { registerTool } = require('./registry');
const { getDb } = require('../../db/database');

function registerIntelTools() {
  registerTool({
    name: 'get_threat_intel',
    desc: '多源威胁情报聚合查询',
    params: ['iocType', 'value'],
    risk: 'low',
    handler: async (params) => {
      const threatIntelligence = require('../../services/threatIntelligence');
      const result = await threatIntelligence.aggregateQuery(params.iocType, params.value);
      return {
        data: {
          riskLevel: result.riskLevel,
          riskScore: result.riskScore,
          sources: result.sources.map((s) => ({ source: s.source, verdict: s.verdict })),
          summary: result.summary
        },
        message: `多源威胁情报查询完成，风险等级: ${result.riskLevel}`
      };
    }
  });

  registerTool({
    name: 'query_shodan',
    desc: 'Shodan 查询 IP 开放端口',
    params: ['ip'],
    risk: 'low',
    handler: async (params) => {
      const threatIntelligence = require('../../services/threatIntelligence');
      const result = await threatIntelligence.queryShodan(params.ip);
      if (result.data) {
        return {
          data: {
            ip: result.data.ip, country: result.data.country, org: result.data.org,
            openPorts: result.data.openPorts, vulns: result.data.vulns, services: result.data.services
          },
          message: `Shodan查询完成，发现 ${result.data.openPorts.length} 个开放端口`
        };
      }
      return { data: null, message: 'Shodan未收录该IP信息' };
    }
  });

  registerTool({
    name: 'query_abuseipdb',
    desc: 'AbuseIPDB 滥用查询',
    params: ['ip'],
    risk: 'low',
    handler: async (params) => {
      const threatIntelligence = require('../../services/threatIntelligence');
      const result = await threatIntelligence.queryAbuseIPDB(params.ip);
      if (result.data) {
        return {
          data: {
            confidence: result.data.confidence, totalReports: result.data.totalReports,
            country: result.data.country, isp: result.data.isp, recentReports: result.data.reports
          },
          message: `AbuseIPDB查询完成，滥用置信度: ${result.data.confidence}%`
        };
      }
      return { data: null, message: 'AbuseIPDB未找到该IP报告' };
    }
  });

  registerTool({
    name: 'query_virustotal',
    desc: 'VirusTotal IOC 查询',
    params: ['iocType', 'value'],
    risk: 'low',
    handler: async (params) => {
      const threatIntelligence = require('../../services/threatIntelligence');
      const result = await threatIntelligence.queryVirusTotal(params.iocType, params.value);
      if (result.data) {
        return {
          data: {
            malicious: result.data.malicious, suspicious: result.data.suspicious,
            harmless: result.data.harmless, communityScore: result.data.communityScore, verdict: result.verdict
          },
          message: `VirusTotal查询完成，${result.data.malicious} 个引擎标记为恶意`
        };
      }
      return { data: null, message: 'VirusTotal未找到该IOC信息' };
    }
  });

  registerTool({
    name: 'analyze_virus_hash',
    desc: '文件哈希多源分析',
    params: ['hash'],
    risk: 'low',
    handler: async (params) => {
      const threatIntelligence = require('../../services/threatIntelligence');
      const [vt, tb] = await Promise.allSettled([
        threatIntelligence.queryVirusTotal('hash', params.hash),
        threatIntelligence.queryThreatBook('hash', params.hash)
      ]);
      const sources = [];
      if (vt.status === 'fulfilled') sources.push(vt.value);
      if (tb.status === 'fulfilled') sources.push(tb.value);
      return { data: { hash: params.hash, sources }, message: `文件哈希 ${params.hash} 分析完成` };
    }
  });
}

module.exports = { registerIntelTools };
```

`server/agents/tools/queryTools.js`（查询组，4 个工具）：

```js
/** 数据查询工具组：get_scan_results / get_alert_summary / get_baseline_results / analyze_alerts */
const { registerTool } = require('./registry');
const { getDb } = require('../../db/database');

function registerQueryTools() {
  registerTool({
    name: 'get_scan_results',
    desc: '获取端口扫描结果',
    params: ['task_id'],
    risk: 'low',
    handler: async (params) => {
      const db = getDb();
      const results = db.all('SELECT * FROM scan_results WHERE task_id = ?', [params.task_id]);
      return { data: results, message: `找到 ${results.length} 条扫描结果` };
    }
  });

  registerTool({
    name: 'get_alert_summary',
    desc: '获取安全告警摘要',
    params: ['severity', 'limit'],
    risk: 'low',
    handler: async (params) => {
      const db = getDb();
      let query = 'SELECT * FROM alert_records';
      const qp = [];
      if (params.severity) { query += ' WHERE severity = ?'; qp.push(params.severity); }
      query += ' ORDER BY created_at DESC LIMIT ?';
      qp.push(params.limit || 10);
      const results = db.all(query, qp);
      return { data: results, message: `找到 ${results.length} 条告警` };
    }
  });

  registerTool({
    name: 'get_baseline_results',
    desc: '获取基线检查结果',
    params: ['task_id'],
    risk: 'low',
    handler: async (params) => {
      const db = getDb();
      const results = db.all('SELECT * FROM baseline_results WHERE task_id = ?', [params.task_id]);
      return { data: results, message: `找到 ${results.length} 条基线检查结果` };
    }
  });

  registerTool({
    name: 'analyze_alerts',
    desc: '分析安全告警并给出研判',
    params: ['severity', 'limit'],
    risk: 'low',
    handler: async (params) => {
      const db = getDb();
      const alerts = db.all('SELECT * FROM alert_records ORDER BY created_at DESC LIMIT ?', [params.limit || 20]);
      const aiService = require('../../services/aiService');
      const result = await aiService.analyzeAlerts(alerts);
      return { data: result.content, message: '告警分析完成' };
    }
  });
}

module.exports = { registerQueryTools };
```

`server/agents/tools/actionTools.js`（动作组，3 个工具）：

```js
/** 业务动作工具组：start_scan / generate_security_report / scan_file_with_ai */
const { registerTool } = require('./registry');
const { getDb } = require('../../db/database');

function registerActionTools() {
  registerTool({
    name: 'start_scan',
    desc: '发起 TCP 端口扫描',
    params: ['target_cidr', 'port_range', 'created_by'],
    risk: 'low',
    handler: async (params) => {
      if (!params.target_cidr || !params.port_range) {
        return { success: false, error: '缺少 target_cidr / port_range 参数' };
      }
      const scanService = require('../../services/scanService');
      const task = await scanService.startScan({
        target_cidr: params.target_cidr,
        port_range: params.port_range,
        scan_mode: 'tcp_connect',
        created_by: params.created_by || 1
      });
      return { data: task, message: `扫描任务已创建: ${task.task_id}` };
    }
  });

  registerTool({
    name: 'generate_security_report',
    desc: '生成安全报告',
    params: ['type'],
    risk: 'low',
    handler: async (params) => {
      const aiService = require('../../services/aiService');
      const report = await aiService.generateSecurityReport(aiService.getDashboardData(), params.type || 'daily');
      return { data: report, message: '安全报告生成完成' };
    }
  });

  registerTool({
    name: 'scan_file_with_ai',
    desc: '文件 AI 分析（多引擎结果汇总）',
    params: ['fileHash', 'fileName', 'engineResults'],
    risk: 'low',
    handler: async (params) => {
      const summary = Object.values(params.engineResults || {})
        .map((e) => `${e.engine}: ${e.verdict} (置信度${(e.confidence * 100).toFixed(0)}%) - ${e.detail}`)
        .join('\n');
      return { data: { fileHash: params.fileHash, fileName: params.fileName, summary }, message: '文件AI分析完成' };
    }
  });
}

module.exports = { registerActionTools };
```

`server/agents/tools/defenseTools.js`（防御组，2 个现有 + 2 个新增）：

```js
/** 防御动作工具组：block_ip / account_lock / search_knowledge / run_playbook */
const { registerTool } = require('./registry');
const { getDb } = require('../../db/database');

function registerDefenseTools() {
  registerTool({
    name: 'block_ip',
    desc: '封禁恶意 IP（高危，需人工确认）',
    params: ['ip', 'duration'],
    risk: 'high',
    handler: async (params) => {
      const { ip, duration = 3600 } = params;
      if (!ip) return { success: false, error: '缺少 ip 参数' };
      const db = getDb();
      db.prepare('INSERT INTO action_logs (policy_id, action_type, action_detail, result) VALUES (?, ?, ?, ?)')
        .run(null, 'block_ip', `人工确认后封禁 IP ${ip}，时长 ${duration}s`, 'success');
      db.prepare('INSERT INTO alert_records (related_asset, alert_type, severity, confidence, description, status) VALUES (?, ?, ?, ?, ?, ?)')
        .run(ip, 'manual_block', 'high', 1.0, `人工确认封禁恶意 IP ${ip}（时长 ${duration}s）`, 'new');
      return { data: { ip, duration, action: 'blocked' }, message: `已封禁 IP ${ip}` };
    }
  });

  registerTool({
    name: 'account_lock',
    desc: '锁定被入侵账号（高危，需人工确认）',
    params: ['username'],
    risk: 'high',
    handler: async (params) => {
      const { username } = params;
      if (!username) return { success: false, error: '缺少 username 参数' };
      const db = getDb();
      db.prepare('INSERT INTO action_logs (policy_id, action_type, action_detail, result) VALUES (?, ?, ?, ?)')
        .run(null, 'account_lock', `人工确认后锁定账号 ${username}`, 'success');
      db.prepare('INSERT INTO alert_records (related_asset, alert_type, severity, confidence, description, status) VALUES (?, ?, ?, ?, ?, ?)')
        .run(username, 'account_locked', 'high', 1.0, `人工确认锁定被入侵账号 ${username}`, 'new');
      return { data: { username, action: 'locked' }, message: `已锁定账号 ${username}` };
    }
  });

  // ---- Tools 增强：新增 2 个工具 ----
  registerTool({
    name: 'search_knowledge',
    desc: '知识库 RAG 检索（处置建议参考）',
    params: ['query', 'top_k'],
    risk: 'low',
    handler: async (params) => {
      const aiService = require('../../services/aiService');
      const results = await aiService.searchKnowledge(params.query, params.top_k || 5);
      return { data: results, message: `知识库检索到 ${results.length} 条相关条目` };
    }
  });

  registerTool({
    name: 'run_playbook',
    desc: '执行 SOAR 剧本',
    params: ['playbook_id', 'event'],
    risk: 'high',
    handler: async (params) => {
      const playbookService = require('../../services/playbookService');
      const result = await playbookService.execute(params.playbook_id, params.event || {}, { userId: params.userId });
      return { data: result, message: '剧本执行完成' };
    }
  });
}

module.exports = { registerDefenseTools };
```

`server/agents/tools/index.js`：

```js
/** 内置工具一次性注册入口 */
const { resetTools } = require('./registry');
const { registerIntelTools } = require('./intelTools');
const { registerQueryTools } = require('./queryTools');
const { registerActionTools } = require('./actionTools');
const { registerDefenseTools } = require('./defenseTools');

let registered = false;
function registerBuiltinTools({ force = false } = {}) {
  if (registered && !force) return;
  if (force) resetTools();
  registerIntelTools();
  registerQueryTools();
  registerActionTools();
  registerDefenseTools();
  registered = true;
}

module.exports = { registerBuiltinTools };
```

**Step 4 — 改造 `aiService.executeTool` 为转发壳**（保持 `executeTool` 名称与导出不变，switch 主体删除，改为调注册表）。在 [aiService.js#L386](file:///e:/迅雷下载/xuanjian-security-agent/server/services/aiService.js#L386) 的 `executeTool` 函数体整体替换为：

```js
async function executeTool(toolName, params) {
  // 兼容壳：转发到工具注册表（N-25 Task A4）
  const { executeToolByName } = require('../agents/tools/registry');
  const { registerBuiltinTools } = require('../agents/tools');
  registerBuiltinTools();
  return executeToolByName(toolName, params);
}
```

同时确保 `aiService` 导出仍含 `getDashboardData`（若被外部引用则补充导出；当前 [exports](file:///e:/迅雷下载/xuanjian-security-agent/server/services/aiService.js#L1293) 已含 `executeTool`）。

**Step 5 — 运行确认通过**：`npx jest test/tools-registry.test.js test/agentService.test.js` → 全 PASS。

**Step 6 — 全量回归**：`cd server && npx jest --silent --forceExit` → 14 suites / 87+ tests 全绿（原有 87 例 + 新增）。

**Step 7 — 提交**：`git add server/agents/tools server/services/aiService.js server/test/tools-registry.test.js && git commit -m "refactor(agents): executeTool 迁移至工具注册表"`。

---

#### Task A5: 七类具体 Agent 实现

**Files:**
- Create: `server/agents/agents/plannerAgent.js`
- Create: `server/agents/agents/executorAgent.js`
- Create: `server/agents/agents/analystAgent.js`
- Create: `server/agents/agents/intelAgent.js`
- Create: `server/agents/agents/reporterAgent.js`
- Create: `server/agents/agents/scanAgent.js`
- Create: `server/agents/agents/defenseAgent.js`
- Create: `server/agents/agents/index.js`
- Modify: `server/test/agent-framework.test.js`（追加编排集成用例）

**Step 1 — 写失败测试**（追加到 `agent-framework.test.js`）：

```js
const { registerAgents } = require('../agents/agents');
const { registerBuiltinTools } = require('../agents/tools');
const { getAgent } = require('../agents/registry');

beforeAll(() => {
  registerAgents();
  registerBuiltinTools({ force: true });
});

test('PlannerAgent 规则回退计划按任务分类', async () => {
  const ctx = createContext('分析内网资产风险', { userId: 1 });
  const r = await getAgent('planner').execute(ctx);
  expect(r.success).toBe(true);
  expect(r.data.steps[0].tool).toBe('start_scan');
  expect(ctx.get('plan')).toBeTruthy();
});

test('ExecutorAgent 顺序执行工具并合并 task_id', async () => {
  const ctx = createContext('扫描并查询结果');
  ctx.set('plan', { goal: '扫描', steps: [
    { tool: 'start_scan', params: { target_cidr: '127.0.0.1', port_range: '3000-3000' }, reason: 'x' },
    { tool: 'get_scan_results', params: {}, reason: 'y' }
  ]});
  const r = await getAgent('executor').execute(ctx);
  expect(r.success).toBe(true);
  expect(r.data.results).toHaveLength(2);
  expect(ctx.get('task_id')).toBeTruthy();
}, 20000);

test('DefenseAgent 高危工具生成人工确认请求', async () => {
  const ctx = createContext('封禁IP');
  ctx.set('plan', { steps: [{ tool: 'block_ip', params: { ip: '1.2.3.4' }, reason: 'x' }] });
  const r = await getAgent('defense').execute(ctx);
  expect(r.success).toBe(true);
  expect(r.data.confirmation_required).toBe(true);
});
```

**Step 2 — 运行确认失败**：`npx jest test/agent-framework.test.js` → FAIL。

**Step 3 — 实现各 Agent**。

`server/agents/agents/plannerAgent.js`：

```js
/** 规划 Agent：LLM 生成计划，失败规则回退（复用 agentService 规划逻辑） */
const { BaseAgent } = require('../baseAgent');

class PlannerAgent extends BaseAgent {
  constructor() { super('planner', '任务拆解与执行计划生成'); }
  async run(ctx) {
    const agentService = require('../../services/agentService');
    let plan;
    try {
      plan = await agentService.planWithLLM(ctx.task);
    } catch (err) {
      plan = agentService.buildFallbackPlan(ctx.task);
    }
    ctx.set('plan', plan);
    return { success: true, data: plan, message: `生成 ${plan.steps.length} 步计划` };
  }
}
module.exports = PlannerAgent;
```

`server/agents/agents/executorAgent.js`：

```js
/** 执行 Agent：按计划逐步调用工具注册表，中间结果注入，失败重试 1 次 */
const { BaseAgent } = require('../baseAgent');
const { executeToolByName } = require('../tools/registry');
const MAX_STEPS = 6;
const MAX_EXECUTION_MS = 120000;

class ExecutorAgent extends BaseAgent {
  constructor() { super('executor', '按计划逐步执行工具'); }
  async run(ctx) {
    const plan = ctx.get('plan') || { steps: [] };
    const start = Date.now();
    const results = [];
    for (const step of plan.steps.slice(0, MAX_STEPS)) {
      if (Date.now() - start > MAX_EXECUTION_MS) {
        results.push({ tool: step.tool, success: false, error: 'Agent 执行超时，已中止' });
        break;
      }
      const params = { ...step.params };
      if (ctx.has('task_id') && params.task_id === undefined &&
          ['get_scan_results', 'get_baseline_results'].includes(step.tool)) {
        params.task_id = ctx.get('task_id');
      }
      if (step.tool === 'start_scan' && !params.created_by) params.created_by = ctx.userId || 1;
      let result = await executeToolByName(step.tool, params);
      let attempt = 1;
      while (!result.success && attempt < 2) {
        attempt++;
        result = await executeToolByName(step.tool, params);
      }
      if (result.data && result.data.task_id) ctx.set('task_id', result.data.task_id);
      results.push({ tool: step.tool, params: step.params, reason: step.reason, ...result });
    }
    ctx.set('results', results);
    return { success: true, data: { results }, message: `执行 ${results.length} 个步骤` };
  }
}
module.exports = ExecutorAgent;
```

`server/agents/agents/analystAgent.js`：

```js
/** 研判 Agent：告警聚合去重 + 根因推断 + 处置建议（复用 copilotService 逻辑） */
const { BaseAgent } = require('../baseAgent');
const { getDb } = require('../../db/database');

class AnalystAgent extends BaseAgent {
  constructor() { super('analyst', '安全告警研判与根因分析'); }
  async run(ctx) {
    const copilotService = require('../../services/copilotService');
    const limit = ctx.get('limit') || 50;
    const result = await copilotService.triageAlerts(limit);
    ctx.set('triage', result);
    return { success: true, data: result, message: `研判 ${result.groups ? result.groups.length : 0} 组告警` };
  }
}
module.exports = AnalystAgent;
```

`server/agents/agents/intelAgent.js`：

```js
/** 情报 Agent：威胁情报多源聚合 */
const { BaseAgent } = require('../baseAgent');
const { executeToolByName } = require('../tools/registry');

class IntelAgent extends BaseAgent {
  constructor() { super('intel', '威胁情报查询与关联'); }
  async run(ctx) {
    const iocType = ctx.get('ioc_type') || 'ip';
    const value = ctx.get('ioc_value') || '185.220.101.34';
    const result = await executeToolByName('get_threat_intel', { iocType, value });
    ctx.set('intel', result.data);
    return result;
  }
}
module.exports = IntelAgent;
```

`server/agents/agents/reporterAgent.js`：

```js
/** 报告 Agent：生成安全报告（daily/weekly/monthly） */
const { BaseAgent } = require('../baseAgent');
const { executeToolByName } = require('../tools/registry');

class ReporterAgent extends BaseAgent {
  constructor() { super('reporter', '安全报告生成'); }
  async run(ctx) {
    const type = ctx.get('report_type') || 'daily';
    const result = await executeToolByName('generate_security_report', { type });
    ctx.set('report', result.data);
    return result;
  }
}
module.exports = ReporterAgent;
```

`server/agents/agents/scanAgent.js`：

```js
/** 扫描 Agent：发起扫描任务并查询结果 */
const { BaseAgent } = require('../baseAgent');
const { executeToolByName } = require('../tools/registry');

class ScanAgent extends BaseAgent {
  constructor() { super('scan', '网络资产扫描'); }
  async run(ctx) {
    const target = ctx.get('target_cidr') || '127.0.0.1';
    const ports = ctx.get('port_range') || '1-1024';
    const task = await executeToolByName('start_scan', { target_cidr: target, port_range: ports, created_by: ctx.userId || 1 });
    if (task.data && task.data.task_id) ctx.set('task_id', task.data.task_id);
    return task;
  }
}
module.exports = ScanAgent;
```

`server/agents/agents/defenseAgent.js`：

```js
/** 防御 Agent：高危动作 + 人工确认（approve/reject） */
const { BaseAgent } = require('../baseAgent');
const { randomUUID } = require('crypto');
const { executeToolByName } = require('../tools/registry');
const { listTools } = require('../tools/registry');

const HIGH_RISK_TOOLS = new Set(['block_ip', 'account_lock', 'delete_scan_task', 'delete_user', 'disable_policy', 'run_playbook']);
const pendingConfirmations = new Map();

class DefenseAgent extends BaseAgent {
  constructor() { super('defense', '防御动作执行与人工确认'); }
  async run(ctx) {
    const plan = ctx.get('plan') || { steps: [] };
    const confirmations = [];
    for (const step of plan.steps) {
      if (HIGH_RISK_TOOLS.has(step.tool)) {
        const id = `cfm_${randomUUID().slice(0, 8)}`;
        pendingConfirmations.set(id, {
          id, taskId: ctx.runId, tool: step.tool, params: step.params,
          reason: step.reason, status: 'pending', createdAt: new Date().toISOString()
        });
        confirmations.push({ tool: step.tool, confirmation_id: id, require_confirmation: true });
        break; // 高危动作暂停后续步骤，等待人工确认
      }
      const result = await executeToolByName(step.tool, step.params);
      confirmations.push({ tool: step.tool, ...result });
    }
    ctx.set('confirmations', confirmations);
    return {
      success: true,
      data: { confirmations, confirmation_required: confirmations.some((c) => c.require_confirmation) },
      message: `处理 ${confirmations.length} 个防御动作`
    };
  }
}

/** 人工确认审批（兼容 agentService.confirmExecution 语义） */
async function confirmExecution(confirmationId, decision) {
  const record = pendingConfirmations.get(confirmationId);
  if (!record) return { success: false, error: '确认请求不存在或已过期' };
  if (record.status !== 'pending') return { success: false, error: '该请求已处理' };
  if (decision !== 'approve') {
    record.status = 'rejected';
    record.reviewedAt = new Date().toISOString();
    return { success: true, data: { confirmation_id: confirmationId, status: 'rejected', message: '已拒绝执行' } };
  }
  record.status = 'approved';
  record.reviewedAt = new Date().toISOString();
  const result = await executeToolByName(record.tool, record.params);
  return { success: true, data: { confirmation_id: confirmationId, status: 'approved', result } };
}

function getPendingConfirmations() {
  return [...pendingConfirmations.values()].filter((r) => r.status === 'pending');
}

module.exports = { DefenseAgent, confirmExecution, getPendingConfirmations, HIGH_RISK_TOOLS };
```

`server/agents/agents/index.js`：

```js
/** 注册全部业务 Agent */
const { registerAgent } = require('../registry');
const PlannerAgent = require('./plannerAgent');
const ExecutorAgent = require('./executorAgent');
const AnalystAgent = require('./analystAgent');
const IntelAgent = require('./intelAgent');
const ReporterAgent = require('./reporterAgent');
const ScanAgent = require('./scanAgent');
const { DefenseAgent } = require('./defenseAgent');

function registerAgents() {
  registerAgent(PlannerAgent);
  registerAgent(ExecutorAgent);
  registerAgent(AnalystAgent);
  registerAgent(IntelAgent);
  registerAgent(ReporterAgent);
  registerAgent(ScanAgent);
  registerAgent(DefenseAgent);
}
module.exports = { registerAgents };
```

> 注：planner/executor/analyst/intel/reporter/scan 各文件为默认导出（`module.exports = PlannerAgent`），index.js 使用默认导入；defenseAgent 为命名导出（`module.exports = { DefenseAgent, ... }`），使用解构导入。

**Step 4 — 运行确认通过**：`npx jest test/agent-framework.test.js` → PASS。

**Step 5 — 提交**：`git add server/agents/agents server/test/agent-framework.test.js && git commit -m "feat(agents): 七类业务 Agent 实现"`。

---

#### Task A6: 编排器 + agentService 兼容壳

**Files:**
- Create: `server/agents/orchestrator.js`
- Modify: `server/services/agentService.js`（转调编排器，保持导出不变）
- Modify: `server/test/agentService.test.js`（原 7 用例即回归用例，不动）

**Step 1 — 写失败测试**（追加到 `agent-framework.test.js`）：

```js
const { runOrchestratedAgent } = require('../agents/orchestrator');

test('Orchestrator 端到端：规划→执行→总结', async () => {
  const result = await runOrchestratedAgent('分析内网资产风险', { userId: 1, plan: null });
  expect(result.success).toBe(true);
  expect(result.plan).toBeTruthy();
  expect(Array.isArray(result.results)).toBe(true);
  expect(result.summary).toBeTruthy();
}, 30000);

test('Orchestrator 注入计划时跳过 LLM 规划', async () => {
  const result = await runOrchestratedAgent('扫描', {
    userId: 1,
    plan: { goal: 'x', steps: [{ tool: 'get_alert_summary', params: { limit: 3 }, reason: 'r' }] }
  });
  expect(result.success).toBe(true);
  expect(result.results[0].tool).toBe('get_alert_summary');
});
```

**Step 2 — 运行确认失败**：`npx jest test/agent-framework.test.js` → FAIL。

**Step 3 — 实现 `server/agents/orchestrator.js`**：

```js
/**
 * 编排器：多 Agent 调度核心
 * 流程：解析任务 → 路由角色 → 按序执行（planner → [analyst/intel/scan] → reporter）
 *      → 高危动作交给 defense → 汇总 → 总结（LLM/模板）
 */
const { createContext } = require('./baseAgent');
const { getAgent } = require('./registry');
const { registerAgents } = require('./agents');
const { registerBuiltinTools } = require('./tools');
const { getPendingConfirmations, confirmExecution } = require('./agents/defenseAgent');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

registerAgents();
registerBuiltinTools();

/** 任务 → 角色路由表（关键词 → Agent 顺序） */
const ROUTES = [
  { match: /告警|研判|分析告警|root cause/i, agents: ['analyst'] },
  { match: /情报|威胁|IOC|ioc|哈希|hash/i, agents: ['intel'] },
  { match: /扫描|资产|端口/i, agents: ['scan'] },
  { match: /报告|周报|月报|日报/i, agents: ['reporter'] }
];
const DEFAULT_ROUTE = ['planner', 'executor'];

/** 汇总总结（LLM → 模板） */
async function summarize(task, plan, results) {
  const aiService = require('../services/aiService');
  const executed = (results || []).filter((r) => r && r.success);
  if (!executed.length) return '任务执行失败，未能产出有效结果。';
  const digest = JSON.stringify(executed.map((r) => ({
    step: r.tool,
    summary: r.data ? (typeof r.data === 'object' ? JSON.stringify(r.data).substring(0, 1200) : String(r.data)) : (r.message || '')
  }))).substring(0, 6000);
  try {
    const resp = await aiService.callDeepSeek([
      { role: 'system', content: '你是安全运营智能体。基于以下各步骤执行结果，输出结构化中文总结：关键发现、风险判断、建议措施。不编造数据。' },
      { role: 'user', content: `任务：${task}\n执行结果：\n${digest}` }
    ], { temperature: 0.3, maxTokens: 2000 });
    const content = resp.data?.choices?.[0]?.message?.content;
    if (content) return content;
  } catch (err) {
    logger.warn(`[Orchestrator] LLM 总结失败，使用模板: ${err.message}`);
  }
  const lines = executed.map((r) => `- ${r.tool}: ${r.message || (r.data ? JSON.stringify(r.data).substring(0, 120) : '完成')}`);
  return `## 任务执行总结\n\n**任务**: ${task}\n\n已执行 ${executed.length} 个步骤：\n${lines.join('\n')}\n\n> 注：LLM 总结不可用，以上为规则汇总。`;
}

async function runOrchestratedAgent(task, opts = {}) {
  const start = Date.now();
  metrics.inc('agent_runs_total', {}, 1, 'Agent 执行次数');
  const ctx = createContext(task, { userId: opts.userId });

  // 1. 规划：注入计划 或 PlannerAgent（LLM → 规则回退）
  let plan;
  if (opts.plan) {
    const { _normalizePlan } = require('../services/agentService');
    plan = _normalizePlan(opts.plan);
    ctx.set('plan', plan);
  } else {
    const planner = getAgent('planner');
    const r = await planner.execute(ctx);
    if (!r.success) return { success: false, error: '无法生成执行计划', plan: null };
    plan = ctx.get('plan');
  }
  if (!plan || !plan.steps.length) return { success: false, error: '无法为任务生成可执行计划', plan };

  // 2. 执行：ExecutorAgent 仅执行非高危步骤（高危步骤留待 defense 人工确认）
  const { HIGH_RISK_TOOLS } = require('./agents/defenseAgent');
  const safeSteps = plan.steps.filter((s) => !HIGH_RISK_TOOLS.has(s.tool));
  const executor = getAgent('executor');
  ctx.set('plan', { ...plan, steps: safeSteps });
  const execResult = await executor.execute(ctx);
  const results = (ctx.get('results') || []).map((r) => ({
    tool: r.tool, params: r.params, reason: r.reason, ...r
  }));

  // 3. 角色补充：按路由执行专属 Agent（analyst/intel/scan/reporter 可叠加）
  for (const route of ROUTES) {
    if (route.match.test(task)) {
      for (const agentName of route.agents) {
        const agent = getAgent(agentName);
        const r = await agent.execute(ctx);
        if (r.success) results.push({ tool: agentName, success: true, data: r.data, message: r.message });
      }
    }
  }

  // 4. 高危动作：DefenseAgent 基于完整计划生成人工确认（暂停后续步骤，等待人工确认）
  ctx.set('plan', plan);
  const defense = getAgent('defense');
  const defenseResult = await defense.execute(ctx);
  const confirmations = (ctx.get('confirmations') || []).filter((c) => c.require_confirmation);
  if (confirmations.length) {
    results.push(...confirmations.map((c) => ({
      tool: c.tool, success: false, require_confirmation: true, confirmation_id: c.confirmation_id
    })));
  }

  // 5. 总结
  const summary = await summarize(task, plan, results);
  metrics.observe('agent_execution_duration', {}, (Date.now() - start) / 1000, 'Agent 执行耗时', { unit: 'seconds' });

  return {
    success: true,
    task_id: ctx.runId,
    plan,
    results,
    summary,
    confirmation_required: results.some((r) => r.require_confirmation),
    duration_ms: Date.now() - start
  };
}

module.exports = { runOrchestratedAgent, getPendingConfirmations, confirmExecution };
```

> 实现要点（A6 实测修正）：
> 1. `agents/agents/index.js` 的 `registerAgents()` 增加 `registered` 幂等标志（与 tools/index.js 一致），避免 orchestrator 顶层注册与测试 beforeAll 重复注册冲突。
> 2. `agentService.js` 原 `module.exports` **不含 `_normalizePlan`**，需补加导出（orchestrator 注入计划路径依赖）。
> 3. **高危语义回归修复**：ExecutorAgent 会无条件执行计划中全部工具，绕过人工确认直接执行 `block_ip`/`account_lock`（导致原 agentService 高危用例失败）。orchestrator 步骤 2 仅对"过滤高危后的 safeSteps"执行，步骤 4 恢复完整 plan 交给 defense 生成确认，对齐原 `runAgent`"高危即暂停等待确认"语义。

**Step 4 — 改造 `agentService.js` 为兼容壳**：保留全部导出签名，`runAgent`/`confirmExecution`/`getPendingConfirmations` 转调编排器；`planWithLLM`/`buildFallbackPlan`/`_normalizePlan`/`AGENT_TOOL_CATALOG`/`HIGH_RISK_TOOLS` 保留供编排器与外部引用。

替换 [runAgent](file:///e:/迅雷下载/xuanjian-security-agent/server/services/agentService.js#L174) 函数体：

```js
async function runAgent(task, opts = {}) {
  const { runOrchestratedAgent } = require('../agents/orchestrator');
  return runOrchestratedAgent(task, opts);
}

async function confirmExecution(confirmationId, decision) {
  const { confirmExecution: orchestratedConfirm } = require('../agents/orchestrator');
  return orchestratedConfirm(confirmationId, decision);
}

function getPendingConfirmations() {
  const { getPendingConfirmations: getOrchestrated } = require('../agents/orchestrator');
  return getOrchestrated();
}
```

（文件顶部原有 `planWithLLM`/`buildFallbackPlan`/`_normalizePlan`/`AGENT_TOOL_CATALOG`/`HIGH_RISK_TOOLS` 定义与导出保持不变。）

**Step 5 — 运行确认通过**：`npx jest test/agent-framework.test.js test/agentService.test.js` → 全 PASS（编排器 2 例 + 原 7 例）。

**Step 6 — 全量回归**：`cd server && npx jest --silent --forceExit` → 全绿。启动冒烟：`node server.js` 后 `curl POST /api/ai/agent/run` 验证接口兼容。

**Step 7 — 提交**：`git add server/agents/orchestrator.js server/services/agentService.js server/test/agent-framework.test.js && git commit -m "feat(agents): 编排器 + agentService 兼容壳"`。

---

#### Task A7: 编排过程接口（前端工作台数据源）

**Files:**
- Modify: `server/routes/ai.js`（新增 `GET /api/ai/agent/tools`、`GET /api/ai/agent/plan`，供 React 工作台展示）
- Modify: `server/test/api.test.js`（追加 2 个接口冒烟用例）

**Step 1 — 写失败测试**（追加到 `api.test.js`）：

```js
test('GET /api/ai/agent/tools 返回工具目录', async () => {
  const res = await request(app).get('/api/ai/agent/tools');
  expect(res.status).toBe(200);
  expect(res.body.data).toBeInstanceOf(Array);
  const names = res.body.data.map((t) => t.name);
  expect(names).toContain('block_ip');
});
```

**Step 2 — 运行确认失败**：`npx jest test/api.test.js` → FAIL（404）。

**Step 3 — 实现路由**（追加到 `routes/ai.js`，Agent 段之后）：

```js
/* ---------------- 多 Agent 工作台数据（N-25） ---------------- */

router.get('/agent/tools', async (req, res) => {
  try {
    const { listTools } = require('../agents/tools/registry');
    const { registerBuiltinTools } = require('../agents/tools');
    registerBuiltinTools();
    res.json({ code: 0, message: '获取成功', data: listTools() });
  } catch (err) {
    res.status(500).json({ code: -1, message: '获取工具目录失败' });
  }
});

router.get('/agent/plan', async (req, res) => {
  try {
    // 计划解析预览：不入库、不执行，供前端先渲染步骤
    const { task } = req.query;
    if (!task) return res.status(400).json({ code: -1, message: '缺少 task 参数' });
    const agentService = require('../services/agentService');
    let plan;
    try {
      plan = await agentService.planWithLLM(String(task));
    } catch (err) {
      plan = agentService.buildFallbackPlan(String(task));
    }
    res.json({ code: 0, message: '计划生成成功', data: plan });
  } catch (err) {
    res.status(500).json({ code: -1, message: '计划生成失败' });
  }
});
```

**Step 4 — 运行确认通过**：`npx jest test/api.test.js` → PASS。

**Step 5 — 提交**：`git add server/routes/ai.js server/test/api.test.js && git commit -m "feat(agents): 工作台工具目录与计划预览接口"`。

**Phase A 验收**：`npx jest --silent --forceExit` 全绿（≥89 例）；手工 curl 三接口（run/confirm/pending/tools/plan）正常。

---

### Phase B 工具能力增强（面向场景补工具）

#### Task B1: 防御工具真实化 + 审计增强

**Files:**
- Modify: `server/agents/tools/defenseTools.js`（block_ip/account_lock 增加审计日志落库 + 权限提示）
- Modify: `server/test/tools-registry.test.js`（追加审计断言）

**Step 1 — 写失败测试**：

```js
test('高危工具执行后产生审计记录', async () => {
  resetTools(); registerBuiltinTools();
  const r = await executeToolByName('block_ip', { ip: '10.0.0.1' });
  expect(r.success).toBe(true);
  const logs = getAuditLogs();
  expect(logs.some((l) => l.tool === 'block_ip' && l.success)).toBe(true);
});
```

**Step 2 — 运行确认失败**：当前 `block_ip` 已走注册表，但 `getAuditLogs` 由注册表记录 —— 该用例可能已通过（前置行为）。若已通过则补强：断言 `listTools().find(t=>t.name==='block_ip').risk === 'high'`。执行前先确认失败点：`npx jest test/tools-registry.test.js`。

**Step 3 — 增强 `defenseTools.js`**：高危工具 handler 内补充 `audit_logs` 表落库（与 action_logs 并列），并返回 `risk: 'high'` 提示：

```js
// block_ip handler 内（account_lock 同理）：
db.prepare('INSERT INTO audit_logs (user_id, username, operation_type, operation_target, operation_detail, result) VALUES (?, ?, ?, ?, ?, ?)')
  .run(params.userId || null, params.username || 'agent', 'defense_action', `ip:${ip}`, `block_ip ${ip} duration=${duration}s`, 'success');
```

**Step 4 — 运行确认通过**：`npx jest test/tools-registry.test.js` → PASS。

**Step 5 — 提交**：`git add server/agents/tools/defenseTools.js server/test/tools-registry.test.js && git commit -m "feat(agents): 防御工具审计落库"`。

---

#### Task B2: 工具目录验证（与 Agent 工作台联动）

**Files:**
- Modify: `server/agents/agents/index.js`（校验注册完整性）
- Modify: `server/test/agent-framework.test.js`（追加断言：所有 AGENT_TOOL_CATALOG 中的工具均已注册）

**Step 1 — 写失败测试**：

```js
test('AGENT_TOOL_CATALOG 全部工具已注册到工具表', () => {
  const { AGENT_TOOL_CATALOG } = require('../services/agentService');
  const names = listTools().map((t) => t.name);
  for (const t of AGENT_TOOL_CATALOG) {
    expect(names).toContain(t.name);
  }
});
```

**Step 2 — 运行确认失败**：`npx jest test/agent-framework.test.js` → FAIL（catalog 含 `start_scan`/`get_threat_intel` 等已注册，但需确认全部命中；若 `get_alert_summary` 等缺失则失败）。

**Step 3 — 修正**：确保 `registerBuiltinTools` 在测试 `beforeAll` 执行；若 catalog 中的工具缺注册，在对应 tools 文件补齐。

**Step 4 — 运行确认通过**：全 PASS。

**Step 5 — 提交**：`git add server/agents server/test/agent-framework.test.js && git commit -m "test(agents): 工具目录完整性校验"`。

**Phase B 验收**：工具目录 ≥ 16 个；`GET /api/ai/agent/tools` 返回完整元数据（name/desc/params/risk）；防御工具审计双落库。

---

### Phase C React 前端工程初始化

> 全量迁移 14 个页面 + 新增 Agent 工作台。React 工程独立于 Vue 版，静态托管按构建产物切换。

#### Task C1: 工程脚手架

**Files:**
- Create: `frontend-react/`（Vite + React 18 + TS + Tailwind + shadcn/ui + Zustand + React Router 6 + Axios）

**Step 1 — 初始化**（命令）：

```powershell
cd e:\迅雷下载\xuanjian-security-agent
npx create-vite@latest frontend-react --template react-ts
cd frontend-react
npm install
npm install zustand react-router-dom@6 axios
npm install -D tailwindcss @tailwindcss/vite
npx shadcn@latest init -d
npx shadcn@latest add button card input dialog table badge toast tabs separator skeleton
```

> 注：若 shadcn CLI 交互受阻，可手动创建 `src/components/ui/*`（按钮/卡片/输入框/弹窗/表格/徽章/Toast/选项卡），不依赖 CLI。

**Step 2 — 配置 Vite 代理**（`frontend-react/vite.config.ts`）：

```ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': new URL('./src', import.meta.url).pathname } },
  server: {
    port: 5174,
    proxy: {
      '/api': { target: 'http://localhost:3000', changeOrigin: true },
      '/ws': { target: 'ws://localhost:3000', ws: true }
    }
  },
  build: { outDir: 'dist', chunkSizeWarningLimit: 1024 }
});
```

**Step 3 — 基础入口**（`src/main.tsx` / `src/App.tsx` 最小可运行：空路由 + Login 占位）。

**Step 4 — 验证**：`npm run build` 成功；`npm run dev` 访问 `http://localhost:5174` 显示占位页。

**Step 5 — 提交**：`git add frontend-react && git commit -m "feat(react): 工程脚手架（Vite+React18+TS+Tailwind）"`。

---

#### Task C2: 基础设施层（http / auth store / ws / layout / router）

**Files:**
- Create: `frontend-react/src/api/http.ts`
- Create: `frontend-react/src/api/index.ts`
- Create: `frontend-react/src/stores/user.ts`
- Create: `frontend-react/src/stores/ws.ts`
- Create: `frontend-react/src/layouts/MainLayout.tsx`
- Create: `frontend-react/src/router/index.tsx`
- Create: `frontend-react/src/pages/Login.tsx`
- Modify: `frontend-react/src/App.tsx`

**Step 1 — 写失败测试**（React 侧无 Jest 环境时，用 `npm run build` + 类型检查作为门禁；逻辑测试留给 Phase D）：

```bash
cd frontend-react && npm run build
```

**Step 2 — 实现 `src/api/http.ts`**（对照 [frontend-app/src/api/http.ts](file:///e:/迅雷下载/xuanjian-security-agent/frontend-app/src/api/http.ts)）：

```ts
import axios, { type AxiosInstance, type AxiosRequestConfig } from 'axios';
import { useUserStore } from '@/stores/user';
import { toast } from '@/components/ui/use-toast';

export interface ApiResponse<T = unknown> { code: number; message: string; data: T; }

const http: AxiosInstance = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' }
});

http.interceptors.request.use((config) => {
  const token = useUserStore.getState().token;
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

http.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    if (status === 401) { useUserStore.getState().logout(false); window.location.href = '/login'; }
    else if (status === 403) toast({ title: '权限不足', variant: 'destructive' });
    else if (status === 429) toast({ title: '操作过于频繁', variant: 'destructive' });
    else if (status >= 500) toast({ title: '服务器内部错误', variant: 'destructive' });
    return Promise.reject(error);
  }
);

export async function request<T = unknown>(config: AxiosRequestConfig): Promise<ApiResponse<T>> {
  const resp = await http.request<ApiResponse<T>>(config);
  return resp.data;
}
export async function requestData<T = unknown>(config: AxiosRequestConfig): Promise<T> {
  const resp = await http.request<ApiResponse<T>>(config);
  if (resp.data.code === 0) return resp.data.data;
  throw new Error(resp.data.message || '请求失败');
}
```

**Step 3 — 实现 `src/stores/user.ts`**（Zustand）：

```ts
import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { authApi } from '@/api';

export interface UserInfo {
  id: number; username: string; role_id: number; org_id: number;
  department?: string; role_name?: string; org_name?: string;
}

interface UserState {
  token: string | null;
  user: UserInfo | null;
  login: (username: string, password: string) => Promise<void>;
  fetchProfile: () => Promise<void>;
  logout: (redirect?: boolean) => void;
}

export const useUserStore = create<UserState>()(
  persist(
    (set, get) => ({
      token: null,
      user: null,
      async login(username, password) {
        const data = await authApi.login(username, password);
        set({ token: data.token });
        await get().fetchProfile();
      },
      async fetchProfile() {
        const user = await authApi.profile();
        set({ user });
      },
      logout(redirect = true) {
        set({ token: null, user: null });
        if (redirect) window.location.href = '/login';
      }
    }),
    { name: 'xuanjian-react-user' }
  )
);
```

**Step 4 — 实现 `src/api/index.ts`**（对照 Vue 版 [api/index.ts](file:///e:/迅雷下载/xuanjian-security-agent/frontend-app/src/api/index.ts)，全量复制 15 个模块：authApi/scanApi/baselineApi/virusApi/situationalApi/djppApi/defenseApi/deviceApi/userApi/playbookApi/configApi/reportsApi/aiApi + 新增 agentApi）：

```ts
// Agent 工作台 API（新增）
export const agentApi = {
  run: (task: string) => requestData<any>({ method: 'POST', url: '/ai/agent/run', data: { task } }),
  confirm: (confirmation_id: string, decision: string) =>
    requestData<any>({ method: 'POST', url: '/ai/agent/confirm', data: { confirmation_id, decision } }),
  pending: () => requestData<any[]>({ method: 'GET', url: '/ai/agent/pending' }),
  tools: () => requestData<any[]>({ method: 'GET', url: '/ai/agent/tools' }),
  plan: (task: string) => requestData<any>({ method: 'GET', url: '/ai/agent/plan', params: { task } })
};
```

（其余 14 个模块逐一从 Vue 版复制，函数签名一致。）

**Step 5 — 实现 `src/router/index.tsx` + `MainLayout.tsx` + `Login.tsx`**：

```tsx
import { createBrowserRouter, Navigate, Outlet } from 'react-router-dom';
import MainLayout from '@/layouts/MainLayout';
import Login from '@/pages/Login';
import { useUserStore } from '@/stores/user';

function RequireAuth() {
  const token = useUserStore((s) => s.token);
  return token ? <Outlet /> : <Navigate to="/login" replace />;
}

export const router = createBrowserRouter([
  { path: '/login', element: <Login /> },
  {
    path: '/',
    element: <RequireAuth />,
    children: [{ path: '/', element: <MainLayout />, children: [
      // 后续 Task 逐一挂载 14 个页面
    ] }]
  }
]);
```

`MainLayout.tsx`：左侧导航（14 菜单 + Agent 工作台），顶栏用户信息/登出，`<Outlet />` 内容区。样式用 Tailwind + shadcn（sidebar 可自绘或引入 shadcn sheet）。

**Step 6 — 验证**：`npm run build` 通过；dev 登录后可跳转布局页。

**Step 7 — 提交**：`git add frontend-react/src && git commit -m "feat(react): 基础设施（http/认证/WS/布局/路由）"`。

---

#### Task C3-C10: 14 个页面迁移（分批，每批 2 页）

> 每页对照 Vue 版 `frontend-app/src/views/<Name>.vue` 迁移：模板 → TSX 组件，script 逻辑 → hooks/组件内逻辑，Element Plus 组件 → shadcn/ui 等价物（表格→Table，弹窗→Dialog，表单→Form，图表→ECharts-for-React）。

**页面分批**（每批提交一次，验收标准：页面功能与 Vue 版一致，接口复用同一 `api/index.ts`）：

| 批 | 页面 | Vue 源文件 | 要点 |
|----|------|-----------|------|
| C3 | Login / AgentWorkbench | Login.vue /（新增） | 登录；工作台：任务输入→`/ai/agent/plan` 预览→`/ai/agent/run` 执行→步骤列表+逐步结果+高危确认弹窗→`/ai/agent/pending` 轮询 |
| C4 | Dashboard / Situational | Dashboard.vue / Situational.vue | ECharts 图表（使用 echarts-for-react 或 echarts 直接渲染） |
| C5 | Scan / Baseline | Scan.vue / Baseline.vue | 表格 + 表单 + 进度 |
| C6 | Virus / Djpp | Virus.vue / Djpp.vue | 上传 + 结果表格；任务/结果联动 |
| C7 | Assistant / Defense | Assistant.vue / Defense.vue | 聊天流（含格式化防 XSS）；策略/审批表格 |
| C8 | Device / Users | Device.vue / Users.vue | 设备表格 + WS 实时状态；用户 CRUD |
| C9 | Playbook / Config | Playbook.vue / Config.vue | SOAR 编辑（步骤 JSON）；配置键值表 |
| C10 | Reports | Reports.vue | 报告列表/生成/导出 |

**Agent 工作台（C3 重点新增页）** `src/pages/AgentWorkbench.tsx` 核心交互（示意）：

```tsx
import { useState } from 'react';
import { agentApi } from '@/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle
} from '@/components/ui/dialog';
import { toast } from '@/components/ui/use-toast';

export default function AgentWorkbench() {
  const [task, setTask] = useState('');
  const [running, setRunning] = useState(false);
  const [plan, setPlan] = useState<any>(null);
  const [result, setResult] = useState<any>(null);
  const [pendingConfirm, setPendingConfirm] = useState<any>(null);

  const previewPlan = async () => {
    if (!task.trim()) return;
    const p = await agentApi.plan(task);
    setPlan(p);
  };

  const run = async () => {
    setRunning(true);
    try {
      const r = await agentApi.run(task);
      setResult(r);
      const confirm = r.results?.find((x: any) => x.require_confirmation);
      if (confirm) setPendingConfirm(confirm);
      else toast({ title: '执行完成', description: r.summary });
    } finally { setRunning(false); }
  };

  const confirmDecision = async (decision: string) => {
    if (!pendingConfirm) return;
    await agentApi.confirm(pendingConfirm.confirmation_id, decision);
    setPendingConfirm(null);
    toast({ title: decision === 'approve' ? '已批准执行' : '已拒绝' });
    run(); // 重新拉取最终结果
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader><CardTitle>多 Agent 安全任务工作台</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          <Textarea value={task} onChange={(e) => setTask(e.target.value)}
            placeholder="输入自然语言安全任务，如：分析内网资产风险" rows={3} />
          <div className="flex gap-2">
            <Button variant="outline" onClick={previewPlan} disabled={running}>预览计划</Button>
            <Button onClick={run} disabled={running || !task.trim()}>{running ? '执行中…' : '执行任务'}</Button>
          </div>
        </CardContent>
      </Card>

      {plan && <Card><CardHeader><CardTitle>执行计划</CardTitle></CardHeader>
        <CardContent>{plan.steps?.map((s: any, i: number) => (
          <div key={i} className="border-l-2 pl-3 py-1">第{i + 1}步：{s.tool}（{s.reason}）</div>
        ))}</CardContent></Card>}

      {result && <Card><CardHeader><CardTitle>执行结果</CardTitle></CardHeader>
        <CardContent>
          {result.results?.map((r: any, i: number) => (
            <div key={i} className="py-1">
              {r.tool}：{r.success ? '成功' : r.require_confirmation ? '等待人工确认' : `失败: ${r.error}`}
              {r.data && <pre className="text-xs mt-1 max-h-40 overflow-auto">{JSON.stringify(r.data, null, 2)}</pre>}
            </div>
          ))}
          <div className="mt-3 whitespace-pre-wrap text-sm">{result.summary}</div>
        </CardContent></Card>}

      <Dialog open={!!pendingConfirm} onOpenChange={() => setPendingConfirm(null)}>
        <DialogContent>
          <DialogHeader><DialogTitle>高危动作需要人工确认</DialogTitle></DialogHeader>
          <p>工具：{pendingConfirm?.tool}</p>
          <DialogFooter>
            <Button variant="destructive" onClick={() => confirmDecision('reject')}>拒绝</Button>
            <Button onClick={() => confirmDecision('approve')}>批准执行</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
```

**每批验收**：`npm run build` 通过；dev 环境人工验证页面与 Vue 版行为一致；提交 `feat(react): 迁移 <页面> 页`。

---

#### Task C11: WebSocket 前端封装

**Files:**
- Create: `frontend-react/src/stores/ws.ts`

**Step 1 — 实现**（对照 Vue 版 [ws.ts](file:///e:/迅雷下载/xuanjian-security-agent/frontend-app/src/utils/ws.ts)：重连、心跳、消息路由）：

```ts
import { create } from 'zustand';

interface WsState {
  connected: boolean;
  lastMessage: Record<string, any> | null;
  connect: () => void;
}

let ws: WebSocket | null = null;
let retry = 0;

export const useWsStore = create<WsState>((set) => ({
  connected: false,
  lastMessage: null,
  connect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws/frontend`);
    ws.onopen = () => { set({ connected: true }); retry = 0; };
    ws.onmessage = (e) => {
      try { set({ lastMessage: JSON.parse(e.data) }); } catch { /* 非 JSON 忽略 */ }
    };
    ws.onclose = () => {
      set({ connected: false });
      setTimeout(() => useWsStore.getState().connect(), Math.min(1000 * 2 ** retry++, 30000));
    };
  }
}));
```

**Step 2 — 验证**：`npm run build` 通过；dev 中 Dashboard/Device 订阅告警与设备状态。

**Step 3 — 提交**：`git add frontend-react/src/stores/ws.ts && git commit -m "feat(react): WebSocket 封装（重连+心跳）"`。

---

#### Task C12: 构建产物接入后端静态托管

**Files:**
- Modify: `server/server.js`（静态托管优先 `frontend-react/dist`）

**Step 1 — 修改** [server.js#L85-L90](file:///e:/迅雷下载/xuanjian-security-agent/server/server.js#L85-L90)：

```js
// 静态资源优先使用 React 构建产物（frontend-react/dist），缺失时回退 frontend-app/dist，再回退旧版 frontend/
const envFrontend = process.env.FRONTEND_DIR; // 显式指定前端目录
const reactDist = path.join(__dirname, '../frontend-react/dist');
const frontendDist = path.join(__dirname, '../frontend-app/dist');
const legacyFrontend = path.join(__dirname, '../frontend');
const staticDir = envFrontend
  ? path.resolve(process.cwd(), envFrontend)
  : [reactDist, frontendDist, legacyFrontend].find((d) => require('fs').existsSync(d));
app.use(express.static(staticDir));
```

**Step 2 — 验证**：构建 `frontend-react` 后启动 server，浏览器访问 `/` 命中 React 应用；删掉 `frontend-react/dist` 后回退 Vue 版。

**Step 3 — 提交**：`git add server/server.js && git commit -m "feat(server): 静态托管支持 React 构建产物"`。

**Phase C 验收**：`frontend-react` 14 页 + Agent 工作台功能对齐 Vue 版；`npm run build` 0 错误；后端 `/` 托管 React 产物，`FRONTEND_DIR` 可切换。

---

### Phase D 工程化与质量门禁

#### Task D1: React 工程 ESLint + Prettier + TS 门禁

**Files:**
- Create: `frontend-react/eslint.config.js`、`.prettierrc.json`
- Modify: `frontend-react/package.json`（scripts）

**Step 1 — 配置**（对照 Vue 版 [eslint.config.js](file:///e:/迅雷下载/xuanjian-security-agent/frontend-app/eslint.config.js)）：

```json
// package.json scripts 追加
"lint": "eslint . --ext .ts,.tsx",
"lint:fix": "eslint . --ext .ts,.tsx --fix",
"format": "prettier --write \"src/**/*.{ts,tsx,css}\"",
"format:check": "prettier --check \"src/**/*.{ts,tsx,css}\"",
"type-check": "tsc --noEmit"
```

**Step 2 — 验证**：`npm run lint` 0 errors；`npm run format:check` 通过；`npm run type-check` 通过。

**Step 3 — 提交**：`git add frontend-react && git commit -m "chore(react): ESLint+Prettier+类型检查门禁"`。

---

#### Task D2: CI 增加 React 构建 job

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1 — 修改**（对照现有 `frontend-build` job 新增 `react-build`）：

```yaml
  react-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: npm, cache-dependency-path: frontend-react/package-lock.json }
      - run: npm ci
        working-directory: frontend-react
      - run: npm run type-check
        working-directory: frontend-react
      - run: npm run lint
        working-directory: frontend-react
      - run: npm run build
        working-directory: frontend-react
```

**Step 2 — 验证**：本地跑通等价命令；提交后 CI 全绿。

**Step 3 — 提交**：`git add .github/workflows/ci.yml && git commit -m "ci: React 构建与质量门禁"`。

---

#### Task D3: 端到端冒烟 + 文档更新

**Files:**
- Modify: `README.md`、`ROADMAP.md`

**Step 1 — 端到端冒烟**：

```bash
# 后端（server）
cd server && npx jest --silent --forceExit   # ≥91 用例全绿
npm audit                                    # 0 漏洞
# 前端（React）
cd ../frontend-react && npm run build        # 0 错误
# 手工：登录 → Agent 工作台 → 输入任务 → 预览计划 → 执行 → 高危确认
```

**Step 2 — 文档更新**：README 增"前端（React 版）"启动说明与架构示意；ROADMAP 增 **Phase 6 Multi-Agent 编排 + React 前端** 归档小节（勾选 A1-A7/B1-B2/C1-C12/D1-D3 清单）。

**Step 3 — 提交**：`git add README.md ROADMAP.md && git commit -m "docs: 架构改造归档（Phase 6）"`。

---

## 五、风险矩阵

| # | 风险 | 等级 | 缓解 |
|---|------|------|------|
| R1 | executeTool 重构回归（87 用例） | 高 | 兼容壳转发 + A4 后立即全量回归；工具 handler 逐 case 搬移不改语义 |
| R2 | agentService 兼容壳破坏现有前端/测试 | 高 | 导出签名完全不变；A6 后跑 agentService.test.js 7 例 + api.test.js |
| R3 | 编排器结果结构偏离原 runAgent 返回 | 中 | 返回字段（plan/results/summary/confirmation_required/duration_ms/task_id）与原结构逐字段对齐 |
| R4 | React 全量迁移量大导致拖期 | 中 | 分 8 批每批 2 页，页面对照 Vue 源文件迁移，接口复用同一 api/index.ts |
| R5 | shadcn CLI 网络/交互受阻 | 低 | 手动创建 ui 组件，不依赖 CLI |
| R6 | 双前端静态托管冲突 | 中 | 优先级 react → vue → legacy，`FRONTEND_DIR` 显式覆盖；dist 目录互不冲突 |
| R7 | 高危工具审计重复（action_logs + audit_logs） | 低 | 明确职责：action_logs=业务动作，audit_logs=审计留痕，测试断言双表落库 |

## 六、回滚方案

- 每 Task 独立提交，可 `git revert` 单点回滚。
- Agent 框架回滚：`git revert` A6 提交后 `agentService.js` 恢复原实现（编排器文件保留不引用）。
- React 回滚：删除/忽略 `frontend-react/dist`，server 自动回退 `frontend-app/dist`；`FRONTEND_DIR` 指回 Vue 产物。

## 七、里程碑

| 里程碑 | 范围 | 验收要点 |
|--------|------|----------|
| M1 | Phase A（A1-A7） | 多 Agent 框架落地，agentService 兼容壳，≥89 Jest 用例全绿，三接口回归 |
| M2 | Phase B（B1-B2） | 工具目录 ≥16 个，防御审计双落库，tools 接口可用 |
| M3 | Phase C（C1-C12） | React 14 页 + Agent 工作台功能对齐，构建 0 错误，静态托管切换 |
| M4 | Phase D（D1-D3） | lint/type-check/build 门禁 + CI job + 冒烟全绿 + 文档归档 |
