const { createContext } = require('../agents/baseAgent');
const { registerAgent, getAgent, listAgents } = require('../agents/registry');
const { registerAgents } = require('../agents/agents');
const { registerBuiltinTools } = require('../agents/tools');
const { listTools } = require('../agents/tools/registry');
const { runOrchestratedAgent } = require('../agents/orchestrator');

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

describe('工具目录完整性（B2）', () => {
  test('AGENT_TOOL_CATALOG 全部工具已注册到工具表', () => {
    const { AGENT_TOOL_CATALOG } = require('../services/agentService');
    const names = listTools().map((t) => t.name);
    for (const t of AGENT_TOOL_CATALOG) {
      expect(names).toContain(t.name);
    }
  });
});
