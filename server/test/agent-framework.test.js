const { createContext } = require('../agents/baseAgent');
const { registerAgent, getAgent, listAgents } = require('../agents/registry');

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
