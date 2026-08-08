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
