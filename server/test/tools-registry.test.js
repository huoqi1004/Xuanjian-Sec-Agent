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
