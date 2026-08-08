const { registerTool, executeToolByName, listTools, resetTools, getAuditLogs } = require('../agents/tools/registry');
const { registerBuiltinTools } = require('../agents/tools');

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

describe('高危工具审计增强（B1）', () => {
  beforeAll(() => { resetTools(); registerBuiltinTools({ force: true }); });

  test('block_ip 执行后产生审计记录', async () => {
    const r = await executeToolByName('block_ip', { ip: '10.0.0.1' });
    expect(r.success).toBe(true);
    const logs = getAuditLogs();
    expect(logs.some((l) => l.tool === 'block_ip' && l.success)).toBe(true);
  });

  test('高危工具元数据含 risk=high', () => {
    const tool = listTools().find((t) => t.name === 'block_ip');
    expect(tool.risk).toBe('high');
  });

  test('block_ip 写入 audit_logs 表（双落库）', () => {
    const db = require('../db/database').getDb();
    const rows = db.all("SELECT * FROM audit_logs WHERE operation_type = 'defense_action' ORDER BY id DESC");
    expect(rows.some((row) => row.operation_target && row.operation_target.includes('10.0.0.1'))).toBe(true);
  });
});
