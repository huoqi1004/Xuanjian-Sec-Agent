const { getDb, resetForTest, closeDb } = require('../db/database');
const { runAgent, confirmExecution, getPendingConfirmations, buildFallbackPlan } = require('../services/agentService');

describe('多步规划 Agent（agentService）', () => {
  beforeEach(() => {
    resetForTest();
  });

  afterAll(() => {
    closeDb();
  });

  test('规则回退计划按任务分类', () => {
    const riskPlan = buildFallbackPlan('分析内网资产风险');
    expect(riskPlan.steps[0].tool).toBe('start_scan');

    const alertPlan = buildFallbackPlan('告警研判一下');
    expect(alertPlan.steps[0].tool).toBe('get_alert_summary');

    const intelPlan = buildFallbackPlan('查询威胁情报 185.220.101.34');
    expect(intelPlan.steps[0].tool).toBe('get_threat_intel');
  });

  test('执行注入计划并生成总结', async () => {
    const result = await runAgent('汇总当前安全状态', {
      plan: { goal: '汇总告警', steps: [{ tool: 'get_alert_summary', params: {}, reason: '拉取告警' }] }
    });
    expect(result.success).toBe(true);
    expect(result.plan.steps).toHaveLength(1);
    expect(result.results).toHaveLength(1);
    expect(result.results[0].tool).toBe('get_alert_summary');
    expect(result.results[0].success).toBe(true);
    expect(result.summary).toContain('任务执行总结');
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });

  test('高危动作触发人工确认并暂停', async () => {
    const result = await runAgent('封禁恶意 IP', {
      plan: { steps: [{ tool: 'block_ip', params: { ip: '185.220.101.34', duration: 3600 }, reason: '封禁已知恶意IP' }] }
    });
    expect(result.success).toBe(true);
    expect(result.confirmation_required).toBe(true);
    expect(result.results[0].require_confirmation).toBe(true);

    const pending = getPendingConfirmations();
    expect(pending.some((p) => p.id === result.results[0].confirmation_id)).toBe(true);
  });

  test('人工批准后执行高危动作并落审计', async () => {
    const result = await runAgent('封禁恶意 IP', {
      plan: { steps: [{ tool: 'block_ip', params: { ip: '1.2.3.4', duration: 3600 }, reason: '测试' }] }
    });
    const confirmationId = result.results[0].confirmation_id;

    const approved = await confirmExecution(confirmationId, 'approve');
    expect(approved.success).toBe(true);
    expect(approved.data.status).toBe('approved');
    expect(approved.data.result.success).toBe(true);

    const db = getDb();
    const logs = db.prepare("SELECT * FROM action_logs WHERE action_type = 'block_ip'").all();
    expect(logs.length).toBe(1);
    expect(logs[0].action_detail).toContain('1.2.3.4');
  });

  test('人工拒绝后不执行高危动作', async () => {
    const result = await runAgent('锁定账号', {
      plan: { steps: [{ tool: 'account_lock', params: { username: 'attacker' }, reason: '测试' }] }
    });
    const confirmationId = result.results[0].confirmation_id;

    const rejected = await confirmExecution(confirmationId, 'reject');
    expect(rejected.success).toBe(true);
    expect(rejected.data.status).toBe('rejected');

    const db = getDb();
    expect(db.prepare("SELECT * FROM action_logs WHERE action_type = 'account_lock'").all().length).toBe(0);
  });

  test('中间结果合并：start_scan 的 task_id 注入 get_scan_results', async () => {
    const result = await runAgent('扫描本机并查看结果', {
      plan: {
        steps: [
          { tool: 'start_scan', params: { target_cidr: '127.0.0.1', port_range: '3000-3000' }, reason: '扫描' },
          { tool: 'get_scan_results', params: {}, reason: '查看结果' }
        ]
      }
    });
    expect(result.success).toBe(true);
    const scanStep = result.results[0];
    const resultsStep = result.results[1];
    expect(scanStep.success).toBe(true);
    expect(scanStep.data.task_id).toBeTruthy();
    expect(resultsStep.success).toBe(true);
    // 自动注入的 task_id 与扫描任务一致
    const db = getDb();
    const task = db.prepare('SELECT * FROM scan_tasks WHERE id = ?').get(scanStep.data.task_id);
    expect(task).toBeTruthy();
  }, 20000);

  test('未知工具的计划步骤被过滤', async () => {
    const result = await runAgent('测试', {
      plan: { steps: [{ tool: 'not_a_tool', params: {}, reason: 'x' }, { tool: 'get_alert_summary', params: {}, reason: 'y' }] }
    });
    expect(result.plan.steps).toHaveLength(1);
    expect(result.plan.steps[0].tool).toBe('get_alert_summary');
  });
});
