const { getDb, resetForTest, closeDb } = require('../db/database');
const playbookService = require('../services/playbookService');

describe('SOAR 剧本引擎（playbookService）', () => {
  beforeEach(() => {
    resetForTest();
  });

  afterAll(() => {
    closeDb();
  });

  test('模板导入幂等', () => {
    const first = playbookService.seedTemplates();
    expect(first).toBe(3);
    const second = playbookService.seedTemplates();
    expect(second).toBe(0);
    const db = getDb();
    expect(db.prepare('SELECT * FROM playbooks').all().length).toBe(3);
  });

  test('条件评估各运算符', () => {
    expect(playbookService.evaluateCondition({ fact: 'fail_count', operator: 'gt', value: 5 }, { fail_count: 8 })).toBe(true);
    expect(playbookService.evaluateCondition({ fact: 'fail_count', operator: 'gt', value: 5 }, { fail_count: 3 })).toBe(false);
    expect(playbookService.evaluateCondition({ fact: 'severity', operator: 'eq', value: 'critical' }, { severity: 'critical' })).toBe(true);
    expect(playbookService.evaluateCondition({ fact: 'confidence', operator: 'gte', value: 0.85 }, { confidence: 0.9 })).toBe(true);
    expect(playbookService.evaluateCondition({ fact: 'type', operator: 'contains', value: 'brute' }, { type: 'brute_force' })).toBe(true);
  });

  test('参数模板替换', () => {
    const out = playbookService.replaceTokens(
      { ip: '{{ip}}', duration: 3600 },
      { ip: '1.2.3.4' }
    );
    expect(out).toEqual({ ip: '1.2.3.4', duration: 3600 });
  });

  test('执行剧本：条件满足 → 动作 → 通知', async () => {
    const db = getDb();
    const { id } = playbookService.createPlaybook({
      name: '测试剧本',
      trigger: 'manual',
      steps: [
        { type: 'condition', name: '失败次数', fact: 'fail_count', operator: 'gt', value: 5 },
        { type: 'action', name: '封禁', action: 'firewall_block', params: { ip: '{{ip}}', duration: 1800 } }
      ]
    }, 1);

    const result = await playbookService.execute(id, { ip: '10.0.0.66', fail_count: 9 }, 1);
    expect(result.success).toBe(true);
    expect(result.status).toBe('completed');
    expect(result.results[0].ok).toBe(true);
    expect(result.results[1].success).toBe(true);

    // 动作已落库：action_logs + alert_records
    const logs = db.prepare("SELECT * FROM action_logs WHERE action_type = 'firewall_block'").all();
    expect(logs.length).toBe(1);
    expect(logs[0].action_detail).toContain('10.0.0.66');
    const alerts = db.prepare("SELECT * FROM alert_records WHERE alert_type = 'soar_block'").all();
    expect(alerts.length).toBe(1);
  });

  test('执行剧本：条件不满足则跳过后续动作', async () => {
    const db = getDb();
    const { id } = playbookService.createPlaybook({
      name: '跳过测试',
      steps: [
        { type: 'condition', fact: 'fail_count', operator: 'gt', value: 5 },
        { type: 'action', action: 'firewall_block', params: { ip: '10.0.0.1' } }
      ]
    }, 1);

    const result = await playbookService.execute(id, { fail_count: 2 }, 1);
    expect(result.status).toBe('skipped');
    expect(result.results[0].ok).toBe(false);
    expect(db.prepare("SELECT * FROM action_logs WHERE action_type = 'firewall_block'").all().length).toBe(0);
  });

  test('审批步骤挂起剧本，批准后继续执行', async () => {
    const db = getDb();
    const { id } = playbookService.createPlaybook({
      name: '审批剧本',
      steps: [
        { type: 'approval', name: '隔离审批', title: '确认隔离' },
        { type: 'action', name: '记录', action: 'log_only', params: { message: '隔离已执行' } }
      ]
    }, 1);

    const result = await playbookService.execute(id, {}, 1);
    expect(result.status).toBe('awaiting_approval');
    const approvalId = result.results[0].approval_id;

    // 待审批列表可见
    expect(playbookService.getPendingApprovals().some((a) => a.id === approvalId)).toBe(true);

    // 批准后异步继续执行剩余步骤
    const approved = await playbookService.confirmApproval(approvalId, 'approve', 1);
    expect(approved.success).toBe(true);
    expect(approved.data.status).toBe('approved');

    // 等待异步后续执行完成
    const deadline = Date.now() + 3000;
    while (Date.now() < deadline) {
      const runs = db.prepare("SELECT * FROM action_logs WHERE action_type = 'playbook_run'").all();
      if (runs.length >= 2) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    expect(db.prepare("SELECT * FROM action_logs WHERE action_type = 'playbook_run'").all().length).toBeGreaterThanOrEqual(2);
  });

  test('审批拒绝不执行后续动作', async () => {
    const db = getDb();
    const { id } = playbookService.createPlaybook({
      name: '拒绝剧本',
      steps: [
        { type: 'approval', title: '确认' },
        { type: 'action', action: 'log_only', params: { message: '不应执行' } }
      ]
    }, 1);
    const result = await playbookService.execute(id, {}, 1);
    const approvalId = result.results[0].approval_id;

    const rejected = await playbookService.confirmApproval(approvalId, 'reject', 1);
    expect(rejected.data.status).toBe('rejected');
    await new Promise((r) => setTimeout(r, 200));
    const runs = db.prepare("SELECT * FROM action_logs WHERE action_type = 'playbook_run'").all();
    expect(runs.length).toBe(1); // 只有执行时的运行日志
  });

  test('剧本 CRUD', () => {
    const { id } = playbookService.createPlaybook({ name: 'CRUD测试', steps: [] }, 1);
    expect(id).toBeTruthy();

    playbookService.updatePlaybook(id, { name: 'CRUD改名', enabled: 0 });
    const updated = playbookService.getPlaybook(id);
    expect(updated.name).toBe('CRUD改名');
    expect(Number(updated.enabled)).toBe(0);

    const r = playbookService.deletePlaybook(id);
    expect(r.changes).toBe(1);
    expect(playbookService.getPlaybook(id)).toBeNull();
  });
});
