const { getDb, resetForTest, closeDb } = require('../db/database');
const { triageAlerts, groupAlerts, inferRootCause } = require('../services/copilotService');

describe('Copilot 告警研判（copilotService）', () => {
  beforeEach(() => {
    resetForTest();
  });

  afterAll(() => {
    closeDb();
  });

  function seedAlerts(db, rows) {
    const stmt = db.prepare(
      'INSERT INTO alert_records (related_asset, alert_type, severity, confidence, description, status) VALUES (?, ?, ?, ?, ?, ?)'
    );
    for (const r of rows) {
      stmt.run(r[0], r[1], r[2], r[3], r[4], r[5] || 'new');
    }
  }

  test('无新告警时返回空研判', async () => {
    const result = await triageAlerts();
    expect(result.source_count).toBe(0);
    expect(result.groups).toEqual([]);
    expect(result.findings).toEqual([]);
  });

  test('按资产聚合去重', () => {
    const db = getDb();
    seedAlerts(db, [
      ['192.168.1.10', 'intel_match', 'high', 0.9, '情报驱动告警', 'new'],
      ['192.168.1.10', 'brute_force', 'high', 0.8, 'SSH暴力破解', 'new'],
      ['10.0.0.50', 'intel_match', 'medium', 0.6, '情报驱动告警', 'new']
    ]);
    const alerts = db.prepare("SELECT * FROM alert_records WHERE status = 'new'").all();
    const groups = groupAlerts(alerts);
    expect(groups).toHaveLength(2);
    const g1 = groups.find((g) => g.asset === '192.168.1.10');
    expect(g1.count).toBe(2);
  });

  test('根因推断识别攻击链特征', () => {
    const db = getDb();
    seedAlerts(db, [
      ['web-01', 'intel_match', 'critical', 0.95, '情报驱动告警', 'new'],
      ['web-01', 'brute_force', 'high', 0.9, 'SSH暴力破解', 'new'],
      ['web-01', 'account_locked', 'high', 0.8, '账号锁定', 'new']
    ]);
    const alerts = db.prepare("SELECT * FROM alert_records WHERE status = 'new'").all();
    const findings = inferRootCause(groupAlerts(alerts));
    expect(findings.length).toBeGreaterThan(0);
    // 命中已知情报 + 暴力破解+账号 → 至少一条根因
    expect(findings.some((f) => f.inference.includes('已知威胁情报'))).toBe(true);
  });

  test('triageAlerts 全流程返回研判结果', async () => {
    const db = getDb();
    seedAlerts(db, [
      ['192.168.1.100', 'intel_match', 'high', 0.92, '命中已知恶意IP', 'new'],
      ['192.168.1.100', 'brute_force', 'high', 0.85, 'SSH爆破', 'new'],
      ['192.168.1.100', 'login_success', 'medium', 0.5, '异常登录成功', 'new']
    ]);

    const result = await triageAlerts(50);
    expect(result.source_count).toBe(3);
    expect(result.groups).toHaveLength(1);
    expect(result.groups[0].asset).toBe('192.168.1.100');
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.recommendations.length).toBe(result.findings.length);
    for (const rec of result.recommendations) {
      expect(rec.recommendation).toBeTruthy();
    }
  });
});
