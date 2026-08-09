const { runAction } = require('../services/adapters');
const { getDb } = require('../db/database');

describe('SIEM Webhook 适配器（N-23D）', () => {
  test('dry-run 模拟推送并落审计', async () => {
    const r = await runAction('siem_webhook', { url: 'https://siem.example.com/hce', action: 'block_ip', ip: '10.0.0.5', dry_run: true });
    expect(r.success).toBe(true);
    expect(r.dry_run).toBe(true);
    expect(r.event.src_ip).toBe('10.0.0.5');
    const db = getDb();
    expect(db.prepare("SELECT * FROM action_logs WHERE action_type = 'siem_webhook'").all().length).toBeGreaterThan(0);
  });

  test('缺少 url 返回失败', async () => {
    const r = await runAction('siem_webhook', { action: 'x' });
    expect(r.success).toBe(false);
  });

  test('真实推送失败（不可达 url）返回失败并落审计', async () => {
    const r = await runAction('siem_webhook', { url: 'http://127.0.0.1:1/none', action: 'test' });
    expect(r.success).toBe(false);
    const db = getDb();
    expect(db.prepare("SELECT * FROM action_logs WHERE action_type = 'siem_webhook' AND result = 'failed'").all().length).toBeGreaterThan(0);
  });
});
