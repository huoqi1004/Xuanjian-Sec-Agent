const { renderCommands, switchAclBlock, switchAclUnblock } = require('../services/adapters/switchAcl');
const { runAction } = require('../services/adapters');
const { getDb } = require('../db/database');

describe('交换机 ACL 适配器（N-23B）', () => {
  test('renderCommands 华为模板替换 IP', () => {
    const cmds = renderCommands('huawei', 'block', '10.1.2.3');
    expect(cmds.some((c) => c.includes('rule deny ip source 10.1.2.3 0'))).toBe(true);
  });

  test('renderCommands 未知 vendor 回退华为', () => {
    const cmds = renderCommands('unknown_vendor', 'unblock', '10.1.2.3');
    expect(cmds.some((c) => c.includes('undo rule deny ip source 10.1.2.3 0'))).toBe(true);
  });

  test('dry-run 模拟封禁并落审计', async () => {
    const r = await switchAclBlock({ ip: '10.1.2.3', vendor: 'huawei', dry_run: true });
    expect(r.success).toBe(true);
    expect(r.dry_run).toBe(true);
    const db = getDb();
    const logs = db.prepare("SELECT * FROM action_logs WHERE action_type = 'switch_acl_block'").all();
    expect(logs.some((l) => l.action_detail.includes('10.1.2.3'))).toBe(true);
  });

  test('runAction 可调用 switch_acl_block', async () => {
    const r = await runAction('switch_acl_block', { ip: '10.0.0.9', dry_run: true });
    expect(r.success).toBe(true);
  });

  test('无凭据时模拟执行不抛错', async () => {
    const r = await switchAclBlock({ ip: '10.0.0.8' });
    expect(r.success).toBe(true);
    expect(r.dry_run).toBe(true);
  });
});
