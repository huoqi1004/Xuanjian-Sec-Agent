const { getDb, resetForTest, closeDb } = require('../db/database');
const { runRetention, RETENTION_TABLES } = require('../services/retentionService');

describe('数据保留策略 retentionService', () => {
  beforeEach(() => {
    resetForTest();
  });

  afterAll(() => {
    closeDb();
  });

  test('清理超期数据并保留有效期内数据', async () => {
    const db = getDb();
    db.prepare("INSERT INTO sys_config (key, value) VALUES ('log_retention_days', '7')").run();

    const oldTs = new Date(Date.now() - 10 * 86400000).toISOString();
    const freshTs = new Date().toISOString();

    db.prepare('INSERT INTO alert_records (alert_type, severity, description, status, created_at) VALUES (?, ?, ?, ?, ?)')
      .run('test', 'low', 'old-record', 'new', oldTs);
    db.prepare('INSERT INTO alert_records (alert_type, severity, description, status, created_at) VALUES (?, ?, ?, ?, ?)')
      .run('test', 'low', 'fresh-record', 'new', freshTs);

    const result = await runRetention();
    expect(result.days).toBe(7);
    expect(result.deleted).toBe(1);

    const rows = db.prepare('SELECT * FROM alert_records').all();
    expect(rows).toHaveLength(1);
    expect(rows[0].description).toBe('fresh-record');
  });

  test('非法保留天数配置回退默认 90 天', async () => {
    const db = getDb();
    db.prepare("INSERT INTO sys_config (key, value) VALUES ('log_retention_days', '0')").run();
    const result = await runRetention();
    expect(result.days).toBe(90);
  });

  test('无过期数据时删除 0 行', async () => {
    const db = getDb();
    db.prepare("INSERT INTO sys_config (key, value) VALUES ('log_retention_days', '365')").run();
    db.prepare('INSERT INTO alert_records (alert_type, severity, description, status) VALUES (?, ?, ?, ?)')
      .run('test', 'low', 'recent', 'new');
    const result = await runRetention();
    expect(result.deleted).toBe(0);
  });
});
