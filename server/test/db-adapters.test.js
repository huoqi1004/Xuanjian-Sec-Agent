/**
 * N-06 双驱动适配测试（对应报告 Phase D）
 *
 * 同一套 CRUD 断言分别在 SQLite（默认）与 MySQL（需环境变量 DB_DRIVER=mysql 且可用）下执行。
 * CI 中增加一个带 mysql 服务的 job 运行本文件即可实现双跑。
 *
 * 运行：
 *   npx jest test/db-adapters.test.js --forceExit               # SQLite
 *   DB_DRIVER=mysql npx jest test/db-adapters.test.js --forceExit  # MySQL
 */
process.env.DB_DRIVER = process.env.DB_DRIVER || 'sqlite';

const fs = require('fs');
const path = require('path');
const { getDao, resetDao } = require('../db/dao');

const TEST_DB = path.resolve(__dirname, '../../data/n06_adapters_test.db');

describe(`N-06 DAO 适配测试（驱动: ${process.env.DB_DRIVER}）`, () => {
  let db;

  beforeAll(async () => {
    if (process.env.DB_DRIVER === 'sqlite') {
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
      process.env.DB_PATH = TEST_DB;
    }
    db = getDao();
    // 建表（schema 全量文件）
    const schemaFile = path.join(__dirname, '../db/schema', `schema.${process.env.DB_DRIVER}.sql`);
    if (fs.existsSync(schemaFile)) {
      await db.exec(fs.readFileSync(schemaFile, 'utf8'));
    }
  });

  afterAll(async () => {
    try { await db.close(); } catch (e) { /* ignore */ }
    resetDao();
    if (process.env.DB_DRIVER === 'sqlite' && fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
  });

  test('INSERT + SELECT by id（get）', async () => {
    const ins = await db.prepare(
      "INSERT INTO sys_config (key, value, description) VALUES (?, ?, ?)"
    ).run('adapt_test_1', 'v1', '适配测试');
    expect(ins.lastInsertRowid).toBeTruthy();

    const row = await db.prepare('SELECT * FROM sys_config WHERE key = ?').get('adapt_test_1');
    expect(row).toBeTruthy();
    expect(row.key).toBe('adapt_test_1');
  });

  test('SELECT all + 多行', async () => {
    await db.prepare('INSERT INTO sys_config (key, value) VALUES (?, ?)').run('adapt_test_2', 'v2');
    const rows = await db.prepare('SELECT * FROM sys_config ORDER BY id').all();
    expect(rows.length).toBeGreaterThanOrEqual(2);
    expect(rows.some((r) => r.key === 'adapt_test_2')).toBe(true);
  });

  test('UPDATE + 条件 WHERE', async () => {
    await db.prepare('UPDATE sys_config SET value = ? WHERE key = ?').run('v1_updated', 'adapt_test_1');
    const row = await db.prepare('SELECT value FROM sys_config WHERE key = ?').get('adapt_test_1');
    expect(row.value).toBe('v1_updated');
  });

  test('DELETE', async () => {
    const res = await db.prepare('DELETE FROM sys_config WHERE key = ?').run('adapt_test_1');
    expect(res.changes).toBeGreaterThan(0);
    const row = await db.prepare('SELECT * FROM sys_config WHERE key = ?').get('adapt_test_1');
    expect(row).toBeUndefined();
  });

  test('COUNT(*)', async () => {
    const c = await db.prepare("SELECT COUNT(*) as c FROM sys_config").get();
    expect(typeof c.c).toBe('number');
  });

  test('事务提交（R4 缓解）', async () => {
    const tx = db.transaction(async () => {
      await db.prepare('INSERT INTO sys_config (key, value) VALUES (?, ?)').run('tx_ok_a', '1');
      await db.prepare('INSERT INTO sys_config (key, value) VALUES (?, ?)').run('tx_ok_b', '1');
    });
    await tx();
    const count = await db.prepare("SELECT COUNT(*) as c FROM sys_config WHERE key LIKE 'tx_ok_%'").get();
    expect(count.c).toBe(2);
  });

  test('事务回滚（R4 缓解）', async () => {
    try {
      const tx = db.transaction(async () => {
        await db.prepare('INSERT INTO sys_config (key, value) VALUES (?, ?)').run('tx_bad', '1');
        throw new Error('模拟失败触发回滚');
      });
      await tx();
    } catch (e) { /* expected */ }
    const count = await db.prepare("SELECT COUNT(*) as c FROM sys_config WHERE key = ?").get('tx_bad');
    expect(count.c).toBe(0);
  });
});
