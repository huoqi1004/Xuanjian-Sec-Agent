const { getDb, resetForTest, closeDb } = require('../db/database');

describe('内存数据库 shim（database.js）', () => {
  beforeEach(() => {
    resetForTest();
  });

  afterAll(() => {
    closeDb();
  });

  test('INSERT + get + 唯一约束', () => {
    const db = getDb();
    db.prepare('INSERT INTO users (username, password_hash, role_id) VALUES (?, ?, ?)').run('tester', 'hash', 1);

    const row = db.prepare('SELECT * FROM users WHERE username = ?').get('tester');
    expect(row.username).toBe('tester');
    expect(row.password_hash).toBe('hash');

    // username 唯一约束：重复插入失败
    const dup = db.prepare('INSERT INTO users (username, password_hash, role_id) VALUES (?, ?, ?)').run('tester', 'h2', 1);
    expect(dup.changes).toBe(0);
  });

  test('UPDATE 参数顺序：SET 参数在前、WHERE 参数在后', () => {
    const db = getDb();
    db.prepare('INSERT INTO users (username, password_hash, role_id) VALUES (?, ?, ?)').run('a', 'h1', 1);
    db.prepare('INSERT INTO users (username, password_hash, role_id) VALUES (?, ?, ?)').run('b', 'h2', 1);

    const r = db.prepare('UPDATE users SET department = ? WHERE username = ?').run('dep-x', 'b');
    expect(r.changes).toBe(1);

    const rowB = db.prepare('SELECT * FROM users WHERE username = ?').get('b');
    expect(rowB.department).toBe('dep-x');
    const rowA = db.prepare('SELECT * FROM users WHERE username = ?').get('a');
    expect(rowA.department).toBeFalsy();
  });

  test('多条件 WHERE 更新', () => {
    const db = getDb();
    db.prepare('INSERT INTO device_commands (device_id, command, status) VALUES (?, ?, ?)').run('d1', 'baseline_check', 'pending');
    db.prepare('INSERT INTO device_commands (device_id, command, status) VALUES (?, ?, ?)').run('d1', 'port_scan', 'pending');

    const r = db.prepare('UPDATE device_commands SET status = ?, result = ? WHERE device_id = ? AND command = ?').run('executed', '{}', 'd1', 'port_scan');
    expect(r.changes).toBe(1);
    const rows = db.prepare('SELECT * FROM device_commands WHERE device_id = ?').all('d1');
    const executed = rows.find((x) => x.command === 'port_scan');
    expect(executed.status).toBe('executed');
  });

  test('_deleteRows 条件删除', () => {
    const db = getDb();
    db.prepare('INSERT INTO users (username, password_hash, role_id) VALUES (?, ?, ?)').run('x1', 'h', 1);
    db.prepare('INSERT INTO users (username, password_hash, role_id) VALUES (?, ?, ?)').run('x2', 'h', 1);

    const deleted = db._deleteRows('users', (row) => row.username === 'x1');
    expect(deleted).toBe(1);
    expect(db.prepare('SELECT COUNT(*) as count FROM users').get().count).toBe(1);
  });

  test('DELETE SQL 支持（参数条件）', () => {
    const db = getDb();
    db.prepare('INSERT INTO users (username, password_hash, role_id) VALUES (?, ?, ?)').run('d1', 'h', 1);
    db.prepare('INSERT INTO users (username, password_hash, role_id) VALUES (?, ?, ?)').run('d2', 'h', 1);

    const r = db.prepare('DELETE FROM users WHERE id = ?').run(1);
    expect(r.changes).toBe(1);
    expect(db.prepare('SELECT COUNT(*) as count FROM users').get().count).toBe(1);

    const r2 = db.prepare('DELETE FROM users WHERE id = ?').run(999);
    expect(r2.changes).toBe(0);
  });

  test('DELETE SQL 支持（字面量条件）', () => {
    const db = getDb();
    db.prepare('INSERT INTO users (username, password_hash, role_id) VALUES (?, ?, ?)').run('lit1', 'h', 1);
    const r = db.prepare("DELETE FROM users WHERE username = 'lit1'").run();
    expect(r.changes).toBe(1);
  });

  test('COUNT 与 WHERE 1=1 字面量恒等式', () => {
    const db = getDb();
    db.prepare('INSERT INTO roles (name) VALUES (?)').run('r1');
    db.prepare('INSERT INTO roles (name) VALUES (?)').run('r2');
    expect(db.prepare('SELECT COUNT(*) as count FROM roles WHERE 1=1').get().count).toBe(2);
  });

  test('无匹配时 get 返回 undefined（不为空对象）', () => {
    const db = getDb();
    const missing = db.prepare('SELECT * FROM users WHERE username = ?').get('nobody');
    expect(missing).toBeUndefined();
  });

  test('JOIN 查询（scan_tasks + users）', () => {
    const db = getDb();
    db.prepare('INSERT INTO scan_tasks (id, target_cidr, status, created_by) VALUES (?, ?, ?, ?)').run('t1', '127.0.0.1', 'completed', 1);
    const rows = db.prepare(
      'SELECT t.*, u.username as created_by_name FROM scan_tasks t LEFT JOIN users u ON t.created_by = u.id WHERE t.id = ?'
    ).all('t1');
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe('t1');
  });
});
