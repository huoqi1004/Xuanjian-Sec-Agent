/**
 * 迁移 004：组织维度（多租户基础，对应 ROADMAP 4.16）
 * - 创建 organizations 表并 seed 默认组织
 * - 为存量 users 补充 org_id（默认加入默认组织）
 */
const logger = require('../../utils/logger');

module.exports = {
  name: '004_add_organizations',
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS organizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    const inserted = db.prepare('INSERT OR IGNORE INTO organizations (id, name, description) VALUES (?, ?, ?)')
      .run(1, '默认组织', '系统初始化默认组织');
    if (inserted.changes > 0) logger.info('[迁移:004] 创建默认组织');

    // 存量用户补 org_id（新用户由 database.js defaultValues 自动补）
    const users = db._rawTable('users') || [];
    let patched = 0;
    for (const row of users) {
      if (row.org_id === undefined || row.org_id === null) {
        row.org_id = 1;
        patched++;
      }
    }
    if (patched > 0) {
      db.saveDb();
      logger.info(`[迁移:004] 为 ${patched} 个存量用户补充 org_id`);
    }
  }
};
