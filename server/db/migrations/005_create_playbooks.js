/**
 * 迁移 005：SOAR 剧本表（对应 ROADMAP 4.17）
 * playbooks：可视化编排剧本（条件/动作/审批/通知/等待步骤）
 */
module.exports = {
  name: '005_create_playbooks',
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS playbooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        trigger TEXT DEFAULT 'manual',
        steps TEXT DEFAULT '[]',
        enabled INTEGER DEFAULT 1,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
  }
};
