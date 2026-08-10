/**
 * 迁移 010：创建 defense_policies 表（动态防御策略）
 * 支持威胁情报 LLM 融合时动态更新防御策略
 */
module.exports = {
  name: '010_create_defense_policies',
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS defense_policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        conditions JSON NOT NULL,
        actions JSON NOT NULL,
        cooldown INTEGER DEFAULT 300,
        unattended INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1,
        approval_status TEXT DEFAULT 'approved',
        created_by INTEGER DEFAULT 1,
        source TEXT DEFAULT 'manual',
        version INTEGER DEFAULT 1,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_defense_policy_enabled ON defense_policies(enabled)'
    );
  },
};
