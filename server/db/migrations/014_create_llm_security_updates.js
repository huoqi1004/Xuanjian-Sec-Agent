/**
 * 迁移 014：创建 llm_security_updates 表（LLM安全更新记录）
 * 记录 Agnes API 推送的安全威胁更新，用于注入系统 prompt
 */
module.exports = {
  name: '014_create_llm_security_updates',
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS llm_security_updates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        update_type TEXT NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        severity TEXT DEFAULT 'medium',
        ioc_list TEXT,
        prompt_injection TEXT,
        applied INTEGER DEFAULT 0,
        source TEXT DEFAULT 'agnes_api',
        version TEXT DEFAULT '1.0',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_lsu_type ON llm_security_updates(update_type)'
    );
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_lsu_applied ON llm_security_updates(applied)'
    );
  },
};
