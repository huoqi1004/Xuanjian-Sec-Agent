/**
 * 迁移 003：创建 chat_history 表（AI 助手对话历史持久化）
 * 对应 ROADMAP 4.15：对话持久化（对话历史入数据库，淘汰内存 Map 方案）
 */
module.exports = {
  name: '003_create_chat_history',
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS chat_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
    db.exec('CREATE INDEX IF NOT EXISTS idx_chat_history_conversation ON chat_history(conversation_id)');
  }
};
