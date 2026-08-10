/**
 * 迁移 011：创建 model_votes 表（多模型仲裁投票记录）
 * 记录各 LLM 模型的输出投票，用于一致性仲裁
 */
module.exports = {
  name: '011_create_model_votes',
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS model_votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        conversation_id TEXT NOT NULL,
        query TEXT NOT NULL,
        model_name TEXT NOT NULL,
        response TEXT NOT NULL,
        confidence REAL DEFAULT 0,
        verdict TEXT,
        latency_ms INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_mv_conv ON model_votes(conversation_id)'
    );
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_mv_model ON model_votes(model_name)'
    );
  },
};
