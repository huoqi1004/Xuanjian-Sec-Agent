/**
 * 迁移 009：创建 kb_documents 表（知识库文档完整性校验）
 * 为每个文档记录 SHA-256 哈希，支持篡改检测和定期完整性校验
 */
module.exports = {
  name: '009_create_kb_documents',
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS kb_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT DEFAULT 'general',
        content_hash TEXT NOT NULL,
        source TEXT DEFAULT 'manual',
        version INTEGER DEFAULT 1,
        approved INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_kb_doc_hash ON kb_documents(content_hash)'
    );
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_kb_doc_cat ON kb_documents(category)'
    );
  },
};
