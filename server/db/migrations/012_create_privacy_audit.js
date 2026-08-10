/**
 * 迁移 012：创建 privacy_audit 表（差分隐私投毒审计）
 * 记录知识库文档的差分隐私扰动参数，用于投毒检测
 */
module.exports = {
  name: '012_create_privacy_audit',
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS privacy_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        doc_id INTEGER NOT NULL,
        epsilon REAL DEFAULT 1.0,
        delta REAL DEFAULT 0.0001,
        sensitivity REAL DEFAULT 1.0,
        noise_type TEXT DEFAULT 'laplace',
        original_hash TEXT,
        perturbed_hash TEXT,
        anomaly_score REAL DEFAULT 0,
        is_anomaly INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (doc_id) REFERENCES kb_documents(id)
      );
    `);
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_pa_doc ON privacy_audit(doc_id)'
    );
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_pa_anomaly ON privacy_audit(is_anomaly)'
    );
  },
};
