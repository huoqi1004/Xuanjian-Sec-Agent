/**
 * 迁移 015：创建 gan_model_versions 表（GAN 模型版本管理）
 * 记录所有 GAN 模型的版本信息、训练指标、部署状态
 */
module.exports = {
  name: '015_create_gan_model_versions',
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS gan_model_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_type TEXT NOT NULL,
        version TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_size_bytes INTEGER DEFAULT 0,
        sha256_hash TEXT,
        training_samples INTEGER DEFAULT 0,
        benign_samples INTEGER DEFAULT 0,
        adversarial_samples INTEGER DEFAULT 0,
        train_accuracy REAL DEFAULT 0,
        test_accuracy REAL DEFAULT 0,
        adv_accuracy REAL DEFAULT 0,
        benign_accuracy REAL DEFAULT 0,
        auc_roc REAL DEFAULT 0,
        f1_score REAL DEFAULT 0,
        trained_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        deployed_at DATETIME,
        status TEXT DEFAULT 'pending',
        deployed_by INTEGER DEFAULT 1,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(model_type, version)
      );
    `);
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_gmv_type ON gan_model_versions(model_type)'
    );
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_gmv_status ON gan_model_versions(status)'
    );
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_gmv_deployed ON gan_model_versions(deployed_at)'
    );
  },
};
