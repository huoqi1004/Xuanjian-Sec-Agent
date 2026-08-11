/**
 * 迁移 016：创建 gan_scan_metrics 表（GAN 扫描指标记录）
 * 记录每次 GAN 扫描的详细信息，用于监控和趋势分析
 */
module.exports = {
  name: '016_create_gan_scan_metrics',
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS gan_scan_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        file_path TEXT NOT NULL,
        file_hash_md5 TEXT,
        file_size_bytes INTEGER DEFAULT 0,
        model_version TEXT,
        recon_error REAL DEFAULT 0,
        is_anomaly INTEGER DEFAULT 0,
        anomaly_score REAL DEFAULT 0,
        confidence REAL DEFAULT 0,
        verdict TEXT DEFAULT 'unknown',
        engine_verdict TEXT,
        engine_confidence REAL,
        vote_merged INTEGER DEFAULT 0,
        gan_boosted INTEGER DEFAULT 0,
        gan_conflicted INTEGER DEFAULT 0,
        response_time_ms INTEGER DEFAULT 0,
        skipped INTEGER DEFAULT 0,
        skip_reason TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_gsm_scan ON gan_scan_metrics(scan_id)'
    );
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_gsm_hash ON gan_scan_metrics(file_hash_md5)'
    );
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_gsm_verdict ON gan_scan_metrics(verdict)'
    );
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_gsm_created ON gan_scan_metrics(created_at)'
    );
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_gsm_anomaly ON gan_scan_metrics(is_anomaly)'
    );
  },
};
