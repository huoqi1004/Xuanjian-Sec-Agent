/**
 * 迁移 013：创建 wasm_sandbox_logs 表（WebAssembly沙箱分析记录）
 */
module.exports = {
  name: '013_create_wasm_sandbox_logs',
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS wasm_sandbox_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_hash TEXT NOT NULL,
        file_name TEXT,
        file_size INTEGER DEFAULT 0,
        verdict TEXT DEFAULT 'unknown',
        confidence REAL DEFAULT 0,
        behaviors TEXT,
        sandbox_engine TEXT DEFAULT 'wasm',
        fallback_reason TEXT,
        analysis_time_ms INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_wsl_hash ON wasm_sandbox_logs(file_hash)'
    );
  },
};
