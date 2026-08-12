/**
 * 迁移 017：病毒扫描记录处置状态机（查杀闭环台账）
 * - 新增字段：status(pending/quarantined/deleted/restored/ignored)、handled_at、handled_by、action_type、quarantine_path
 * - shim 内存库：为已有记录回填默认值；真实数据库：尝试 ALTER TABLE（方言容错）
 */
module.exports = {
  name: '017_virus_scan_status',
  up(db) {
    if (typeof db._rawTable === 'function') {
      // shim 内存库：回填处置状态字段
      const rows = db._rawTable('virus_scan_records') || [];
      rows.forEach((r) => {
        if (r.status === undefined) r.status = 'pending';
        if (r.handled_at === undefined) r.handled_at = null;
        if (r.handled_by === undefined) r.handled_by = null;
        if (r.action_type === undefined) r.action_type = null;
        if (r.quarantine_path === undefined) r.quarantine_path = null;
      });
    } else {
      // 真实数据库（MySQL/PG/SQLite 驱动）：列不存在时补充，方言差异用 try/catch 容错
      const stmts = [
        "ALTER TABLE virus_scan_records ADD COLUMN status TEXT DEFAULT 'pending'",
        'ALTER TABLE virus_scan_records ADD COLUMN handled_at DATETIME',
        'ALTER TABLE virus_scan_records ADD COLUMN handled_by BIGINT',
        'ALTER TABLE virus_scan_records ADD COLUMN action_type TEXT',
        'ALTER TABLE virus_scan_records ADD COLUMN quarantine_path TEXT'
      ];
      for (const stmt of stmts) {
        try { db.exec(stmt); } catch (e) { /* 列可能已存在 */ }
      }
    }
    try {
      db.exec('CREATE INDEX IF NOT EXISTS idx_virus_records_status ON virus_scan_records(status)');
    } catch (e) { /* shim 下 CREATE INDEX 为 no-op */ }
  },
};
