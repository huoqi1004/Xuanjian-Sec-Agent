/**
 * 迁移 006：扫描任务审批字段（对应 NEXT_ITERATIONS N-04）
 * scan_tasks 增加 approved_by / approved_at，用于大型扫描任务人工审批留痕
 */
const logger = require('../../utils/logger');

module.exports = {
  name: '006_scan_approval',
  up(db) {
    // 内存 shim 无 ALTER TABLE 能力，直接为存量行补齐字段（新行由服务写入）
    const tasks = db._rawTable('scan_tasks') || [];
    let patched = 0;
    for (const row of tasks) {
      if (row.approved_by === undefined) {
        row.approved_by = null;
        row.approved_at = null;
        patched++;
      }
    }
    if (patched > 0) {
      db.saveDb();
      logger.info(`[迁移:006] 为 ${patched} 个存量扫描任务补齐审批字段`);
    }
  }
};
