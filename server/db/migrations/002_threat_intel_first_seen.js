/**
 * 迁移 002：为存量 threat_intel 数据补充 first_seen 字段
 *
 * 新数据在写入时（upsertIntel）已带 first_seen；此迁移仅为老数据补齐。
 */
const logger = require('../../utils/logger');

module.exports = {
  name: '002_threat_intel_first_seen',
  up(db) {
    const rows = db._rawTable('threat_intel') || [];
    let patched = 0;
    for (const row of rows) {
      if (!row.first_seen) {
        row.first_seen = row.updated_at || new Date().toISOString();
        patched++;
      }
    }
    if (patched > 0) {
      db.saveDb();
      logger.info(`[迁移:002] 为 ${patched} 条威胁情报补充 first_seen`);
    }
  }
};
