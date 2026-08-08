/**
 * 玄鉴安全智能体 - 数据保留策略
 *
 * 按 sys_config.log_retention_days 配置，定期清理超过保留期的历史数据，
 * 防止数据无限膨胀（对应 ROADMAP 4.11 数据保留策略）。
 */

const { getDb } = require('../db/database');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

// 参与保留清理的表（均含 created_at 时间字段）
// 注意：audit_logs 审计日志为 append-only（防篡改，对应 ROADMAP 4.16），不参与自动清理
const RETENTION_TABLES = [
  'scan_results',
  'alert_records',
  'action_logs',
  'virus_scan_records',
  'threat_intel'
];

function getRetentionDays() {
  const db = getDb();
  const row = db.prepare("SELECT * FROM sys_config WHERE key = 'log_retention_days'").get();
  const days = parseInt(row?.value, 10);
  return Number.isFinite(days) && days > 0 ? days : 90;
}

/**
 * 执行数据保留清理，返回删除统计
 */
async function runRetention() {
  const db = getDb();
  const days = getRetentionDays();
  const cutoff = new Date(Date.now() - days * 86400000).toISOString();

  let totalDeleted = 0;
  const detail = [];

  for (const table of RETENTION_TABLES) {
    const deleted = db._deleteRows(table, (row) => row.created_at && String(row.created_at) < cutoff);
    if (deleted > 0) {
      totalDeleted += deleted;
      detail.push(`${table}:${deleted}`);
    }
  }

  if (totalDeleted > 0) {
    metrics.inc('retention_deleted_rows_total', {}, totalDeleted, '数据保留策略清理的行数');
    logger.info(`[数据保留] 清理 ${days} 天前历史数据完成，共删除 ${totalDeleted} 行（${detail.join(', ')}）`);
  } else {
    logger.debug('[数据保留] 本次执行无过期数据');
  }

  return { days, deleted: totalDeleted, detail };
}

module.exports = { runRetention, getRetentionDays, RETENTION_TABLES };
