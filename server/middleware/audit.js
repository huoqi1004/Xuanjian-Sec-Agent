const { getDb } = require('../db/database');
const { getClientIp } = require('../utils/helpers');
const logger = require('../utils/logger');

/**
 * 审计日志中间件
 * 记录所有关键操作到audit_logs表
 */
function auditLog(operationType) {
  return (req, res, next) => {
    // 保存原始的res.json方法
    const originalJson = res.json.bind(res);

    res.json = function (data) {
      // 只记录成功的操作
      if (data && data.code === 0) {
        try {
          const db = getDb();
          const insertLog = db.prepare(`
            INSERT INTO audit_logs (user_id, username, operation_type, operation_target, operation_detail, result, client_ip)
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `);

          insertLog.run(
            req.user ? req.user.id : null,
            req.user ? req.user.username : 'anonymous',
            operationType,
            req.originalUrl,
            `${req.method} ${req.originalUrl}`,
            'success',
            getClientIp(req)
          );
        } catch (err) {
          logger.error('写入审计日志失败:', err.message);
        }
      }

      return originalJson(data);
    };

    next();
  };
}

/**
 * 手动记录审计日志
 */
function recordAudit(userId, username, operationType, target, detail, result = 'success', clientIp = '') {
  try {
    const db = getDb();
    const insertLog = db.prepare(`
      INSERT INTO audit_logs (user_id, username, operation_type, operation_target, operation_detail, result, client_ip)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    insertLog.run(userId, username, operationType, target, detail, result, clientIp);
  } catch (err) {
    logger.error('写入审计日志失败:', err.message);
  }
}

module.exports = { auditLog, recordAudit };
