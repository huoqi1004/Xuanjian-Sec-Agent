/**
 * 迁移 001：补全 sys_config 缺失的配置项（存量库升级）
 *
 * 老版本数据库可能缺失新增配置键，此处 INSERT OR IGNORE 幂等补全。
 */
const logger = require('../../utils/logger');

const REQUIRED_KEYS = [
  ['log_retention_days', '90', '日志保留天数'],
  ['smtp_host', '', 'SMTP服务器地址'],
  ['smtp_port', '587', 'SMTP端口'],
  ['smtp_user', '', 'SMTP用户名'],
  ['smtp_pass', '', 'SMTP密码'],
  ['notify_email', '', '告警通知接收邮箱'],
  ['webhook_url', '', 'Webhook通知URL'],
  ['backup_retention_count', '7', '备份保留份数'],
  ['metrics_enabled', '1', 'Prometheus 指标开关']
];

module.exports = {
  name: '001_seed_config_keys',
  up(db) {
    const stmt = db.prepare('INSERT OR IGNORE INTO sys_config (key, value, description) VALUES (?, ?, ?)');
    let added = 0;
    for (const [key, value, description] of REQUIRED_KEYS) {
      const result = stmt.run(key, value, description);
      if (result.changes > 0) added++;
    }
    if (added > 0) logger.info(`[迁移:001] 补全 sys_config ${added} 个配置项`);
  }
};
