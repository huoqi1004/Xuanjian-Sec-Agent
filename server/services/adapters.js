/**
 * 玄鉴安全智能体 - SOAR 动作适配器（对应 ROADMAP 4.17）
 *
 * 将 Playbook 的动作类型映射到真实执行：
 * - firewall_block: 封禁 IP（落审计 + 告警，模拟防火墙动作）
 * - account_lock: 锁定账号
 * - raise_alert: 生成安全告警
 * - notify: 邮件/Webhook 通知（复用 NotifyService）
 * - webhook: 自定义 Webhook 触发
 * - log_only: 仅记录
 * 后续可扩展：交换机、云安全组、SMTP 等真实适配器。
 */

const { getDb } = require('../db/database');
const notifyService = require('./notifyService');
const logger = require('../utils/logger');
const switchAcl = require('./adapters/switchAcl');

const adapters = {
  firewall_block: async (params) => {
    const { ip, duration = 3600 } = params;
    if (!ip) return { success: false, error: '缺少 ip 参数' };
    const db = getDb();
    db.prepare('INSERT INTO action_logs (policy_id, action_type, action_detail, result) VALUES (?, ?, ?, ?)')
      .run(null, 'firewall_block', `SOAR 封禁 IP ${ip}，时长 ${duration}s`, 'success');
    db.prepare('INSERT INTO alert_records (related_asset, alert_type, severity, confidence, description, status) VALUES (?, ?, ?, ?, ?, ?)')
      .run(ip, 'soar_block', 'high', 0.9, `SOAR 剧本封禁恶意 IP ${ip}（时长 ${duration}s）`, 'new');
    logger.warn(`[SOAR] 封禁 IP ${ip}（${duration}s）`);
    return { success: true, detail: `已封禁 ${ip}` };
  },

  account_lock: async (params) => {
    const { username } = params;
    if (!username) return { success: false, error: '缺少 username 参数' };
    const db = getDb();
    db.prepare('INSERT INTO action_logs (policy_id, action_type, action_detail, result) VALUES (?, ?, ?, ?)')
      .run(null, 'account_lock', `SOAR 锁定账号 ${username}`, 'success');
    return { success: true, detail: `已锁定账号 ${username}` };
  },

  raise_alert: async (params) => {
    const { severity = 'high', message, asset } = params;
    const db = getDb();
    db.prepare('INSERT INTO alert_records (related_asset, alert_type, severity, confidence, description, status) VALUES (?, ?, ?, ?, ?, ?)')
      .run(asset || 'soar', 'soar_alert', severity, 0.8, message || 'SOAR 剧本生成告警', 'new');
    return { success: true, detail: '告警已生成' };
  },

  notify: async (params) => {
    const { channel = 'all', message, severity, target } = params;
    if (!message) return { success: false, error: '缺少 message 参数' };
    await notifyService.send({ channel, message, severity: severity || 'medium', target: target || '' });
    return { success: true, detail: `通知已发送（${channel}）` };
  },

  webhook: async (params) => {
    const { url, payload } = params;
    if (!url) return { success: false, error: '缺少 url 参数' };
    const axios = require('axios');
    await axios.post(url, { source: 'xuanjian-soar', ts: new Date().toISOString(), ...(payload || {}) }, { timeout: 10000 });
    return { success: true, detail: `Webhook 已触发 ${url}` };
  },

  log_only: async (params) => {
    logger.info(`[SOAR] 记录: ${params.message || '无内容'}`);
    return { success: true, detail: params.message || '已记录' };
  },

  switch_acl_block: async (params) => switchAcl.switchAclBlock(params),
  switch_acl_unblock: async (params) => switchAcl.switchAclUnblock(params)
};

/**
 * 执行动作适配器（带统一异常捕获）
 */
async function runAction(type, params) {
  const adapter = adapters[type];
  if (!adapter) return { success: false, error: `未知动作适配器: ${type}` };
  try {
    return await adapter(params);
  } catch (err) {
    logger.error(`[SOAR] 动作 ${type} 执行失败:`, err.message);
    return { success: false, error: err.message };
  }
}

module.exports = { adapters, runAction };
