/** 防御动作工具组：block_ip / account_lock / search_knowledge / run_playbook */
const { registerTool } = require('./registry');
const { getDb } = require('../../db/database');

function registerDefenseTools() {
  registerTool({
    name: 'block_ip',
    desc: '封禁恶意 IP（高危，需人工确认）',
    params: ['ip', 'duration'],
    risk: 'high',
    handler: async (params) => {
      const { ip, duration = 3600 } = params;
      if (!ip) return { success: false, error: '缺少 ip 参数' };
      const db = getDb();
      db.prepare('INSERT INTO action_logs (policy_id, action_type, action_detail, result) VALUES (?, ?, ?, ?)')
        .run(null, 'block_ip', `人工确认后封禁 IP ${ip}，时长 ${duration}s`, 'success');
      db.prepare('INSERT INTO alert_records (related_asset, alert_type, severity, confidence, description, status) VALUES (?, ?, ?, ?, ?, ?)')
        .run(ip, 'manual_block', 'high', 1.0, `人工确认封禁恶意 IP ${ip}（时长 ${duration}s）`, 'new');
      db.prepare('INSERT INTO audit_logs (user_id, username, operation_type, operation_target, operation_detail, result) VALUES (?, ?, ?, ?, ?, ?)')
        .run(params.userId || null, params.username || 'agent', 'defense_action', `ip:${ip}`, `block_ip ${ip} duration=${duration}s`, 'success');
      return { data: { ip, duration, action: 'blocked' }, message: `已封禁 IP ${ip}` };
    }
  });

  registerTool({
    name: 'account_lock',
    desc: '锁定被入侵账号（高危，需人工确认）',
    params: ['username'],
    risk: 'high',
    handler: async (params) => {
      const { username } = params;
      if (!username) return { success: false, error: '缺少 username 参数' };
      const db = getDb();
      db.prepare('INSERT INTO action_logs (policy_id, action_type, action_detail, result) VALUES (?, ?, ?, ?)')
        .run(null, 'account_lock', `人工确认后锁定账号 ${username}`, 'success');
      db.prepare('INSERT INTO alert_records (related_asset, alert_type, severity, confidence, description, status) VALUES (?, ?, ?, ?, ?, ?)')
        .run(username, 'account_locked', 'high', 1.0, `人工确认锁定被入侵账号 ${username}`, 'new');
      db.prepare('INSERT INTO audit_logs (user_id, username, operation_type, operation_target, operation_detail, result) VALUES (?, ?, ?, ?, ?, ?)')
        .run(params.userId || null, params.username || 'agent', 'defense_action', `user:${username}`, `account_lock ${username}`, 'success');
      return { data: { username, action: 'locked' }, message: `已锁定账号 ${username}` };
    }
  });

  // ---- Tools 增强：新增 2 个工具 ----
  registerTool({
    name: 'search_knowledge',
    desc: '知识库 RAG 检索（处置建议参考）',
    params: ['query', 'top_k'],
    risk: 'low',
    handler: async (params) => {
      const aiService = require('../../services/aiService');
      const results = await aiService.searchKnowledge(params.query, params.top_k || 5);
      return { data: results, message: `知识库检索到 ${results.length} 条相关条目` };
    }
  });

  registerTool({
    name: 'run_playbook',
    desc: '执行 SOAR 剧本',
    params: ['playbook_id', 'event'],
    risk: 'high',
    handler: async (params) => {
      const playbookService = require('../../services/playbookService');
      const result = await playbookService.execute(params.playbook_id, params.event || {}, { userId: params.userId });
      return { data: result, message: '剧本执行完成' };
    }
  });
}

module.exports = { registerDefenseTools };
