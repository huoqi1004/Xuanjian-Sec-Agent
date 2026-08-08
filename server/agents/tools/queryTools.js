/** 数据查询工具组：get_scan_results / get_alert_summary / get_baseline_results / analyze_alerts */
const { registerTool } = require('./registry');
const { getDb } = require('../../db/database');

function registerQueryTools() {
  registerTool({
    name: 'get_scan_results',
    desc: '获取端口扫描结果',
    params: ['task_id'],
    risk: 'low',
    handler: async (params) => {
      const db = getDb();
      const results = db.all('SELECT * FROM scan_results WHERE task_id = ?', [params.task_id]);
      return { data: results, message: `找到 ${results.length} 条扫描结果` };
    }
  });

  registerTool({
    name: 'get_alert_summary',
    desc: '获取安全告警摘要',
    params: ['severity', 'limit'],
    risk: 'low',
    handler: async (params) => {
      const db = getDb();
      let query = 'SELECT * FROM alert_records';
      const qp = [];
      if (params.severity) { query += ' WHERE severity = ?'; qp.push(params.severity); }
      query += ' ORDER BY created_at DESC LIMIT ?';
      qp.push(params.limit || 10);
      const results = db.all(query, qp);
      return { data: results, message: `找到 ${results.length} 条告警` };
    }
  });

  registerTool({
    name: 'get_baseline_results',
    desc: '获取基线检查结果',
    params: ['task_id'],
    risk: 'low',
    handler: async (params) => {
      const db = getDb();
      const results = db.all('SELECT * FROM baseline_results WHERE task_id = ?', [params.task_id]);
      return { data: results, message: `找到 ${results.length} 条基线检查结果` };
    }
  });

  registerTool({
    name: 'analyze_alerts',
    desc: '分析安全告警并给出研判',
    params: ['severity', 'limit'],
    risk: 'low',
    handler: async (params) => {
      const db = getDb();
      const alerts = db.all('SELECT * FROM alert_records ORDER BY created_at DESC LIMIT ?', [params.limit || 20]);
      const aiService = require('../../services/aiService');
      const result = await aiService.analyzeAlerts(alerts);
      return { data: result.content, message: '告警分析完成' };
    }
  });
}

module.exports = { registerQueryTools };
