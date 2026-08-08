/** 业务动作工具组：start_scan / generate_security_report / scan_file_with_ai */
const { registerTool } = require('./registry');
const { getDb } = require('../../db/database');

function registerActionTools() {
  registerTool({
    name: 'start_scan',
    desc: '发起 TCP 端口扫描',
    params: ['target_cidr', 'port_range', 'created_by'],
    risk: 'low',
    handler: async (params) => {
      if (!params.target_cidr || !params.port_range) {
        return { success: false, error: '缺少 target_cidr / port_range 参数' };
      }
      const scanService = require('../../services/scanService');
      const task = await scanService.startScan({
        target_cidr: params.target_cidr,
        port_range: params.port_range,
        scan_mode: 'tcp_connect',
        created_by: params.created_by || 1
      });
      return { data: task, message: `扫描任务已创建: ${task.task_id}` };
    }
  });

  registerTool({
    name: 'generate_security_report',
    desc: '生成安全报告',
    params: ['type'],
    risk: 'low',
    handler: async (params) => {
      const aiService = require('../../services/aiService');
      const report = await aiService.generateSecurityReport(aiService.getDashboardData(), params.type || 'daily');
      return { data: report, message: '安全报告生成完成' };
    }
  });

  registerTool({
    name: 'scan_file_with_ai',
    desc: '文件 AI 分析（多引擎结果汇总）',
    params: ['fileHash', 'fileName', 'engineResults'],
    risk: 'low',
    handler: async (params) => {
      const summary = Object.values(params.engineResults || {})
        .map((e) => `${e.engine}: ${e.verdict} (置信度${(e.confidence * 100).toFixed(0)}%) - ${e.detail}`)
        .join('\n');
      return { data: { fileHash: params.fileHash, fileName: params.fileName, summary }, message: '文件AI分析完成' };
    }
  });
}

module.exports = { registerActionTools };
