/**
 * 玄鉴安全智能体 - 工具注册表（Tools 增强核心）
 * 每个工具：{ name, desc, params[], risk: low|high, handler(params) }
 * handler 统一返回 { success?, data?, message? }；注册表负责异常兜底与审计。
 */
const logger = require('../../utils/logger');
const metrics = require('../../utils/metrics');

const tools = new Map();
const auditLogs = [];

function registerTool(spec, { override = false } = {}) {
  if (!spec || !spec.name || typeof spec.handler !== 'function') {
    throw new Error('工具注册失败：需要 name 与 handler');
  }
  if (!override && tools.has(spec.name)) throw new Error(`工具已注册: ${spec.name}`);
  tools.set(spec.name, {
    name: spec.name,
    desc: spec.desc || '',
    params: spec.params || [],
    risk: spec.risk || 'low',
    handler: spec.handler
  });
  return spec.name;
}

function listTools() {
  return [...tools.values()].map(({ handler, ...meta }) => meta);
}

function getTool(name) {
  return tools.get(name);
}

function resetTools() {
  tools.clear();
  auditLogs.length = 0;
}

/** 记录工具调用审计（含高危动作留痕） */
function recordAudit(tool, params, result) {
  auditLogs.push({
    tool: tool.name,
    params,
    success: result.success !== false,
    error: result.error || null,
    at: new Date().toISOString()
  });
  if (auditLogs.length > 200) auditLogs.shift();
}

function getAuditLogs() {
  return [...auditLogs];
}

/** 统一执行入口 */
async function executeToolByName(name, params = {}) {
  const tool = tools.get(name);
  if (!tool) {
    logger.warn(`[Tool] 未知工具: ${name}`);
    return { success: false, error: `未知工具: ${name}` };
  }
  metrics.inc('tool_calls_total', { tool: name }, 1, '工具调用次数');
  const start = Date.now();
  try {
    const result = await tool.handler(params || {});
    const normalized = { success: true, ...result };
    recordAudit(tool, params, normalized);
    metrics.observe('tool_execution_duration', { tool: name }, (Date.now() - start) / 1000, '工具执行耗时');
    return normalized;
  } catch (err) {
    logger.error(`[Tool:${name}] 执行异常:`, err.message);
    const failed = { success: false, error: err.message };
    recordAudit(tool, params, failed);
    return failed;
  }
}

module.exports = {
  registerTool,
  listTools,
  getTool,
  executeToolByName,
  resetTools,
  getAuditLogs
};
