/**
 * 玄鉴安全智能体 - 多步规划 Agent（对应 ROADMAP 4.13）
 *
 * 在现有 Function Calling 之上实现"计划 → 执行 → 验证 → 总结"循环：
 * 1. 规划：LLM 根据任务输出 JSON 执行计划（失败时规则回退，保证可演示）
 * 2. 执行：逐步调用 aiService.executeTool，失败自动重试 1 次
 * 3. 中间结果合并：上一步产出（如 task_id）自动注入下一步缺失参数
 * 4. 人工确认点：高危动作（封禁/锁定等）执行前要求人工确认（approve/reject）
 * 5. 总结：将中间结果交由 LLM 生成最终结论（失败时模板汇总）
 */

const { randomUUID } = require('crypto');
const aiService = require('./aiService');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

/** 高危动作集合：执行前强制人工确认 */
const HIGH_RISK_TOOLS = new Set(['block_ip', 'account_lock', 'delete_scan_task', 'delete_user', 'disable_policy']);

/** 规划阶段向 LLM 暴露的工具目录（仅限当前可执行的工具） */
const AGENT_TOOL_CATALOG = [
  { name: 'start_scan', params: 'target_cidr, port_range', desc: '发起 TCP 端口扫描', risk: 'low' },
  { name: 'get_scan_results', params: 'task_id', desc: '获取端口扫描结果', risk: 'low' },
  { name: 'get_alert_summary', params: 'severity(可选), limit', desc: '获取安全告警摘要', risk: 'low' },
  { name: 'analyze_alerts', params: 'severity(可选), limit', desc: '分析安全告警并给出研判', risk: 'low' },
  { name: 'get_baseline_results', params: 'task_id', desc: '获取基线检查结果', risk: 'low' },
  { name: 'get_threat_intel', params: 'ioc_type, value', desc: '多源威胁情报聚合查询', risk: 'low' },
  { name: 'generate_security_report', params: 'type(daily/weekly/monthly)', desc: '生成安全报告', risk: 'low' },
  { name: 'block_ip', params: 'ip, duration(秒)', desc: '封禁恶意 IP（高危，需人工确认）', risk: 'high' },
  { name: 'account_lock', params: 'username', desc: '锁定被入侵账号（高危，需人工确认）', risk: 'high' }
];

const MAX_STEPS = 6;
const MAX_EXECUTION_MS = 120000;

/** 人工确认请求登记表 */
const pendingConfirmations = new Map();

/* ---------------- 计划生成 ---------------- */

function _extractJson(text) {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end <= start) return null;
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch (e) {
    return null;
  }
}

function _normalizePlan(plan) {
  const steps = (plan.steps || []).slice(0, MAX_STEPS).map((s) => ({
    tool: String(s.tool || s.name || '').trim(),
    params: (s.params && typeof s.params === 'object') ? s.params : {},
    reason: String(s.reason || s.description || '')
  })).filter((s) => s.tool && AGENT_TOOL_CATALOG.some((t) => t.name === s.tool));
  return { goal: String(plan.goal || ''), steps };
}

async function planWithLLM(task) {
  const catalog = AGENT_TOOL_CATALOG.map((t) => `- ${t.name}(${t.params}): ${t.desc} [风险:${t.risk}]`).join('\n');
  const resp = await aiService.callDeepSeek([
    {
      role: 'system',
      content: `你是安全运营智能体规划器。根据用户任务输出可执行计划。
可用工具：
${catalog}

输出严格 JSON（不要多余文字）：
{"goal":"任务目标","steps":[{"tool":"工具名","params":{"参数":"值"},"reason":"为什么用这步"}]}
规则：步骤≤6；只使用列表中的工具；高危工具放最后；不确定参数值可省略。`
    },
    { role: 'user', content: String(task) }
  ], { temperature: 0.2, maxTokens: 1200 });

  if (!resp.success) throw new Error(resp.error || 'LLM 规划失败');
  const content = resp.data?.choices?.[0]?.message?.content || '';
  const plan = _extractJson(content);
  if (!plan) throw new Error('LLM 未返回合法计划');
  return _normalizePlan(plan);
}

/** 规则回退计划：LLM 不可用时按任务关键词生成可演示计划 */
function buildFallbackPlan(task) {
  const t = String(task || '');
  const steps = [];
  if (/资产|风险|内网|排查|评估/.test(t)) {
    steps.push({ tool: 'start_scan', params: { target_cidr: '127.0.0.1', port_range: '1-1024' }, reason: '扫描本机开放端口' });
    steps.push({ tool: 'get_alert_summary', params: {}, reason: '汇总现有安全告警' });
    steps.push({ tool: 'get_threat_intel', params: { ioc_type: 'ip', value: '185.220.101.34' }, reason: '关联威胁情报' });
    steps.push({ tool: 'generate_security_report', params: { type: 'daily' }, reason: '生成风险评估报告' });
  } else if (/告警|研判|分析告警/.test(t)) {
    steps.push({ tool: 'get_alert_summary', params: { severity: 'high' }, reason: '拉取高危告警' });
    steps.push({ tool: 'analyze_alerts', params: {}, reason: '分析告警根因' });
  } else if (/情报|威胁|IOC|ioc|哈希|hash/.test(t)) {
    steps.push({ tool: 'get_threat_intel', params: { ioc_type: 'ip', value: '185.220.101.34' }, reason: '查询威胁情报' });
  } else {
    steps.push({ tool: 'get_alert_summary', params: {}, reason: '汇总安全告警' });
    steps.push({ tool: 'generate_security_report', params: { type: 'daily' }, reason: '生成安全报告' });
  }
  return { goal: t, steps };
}

/* ---------------- 执行 ---------------- */

function _isHighRisk(toolName) {
  return HIGH_RISK_TOOLS.has(toolName);
}

function _createConfirmation(step, taskId) {
  const id = `cfm_${randomUUID().slice(0, 8)}`;
  const record = { id, taskId, tool: step.tool, params: step.params, reason: step.reason, status: 'pending', createdAt: new Date().toISOString() };
  pendingConfirmations.set(id, record);
  return record;
}

/**
 * 人工确认审批（转调编排器）
 * @param {string} confirmationId
 * @param {'approve'|'reject'} decision
 */
async function confirmExecution(confirmationId, decision) {
  const { confirmExecution: orchestratedConfirm } = require('../agents/orchestrator');
  return orchestratedConfirm(confirmationId, decision);
}

function getPendingConfirmations() {
  const { getPendingConfirmations: getOrchestrated } = require('../agents/orchestrator');
  return getOrchestrated();
}

/**
 * 执行单步：失败自动重试 1 次，产出注入 context 合并
 */
async function executeStep(step, context) {
  // 中间结果合并：上一步的 task_id 注入缺失参数
  const params = { ...step.params };
  if (context.task_id && params.task_id === undefined && ['get_scan_results', 'get_baseline_results'].includes(step.tool)) {
    params.task_id = context.task_id;
  }
  if (step.tool === 'start_scan' && !params.created_by) params.created_by = context.userId || 1;

  const result = await aiService.executeTool(step.tool, params);
  let attempt = 1;
  while (!result.success && attempt < 2) {
    logger.warn(`[Agent] 步骤 ${step.tool} 失败，第 ${attempt + 1} 次重试: ${result.error}`);
    Object.assign(result, await aiService.executeTool(step.tool, params));
    attempt++;
  }
  if (result.data && result.data.task_id) context.task_id = result.data.task_id;
  return result;
}

/**
 * 运行多步 Agent
 * @param {string} task 用户任务描述
 * @param {object} opts { userId, plan? }
 */
async function runAgent(task, opts = {}) {
  const { runOrchestratedAgent } = require('../agents/orchestrator');
  return runOrchestratedAgent(task, opts);
}

/**
 * 总结：LLM 基于中间结果生成最终结论；失败时用规则模板
 */
async function summarize(task, goal, results) {
  const executed = results.filter((r) => !r.require_confirmation && r.success);
  if (executed.length === 0) {
    return results.some((r) => r.require_confirmation)
      ? '任务包含高危动作，等待人工确认后继续。'
      : '任务执行失败，未能产出有效结果。';
  }

  const digest = JSON.stringify(executed.map((r) => ({
    step: r.tool,
    summary: r.data ? (typeof r.data === 'object' ? JSON.stringify(r.data).substring(0, 1200) : String(r.data)) : (r.message || '')
  })), null, 2).substring(0, 6000);

  try {
    const resp = await aiService.callDeepSeek([
      {
        role: 'system',
        content: '你是安全运营智能体。基于以下各步骤执行结果，为用户的任务输出一份结构化中文总结，包含：关键发现、风险判断、建议措施。不要编造数据，只基于给定结果。'
      },
      { role: 'user', content: `任务：${task}\n目标：${goal || ''}\n执行结果：\n${digest}` }
    ], { temperature: 0.3, maxTokens: 2000 });
    const content = resp.data?.choices?.[0]?.message?.content;
    if (content) return content;
  } catch (err) {
    logger.warn(`[Agent] LLM 总结失败，使用模板: ${err.message}`);
  }

  // 模板汇总
  const lines = executed.map((r) => `- ${r.tool}: ${r.message || (r.data ? JSON.stringify(r.data).substring(0, 120) : '完成')}`);
  return `## 任务执行总结\n\n**任务**: ${task}\n\n已执行 ${executed.length} 个步骤：\n${lines.join('\n')}\n\n> 注：LLM 总结不可用，以上为规则汇总。`;
}

module.exports = {
  runAgent,
  confirmExecution,
  getPendingConfirmations,
  buildFallbackPlan,
  planWithLLM,
  _normalizePlan,
  AGENT_TOOL_CATALOG,
  HIGH_RISK_TOOLS
};
