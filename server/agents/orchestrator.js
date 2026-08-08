/**
 * 编排器：多 Agent 调度核心
 * 流程：解析任务 → 路由角色 → 按序执行（planner → [analyst/intel/scan] → reporter）
 *      → 高危动作交给 defense → 汇总 → 总结（LLM/模板）
 */
const { createContext } = require('./baseAgent');
const { getAgent } = require('./registry');
const { registerAgents } = require('./agents');
const { registerBuiltinTools } = require('./tools');
const { getPendingConfirmations, confirmExecution } = require('./agents/defenseAgent');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

registerAgents();
registerBuiltinTools();

/** 任务 → 角色路由表（关键词 → Agent 顺序） */
const ROUTES = [
  { match: /告警|研判|分析告警|root cause/i, agents: ['analyst'] },
  { match: /情报|威胁|IOC|ioc|哈希|hash/i, agents: ['intel'] },
  { match: /扫描|资产|端口/i, agents: ['scan'] },
  { match: /报告|周报|月报|日报/i, agents: ['reporter'] }
];
const DEFAULT_ROUTE = ['planner', 'executor'];

/** 汇总总结（LLM → 模板） */
async function summarize(task, plan, results) {
  const aiService = require('../services/aiService');
  const executed = (results || []).filter((r) => r && r.success);
  if (!executed.length) return '任务执行失败，未能产出有效结果。';
  const digest = JSON.stringify(executed.map((r) => ({
    step: r.tool,
    summary: r.data ? (typeof r.data === 'object' ? JSON.stringify(r.data).substring(0, 1200) : String(r.data)) : (r.message || '')
  }))).substring(0, 6000);
  try {
    const resp = await aiService.callDeepSeek([
      { role: 'system', content: '你是安全运营智能体。基于以下各步骤执行结果，输出结构化中文总结：关键发现、风险判断、建议措施。不编造数据。' },
      { role: 'user', content: `任务：${task}\n执行结果：\n${digest}` }
    ], { temperature: 0.3, maxTokens: 2000 });
    const content = resp.data?.choices?.[0]?.message?.content;
    if (content) return content;
  } catch (err) {
    logger.warn(`[Orchestrator] LLM 总结失败，使用模板: ${err.message}`);
  }
  const lines = executed.map((r) => `- ${r.tool}: ${r.message || (r.data ? JSON.stringify(r.data).substring(0, 120) : '完成')}`);
  return `## 任务执行总结\n\n**任务**: ${task}\n\n已执行 ${executed.length} 个步骤：\n${lines.join('\n')}\n\n> 注：LLM 总结不可用，以上为规则汇总。`;
}

async function runOrchestratedAgent(task, opts = {}) {
  const start = Date.now();
  metrics.inc('agent_runs_total', {}, 1, 'Agent 执行次数');
  const ctx = createContext(task, { userId: opts.userId });

  // 1. 规划：注入计划 或 PlannerAgent（LLM → 规则回退）
  let plan;
  if (opts.plan) {
    const { _normalizePlan } = require('../services/agentService');
    plan = _normalizePlan(opts.plan);
    ctx.set('plan', plan);
  } else {
    const planner = getAgent('planner');
    const r = await planner.execute(ctx);
    if (!r.success) return { success: false, error: '无法生成执行计划', plan: null };
    plan = ctx.get('plan');
  }
  if (!plan || !plan.steps.length) return { success: false, error: '无法为任务生成可执行计划', plan };

  // 2. 执行：ExecutorAgent 逐步执行工具（高危步骤跳过，交由 DefenseAgent 生成人工确认）
  const { HIGH_RISK_TOOLS } = require('./agents/defenseAgent');
  const safePlan = { ...plan, steps: plan.steps.filter((s) => !HIGH_RISK_TOOLS.has(s.tool)) };
  ctx.set('plan', safePlan);
  const executor = getAgent('executor');
  const execResult = await executor.execute(ctx);
  const results = (ctx.get('results') || []).map((r) => ({
    tool: r.tool, params: r.params, reason: r.reason, ...r
  }));

  // 3. 角色补充：按路由执行专属 Agent（analyst/intel/scan/reporter 可叠加）
  for (const route of ROUTES) {
    if (route.match.test(task)) {
      for (const agentName of route.agents) {
        const agent = getAgent(agentName);
        const r = await agent.execute(ctx);
        if (r.success) results.push({ tool: agentName, success: true, data: r.data, message: r.message });
      }
    }
  }

  // 4. 高危动作：DefenseAgent 生成人工确认（来自计划中的高危工具）
  ctx.set('plan', plan); // 恢复完整计划，供 defense 识别高危步骤
  const defense = getAgent('defense');
  const defenseResult = await defense.execute(ctx);
  const confirmations = (ctx.get('confirmations') || []).filter((c) => c.require_confirmation);
  if (confirmations.length) {
    results.push(...confirmations.map((c) => ({
      tool: c.tool, success: false, require_confirmation: true, confirmation_id: c.confirmation_id
    })));
  }

  // 5. 总结
  const summary = await summarize(task, plan, results);
  metrics.observe('agent_execution_duration', {}, (Date.now() - start) / 1000, 'Agent 执行耗时', { unit: 'seconds' });

  return {
    success: true,
    task_id: ctx.runId,
    plan,
    results,
    summary,
    confirmation_required: results.some((r) => r.require_confirmation),
    duration_ms: Date.now() - start
  };
}

module.exports = { runOrchestratedAgent, getPendingConfirmations, confirmExecution };
