/** 执行 Agent：按计划逐步调用工具注册表，中间结果注入，失败重试 1 次 */
const { BaseAgent } = require('../baseAgent');
const { executeToolByName } = require('../tools/registry');
const MAX_STEPS = 6;
const MAX_EXECUTION_MS = 120000;

class ExecutorAgent extends BaseAgent {
  constructor() { super('executor', '按计划逐步执行工具'); }
  async run(ctx) {
    const plan = ctx.get('plan') || { steps: [] };
    const start = Date.now();
    const results = [];
    for (const step of plan.steps.slice(0, MAX_STEPS)) {
      if (Date.now() - start > MAX_EXECUTION_MS) {
        results.push({ tool: step.tool, success: false, error: 'Agent 执行超时，已中止' });
        break;
      }
      const params = { ...step.params };
      if (ctx.has('task_id') && params.task_id === undefined &&
          ['get_scan_results', 'get_baseline_results'].includes(step.tool)) {
        params.task_id = ctx.get('task_id');
      }
      if (step.tool === 'start_scan' && !params.created_by) params.created_by = ctx.userId || 1;
      let result = await executeToolByName(step.tool, params);
      let attempt = 1;
      while (!result.success && attempt < 2) {
        attempt++;
        result = await executeToolByName(step.tool, params);
      }
      if (result.data && result.data.task_id) ctx.set('task_id', result.data.task_id);
      results.push({ tool: step.tool, params: step.params, reason: step.reason, ...result });
    }
    ctx.set('results', results);
    return { success: true, data: { results }, message: `执行 ${results.length} 个步骤` };
  }
}
module.exports = ExecutorAgent;
