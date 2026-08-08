/** 规划 Agent：LLM 生成计划，失败规则回退（复用 agentService 规划逻辑） */
const { BaseAgent } = require('../baseAgent');

class PlannerAgent extends BaseAgent {
  constructor() { super('planner', '任务拆解与执行计划生成'); }
  async run(ctx) {
    const agentService = require('../../services/agentService');
    let plan;
    try {
      plan = await agentService.planWithLLM(ctx.task);
    } catch (err) {
      plan = agentService.buildFallbackPlan(ctx.task);
    }
    ctx.set('plan', plan);
    return { success: true, data: plan, message: `生成 ${plan.steps.length} 步计划` };
  }
}
module.exports = PlannerAgent;
