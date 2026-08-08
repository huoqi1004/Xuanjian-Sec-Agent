/** 研判 Agent：告警聚合去重 + 根因推断 + 处置建议（复用 copilotService 逻辑） */
const { BaseAgent } = require('../baseAgent');

class AnalystAgent extends BaseAgent {
  constructor() { super('analyst', '安全告警研判与根因分析'); }
  async run(ctx) {
    const copilotService = require('../../services/copilotService');
    const limit = ctx.get('limit') || 50;
    const result = await copilotService.triageAlerts(limit);
    ctx.set('triage', result);
    return { success: true, data: result, message: `研判 ${result.groups ? result.groups.length : 0} 组告警` };
  }
}
module.exports = AnalystAgent;
