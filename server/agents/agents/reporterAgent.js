/** 报告 Agent：生成安全报告（daily/weekly/monthly） */
const { BaseAgent } = require('../baseAgent');
const { executeToolByName } = require('../tools/registry');

class ReporterAgent extends BaseAgent {
  constructor() { super('reporter', '安全报告生成'); }
  async run(ctx) {
    const type = ctx.get('report_type') || 'daily';
    const result = await executeToolByName('generate_security_report', { type });
    ctx.set('report', result.data);
    return result;
  }
}
module.exports = ReporterAgent;
