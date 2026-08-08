/** 扫描 Agent：发起扫描任务并查询结果 */
const { BaseAgent } = require('../baseAgent');
const { executeToolByName } = require('../tools/registry');

class ScanAgent extends BaseAgent {
  constructor() { super('scan', '网络资产扫描'); }
  async run(ctx) {
    const target = ctx.get('target_cidr') || '127.0.0.1';
    const ports = ctx.get('port_range') || '1-1024';
    const task = await executeToolByName('start_scan', { target_cidr: target, port_range: ports, created_by: ctx.userId || 1 });
    if (task.data && task.data.task_id) ctx.set('task_id', task.data.task_id);
    return task;
  }
}
module.exports = ScanAgent;
