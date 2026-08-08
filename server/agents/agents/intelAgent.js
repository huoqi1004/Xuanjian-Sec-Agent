/** 情报 Agent：威胁情报多源聚合 */
const { BaseAgent } = require('../baseAgent');
const { executeToolByName } = require('../tools/registry');

class IntelAgent extends BaseAgent {
  constructor() { super('intel', '威胁情报查询与关联'); }
  async run(ctx) {
    const iocType = ctx.get('ioc_type') || 'ip';
    const value = ctx.get('ioc_value') || '185.220.101.34';
    const result = await executeToolByName('get_threat_intel', { iocType, value });
    ctx.set('intel', result.data);
    return result;
  }
}
module.exports = IntelAgent;
