/** 防御 Agent：高危动作 + 人工确认（approve/reject） */
const { BaseAgent } = require('../baseAgent');
const { randomUUID } = require('crypto');
const { executeToolByName } = require('../tools/registry');

const HIGH_RISK_TOOLS = new Set(['block_ip', 'account_lock', 'delete_scan_task', 'delete_user', 'disable_policy', 'run_playbook']);
const pendingConfirmations = new Map();

class DefenseAgent extends BaseAgent {
  constructor() { super('defense', '防御动作执行与人工确认'); }
  async run(ctx) {
    const plan = ctx.get('plan') || { steps: [] };
    const confirmations = [];
    for (const step of plan.steps) {
      if (HIGH_RISK_TOOLS.has(step.tool)) {
        const id = `cfm_${randomUUID().slice(0, 8)}`;
        pendingConfirmations.set(id, {
          id, taskId: ctx.runId, tool: step.tool, params: step.params,
          reason: step.reason, status: 'pending', createdAt: new Date().toISOString()
        });
        confirmations.push({ tool: step.tool, confirmation_id: id, require_confirmation: true });
        break; // 高危动作暂停后续步骤，等待人工确认
      }
      const result = await executeToolByName(step.tool, step.params);
      confirmations.push({ tool: step.tool, ...result });
    }
    ctx.set('confirmations', confirmations);
    return {
      success: true,
      data: { confirmations, confirmation_required: confirmations.some((c) => c.require_confirmation) },
      message: `处理 ${confirmations.length} 个防御动作`
    };
  }
}

/** 人工确认审批（兼容 agentService.confirmExecution 语义） */
async function confirmExecution(confirmationId, decision) {
  const record = pendingConfirmations.get(confirmationId);
  if (!record) return { success: false, error: '确认请求不存在或已过期' };
  if (record.status !== 'pending') return { success: false, error: '该请求已处理' };
  if (decision !== 'approve') {
    record.status = 'rejected';
    record.reviewedAt = new Date().toISOString();
    return { success: true, data: { confirmation_id: confirmationId, status: 'rejected', message: '已拒绝执行' } };
  }
  record.status = 'approved';
  record.reviewedAt = new Date().toISOString();
  const result = await executeToolByName(record.tool, record.params);
  return { success: true, data: { confirmation_id: confirmationId, status: 'approved', result } };
}

function getPendingConfirmations() {
  return [...pendingConfirmations.values()].filter((r) => r.status === 'pending');
}

module.exports = { DefenseAgent, confirmExecution, getPendingConfirmations, HIGH_RISK_TOOLS };
