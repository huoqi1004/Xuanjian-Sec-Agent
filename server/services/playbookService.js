/**
 * 玄鉴安全智能体 - SOAR 剧本引擎（对应 ROADMAP 4.17）
 *
 * Playbook = { name, description, trigger, steps }
 * 步骤类型：
 * - condition:   条件判断（fact/operator/value），不满足则终止（skipped）
 * - action:      动作适配器（firewall_block/account_lock/raise_alert/notify/webhook/log_only）
 * - approval:    人工审批，挂起剧本等待审批，批准后自动继续剩余步骤
 * - notification: 邮件/Webhook 通知
 * - wait:        等待（秒）
 * 参数模板：action params 中 "{{fact}}" 引用触发事件的字段。
 */

const { randomUUID } = require('crypto');
const { getDb } = require('../db/database');
const { runAction } = require('./adapters');
const notifyService = require('./notifyService');
const logger = require('../utils/logger');
const { sleep } = require('../utils/helpers');
const metrics = require('../utils/metrics');

/** 剧本模板库（seed 到 playbooks 表） */
const PLAYBOOK_TEMPLATES = [
  {
    name: '暴力破解自动防御',
    description: '检测到暴力破解（失败次数>5）时自动封禁来源 IP 并发送告警通知',
    trigger: 'brute_force',
    steps: [
      { type: 'condition', name: '失败次数超限', fact: 'fail_count', operator: 'gt', value: 5 },
      { type: 'action', name: '封禁来源IP', action: 'firewall_block', params: { ip: '{{ip}}', duration: 1800 } },
      { type: 'notification', name: '发送告警通知', channel: 'all', message: '检测到暴力破解攻击，已自动封禁来源 IP' },
      { type: 'approval', name: '确认持久封禁', title: '是否对攻击源执行持久封禁（24小时）' }
    ]
  },
  {
    name: '恶意IP自动封禁',
    description: '命中高置信度威胁情报时自动封禁并通知',
    trigger: 'intel_match',
    steps: [
      { type: 'condition', name: '置信度达标', fact: 'confidence', operator: 'gte', value: 0.85 },
      { type: 'action', name: '封禁恶意IP', action: 'firewall_block', params: { ip: '{{ip}}', duration: 3600 } },
      { type: 'notification', name: '发送告警', channel: 'all', message: '命中已知恶意IP，已自动封禁' }
    ]
  },
  {
    name: '勒索告警应急响应',
    description: '勒索软件告警触发紧急通知与人工隔离审批',
    trigger: 'ransomware',
    steps: [
      { type: 'condition', name: '严重级别达标', fact: 'severity', operator: 'eq', value: 'critical' },
      { type: 'notification', name: '紧急通知', channel: 'email', message: '检测到勒索软件事件，请立即处置', severity: 'critical' },
      { type: 'approval', name: '隔离审批', title: '是否对受影响主机执行隔离处置' },
      { type: 'action', name: '记录隔离动作', action: 'log_only', params: { message: '主机隔离动作已记录（需人工执行）' } }
    ]
  }
];

/** 人工审批登记表 */
const approvals = new Map();

/* ---------------- 条件评估 ---------------- */

function evaluateCondition(step, event) {
  const actual = event[step.fact];
  const expected = step.value;
  switch (step.operator) {
    case 'eq': case 'equal': return String(actual) === String(expected);
    case 'neq': case 'not_equal': return String(actual) !== String(expected);
    case 'gt': case 'greaterThan': return Number(actual) > Number(expected);
    case 'gte': case 'greaterThanInclusive': return Number(actual) >= Number(expected);
    case 'lt': case 'lessThan': return Number(actual) < Number(expected);
    case 'lte': case 'lessThanInclusive': return Number(actual) <= Number(expected);
    case 'contains': return String(actual || '').includes(String(expected));
    case 'in': return Array.isArray(expected) ? expected.includes(actual) : false;
    default: return true;
  }
}

/** 模板引用替换：params 中 "{{fact}}" 从触发事件取值 */
function replaceTokens(params, event) {
  const out = {};
  for (const [k, v] of Object.entries(params || {})) {
    if (typeof v === 'string' && v.startsWith('{{') && v.endsWith('}}')) {
      const key = v.slice(2, -2);
      out[k] = event[key] !== undefined ? event[key] : v;
    } else {
      out[k] = v;
    }
  }
  return out;
}

/* ---------------- 剧本 CRUD ---------------- */

function _parseSteps(playbook) {
  try { return JSON.parse(playbook.steps || '[]'); } catch (e) { return []; }
}

function listPlaybooks(page = 1, pageSize = 20, enabled, tenant) {
  const db = getDb();
  const offset = (page - 1) * pageSize;
  let rows = db.prepare('SELECT * FROM playbooks').all();
  if (enabled !== undefined && enabled !== '') {
    rows = rows.filter((r) => Number(r.enabled) === Number(enabled));
  }
  // N-02：非管理员仅可见本组织剧本
  const { inOrg } = require('../utils/tenantHelpers');
  rows = inOrg(rows, tenant, 'created_by');
  rows.sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));
  return {
    list: rows.slice(offset, offset + pageSize).map((r) => ({ ...r, steps: _parseSteps(r) })),
    total: rows.length,
    page,
    pageSize
  };
}

function getPlaybook(id, tenant) {
  const db = getDb();
  const row = db.prepare('SELECT * FROM playbooks WHERE id = ?').get(id);
  if (!row) return null;
  // N-01/N-02：非管理员仅可访问本组织剧本
  if (!require('../utils/tenantHelpers').inOrg([row], tenant, 'created_by').length) return null;
  return { ...row, steps: _parseSteps(row) };
}

function createPlaybook(data, userId = 1) {
  const { name, description = '', trigger = 'manual', steps = [] } = data;
  if (!name) throw new Error('剧本名称不能为空');
  const db = getDb();
  const result = db.prepare(
    'INSERT INTO playbooks (name, description, trigger, steps, enabled, created_by) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(name, description, trigger, JSON.stringify(steps), 1, userId);
  return { id: result.lastInsertRowid, name, trigger };
}

function updatePlaybook(id, data) {
  const db = getDb();
  const existing = db.prepare('SELECT * FROM playbooks WHERE id = ?').get(id);
  if (!existing) throw new Error('剧本不存在');
  const { name, description, trigger, steps, enabled } = data;
  const updates = [];
  const values = [];
  if (name !== undefined) { updates.push('name = ?'); values.push(name); }
  if (description !== undefined) { updates.push('description = ?'); values.push(description); }
  if (trigger !== undefined) { updates.push('trigger = ?'); values.push(trigger); }
  if (steps !== undefined) { updates.push('steps = ?'); values.push(JSON.stringify(steps)); }
  if (enabled !== undefined) { updates.push('enabled = ?'); values.push(enabled ? 1 : 0); }
  if (updates.length === 0) return { changes: 0 };
  updates.push('updated_at = CURRENT_TIMESTAMP');
  values.push(id);
  return db.prepare(`UPDATE playbooks SET ${updates.join(', ')} WHERE id = ?`).run(...values);
}

function deletePlaybook(id) {
  const db = getDb();
  return db.prepare('DELETE FROM playbooks WHERE id = ?').run(id);
}

/** 幂等导入剧本模板 */
function seedTemplates() {
  const db = getDb();
  const existing = db.prepare('SELECT name FROM playbooks').all();
  const existingNames = new Set(existing.map((r) => r.name));
  let seeded = 0;
  for (const tpl of PLAYBOOK_TEMPLATES) {
    if (existingNames.has(tpl.name)) continue;
    db.prepare('INSERT INTO playbooks (name, description, trigger, steps, enabled, created_by) VALUES (?, ?, ?, ?, ?, ?)')
      .run(tpl.name, tpl.description, tpl.trigger, JSON.stringify(tpl.steps), 1, 1);
    seeded++;
  }
  // 确保管理员拥有剧本管理权限（role_permissions 无唯一约束，需手动判重）
  const perms = db.prepare('SELECT * FROM role_permissions WHERE role_id = ?').all(1);
  if (!perms.some((p) => p.resource === '/api/playbook')) {
    db.prepare('INSERT INTO role_permissions (role_id, resource, actions) VALUES (?, ?, ?)')
      .run(1, '/api/playbook', '["GET","POST","PUT","DELETE"]');
  }
  if (seeded > 0) logger.info(`[SOAR] 已导入 ${seeded} 个剧本模板`);
  return seeded;
}

/* ---------------- 执行引擎 ---------------- */

/**
 * 执行剧本
 * 默认将执行任务入队（playbook_run 队列），由处理器异步执行步骤循环，返回 { queued: true, run_id }；
 * 传 opts.sync = true 时同步执行（测试/内部使用），返回完整执行结果。
 * @param {number} playbookId
 * @param {object} event 触发事件上下文（{ ip, severity, confidence, fail_count, asset, ... }）
 * @param {number|object} userId 用户 ID（旧签名），或 opts 对象 { userId, sync, tenant }
 * @param {string} tenant
 * @param {object} opts { sync }
 */
async function execute(playbookId, event = {}, userId = 1, tenant, opts = {}) {
  // 兼容：第 3 参数可为旧式数字 userId，也可为 opts 对象（新调用方传 { userId, sync, tenant }）
  if (userId && typeof userId === 'object') {
    opts = userId;
    userId = opts.userId || 1;
    tenant = opts.tenant || tenant;
  }
  const db = getDb();
  const playbook = db.prepare('SELECT * FROM playbooks WHERE id = ?').get(playbookId);
  if (!playbook) return { success: false, error: '剧本不存在' };
  // N-02：非管理员仅可触发本组织剧本
  if (!require('../utils/tenantHelpers').inOrg([playbook], tenant, 'created_by').length) {
    return { success: false, error: '无权访问该剧本' };
  }
  if (!Number(playbook.enabled)) return { success: false, error: '剧本未启用' };
  const steps = _parseSteps(playbook);
  if (steps.length === 0) return { success: false, error: '剧本步骤为空' };

  // 同步执行（测试/内部使用）
  if (opts.sync) {
    return _executeSteps(playbookId, event, { userId, fromApproval: false });
  }

  // 默认异步：入队 playbook_run，由处理器执行步骤循环
  const runId = `run_${randomUUID().slice(0, 8)}`;
  const { getQueue } = require('./queue');
  await getQueue().add('playbook_run', { playbookId, event, userId, fromApproval: false, runId }, { attempts: 1 });
  metrics.inc('soar_runs_total', { trigger: playbook.trigger, status: 'queued' }, 1, 'SOAR 剧本执行次数');
  logger.info(`[SOAR] 剧本「${playbook.name}」执行任务已入队（run=${runId}）`);
  return { success: true, queued: true, run_id: runId, playbook_id: playbook.id, playbook_name: playbook.name };
}

/**
 * 剧本步骤执行循环（playbook_run 处理器与同步执行共用）
 * @param {number} playbookId
 * @param {object} event 触发事件上下文
 * @param {object} opts { userId, fromApproval, startIndex, runId }
 */
async function _executeSteps(playbookId, event = {}, opts = {}) {
  const { userId = 1, fromApproval = false, startIndex = 0, runId } = opts;
  const db = getDb();
  const playbook = db.prepare('SELECT * FROM playbooks WHERE id = ?').get(playbookId);
  if (!playbook) return { success: false, error: '剧本不存在' };

  const steps = _parseSteps(playbook);
  if (steps.length === 0) return { success: false, error: '剧本步骤为空' };

  const finalRunId = runId || `run_${randomUUID().slice(0, 8)}`;
  // 审批续跑：携带审批人上下文
  if (fromApproval && !event.approved_by) event = { ...event, approved_by: userId };

  const results = [];
  let status = 'completed';

  for (let i = startIndex; i < steps.length; i++) {
    const step = steps[i];
    try {
      if (step.type === 'condition') {
        const ok = evaluateCondition(step, event);
        results.push({ step: i, type: 'condition', name: step.name || step.fact, ok });
        if (!ok) { status = 'skipped'; break; }
      } else if (step.type === 'action') {
        const r = await runAction(step.action, replaceTokens(step.params, event));
        results.push({ step: i, type: 'action', name: step.name || step.action, ...r });
        if (!r.success) { status = 'failed'; break; }
      } else if (step.type === 'notification') {
        await notifyService.send({
          channel: step.channel || 'all',
          message: step.message || 'SOAR 剧本通知',
          severity: event.severity || 'medium',
          target: event.asset || ''
        });
        results.push({ step: i, type: 'notification', name: step.name || '通知', success: true });
      } else if (step.type === 'approval') {
        const approval = _createApproval(playbook.id, i, step, userId);
        results.push({ step: i, type: 'approval', name: step.name || '人工审批', approval_id: approval.id, status: 'pending' });
        status = 'awaiting_approval';
        break;
      } else if (step.type === 'wait') {
        await sleep((Number(step.seconds) || 1) * 1000);
        results.push({ step: i, type: 'wait', name: step.name || '等待', success: true });
      } else {
        results.push({ step: i, type: step.type, name: step.name, success: false, error: `未知步骤类型: ${step.type}` });
        status = 'failed';
        break;
      }
    } catch (err) {
      results.push({ step: i, type: step.type || 'unknown', name: step.name, success: false, error: err.message });
      status = 'failed';
      break;
    }
  }

  _logRun(playbook, finalRunId, status, results.length, userId);
  metrics.inc('soar_runs_total', { trigger: playbook.trigger, status }, 1, 'SOAR 剧本执行次数');
  logger.info(`[SOAR] 剧本「${playbook.name}」执行完成（run=${finalRunId}），状态=${status}`);
  return { success: true, run_id: finalRunId, playbook_id: playbook.id, playbook_name: playbook.name, status, results };
}

function _logRun(playbook, runId, status, stepCount, userId) {
  try {
    const db = getDb();
    db.prepare('INSERT INTO action_logs (policy_id, action_type, action_detail, result) VALUES (?, ?, ?, ?)')
      .run(playbook.id, 'playbook_run', JSON.stringify({ runId, status, step_count: stepCount, by: userId }), status);
  } catch (err) {
    logger.warn(`[SOAR] 剧本运行日志落库失败: ${err.message}`);
  }
}

/* ---------------- 人工审批 ---------------- */

function _createApproval(playbookId, stepIndex, step, userId) {
  const id = `appr_${randomUUID().slice(0, 8)}`;
  approvals.set(id, {
    id,
    playbookId,
    stepIndex,
    title: step.title || '剧本步骤审批',
    userId,
    status: 'pending',
    createdAt: new Date().toISOString()
  });
  return approvals.get(id);
}

function getPendingApprovals() {
  return [...approvals.values()].filter((a) => a.status === 'pending');
}

/**
 * 审批处理：批准后自动继续执行剧本剩余步骤
 */
async function confirmApproval(approvalId, decision, reviewerId = 1) {
  const approval = approvals.get(approvalId);
  if (!approval) return { success: false, error: '审批请求不存在' };
  if (approval.status !== 'pending') return { success: false, error: '该审批已处理' };

  approval.status = decision === 'approve' ? 'approved' : 'rejected';
  approval.reviewedAt = new Date().toISOString();
  approval.reviewerId = reviewerId;

  if (decision === 'approve') {
    // 批准后继续执行剩余步骤（异步，不阻塞响应）
    _continueAfterApproval(approval, reviewerId);
  } else {
    logger.warn(`[SOAR] 审批被拒绝: ${approval.title}`);
  }
  return { success: true, data: { approval_id: approvalId, status: approval.status, title: approval.title } };
}

async function _continueAfterApproval(approval, reviewerId) {
  try {
    const db = getDb();
    const playbook = db.prepare('SELECT * FROM playbooks WHERE id = ?').get(approval.playbookId);
    if (!playbook) return;
    // 审批通过：将剩余步骤重新入队 playbook_run，由处理器继续执行（fromApproval: true）
    const { getQueue } = require('./queue');
    await getQueue().add('playbook_run', {
      playbookId: approval.playbookId,
      event: { approved_by: reviewerId },
      userId: reviewerId,
      fromApproval: true,
      startIndex: approval.stepIndex + 1
    }, { attempts: 1 });
    logger.info(`[SOAR] 审批通过，剧本续跑任务已入队（approval=${approval.id}，playbook=${approval.playbookId}）`);
  } catch (err) {
    logger.error(`[SOAR] 审批后续执行入队失败: ${err.message}`);
  }
}

module.exports = {
  PLAYBOOK_TEMPLATES,
  listPlaybooks,
  getPlaybook,
  createPlaybook,
  updatePlaybook,
  deletePlaybook,
  seedTemplates,
  execute,
  _executeSteps,
  getPendingApprovals,
  confirmApproval,
  evaluateCondition,
  replaceTokens
};
