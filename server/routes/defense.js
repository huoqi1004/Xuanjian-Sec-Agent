const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const { checkPermission, adminOnly } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { success, fail, asyncHandler } = require('../utils/helpers');
const defenseService = require('../services/defenseService');
const { getDb } = require('../db/database');

const router = express.Router();

router.use(authMiddleware);

/**
 * GET /api/defense/policies - 获取防御策略列表
 */
router.get('/policies', checkPermission('GET'), asyncHandler(async (req, res) => {
  const policies = defenseService.getPolicies();
  return success(res, policies);
}));

/**
 * POST /api/defense/policies - 创建防御策略
 */
router.post('/policies', checkPermission('POST'), auditLog('policy_create'), asyncHandler(async (req, res) => {
  const { name, description, conditions, actions, cooldown, unattended } = req.body;

  if (!name) {
    return fail(res, '策略名称不能为空');
  }

  const policy = defenseService.createPolicy({
    name,
    description,
    conditions: JSON.stringify(conditions || []),
    actions: JSON.stringify(actions || []),
    cooldown,
    unattended,
    created_by: req.user.id
  });

  return success(res, policy, '策略创建成功');
}));

/**
 * PUT /api/defense/policies/:id - 更新策略
 */
router.put('/policies/:id', checkPermission('PUT'), auditLog('policy_update'), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  const policy = defenseService.updatePolicy(parseInt(id), updates);
  if (!policy) {
    return fail(res, '策略不存在');
  }

  return success(res, policy, '策略更新成功');
}));

/**
 * DELETE /api/defense/policies/:id - 删除策略
 */
router.delete('/policies/:id', checkPermission('DELETE'), auditLog('policy_delete'), asyncHandler(async (req, res) => {
  const { id } = req.params;
  defenseService.deletePolicy(parseInt(id));
  return success(res, null, '策略已删除');
}));

/**
 * GET /api/defense/action-logs - 获取动作日志
 */
router.get('/action-logs', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { page = 1, pageSize = 10, policy_id } = req.query;
  const logs = defenseService.getActionLogs(parseInt(page), parseInt(pageSize), policy_id);
  return success(res, logs);
}));

/**
 * POST /api/defense/approvals/:id - 审批策略
 */
router.post('/approvals/:id', checkPermission('POST'), auditLog('policy_approve'), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { status, risk_assessment } = req.body;

  if (!['approved', 'rejected'].includes(status)) {
    return fail(res, '无效的审批状态');
  }

  const result = defenseService.approvePolicy(parseInt(id), status, risk_assessment, req.user.id);
  if (!result) {
    return fail(res, '审批记录不存在');
  }

  return success(res, result, '审批完成');
}));

/**
 * GET /api/defense/pending-approvals - 获取待审批策略列表
 */
router.get('/pending-approvals', checkPermission('GET'), asyncHandler(async (req, res) => {
    const db = getDb();
    const pending = db.prepare(`
        SELECT p.*, pa.id as approval_id, pa.created_at as request_date,
               u.username as requester_name
        FROM auto_policies p
        JOIN policy_approvals pa ON pa.policy_id = p.id
        LEFT JOIN users u ON u.id = pa.requester_id
        WHERE pa.status = 'pending'
        ORDER BY pa.created_at DESC
    `).all();
    return success(res, pending);
}));

module.exports = router;
