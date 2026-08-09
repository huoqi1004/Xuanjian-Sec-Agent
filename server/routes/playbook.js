/**
 * SOAR 剧本路由（对应 ROADMAP 4.17）
 */
const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../middleware/auth');
const { tenantScope } = require('../middleware/tenant');
const { checkPermission, adminOnly } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { success, fail, asyncHandler } = require('../utils/helpers');
const playbookService = require('../services/playbookService');
const logger = require('../utils/logger');

router.use(authMiddleware);
// N-01/N-02：注入租户上下文，剧本列表/详情按组织过滤
router.use(tenantScope);

/* 静态路径需定义在 /:id 之前 */

/**
 * GET /api/playbook/list - 剧本列表
 */
router.get('/list', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { page = 1, pageSize = 20, enabled } = req.query;
  const result = playbookService.listPlaybooks(parseInt(page), parseInt(pageSize), enabled, req.tenant);
  return success(res, result);
}));

/**
 * GET /api/playbook/approvals/pending - 待审批列表
 */
router.get('/approvals/pending', checkPermission('GET'), asyncHandler(async (req, res) => {
  return success(res, playbookService.getPendingApprovals());
}));

/**
 * POST /api/playbook/approvals/:id - 审批处理（approve/reject）
 */
router.post('/approvals/:id', checkPermission('POST'), auditLog('playbook_approval'), asyncHandler(async (req, res) => {
  const { decision = 'approve' } = req.body;
  const result = await playbookService.confirmApproval(req.params.id, decision, req.user?.id || 1);
  if (!result.success) return fail(res, result.error);
  return success(res, result.data, '审批处理完成');
}));

/**
 * POST /api/playbook/templates/seed - 重新导入剧本模板（管理员）
 */
router.post('/templates/seed', adminOnly, asyncHandler(async (req, res) => {
  const seeded = playbookService.seedTemplates();
  return success(res, { seeded }, `模板导入完成（新增 ${seeded} 个）`);
}));

/* ---------------- 动态路径 ---------------- */

/**
 * GET /api/playbook/:id - 剧本详情
 */
router.get('/:id', checkPermission('GET'), asyncHandler(async (req, res) => {
  const playbook = playbookService.getPlaybook(parseInt(req.params.id), req.tenant);
  if (!playbook) return fail(res, '剧本不存在或无权访问');
  return success(res, playbook);
}));

/**
 * POST /api/playbook/:id/execute - 执行剧本
 */
router.post('/:id/execute', checkPermission('POST'), auditLog('playbook_execute'), asyncHandler(async (req, res) => {
  const { event = {} } = req.body;
  const result = await playbookService.execute(parseInt(req.params.id), event, req.user?.id || 1, req.tenant);
  if (!result.success) return fail(res, result.error);
  // N-07 Task B：execute 默认入队，data 为 { queued: true, run_id, ... }
  return success(res, result, result.queued ? '剧本执行任务已入队' : '剧本执行完成');
}));

/**
 * POST /api/playbook/create - 创建剧本（管理员）
 */
router.post('/create', adminOnly, auditLog('playbook_create'), asyncHandler(async (req, res) => {
  const playbook = playbookService.createPlaybook(req.body, req.user?.id || 1);
  return success(res, playbook, '剧本创建成功');
}));

/**
 * PUT /api/playbook/:id - 更新剧本（管理员）
 */
router.put('/:id', adminOnly, auditLog('playbook_update'), asyncHandler(async (req, res) => {
  const result = playbookService.updatePlaybook(parseInt(req.params.id), req.body);
  if (result.error) return fail(res, result.error);
  return success(res, null, '剧本已更新');
}));

/**
 * DELETE /api/playbook/:id - 删除剧本（管理员）
 */
router.delete('/:id', adminOnly, auditLog('playbook_delete'), asyncHandler(async (req, res) => {
  playbookService.deletePlaybook(parseInt(req.params.id));
  return success(res, null, '剧本已删除');
}));

module.exports = router;
