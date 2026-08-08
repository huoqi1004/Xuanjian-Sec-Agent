const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const { tenantScope } = require('../middleware/tenant');
const { checkPermission } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { success, fail, asyncHandler } = require('../utils/helpers');
const scanService = require('../services/scanService');

const router = express.Router();

// 所有扫描路由需要认证，并注入租户上下文（N-01/N-02）
router.use(authMiddleware);
router.use(tenantScope);

/**
 * POST /api/scan/start - 启动扫描任务（N-04：白名单校验 + 大任务审批）
 */
router.post('/start', checkPermission('POST'), auditLog('scan_start'), asyncHandler(async (req, res) => {
  const { target_cidr, scan_mode, port_range } = req.body;

  if (!target_cidr) {
    return fail(res, '扫描目标不能为空');
  }

  try {
    const task = await scanService.startScan({
      target_cidr,
      scan_mode: scan_mode || 'tcp_connect',
      port_range: port_range || '1-1024',
      created_by: req.user.id
    });

    return success(res, task, '扫描任务已启动');
  } catch (err) {
    if (err.code === 'SCAN_TARGET_DENIED') {
      // N-04：白名单外目标直接拒绝
      return fail(res, err.message);
    }
    if (err.message && err.message.includes('没有有效的')) {
      return fail(res, err.message);
    }
    throw err;
  }
}));

/**
 * POST /api/scan/tasks/:id/review - N-04 大型扫描任务人工审批（approve/reject，仅管理员）
 */
router.post('/tasks/:id/review', checkPermission('POST'), auditLog('scan_review'), asyncHandler(async (req, res) => {
  const { decision = 'approve' } = req.body;
  const { id } = req.params;
  if (!['approve', 'reject'].includes(decision)) {
    return fail(res, '审批决策仅支持 approve / reject');
  }

  // 仅管理员可审批大型扫描
  if (!req.tenant.isAdmin) {
    return fail(res, '仅管理员可审批扫描任务', 1, 403);
  }

  const result = scanService.reviewScanTask(id, decision, req.user.id);
  if (result.error) return fail(res, result.error);
  return success(res, { task_id: id, status: result.status }, decision === 'approve' ? '任务已批准，开始执行' : '任务已拒绝');
}));

/**
 * GET /api/scan/tasks - 获取扫描任务列表
 */
router.get('/tasks', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { page = 1, pageSize = 10, status } = req.query;
  const result = scanService.getTasks(parseInt(page), parseInt(pageSize), status, req.tenant);
  return success(res, result);
}));

/**
 * GET /api/scan/tasks/:id - 获取任务详情和结果
 */
router.get('/tasks/:id', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const task = scanService.getTaskDetail(id, req.tenant);
  if (!task) {
    return fail(res, '任务不存在或无权访问');
  }
  return success(res, task);
}));

/**
 * DELETE /api/scan/tasks/:id - 删除任务
 */
router.delete('/tasks/:id', checkPermission('DELETE'), auditLog('scan_delete'), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const result = scanService.deleteTask(id, req.tenant);
  if (result.error) {
    return fail(res, result.error);
  }
  return success(res, null, '任务已删除');
}));

module.exports = router;
