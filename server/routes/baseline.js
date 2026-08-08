const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const { checkPermission } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { success, fail, asyncHandler } = require('../utils/helpers');
const baselineService = require('../services/baselineService');

const router = express.Router();

router.use(authMiddleware);

/**
 * GET /api/baseline/policies - 获取基线策略列表
 */
router.get('/policies', checkPermission('GET'), asyncHandler(async (req, res) => {
  const policies = baselineService.getPolicies();
  return success(res, policies);
}));

/**
 * GET /api/baseline/policies/:id - 获取策略详情
 */
router.get('/policies/:id', checkPermission('GET'), asyncHandler(async (req, res) => {
  const baselineService = require('../services/baselineService');
  const policy = baselineService.getPolicyById(parseInt(req.params.id));
  if (!policy) return fail(res, '策略不存在');
  return success(res, policy);
}));

/**
 * POST /api/baseline/check - 启动基线检查
 */
router.post('/check', checkPermission('POST'), auditLog('baseline_check'), asyncHandler(async (req, res) => {
  const { policy_id, host_id } = req.body;

  if (!policy_id) {
    return fail(res, '策略ID不能为空');
  }

  const result = baselineService.runCheck(policy_id, host_id, req.user.id);
  return success(res, result, '基线检查已启动');
}));

/**
 * GET /api/baseline/results/:taskId - 获取检查结果
 */
router.get('/results/:taskId', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { taskId } = req.params;
  const results = baselineService.getResults(taskId);
  return success(res, results);
}));

/**
 * GET /api/baseline/report/:taskId - 生成合规报告
 */
router.get('/report/:taskId', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { taskId } = req.params;
  const report = await baselineService.generateReport(taskId);
  return success(res, report);
}));

/**
 * GET /api/baseline/checks - 获取基线策略列表（别名）
 */
router.get('/checks', checkPermission('GET'), asyncHandler(async (req, res) => {
  const policies = baselineService.getPolicies();
  return success(res, policies);
}));

/**
 * POST /api/baseline/execute - 启动基线检查（别名）
 */
router.post('/execute', checkPermission('POST'), auditLog('baseline_check'), asyncHandler(async (req, res) => {
  const { policy_id, host_id } = req.body;

  if (!policy_id) {
    return fail(res, '策略ID不能为空');
  }

  const result = baselineService.runCheck(policy_id, host_id, req.user.id);
  return success(res, result, '基线检查已启动');
}));

module.exports = router;
