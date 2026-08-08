const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const { checkPermission } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { success, fail, asyncHandler } = require('../utils/helpers');
const situationalService = require('../services/situationalService');

const router = express.Router();

router.use(authMiddleware);

/**
 * GET /api/situational/dashboard - 获取态势感知仪表盘数据
 */
router.get('/dashboard', checkPermission('GET'), asyncHandler(async (req, res) => {
  const dashboard = await situationalService.getDashboard();
  return success(res, dashboard);
}));

/**
 * GET /api/situational/alerts - 获取告警列表
 */
router.get('/alerts', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { page = 1, pageSize = 10, severity, status } = req.query;
  const result = situationalService.getAlerts(parseInt(page), parseInt(pageSize), severity, status);
  return success(res, result.list);
}));

/**
 * PUT /api/situational/alerts/:id - 更新告警状态
 */
router.put('/alerts/:id', checkPermission('PUT'), auditLog('alert_update'), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!['acknowledged', 'resolved', 'false_positive'].includes(status)) {
    return fail(res, '无效的告警状态');
  }

  situationalService.updateAlertStatus(parseInt(id), status);
  return success(res, null, '告警状态已更新');
}));

/**
 * GET /api/situational/threat-intel - 获取威胁情报
 */
router.get('/threat-intel', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { ioc_type, page = 1, pageSize = 20 } = req.query;
  const intel = situationalService.getThreatIntel(ioc_type, parseInt(page), parseInt(pageSize));
  return success(res, intel);
}));

/**
 * POST /api/situational/report - 生成安全报告
 */
router.post('/report', checkPermission('POST'), auditLog('report_generate'), asyncHandler(async (req, res) => {
  const { title, type, time_range } = req.body;
  const report = await situationalService.generateReport(title, type, time_range, req.user.id);
  return success(res, report, '报告生成完成');
}));

/**
 * GET /api/situational/reports - 获取报告列表
 */
router.get('/reports', checkPermission('GET'), asyncHandler(async (req, res) => {
  const reportService = require('../services/reportService');
  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 20;
  const result = reportService.getReports(page, pageSize, req.query.type);
  return success(res, result.list || result);
}));

/**
 * GET /api/situational/reports/:id - 获取报告详情
 */
router.get('/reports/:id', checkPermission('GET'), asyncHandler(async (req, res) => {
  const reportService = require('../services/reportService');
  const report = reportService.getReportDetail(parseInt(req.params.id));
  if (!report) return fail(res, '报告不存在');
  return success(res, report);
}));

module.exports = router;
