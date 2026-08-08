const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const { checkPermission } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { success, fail, asyncHandler } = require('../utils/helpers');
const threatIntel = require('../services/threatIntelligence');
const situationalService = require('../services/situationalService');

const router = express.Router();

router.use(authMiddleware);

/**
 * POST /api/intel/query - 多源威胁情报聚合查询
 * Body: { iocType: 'ip|domain|hash|url', value: '...' }
 */
router.post('/query', checkPermission('GET'), auditLog('intel_query'), asyncHandler(async (req, res) => {
  const { iocType, value } = req.body;
  if (!iocType || !value) return fail(res, '请提供IOC类型和值');
  
  const validTypes = ['ip', 'domain', 'hash', 'url', 'cve'];
  if (!validTypes.includes(iocType)) return fail(res, '不支持的IOC类型');

  const result = await threatIntel.aggregateQuery(iocType, value);
  
  // 保存到本地威胁情报库
  const { getDb } = require('../db/database');
  const db = getDb();
  try {
    db.prepare(`
      INSERT OR REPLACE INTO threat_intel (ioc_type, ioc_value, source, confidence, description, updated_at)
      VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(iocType, value, 'MULTI-SOURCE', result.riskScore / 100, result.summary);
  } catch (e) {}

  return success(res, result);
}));

/**
 * GET /api/intel/sources - 获取数据源状态
 */
router.get('/sources', checkPermission('GET'), asyncHandler(async (req, res) => {
  const sources = threatIntel.getSourcesStatus();
  return success(res, sources);
}));

/**
 * POST /api/intel/threatbook - 单查微步TI
 */
router.post('/threatbook', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { iocType, value } = req.body;
  if (!iocType || !value) return fail(res, '请提供IOC类型和值');
  const result = await threatIntel.queryThreatBook(iocType, value);
  return success(res, result);
}));

/**
 * POST /api/intel/shodan - 单查Shodan
 */
router.post('/shodan', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { ip } = req.body;
  if (!ip) return fail(res, '请提供IP地址');
  const result = await threatIntel.queryShodan(ip);
  return success(res, result);
}));

/**
 * POST /api/intel/abuseipdb - 单查AbuseIPDB
 */
router.post('/abuseipdb', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { ip } = req.body;
  if (!ip) return fail(res, '请提供IP地址');
  const result = await threatIntel.queryAbuseIPDB(ip);
  return success(res, result);
}));

/**
 * POST /api/intel/virustotal - 单查VirusTotal
 */
router.post('/virustotal', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { iocType, value } = req.body;
  if (!iocType || !value) return fail(res, '请提供IOC类型和值');
  const result = await threatIntel.queryVirusTotal(iocType, value);
  return success(res, result);
}));

/**
 * POST /api/intel/gsb - 单查Google Safe Browsing
 */
router.post('/gsb', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { url } = req.body;
  if (!url) return fail(res, '请提供URL');
  const result = await threatIntel.queryGoogleSafeBrowsing(url);
  return success(res, result);
}));

/**
 * GET /api/intel/alerts-enhanced - 增强版告警查询（含外部情报）
 */
router.get('/alerts-enhanced', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { page = 1, pageSize = 10, severity } = req.query;
  const alerts = situationalService.getAlerts(parseInt(page), parseInt(pageSize), severity, null);
  
  // 对每条告警进行IP情报增强
  const enhanced = alerts.list.map(alert => {
    const ipMatch = alert.description?.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    if (ipMatch) {
      alert.source_ip = ipMatch[1];
    }
    return alert;
  });

  return success(res, { list: enhanced, total: alerts.total, page: alerts.page, pageSize: alerts.pageSize });
}));

/**
 * POST /api/intel/batch-query - 批量威胁情报查询
 * Body: { queries: [{ iocType, value }, ...] }
 */
router.post('/batch-query', checkPermission('GET'), auditLog('intel_batch'), asyncHandler(async (req, res) => {
  const { queries = [] } = req.body;
  if (queries.length === 0 || queries.length > 50) return fail(res, '查询列表不能为空且不超过50条');
  
  const results = [];
  for (const q of queries) {
    try {
      const r = await threatIntel.aggregateQuery(q.iocType, q.value);
      results.push(r);
    } catch (e) {
      results.push({ iocType: q.iocType, value: q.value, error: e.message });
    }
  }

  return success(res, results);
}));

module.exports = router;
