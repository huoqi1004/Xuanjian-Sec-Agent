const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../middleware/auth');
const { tenantScope } = require('../middleware/tenant');
const { getDb } = require('../db/database');
const djppService = require('../services/djppService');
const reportService = require('../services/reportService');
const logger = require('../utils/logger');
const path = require('path');
const fs = require('fs');

router.use(authMiddleware);
// N-01/N-02：注入租户上下文，报告列表/详情/删除按组织与对象级过滤
router.use(tenantScope);

/** N-02：报告列表按组织过滤（reports.generated_by） */
function filterReportsByOrg(rows, tenant) {
  const { inOrg } = require('../utils/tenantHelpers');
  return inOrg(rows || [], tenant, 'generated_by');
}

/** N-01：对象级校验，非管理员仅本人生成的报告可访问 */
function isReportOwner(tenant, report) {
  return require('../utils/tenantHelpers').isOwner(tenant, report, 'generated_by');
}

router.get('/list', (req, res) => {
  try {
    const db = getDb();
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 20;
    const type = req.query.type;

    let whereClause = '';
    let params = [];
    if (type) {
      whereClause = 'WHERE r.type = ?';
      params.push(type);
    }

    const reports = filterReportsByOrg(db.prepare(`
      SELECT r.*, u.username as generated_by_name 
      FROM reports r 
      LEFT JOIN users u ON r.generated_by = u.id 
      ${whereClause}
      ORDER BY r.created_at DESC 
    `).all(...params), req.tenant);

    const total = reports.length;

    const typeLabels = {
      djpp: '等保测评报告',
      virus: '病毒查杀报告',
      baseline: '基线检查报告',
      scan: '安全扫描报告',
      weekly: '安全态势周报',
      monthly: '安全态势月报'
    };

    const reportList = reports.map(r => {
      let content = null;
      try {
        content = JSON.parse(r.content || '{}');
      } catch (e) {}
      return {
        id: r.id,
        reportId: r.id,
        title: r.title,
        type: r.type,
        typeLabel: typeLabels[r.type] || r.type,
        generatedBy: r.generated_by_name || '-',
        generatedAt: r.created_at,
        stats: content?.stats || null,
        hasMD: true,
        hasDOCX: r.has_docx || false
      };
    });

    res.json({ code: 0, data: { reports: reportList, total, page, pageSize } });
  } catch (err) {
    logger.error('获取报告列表失败:', err);
    res.status(500).json({ code: -1, message: '获取报告列表失败' });
  }
});

/**
 * GET /api/reports/export/csv?type=alerts|scan|baseline|reports - 批量导出 CSV
 */
router.get('/export/csv', (req, res) => {
  try {
    const { type = 'alerts' } = req.query;
    const db = getDb();
    const escape = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;

    let rows = [];
    let columns = [];
    let header = [];
    let filename = 'export';

    switch (type) {
      case 'scan':
        rows = db.prepare('SELECT * FROM scan_results ORDER BY created_at DESC').all();
        columns = ['id', 'task_id', 'ip', 'port', 'service', 'version', 'banner', 'state'];
        header = ['ID', '任务ID', 'IP', '端口', '服务', '版本', 'Banner', '状态'];
        filename = 'scan_results_export';
        break;
      case 'baseline':
        rows = db.prepare('SELECT * FROM baseline_results ORDER BY created_at DESC').all();
        columns = ['id', 'task_id', 'check_id', 'check_name', 'status', 'severity', 'remediation'];
        header = ['ID', '任务ID', '检查项ID', '检查项', '状态', '严重级别', '修复建议'];
        filename = 'baseline_export';
        break;
      case 'reports':
        rows = db.prepare('SELECT * FROM reports ORDER BY created_at DESC').all();
        columns = ['id', 'title', 'type', 'created_at'];
        header = ['ID', '标题', '类型', '生成时间'];
        filename = 'reports_export';
        break;
      case 'alerts':
      default:
        rows = db.prepare('SELECT * FROM alert_records ORDER BY created_at DESC').all();
        columns = ['id', 'related_asset', 'alert_type', 'severity', 'confidence', 'description', 'status', 'created_at'];
        header = ['ID', '关联资产', '告警类型', '严重级别', '置信度', '描述', '状态', '时间'];
        filename = 'alerts_export';
        break;
    }

    const lines = [header.map(escape).join(',')];
    for (const r of rows) {
      lines.push(columns.map((c) => escape(r[c])).join(','));
    }
    // BOM 前缀，兼容 Excel 中文
    const csv = '\ufeff' + lines.join('\r\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}_${new Date().toISOString().slice(0, 10)}.csv"`);
    res.send(csv);
  } catch (err) {
    logger.error('CSV 导出失败:', err);
    res.status(500).json({ code: -1, message: 'CSV 导出失败' });
  }
});

/**
 * GET /api/reports/overview - 数据大屏聚合数据（领导视图：合规态势/风险排行）
 */
router.get('/overview', (req, res) => {
  try {
    const db = getDb();
    const rowCount = (t) => (db._rawTable(t) || []).length;

    // 风险排行：按资产聚合告警严重度
    const alerts = db.prepare('SELECT * FROM alert_records').all();
    const riskMap = {};
    for (const a of alerts) {
      const asset = a.related_asset || 'unknown';
      if (!riskMap[asset]) riskMap[asset] = { asset, total: 0, critical: 0, high: 0, unresolved: 0 };
      riskMap[asset].total++;
      if (a.severity === 'critical') riskMap[asset].critical++;
      if (a.severity === 'high') riskMap[asset].high++;
      if (a.status === 'new') riskMap[asset].unresolved++;
    }
    const riskRanking = Object.values(riskMap)
      .sort((a, b) => (b.critical * 10 + b.high * 3 + b.unresolved) - (a.critical * 10 + a.high * 3 + a.unresolved))
      .slice(0, 10);

    // 合规态势：等保任务合规率
    const djppTasks = db._rawTable('djpp_tasks') || [];
    const djppResults = db._rawTable('djpp_results') || [];
    const passCount = djppResults.filter((r) => r.status === 'pass').length;
    const compliance = djppResults.length ? Math.round((passCount / djppResults.length) * 100) : 0;

    const summary = {
      alerts: alerts.length,
      unresolved_alerts: alerts.filter((a) => a.status === 'new').length,
      scan_tasks: rowCount('scan_tasks'),
      open_ports: (db._rawTable('scan_results') || []).filter((r) => r.state === 'open').length,
      virus_scans: rowCount('virus_scan_records'),
      threat_intel: rowCount('threat_intel'),
      baseline_checks: rowCount('baseline_results'),
      playbooks: rowCount('playbooks'),
      edge_devices: rowCount('edge_devices')
    };

    res.json({
      code: 0,
      data: {
        risk_ranking: riskRanking,
        compliance: { total_tasks: djppTasks.length, total_checks: djppResults.length, compliance_rate: compliance },
        summary
      }
    });
  } catch (err) {
    logger.error('获取数据大屏聚合失败:', err);
    res.status(500).json({ code: -1, message: '获取数据大屏聚合失败' });
  }
});

router.get('/stats', (req, res) => {
  try {
    const db = getDb();
    const stats = {
      total: 0,
      djpp: 0,
      virus: 0,
      baseline: 0,
      scan: 0,
      weekly: 0,
      monthly: 0
    };

    const totalResult = db.prepare('SELECT COUNT(*) as count FROM reports').get();
    stats.total = totalResult.count;

    const djppResult = db.prepare("SELECT COUNT(*) as count FROM reports WHERE type = 'djpp'").get();
    stats.djpp = djppResult.count;

    const virusResult = db.prepare("SELECT COUNT(*) as count FROM reports WHERE type = 'virus'").get();
    stats.virus = virusResult.count;

    const baselineResult = db.prepare("SELECT COUNT(*) as count FROM reports WHERE type = 'baseline'").get();
    stats.baseline = baselineResult.count;

    const scanResult = db.prepare("SELECT COUNT(*) as count FROM reports WHERE type = 'scan'").get();
    stats.scan = scanResult.count;

    const weeklyResult = db.prepare("SELECT COUNT(*) as count FROM reports WHERE type = 'weekly'").get();
    stats.weekly = weeklyResult.count;

    const monthlyResult = db.prepare("SELECT COUNT(*) as count FROM reports WHERE type = 'monthly'").get();
    stats.monthly = monthlyResult.count;

    res.json({ code: 0, data: stats });
  } catch (err) {
    logger.error('获取报告统计失败:', err);
    res.status(500).json({ code: -1, message: '获取报告统计失败' });
  }
});

router.post('/:reportId/generate-md', async (req, res) => {
  try {
    const { reportId } = req.params;
    const db = getDb();
    
    const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(reportId);
    if (!report) {
      return res.status(404).json({ code: -1, message: '报告不存在' });
    }
    if (!isReportOwner(req.tenant, report)) {
      return res.status(403).json({ code: -1, message: '无权访问该报告' });
    }

    let content = null;
    try {
      content = JSON.parse(report.content || '{}');
    } catch (e) {
      return res.status(400).json({ code: -1, message: '报告内容解析失败' });
    }

    let mdContent;
    if (report.type === 'djpp') {
      mdContent = reportService.generateDJPPReportMD(content);
    } else if (report.type === 'virus') {
      mdContent = reportService.generateScanReportMD(content);
    } else if (report.type === 'baseline') {
      mdContent = reportService.generateBaselineReportMD(content);
    } else if (report.type === 'weekly' || report.type === 'monthly') {
      mdContent = reportService.generateSituationalReportMD(content, report.type);
    } else {
      mdContent = reportService.generateDJPPReportMD(content);
    }

    const mdPath = path.join(reportService.REPORTS_DIR, `${reportId}_${Date.now()}.md`);
    fs.writeFileSync(mdPath, mdContent, 'utf-8');

    const relativePath = path.relative(path.resolve(__dirname, '../../'), mdPath);
    res.json({ 
      code: 0, 
      message: 'MD报告生成成功',
      data: { 
        mdPath: relativePath,
        downloadUrl: `/api/reports/download/${path.basename(mdPath)}`
      } 
    });
  } catch (err) {
    logger.error('MD报告生成失败:', err);
    res.status(500).json({ code: -1, message: 'MD报告生成失败: ' + err.message });
  }
});

router.post('/:reportId/generate-docx', async (req, res) => {
  try {
    const { reportId } = req.params;
    const db = getDb();
    
    const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(reportId);
    if (!report) {
      return res.status(404).json({ code: -1, message: '报告不存在' });
    }
    if (!isReportOwner(req.tenant, report)) {
      return res.status(403).json({ code: -1, message: '无权访问该报告' });
    }

    let content = null;
    try {
      content = JSON.parse(report.content || '{}');
    } catch (e) {
      return res.status(400).json({ code: -1, message: '报告内容解析失败' });
    }

    let docxPath;
    if (report.type === 'djpp') {
      docxPath = await reportService.generateDJPPReportDOCX(content);
    } else if (report.type === 'virus') {
      docxPath = await reportService.generateScanReportDOCX(content);
    } else if (report.type === 'weekly' || report.type === 'monthly') {
      docxPath = await reportService.generateSituationalReportDOCX(content, report.type);
    } else {
      docxPath = await reportService.generateDJPPReportDOCX(content);
    }

    const relativePath = path.relative(path.resolve(__dirname, '../../'), docxPath);
    
    db.prepare('UPDATE reports SET has_docx = 1 WHERE id = ?').run(reportId);

    res.json({ 
      code: 0, 
      message: 'DOCX报告生成成功',
      data: { 
        docxPath: relativePath,
        downloadUrl: `/api/reports/download/${path.basename(docxPath)}`
      } 
    });
  } catch (err) {
    logger.error('DOCX报告生成失败:', err);
    res.status(500).json({ code: -1, message: 'DOCX报告生成失败: ' + err.message });
  }
});

router.get('/download/:filename', (req, res) => {
  try {
    const { filename } = req.params;
    const filePath = path.join(reportService.REPORTS_DIR, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ code: -1, message: '文件不存在' });
    }

    res.download(filePath, filename);
  } catch (err) {
    logger.error('文件下载失败:', err);
    res.status(500).json({ code: -1, message: '文件下载失败' });
  }
});

router.get('/:reportId', (req, res) => {
  try {
    const { reportId } = req.params;
    const db = getDb();
    
    const report = db.prepare(`
      SELECT r.*, u.username as generated_by_name 
      FROM reports r 
      LEFT JOIN users u ON r.generated_by = u.id 
      WHERE r.id = ?
    `).get(reportId);

    if (!report) {
      return res.status(404).json({ code: -1, message: '报告不存在' });
    }
    if (!isReportOwner(req.tenant, report)) {
      return res.status(403).json({ code: -1, message: '无权访问该报告' });
    }

    let content = null;
    try {
      content = JSON.parse(report.content || '{}');
    } catch (e) {}

    res.json({ 
      code: 0, 
      data: {
        ...report,
        content
      } 
    });
  } catch (err) {
    logger.error('获取报告详情失败:', err);
    res.status(500).json({ code: -1, message: '获取报告详情失败' });
  }
});

router.delete('/:reportId', (req, res) => {
  try {
    const { reportId } = req.params;
    const db = getDb();
    
    const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(reportId);
    if (!report) {
      return res.status(404).json({ code: -1, message: '报告不存在' });
    }
    if (!isReportOwner(req.tenant, report)) {
      return res.status(403).json({ code: -1, message: '无权删除该报告' });
    }

    db.prepare('DELETE FROM reports WHERE id = ?').run(reportId);
    res.json({ code: 0, message: '报告删除成功' });
  } catch (err) {
    logger.error('删除报告失败:', err);
    res.status(500).json({ code: -1, message: '删除报告失败' });
  }
});

module.exports = router;