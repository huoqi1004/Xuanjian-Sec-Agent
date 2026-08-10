const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const { authMiddleware } = require('../middleware/auth');
const { tenantScope } = require('../middleware/tenant');
const { checkPermission } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { success, fail, asyncHandler } = require('../utils/helpers');
const multiEngineScanService = require('../services/multiEngineScanService');
const aiService = require('../services/aiService');

const router = express.Router();
router.use(authMiddleware);
// N-01/N-02：注入租户上下文，扫描记录/报告按组织与对象级过滤
router.use(tenantScope);

// 允许上传的文件类型白名单（常见可检测类型）
const ALLOWED_EXTENSIONS = new Set([
  'exe', 'dll', 'sys', 'bin', 'bat', 'cmd', 'com', 'scr', 'msi', 'ps1', 'vbs', 'js', 'jar',
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'txt', 'csv',
  'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'iso', 'img', 'apk', 'dmg', 'deb', 'rpm', 'elf', 'so', 'py'
]);

// 配置文件上传
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = './uploads/virus';
        if (!require('fs').existsSync(dir)) {
            require('fs').mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        // 随机文件名，避免路径穿越/覆盖与文件名注入
        const ext = (path.extname(file.originalname || '') || '').toLowerCase().replace(/[^a-z0-9.]/g, '');
        cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
    fileFilter: (req, file, cb) => {
        const ext = (path.extname(file.originalname || '') || '').replace('.', '').toLowerCase();
        if (!ALLOWED_EXTENSIONS.has(ext)) {
            return cb(null, false); // 拒绝上传，由 handler 返回明确提示
        }
        cb(null, true);
    }
});

/**
 * POST /api/virus/upload - 上传文件进行病毒查杀
 */
router.post('/upload', upload.single('file'), checkPermission('POST'), auditLog('virus_upload'), asyncHandler(async (req, res) => {
    if (!req.file) return fail(res, '未上传文件或文件类型不受支持（请使用可执行文件/文档/压缩包等常见格式）');

    const result = await multiEngineScanService.scanFile(req.file, req.user.id);
    return success(res, result, '文件扫描完成');
}));

/**
 * GET /api/virus/scan-history - 获取历史扫描记录
 */
router.get('/scan-history', checkPermission('GET'), asyncHandler(async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 20;

    const records = multiEngineScanService.getScanHistory(page, pageSize, req.tenant);
    return success(res, records);
}));

/**
 * GET /api/virus/report/:scanId - 获取扫描报告
 */
router.get('/report/:scanId', checkPermission('GET'), asyncHandler(async (req, res) => {
    const report = multiEngineScanService.getScanReport(req.params.scanId, req.tenant);
    if (!report) return fail(res, '未找到扫描报告或无权访问');
    return success(res, report);
}));

/**
 * POST /api/virus/analyze-hash - 根据哈希查询病毒信息
 */
router.post('/analyze-hash', checkPermission('GET'), auditLog('virus_analyze_hash'), asyncHandler(async (req, res) => {
    const { hash, hashType = 'md5' } = req.body;
    if (!hash) return fail(res, '请提供文件哈希值');

    const { getDb } = require('../db/database');
    const db = getDb();
    const records = db.prepare('SELECT * FROM virus_hashes WHERE hash_value = ? AND hash_type = ?').all(hash, hashType);
    return success(res, records);
}));

/**
 * POST /api/virus/export-report - 导出AI查杀报告
 */
router.post('/export-report', checkPermission('GET'), auditLog('virus_export_report'), asyncHandler(async (req, res) => {
    const { scanId, format = 'markdown' } = req.body;
    if (!scanId) return fail(res, '请提供扫描ID');

    const scanData = multiEngineScanService.getScanReport(scanId, req.tenant);
    if (!scanData) return fail(res, '未找到扫描记录或无权访问');

    try {
        const report = await aiService.generateVirusReport({
            fileName: scanData.file.originalname || 'unknown',
            fileSize: scanData.file.size || 0,
            hashes: scanData.hashes || {},
            engineSummary: scanData.decision.engineSummary || [],
            decision: scanData.decision,
            scanTime: scanData.scannedAt,
            totalTime: scanData.totalTime || '0'
        });

        return success(res, {
            report,
            format,
            scanId,
            fileName: scanData.file.originalname || 'unknown'
        }, '报告生成成功');
    } catch (e) {
        return fail(res, `报告生成失败: ${e.message}`);
    }
}));

/**
 * POST /api/virus/ai-scan - AI驱动智能查杀
 * 根据文件特征自动选择最佳查杀策略
 */
router.post('/ai-scan', upload.single('file'), checkPermission('POST'), auditLog('virus_ai_scan'), asyncHandler(async (req, res) => {
    if (!req.file) return fail(res, '未上传文件或文件类型不受支持（请使用可执行文件/文档/压缩包等常见格式）');

    const result = await multiEngineScanService.scanFile(req.file, req.user.id);
    return success(res, result, 'AI智能查杀完成');
}));

/**
 * POST /api/virus/llm-scan - LLM 驱动智能病毒查杀
 * 7引擎并行扫描 + LLM深度分析 + 自动生成处置方案
 */
router.post('/llm-scan', upload.single('file'), checkPermission('POST'), auditLog('virus_llm_scan'), asyncHandler(async (req, res) => {
    if (!req.file) return fail(res, '未上传文件或文件类型不受支持（请使用可执行文件/文档/压缩包等常见格式）');

    const llmVirusScan = require('../services/llmVirusScanService');
    const result = await llmVirusScan.runLLMVirusScan(req.file, req.user.id);
    return success(res, result, 'LLM智能查杀完成');
}));

/**
 * POST /api/virus/schedule-scan - 手动触发定时扫描任务
 * 扫描 VIRUS_SCAN_WATCH_DIRS 配置的所有目录
 */
router.post('/schedule-scan', checkPermission('POST'), auditLog('virus_schedule_scan'), asyncHandler(async (req, res) => {
    const { runScanTask } = require('../services/virusScanScheduler');
    const summary = await runScanTask();
    return success(res, summary, '定时扫描任务完成');
}));

/**
 * GET /api/virus/hash-list - 获取病毒哈希列表
 */
router.get('/hash-list', checkPermission('GET'), asyncHandler(async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 20;
    const search = req.query.search || '';

    const { getDb } = require('../db/database');
    const db = getDb();
    const offset = (page - 1) * pageSize;

    const whereClause = search ? `WHERE (virus_name LIKE ? OR threat_level LIKE ? OR source LIKE ?)` : '';
    const params = search ? [`%${search}%`, `%${search}%`, `%${search}%`] : [];

    const records = db.prepare(`SELECT * FROM virus_hashes ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, pageSize, offset);
    const total = db.prepare(`SELECT COUNT(*) as cnt FROM virus_hashes ${whereClause}`).get(...params).cnt;

    return success(res, { list: records, total, page, pageSize });
}));

module.exports = router;
