// 病毒扫描定时任务调度服务
// 功能：定时扫描上传目录文件，执行多引擎扫描 + LLM 分析
const fs = require('fs');
const path = require('path');
const { config } = require('../config');
const logger = require('../utils/logger');
const multiEngineScanService = require('./multiEngineScanService');
const llmVirusScanService = require('./llmVirusScanService');

const ALLOWED_EXTENSIONS = new Set([
  'exe', 'dll', 'sys', 'bin', 'bat', 'cmd', 'com', 'scr', 'msi', 'ps1', 'vbs', 'js', 'jar',
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'txt', 'csv',
  'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'iso', 'img', 'apk', 'dmg', 'deb', 'rpm', 'elf', 'so', 'py'
]);

/** 获取目录中待扫描的文件列表 */
function getFilesToScan(watchDirs) {
  const files = [];
  for (const dir of watchDirs) {
    try {
      if (!fs.existsSync(dir)) continue;
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isFile()) continue;
        const ext = path.extname(entry.name).toLowerCase().replace('.', '');
        if (!ALLOWED_EXTENSIONS.has(ext)) continue;
        const filePath = path.join(dir, entry.name);
        const stat = fs.statSync(filePath);
        files.push({
          path: filePath,
          originalname: entry.name,
          size: stat.size,
          mimetype: 'application/octet-stream',
          dir,
          stat
        });
      }
    } catch (err) {
      logger.warn(`读取扫描目录失败: ${dir}`, err.message);
    }
  }
  return files;
}

/** 执行单文件病毒扫描，并根据结果自动执行隔离/删除策略 */
async function scanFile(file, userId = 0) {
  try {
    const multiResult = await multiEngineScanService.scanFile(file, userId);

    const llmResult = await llmVirusScanService.runLLMVirusScan(file, userId);

    const verdict = llmResult.decision?.verdict || multiResult.decision?.verdict || 'unknown';
    const threatLevel = llmResult.llmAnalysis?.threat_level || multiResult.decision?.verdict || 'unknown';
    const threatName = llmResult.llmAnalysis?.threat_family || 'unknown';
    const confidence = llmResult.decision?.confidence || multiResult.decision?.confidence || 0;

    // 若判定为恶意，触发防御策略（隔离/删除/告警）
    if (verdict === 'malicious') {
      try {
        const { evaluatePolicies } = require('./defenseService');
        await evaluatePolicies({
          source: 'virus_scan',
          file_path: file.path,
          file_name: file.originalname,
          md5: llmResult.llmAnalysis?.ioc_indicators?.[0] || '',
          sha256: '',
          threat_name: threatName,
          threat_level: threatLevel,
          confidence,
          severity: threatLevel,
          related_asset: file.path
        });
      } catch (policyErr) {
        logger.warn(`[病毒扫描] 防御策略执行失败: ${file.originalname}`, policyErr.message);
      }
    }

    return {
      file: file.originalname,
      path: file.path,
      multiEngine: multiResult,
      llm: llmResult,
      verdict,
      confidence,
      threatLevel,
      threatName,
      priority: llmResult.remediationPlan?.priority || 'normal',
      escalation: llmResult.remediationPlan?.escalation_needed || false
    };
  } catch (err) {
    logger.error(`文件扫描失败: ${file.originalname}`, err.message);
    return {
      file: file.originalname,
      path: file.path,
      error: err.message,
      verdict: 'error'
    };
  }
}

/** 执行一次完整扫描任务 */
async function runScanTask() {
  const { virusScan } = config;
  if (!virusScan.enabled) {
    logger.info('[病毒扫描调度] 定时扫描已禁用');
    return;
  }

  logger.info('[病毒扫描调度] 开始定时扫描任务');
  const startTime = Date.now();

  // 1. 获取待扫描文件
  const files = getFilesToScan(virusScan.watchDirs);
  if (files.length === 0) {
    logger.info('[病毒扫描调度] 无待扫描文件');
    return { filesScanned: 0, results: [] };
  }
  logger.info(`[病毒扫描调度] 发现 ${files.length} 个待扫描文件`);

  // 2. 执行扫描
  const results = [];
  for (const file of files) {
    logger.info(`[病毒扫描调度] 正在扫描: ${file.originalname} (${(file.size / 1024).toFixed(1)}KB)`);
    const result = await scanFile(file);
    results.push(result);

    if (result.error) {
      logger.warn(`[病毒扫描调度] 扫描失败: ${result.file} | ${result.error}`);
    } else {
      logger.info(
        `[病毒扫描调度] ${result.file} | ${result.verdict.toUpperCase()} | ` +
        `threatLevel=${result.threatLevel} | confidence=${(result.confidence * 100).toFixed(0)}% | ` +
        `priority=${result.priority} | escalation=${result.escalation}`
      );
    }
  }

  // 3. 汇总统计
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  const summary = {
    filesScanned: results.length,
    malicious: results.filter(r => r.verdict === 'malicious').length,
    suspicious: results.filter(r => r.verdict === 'suspicious').length,
    clean: results.filter(r => r.verdict === 'clean').length,
    errors: results.filter(r => r.error).length,
    elapsed: `${elapsed}s`,
    results
  };

  logger.info(
    `[病毒扫描调度] 任务完成: ${summary.filesScanned} 个文件 | ` +
    `malicious=${summary.malicious} | suspicious=${summary.suspicious} | ` +
    `clean=${summary.clean} | errors=${summary.errors} | 耗时=${summary.elapsed}`
  );

  return summary;
}

module.exports = {
  getFilesToScan,
  scanFile,
  runScanTask
};
