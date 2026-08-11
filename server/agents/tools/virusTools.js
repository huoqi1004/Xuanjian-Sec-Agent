/**
 * LLM 病毒查杀工具组
 * 工具: scan_virus_file / analyze_virus_hash / get_virus_report
 */
const { registerTool } = require('./registry');
const path = require('path');
const fs = require('fs');

function registerVirusTools() {
  /**
   * scan_virus_file - LLM 驱动的文件查杀
   */
  registerTool({
    name: 'scan_virus_file',
    desc: 'LLM 驱动的智能病毒查杀（多引擎并行 + LLM 深度分析 + 自动处置建议）',
    params: ['filePath', 'fileName'],
    risk: 'low',
    handler: async (params) => {
      const llmVirusScan = require('../../services/llmVirusScanService');
      if (!params.filePath) {
        return { success: false, error: '缺少 filePath 参数' };
      }
      const file = {
        path: params.filePath,
        originalname: params.fileName || path.basename(params.filePath),
        size: fs.statSync(params.filePath).size,
        mimetype: 'application/octet-stream'
      };
      const result = await llmVirusScan.runLLMVirusScan(file, 1);
      return {
        data: {
          scanId: result.scanId,
          fileName: result.fileName,
          verdict: result.decision.verdict,
          confidence: result.decision.confidence,
          llmUsed: result.llmUsed,
          threatClassification: result.llmAnalysis?.threat_classification,
          threatFamily: result.llmAnalysis?.threat_family,
          threatLevel: result.llmAnalysis?.threat_level,
          analysisReasoning: result.llmAnalysis?.analysis_reasoning,
          priority: result.remediationPlan?.priority,
          totalTime: result.totalTime
        },
        message: `LLM查杀完成: ${result.decision.verdict} (${(result.decision.confidence * 100).toFixed(0)}%)，耗时 ${result.totalTime}s`
      };
    }
  });

  /**
   * analyze_virus_hash_v2 - 基于哈希的 LLM 威胁分析
   */
  registerTool({
    name: 'analyze_virus_hash_v2',
    desc: '基于文件哈希进行 LLM 威胁分析（本地库 + 威胁情报 + LLM 研判）',
    params: ['hash', 'hashType'],
    risk: 'low',
    handler: async (params) => {
      const llmVirusScan = require('../../services/llmVirusScanService');
      if (!params.hash) return { success: false, error: '缺少 hash 参数' };
      const hashType = params.hashType === 'sha256' ? 'sha256' : 'md5';
      const result = await llmVirusScan.analyzeHashWithLLM(params.hash, hashType, 1);
      return {
        data: {
          hash: result.hashes,
          localMatch: result.localMatch,
          intelResult: result.intelResult,
          llmAnalysis: result.llmAnalysis,
          totalTime: result.totalTime
        },
        message: `哈希分析完成: ${result.llmAnalysis?.threat_classification || 'unknown'}`
      };
    }
  });

  /**
   * get_virus_report - 获取病毒查杀报告（含 LLM 分析）
   */
  registerTool({
    name: 'get_virus_report',
    desc: '获取指定扫描记录的完整报告（含多引擎结果 + LLM 分析 + 处置建议）',
    params: ['scanId'],
    risk: 'low',
    handler: async (params) => {
      const multiEngine = require('../../services/multiEngineScanService');
      if (!params.scanId) return { success: false, error: '缺少 scanId 参数' };
      const scanResult = multiEngine.getScanReport(params.scanId);
      if (!scanResult) return { success: false, error: '未找到扫描报告' };
      return {
        data: scanResult,
        message: `报告获取完成: ${scanResult.file?.name || params.scanId}`
      };
    }
  });
}

module.exports = { registerVirusTools };
