/**
 * LLM 驱动病毒查杀服务（v1.4.0 优化版）
 * 优化：
 *  1. analyzeThreatWithLLM + generateRemediationPlan 合并为一次 callDeepSeek
 *  2. LLM 结果缓存（LRU，key=sha256+引擎集版本，TTL 7天，上限 5000 条）
 *  3. 失败逐级降级
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multiEngine = require('./multiEngineScanService');
const aiService = require('./aiService');
const { getDb } = require('../db/database');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

// ─── B3: LRU 缓存 ───────────────────────────────────────────────
class LRUCache {
  constructor(maxSize = 5000, ttlMs = 7 * 24 * 60 * 60 * 1000) {
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
    this.store = new Map();
  }

  _key(entryKey) { return entryKey; }

  get(key) {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() - entry.ts > this.ttlMs) {
      this.store.delete(key);
      return null;
    }
    // 刷新顺序（最近使用）
    this.store.delete(key);
    this.store.set(key, entry);
    return entry.value;
  }

  set(key, value) {
    if (this.store.has(key)) this.store.delete(key);
    else if (this.store.size >= this.maxSize) {
      // 淘汰最老条目
      const oldest = this.store.keys().next().value;
      this.store.delete(oldest);
    }
    this.store.set(key, { value, ts: Date.now() });
  }

  get size() { return this.store.size; }
}

/** LLM 结果缓存：key = sha256 + engineVersions 排序后拼接 */
const llmCache = new LRUCache(5000, 7 * 24 * 60 * 60 * 1000);

function _buildCacheKey(hashes, engineResults) {
  const versions = Object.entries(engineResults || {})
    .filter(([, v]) => v && v.verdict)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([k, v]) => `${k}:${v.verdict}`)
    .join('|');
  return `${hashes.sha256}::${versions}`;
}

// ─── B3: 合并 analyze + remediation 为一次 LLM 调用 ─────────────
async function runLLMVirusScan(file, userId) {
  const startTime = Date.now();
  const scanId = crypto.randomUUID();

  logger.info(`[LLM病毒查杀] 开始: ${file.originalname} (${(file.size / 1024).toFixed(1)}KB)`);

  // 1. 计算哈希（先读文件，复用 fileData 避免重复读取）
  const fileData = fs.readFileSync(file.path);
  const hashes = multiEngine._calculateHashes(fileData);
  logger.info(`[LLM病毒查杀] MD5: ${hashes.md5}, SHA256: ${hashes.sha256}`);

  // 2. 多引擎并行扫描
  const scanResult = await multiEngine.scanFile(file, userId);

  // 3. B3: LLM 合并调用（一次 callDeepSeek 含 analysis + remediation）
  let llmResult = null;
  const cacheKey = _buildCacheKey(hashes, scanResult.engines);
  const cached = llmCache.get(cacheKey);
  if (cached) {
    logger.info(`[LLM病毒查杀] 缓存命中: ${file.originalname}`);
    metrics.inc('llm_cache_hits_total', 1);
    llmResult = cached;
  } else {
    try {
      llmResult = await analyzeAndRemediateWithLLM(file, hashes, scanResult.engines, scanResult.decision);
      llmCache.set(cacheKey, llmResult);
      logger.info(`[LLM病毒查杀] LLM分析+处置建议完成，缓存已写入 (cacheSize=${llmCache.size})`);
    } catch (err) {
      logger.warn(`[LLM病毒查杀] LLM合并调用失败，使用规则降级: ${err.message}`);
      llmResult = generateFallbackCombined(file, hashes, scanResult.engines, scanResult.decision);
    }
  }

  const totalTime = ((Date.now() - startTime) / 1000).toFixed(1);

  return {
    scanId,
    recordId: scanResult.recordId,
    fileName: file.originalname,
    fileSize: file.size,
    fileExtension: path.extname(file.originalname).toLowerCase(),
    hashes,
    engines: scanResult.engines,
    decision: scanResult.decision,
    llmAnalysis: llmResult.analysis,
    remediationPlan: llmResult.remediation,
    totalTime: parseFloat(totalTime),
    llmUsed: llmResult.usedLLM,
    llmCacheHit: !!cached
  };
}

/**
 * B3: 合并威胁分析 + 处置建议为一次 LLM 调用
 */
async function analyzeAndRemediateWithLLM(file, hashes, engineResults, decision) {
  const engineSummary = Object.values(engineResults || {}).map((e) => ({
    engine: e.engine, status: e.status, verdict: e.verdict,
    confidence: e.confidence, detail: e.detail
  }));

  const maliciousEngines = engineSummary.filter((e) => e.verdict === 'malicious' || e.verdict === 'poisoned');
  const suspiciousEngines = engineSummary.filter((e) => e.verdict === 'suspicious');
  logger.info(`[LLM合并分析] 引擎分布: malicious=${maliciousEngines.length} | suspicious=${suspiciousEngines.length} | clean=${engineSummary.length - maliciousEngines.length - suspiciousEngines.length}`);

  const ext = path.extname(file.originalname).toLowerCase();
  const mime = file.mimetype || 'application/octet-stream';

  const prompt = `你是一个专业的恶意软件分析专家。请分析以下文件的病毒查杀结果，同时给出处置方案。

## 文件信息
- 文件名: ${file.originalname}
- 扩展名: ${ext || '未知'}
- MIME类型: ${mime}
- 文件大小: ${file.size} bytes
- MD5: ${hashes.md5}
- SHA256: ${hashes.sha256}

## 引擎检测结果
${engineSummary.map((e) =>
  `- [${e.engine}] ${e.verdict} (置信度 ${(e.confidence * 100).toFixed(0)}%) - ${e.detail}`
).join('\n')}

## 规则判定结果
- 结论: ${decision.verdict === 'malicious' ? '恶意' : (decision.verdict === 'suspicious' ? '疑似' : '安全')}
- 置信度: ${(decision.confidence * 100).toFixed(1)}%
- 主要判定引擎: ${decision.primaryEngine}

请输出单一 JSON 对象（不要 markdown 代码块），包含 analysis 和 remediation 两部分：
{
  "analysis": {
    "threat_classification": "trojan/worm/ransomware/spyware/adware/keylogger/backdoor/wiper/banker/rootkit/unknown",
    "threat_family": "具体家族名称，未知则填unknown",
    "threat_level": "critical/high/medium/low/info",
    "confidence": 0-1之间的浮点数,
    "analysis_reasoning": "详细分析推理过程，100-300字",
    "behavioral_indicators": ["可疑行为特征1"],
    "ioc_indicators": ["IOCs"],
    "similar_threats": ["相似威胁名称"]
  },
  "remediation": {
    "priority": "immediate/urgent/normal/low",
    "containment_steps": ["隔离步骤1"],
    "eradication_steps": ["清除步骤1"],
    "recovery_steps": ["恢复步骤1"],
    "monitoring_suggestions": ["监控建议1"],
    "prevention_recommendations": ["预防措施1"],
    "escalation_needed": true/false,
    "escalation_reason": "需要升级的原因或空字符串"
  }
}`;

  const response = await aiService.callDeepSeek([
    {
      role: 'system',
      content: '你是玄鉴安全智能体的恶意软件分析专家，擅长多引擎结果综合研判、威胁分类、家族识别和应急处置方案制定。输出单一JSON，不要markdown代码块。'
    },
    { role: 'user', content: prompt }
  ], { temperature: 0.2, maxTokens: 2500 });

  const content = response.data?.choices?.[0]?.message?.content;
  if (!content) throw new Error('LLM响应为空');

  // 解析合并 JSON
  let parsed;
  try {
    const clean = content.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim();
    parsed = JSON.parse(clean);
  } catch {
    // 降级：分别提取 analysis 和 remediation 字段
    parsed = extractCombinedLLMJSON(content);
  }

  return {
    usedLLM: true,
    analysis: {
      threat_classification: parsed.analysis?.threat_classification || 'unknown',
      threat_family: parsed.analysis?.threat_family || 'unknown',
      threat_level: parsed.analysis?.threat_level || (decision.verdict === 'malicious' ? 'high' : 'low'),
      confidence: Math.min(1, Math.max(0, parsed.analysis?.confidence || decision.confidence)),
      analysis_reasoning: parsed.analysis?.analysis_reasoning || decision.recommendation || '',
      behavioral_indicators: Array.isArray(parsed.analysis?.behavioral_indicators) ? parsed.analysis.behavioral_indicators : [],
      ioc_indicators: Array.isArray(parsed.analysis?.ioc_indicators) ? parsed.analysis.ioc_indicators : [],
      similar_threats: Array.isArray(parsed.analysis?.similar_threats) ? parsed.analysis.similar_threats : []
    },
    remediation: {
      priority: parsed.remediation?.priority || (decision.verdict === 'malicious' ? 'immediate' : 'normal'),
      containment_steps: Array.isArray(parsed.remediation?.containment_steps) ? parsed.remediation.containment_steps : [],
      eradication_steps: Array.isArray(parsed.remediation?.eradication_steps) ? parsed.remediation.eradication_steps : [],
      recovery_steps: Array.isArray(parsed.remediation?.recovery_steps) ? parsed.remediation.recovery_steps : [],
      monitoring_suggestions: Array.isArray(parsed.remediation?.monitoring_suggestions) ? parsed.remediation.monitoring_suggestions : [],
      prevention_recommendations: Array.isArray(parsed.remediation?.prevention_recommendations) ? parsed.remediation.prevention_recommendations : [],
      escalation_needed: parsed.remediation?.escalation_needed === true,
      escalation_reason: parsed.remediation?.escalation_reason || ''
    }
  };
}

/** 从合并 JSON 文本中降级提取 */
function extractCombinedLLMJSON(text) {
  const analysisFields = ['threat_classification', 'threat_family', 'threat_level', 'confidence', 'analysis_reasoning', 'behavioral_indicators', 'ioc_indicators', 'similar_threats'];
  const remediationFields = ['priority', 'escalation_needed', 'escalation_reason'];
  const result = { analysis: {}, remediation: {} };
  for (const f of analysisFields) {
    const match = text.match(new RegExp(`"analysis"\\s*[:：]\\s*\\{[^}]*"?${f}"?\\s*[:：]\\s*"([^"]*)"`, 's'));
    if (match) result.analysis[f] = match[1];
  }
  for (const f of remediationFields) {
    const match = text.match(new RegExp(`"remediation"\\s*[:：]\\s*\\{[^}]*"?${f}"?\\s*[:：]\\s*([^,}\\s]+)`, 's'));
    if (match) result.remediation[f] = match[1];
  }
  return result;
}

/**
 * 基于哈希的 LLM 病毒查询（无需上传文件）
 */
async function analyzeHashWithLLM(hashValue, hashType, userId) {
  const startTime = Date.now();
  const scanId = crypto.randomUUID();

  logger.info(`[LLM哈希分析] ${hashType}: ${hashValue}`);

  const db = getDb();
  const localMatch = db.prepare(
    `SELECT * FROM virus_hashes WHERE hash_value = ? AND hash_type = ?`
  ).get(hashValue, hashType);
  logger.info(`[LLM哈希分析] 本地库查询: ${hashType}=${hashValue} | 命中: ${localMatch ? `${localMatch.threat_name}(严重程度:${localMatch.severity},来源:${localMatch.source})` : '未找到匹配记录'}`);

  const historyRecord = db.prepare(
    `SELECT * FROM virus_scan_records WHERE file_hash_md5 = ? OR file_hash_sha256 = ?
     ORDER BY created_at DESC LIMIT 1`
  ).get(hashValue, hashValue);
  logger.info(`[LLM哈希分析] 历史扫描记录: ${historyRecord ? `判定=${historyRecord.detection_result}, 置信度=${(historyRecord.model_score * 100).toFixed(0)}%, 来源=${historyRecord.detection_source}` : '无历史记录'}`);

  let intelResult = null;
  try {
    const threatIntel = require('../services/threatIntelligence');
    intelResult = await threatIntel.aggregateQuery('hash', hashValue);
    logger.info(`[LLM哈希分析] 威胁情报: 风险等级=${intelResult?.riskLevel || 'N/A'}, 风险评分=${intelResult?.riskScore?.toFixed(4) || 'N/A'}, 来源数=${intelResult?.sources?.length || 0}`);
  } catch (err) {
    logger.warn(`[LLM哈希分析] 威胁情报查询失败: ${err.message}`);
  }

  const scanData = {
    hashType, hashValue,
    localMatch: localMatch ? { threat_name: localMatch.threat_name, severity: localMatch.severity, source: localMatch.source } : null,
    history: historyRecord ? { result: historyRecord.detection_result, score: historyRecord.model_score, source: historyRecord.detection_source, scanned_at: historyRecord.created_at } : null,
    intel: intelResult ? { riskLevel: intelResult.riskLevel, riskScore: intelResult.riskScore, sources: intelResult.sources } : null
  };

  let llmAnalysis = null;
  try {
    llmAnalysis = await analyzeHashWithDeepSeek(scanData);
  } catch (err) {
    logger.warn(`[LLM哈希分析] LLM分析失败: ${err.message}`);
    llmAnalysis = generateHashFallbackAnalysis(scanData);
  }

  const totalTime = ((Date.now() - startTime) / 1000).toFixed(1);

  return {
    scanId, fileName: null,
    hashes: { md5: hashType === 'md5' ? hashValue : null, sha256: hashType === 'sha256' ? hashValue : null },
    localMatch, historyRecord, intelResult,
    llmAnalysis, totalTime: parseFloat(totalTime), llmUsed: llmAnalysis !== null
  };
}

async function analyzeHashWithDeepSeek(scanData) {
  const hasThreat = scanData.localMatch || (scanData.intel && scanData.intel.riskScore > 0.5);
  logger.info(`[LLM哈希分析DeepSeek] 调用前: 本地库=${scanData.localMatch ? scanData.localMatch.threat_name : '未命中'}, 情报风险=${scanData.intel?.riskLevel || '无'}, hasThreat=${Boolean(hasThreat)}`);

  const prompt = `你是一个专业的恶意软件分析专家。请分析以下文件哈希的威胁情报数据。

## 哈希信息
- 哈希类型: ${scanData.hashType}
- 哈希值: ${scanData.hashValue}

## 本地病毒库
${scanData.localMatch ? `- 威胁名称: ${scanData.localMatch.threat_name}\n- 严重级别: ${scanData.localMatch.severity}\n- 来源: ${scanData.localMatch.source}` : '未找到匹配记录'}

## 历史扫描记录
${scanData.history ? `- 判定: ${scanData.history.result}\n- 置信度: ${(scanData.history.score * 100).toFixed(0)}%\n- 来源: ${scanData.history.source}` : '无历史记录'}

## 威胁情报
${scanData.intel ? `- 风险等级: ${scanData.intel.riskLevel}\n- 风险评分: ${scanData.intel.riskScore}\n- 来源数: ${scanData.intel.sources?.length || 0}` : '无情报数据'}

请输出 JSON 格式的深度分析（不要 markdown 代码块）：
{
  "threat_classification": "trojan/worm/ransomware/spyware/adware/keylogger/backdoor/wiper/banker/rootkit/unknown/clean",
  "threat_family": "具体家族名称，无记录则填unknown",
  "threat_level": "critical/high/medium/low/info",
  "confidence": 0-1之间的浮点数,
  "analysis_reasoning": "分析推理过程，80-200字",
  "behavioral_indicators": [],
  "ioc_indicators": ["${scanData.hashValue}"],
  "similar_threats": []
}`;

  const response = await aiService.callDeepSeek([
    { role: 'system', content: '你是玄鉴安全智能体的恶意软件分析专家，擅长基于威胁情报和病毒库数据研判文件哈希风险。' },
    { role: 'user', content: prompt }
  ], { temperature: 0.2, maxTokens: 1200 });

  const content = response.data?.choices?.[0]?.message?.content;
  if (!content) throw new Error('LLM响应为空');

  let parsed;
  try {
    const clean = content.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim();
    parsed = JSON.parse(clean);
  } catch {
    parsed = extractLLMJSON(content);
  }

  return {
    threat_classification: parsed.threat_classification || (hasThreat ? 'unknown' : 'clean'),
    threat_family: parsed.threat_family || (scanData.localMatch?.threat_name || 'unknown'),
    threat_level: parsed.threat_level || (hasThreat ? 'high' : 'low'),
    confidence: Math.min(1, Math.max(0, parsed.confidence || (hasThreat ? 0.85 : 0.1))),
    analysis_reasoning: parsed.analysis_reasoning || `本地库${scanData.localMatch ? '命中' : '未命中'}，情报风险等级: ${scanData.intel?.riskLevel || 'unknown'}`,
    behavioral_indicators: Array.isArray(parsed.behavioral_indicators) ? parsed.behavioral_indicators : [],
    ioc_indicators: [scanData.hashValue],
    similar_threats: Array.isArray(parsed.similar_threats) ? parsed.similar_threats : []
  };
}

function extractLLMJSON(text) {
  const fields = ['threat_classification', 'threat_family', 'threat_level', 'confidence', 'analysis_reasoning', 'behavioral_indicators', 'ioc_indicators', 'similar_threats'];
  const result = {};
  for (const f of fields) {
    const match = text.match(new RegExp(`${f}\\s*[:：]\\s*"([^"]*)"`, 'i'));
    if (match) result[f] = match[1];
  }
  return result;
}

/**
 * B3: 降级合并方案（LLM 不可用时）
 */
function generateFallbackCombined(file, hashes, engineResults, decision) {
  const maliciousEngines = Object.values(engineResults || {})
    .filter((e) => e.verdict === 'malicious' || e.verdict === 'poisoned');
  const isMalicious = decision.verdict === 'malicious' || decision.verdict === 'poisoned';

  return {
    usedLLM: false,
    analysis: {
      threat_classification: maliciousEngines.length > 0 ? 'unknown' : 'clean',
      threat_family: 'unknown',
      threat_level: isMalicious ? 'high' : 'low',
      confidence: decision.confidence,
      analysis_reasoning: `规则引擎判定: ${decision.primaryEngine} 给出 ${decision.verdict} 结论，置信度 ${(decision.confidence * 100).toFixed(0)}%。${maliciousEngines.length > 0 ? `检测到 ${maliciousEngines.length} 个引擎标记为恶意。` : '未发现明确恶意特征。'}`,
      behavioral_indicators: maliciousEngines.map((e) => e.detail).filter(Boolean),
      ioc_indicators: [],
      similar_threats: maliciousEngines.map((e) => e.threatName).filter(Boolean)
    },
    remediation: {
      priority: isMalicious ? 'immediate' : 'normal',
      containment_steps: isMalicious
        ? ['立即隔离文件所在目录', '阻断相关文件传播路径', '检查同目录其他文件']
        : [],
      eradication_steps: isMalicious
        ? ['将恶意文件移至隔离区', '清除可能的持久化机制', '检查注册表/启动项/计划任务']
        : [],
      recovery_steps: ['恢复受影响的系统配置', '验证系统完整性'],
      monitoring_suggestions: isMalicious
        ? ['持续监控该文件相关进程活动', '检查网络连接日志']
        : ['常规安全监控'],
      prevention_recommendations: isMalicious
        ? ['更新终端防护策略', '加强文件上传审计', '对用户进行安全意识培训']
        : [],
      escalation_needed: isMalicious && decision.confidence > 0.8,
      escalation_reason: isMalicious && decision.confidence > 0.8 ? '高置信度恶意判定，建议上报安全团队' : ''
    }
  };
}

function generateFallbackRemediation(decision) {
  const isMalicious = decision.verdict === 'malicious' || decision.verdict === 'poisoned';
  return {
    priority: isMalicious ? 'immediate' : 'normal',
    containment_steps: isMalicious
      ? ['立即隔离文件所在目录', '阻断相关文件传播路径', '检查同目录其他文件']
      : [],
    eradication_steps: isMalicious
      ? ['将恶意文件移至隔离区', '清除可能的持久化机制', '检查注册表/启动项/计划任务']
      : [],
    recovery_steps: ['恢复受影响的系统配置', '验证系统完整性'],
    monitoring_suggestions: isMalicious
      ? ['持续监控该文件相关进程活动', '检查网络连接日志']
      : ['常规安全监控'],
    prevention_recommendations: isMalicious
      ? ['更新终端防护策略', '加强文件上传审计', '对用户进行安全意识培训']
      : [],
    escalation_needed: isMalicious && decision.confidence > 0.8,
    escalation_reason: isMalicious && decision.confidence > 0.8 ? '高置信度恶意判定，建议上报安全团队' : ''
  };
}

function generateHashFallbackAnalysis(scanData) {
  const hasThreat = scanData.localMatch || (scanData.intel && scanData.intel.riskScore > 0.5);
  return {
    threat_classification: hasThreat ? 'unknown' : 'clean',
    threat_family: hasThreat ? (scanData.localMatch?.threat_name || 'unknown') : 'unknown',
    threat_level: hasThreat ? 'high' : 'low',
    confidence: hasThreat ? 0.9 : 0.1,
    analysis_reasoning: hasThreat
      ? `本地库${scanData.localMatch ? '命中' : '未命中'}，威胁情报风险等级: ${scanData.intel?.riskLevel || 'unknown'}`
      : '本地库和威胁情报均未发现匹配记录',
    behavioral_indicators: [],
    ioc_indicators: [scanData.hashValue],
    similar_threats: scanData.localMatch ? [scanData.localMatch.threat_name] : []
  };
}

module.exports = {
  runLLMVirusScan,
  analyzeHashWithLLM,
  analyzeAndRemediateWithLLM,
  analyzeThreatWithLLM: null, // v1.4.0 已合并，保留兼容别名
  generateRemediationPlan: null, // v1.4.0 已合并，保留兼容别名
  llmCache,
  _buildCacheKey,
  generateFallbackCombined
};
