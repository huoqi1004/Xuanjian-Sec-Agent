/**
 * LLM 驱动病毒查杀服务
 * 流程：文件哈希 → 7引擎并行扫描 → LLM 威胁分析 → LLM 处置建议
 * 相比规则仲裁的增强：
 *  1. LLM 综合多引擎结果，给出可解释的威胁判定与家族归属
 *  2. 结合威胁情报关联分析（IOC 交叉验证）
 *  3. 生成结构化处置建议（隔离/删除/沙箱/上报）
 *  4. 支持哈希驱动（无需文件上传，仅凭 hash 查询分析）
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multiEngine = require('./multiEngineScanService');
const aiService = require('./aiService');
const { getDb } = require('../db/database');
const logger = require('../utils/logger');

/**
 * 执行 LLM 驱动的病毒查杀
 * @param {Object} file - { path, originalname, size }
 * @param {number} userId - 操作用户ID
 * @returns {Object} 完整查杀结果含 LLM 分析
 */
async function runLLMVirusScan(file, userId) {
  const startTime = Date.now();
  const scanId = crypto.randomUUID();

  logger.info(`[LLM病毒查杀] 开始: ${file.originalname} (${(file.size / 1024).toFixed(1)}KB)`);

  // 1. 计算哈希
  const hashes = multiEngine._calculateHashes(file.path);
  logger.info(`[LLM病毒查杀] MD5: ${hashes.md5}, SHA256: ${hashes.sha256}`);

  // 2. 多引擎并行扫描
  const scanResult = await multiEngine.scanFile(file, userId);

  // 3. LLM 威胁深度分析
  let llmAnalysis = null;
  try {
    llmAnalysis = await analyzeThreatWithLLM(file, hashes, scanResult.engines, scanResult.decision);
    logger.info(`[LLM病毒查杀] LLM分析完成`);
  } catch (err) {
    logger.warn(`[LLM病毒查杀] LLM分析失败，使用规则判定: ${err.message}`);
    llmAnalysis = generateFallbackAnalysis(file, hashes, scanResult.engines, scanResult.decision);
  }

  // 4. LLM 处置建议
  let remediationPlan = null;
  try {
    remediationPlan = await generateRemediationPlan(llmAnalysis);
    logger.info(`[LLM病毒查杀] 处置建议生成完成`);
  } catch (err) {
    logger.warn(`[LLM病毒查杀] 处置建议生成失败: ${err.message}`);
    remediationPlan = generateFallbackRemediation(scanResult.decision);
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
    llmAnalysis,
    remediationPlan,
    totalTime: parseFloat(totalTime),
    llmUsed: llmAnalysis !== null
  };
}

/**
 * 基于哈希的 LLM 病毒查询（无需上传文件）
 * @param {string} hashValue - MD5 或 SHA256
 * @param {string} hashType - md5 | sha256
 * @param {number} userId - 操作用户ID
 */
async function analyzeHashWithLLM(hashValue, hashType, userId) {
  const startTime = Date.now();
  const scanId = crypto.randomUUID();

  logger.info(`[LLM哈希分析] ${hashType}: ${hashValue}`);

  const db = getDb();

  // 1. 本地病毒库查询
  const localMatch = db.prepare(
    `SELECT * FROM virus_hashes WHERE hash_value = ? AND hash_type = ?`
  ).get(hashValue, hashType);
  logger.info(`[LLM哈希分析] 本地库查询: ${hashType}=${hashValue} | 命中: ${localMatch ? `${localMatch.threat_name}(严重程度:${localMatch.severity},来源:${localMatch.source})` : '未找到匹配记录'}`);

  // 2. 查询历史扫描记录
  const historyRecord = db.prepare(
    `SELECT * FROM virus_scan_records WHERE file_hash_md5 = ? OR file_hash_sha256 = ?
     ORDER BY created_at DESC LIMIT 1`
  ).get(hashValue, hashValue);
  logger.info(`[LLM哈希分析] 历史扫描记录: ${historyRecord ? `判定=${historyRecord.detection_result}, 置信度=${(historyRecord.model_score * 100).toFixed(0)}%, 来源=${historyRecord.detection_source}` : '无历史记录'}`);

  // 3. 威胁情报关联
  let intelResult = null;
  try {
    const threatIntel = require('../services/threatIntelligence');
    intelResult = await threatIntel.aggregateQuery('hash', hashValue);
    logger.info(`[LLM哈希分析] 威胁情报: 风险等级=${intelResult?.riskLevel || 'N/A'}, 风险评分=${intelResult?.riskScore?.toFixed(4) || 'N/A'}, 来源数=${intelResult?.sources?.length || 0}`);
  } catch (err) {
    logger.warn(`[LLM哈希分析] 威胁情报查询失败: ${err.message}`);
  }

  // 4. 构造 LLM 输入
  const scanData = {
    hashType,
    hashValue,
    localMatch: localMatch ? {
      threat_name: localMatch.threat_name,
      severity: localMatch.severity,
      source: localMatch.source
    } : null,
    history: historyRecord ? {
      result: historyRecord.detection_result,
      score: historyRecord.model_score,
      source: historyRecord.detection_source,
      scanned_at: historyRecord.created_at
    } : null,
    intel: intelResult ? {
      riskLevel: intelResult.riskLevel,
      riskScore: intelResult.riskScore,
      sources: intelResult.sources
    } : null
  };

  // 5. LLM 分析
  let llmAnalysis = null;
  try {
    llmAnalysis = await analyzeHashWithDeepSeek(scanData);
  } catch (err) {
    logger.warn(`[LLM哈希分析] LLM分析失败: ${err.message}`);
    llmAnalysis = generateHashFallbackAnalysis(scanData);
  }

  const totalTime = ((Date.now() - startTime) / 1000).toFixed(1);

  return {
    scanId,
    fileName: null,
    hashes: { md5: hashType === 'md5' ? hashValue : null, sha256: hashType === 'sha256' ? hashValue : null },
    localMatch,
    historyRecord,
    intelResult,
    llmAnalysis,
    totalTime: parseFloat(totalTime),
    llmUsed: llmAnalysis !== null
  };
}

/**
 * LLM 威胁深度分析
 */
async function analyzeThreatWithLLM(file, hashes, engineResults, decision) {
  const engineSummary = Object.values(engineResults || {}).map((e) => ({
    engine: e.engine,
    status: e.status,
    verdict: e.verdict,
    confidence: e.confidence,
    detail: e.detail
  }));

  const maliciousEngines = engineSummary.filter((e) => e.verdict === 'malicious' || e.verdict === 'poisoned');
  const suspiciousEngines = engineSummary.filter((e) => e.verdict === 'suspicious');
  const cleanEngines = engineSummary.filter((e) => e.verdict === 'clean');
  logger.info(`[LLM威胁分析] 引擎分布: malicious=${maliciousEngines.length} | suspicious=${suspiciousEngines.length} | clean=${cleanEngines.length} | total=${engineSummary.length}`);

  // 获取文件扩展名和 MIME 类型
  const ext = path.extname(file.originalname).toLowerCase();
  const mime = file.mimetype || 'application/octet-stream';

  const prompt = `你是一个专业的恶意软件分析专家。请分析以下文件的病毒查杀结果并给出专业研判。

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

## 检测到的威胁名称
${maliciousEngines.map((e) => `- ${e.threatName || e.detail}`).join('\n') || '无'}

请基于以上数据，输出 JSON 格式的深度分析（不要 markdown 代码块，只输出 JSON）：
{
  "threat_classification": "trojan/worm/ransomware/spyware/adware/keylogger/backdoor/wiper/banker/rootkit/unknown",
  "threat_family": "具体家族名称，未知则填unknown",
  "threat_level": "critical/high/medium/low/info",
  "confidence": 0-1之间的浮点数,
  "analysis_reasoning": "详细分析推理过程，100-300字",
  "behavioral_indicators": ["可疑行为特征1", "可疑行为特征2"],
  "ioc_indicators": ["IOCs or null"],
  "similar_threats": ["相似威胁名称"]
}`;

  const response = await aiService.callDeepSeek([
    {
      role: 'system',
      content: '你是玄鉴安全智能体的恶意软件分析专家，擅长多引擎结果综合研判、威胁分类与家族识别。你的分析应专业、可解释、基于数据。'
    },
    { role: 'user', content: prompt }
  ], { temperature: 0.2, maxTokens: 1500 });

  const content = response.data?.choices?.[0]?.message?.content;
  if (!content) throw new Error('LLM响应为空');

  // 尝试解析 JSON
  let parsed;
  try {
    // 移除可能的 markdown 代码块
    const clean = content.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim();
    parsed = JSON.parse(clean);
  } catch {
    // 降级：从文本中提取关键信息
    parsed = extractLLMJSON(content);
  }

  return {
    threat_classification: parsed.threat_classification || 'unknown',
    threat_family: parsed.threat_family || 'unknown',
    threat_level: parsed.threat_level || decision.verdict === 'malicious' ? 'high' : 'low',
    confidence: Math.min(1, Math.max(0, parsed.confidence || decision.confidence)),
    analysis_reasoning: parsed.analysis_reasoning || decision.recommendation || '',
    behavioral_indicators: Array.isArray(parsed.behavioral_indicators) ? parsed.behavioral_indicators : [],
    ioc_indicators: Array.isArray(parsed.ioc_indicators) ? parsed.ioc_indicators : [],
    similar_threats: Array.isArray(parsed.similar_threats) ? parsed.similar_threats : []
  };
}

/**
 * 从非结构化文本中提取 JSON 字段（降级方案）
 */
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
 * LLM 哈希威胁分析（基于本地库 + 威胁情报数据，无需上传文件）
 */
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

请输出 JSON 格式的深度分析（不要 markdown 代码块，只输出 JSON）：
{
  "threat_classification": "trojan/worm/ransomware/spyware/adware/keylogger/backdoor/wiper/banker/rootkit/unknown/clean",
  "threat_family": "具体家族名称，无记录则填unknown",
  "threat_level": "critical/high/medium/low/info",
  "confidence": 0-1之间的浮点数,
  "analysis_reasoning": "分析推理过程，80-200字，基于以上所有数据",
  "behavioral_indicators": [],
  "ioc_indicators": ["${scanData.hashValue}"],
  "similar_threats": []
}`;

  const response = await aiService.callDeepSeek([
    {
      role: 'system',
      content: '你是玄鉴安全智能体的恶意软件分析专家，擅长基于威胁情报和病毒库数据研判文件哈希风险。'
    },
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

/**
 * LLM 处置建议生成
 */
async function generateRemediationPlan(analysis) {
  const threatLevel = analysis.threat_level || 'low';
  const classification = analysis.threat_classification || 'unknown';
  const family = analysis.threat_family || 'unknown';

  const prompt = `你是安全运营应急响应专家。基于以下威胁分析结果，生成结构化的应急处置方案。

## 威胁分析摘要
- 威胁分类: ${classification}
- 威胁家族: ${family}
- 威胁等级: ${threatLevel}
- 置信度: ${(analysis.confidence * 100).toFixed(1)}%
- 分析推理: ${analysis.analysis_reasoning}

## 行为指标
${(analysis.behavioral_indicators || []).map((b) => `- ${b}`).join('\n') || '无'}

## IOC 指标
${(analysis.ioc_indicators || []).map((i) => `- ${i}`).join('\n') || '无'}

请输出 JSON 格式的处置方案（不要 markdown 代码块）：
{
  "priority": "immediate/urgent/normal/low",
  "containment_steps": ["隔离步骤1", "隔离步骤2"],
  "eradication_steps": ["清除步骤1", "清除步骤2"],
  "recovery_steps": ["恢复步骤1"],
  "monitoring_suggestions": ["监控建议1"],
  "prevention_recommendations": ["预防措施1"],
  "escalation_needed": true/false,
  "escalation_reason": "需要升级的原因"
}`;

  logger.info(`[LLM处置建议] 开始生成: threatLevel=${threatLevel} | classification=${classification} | family=${family}`);
  const response = await aiService.callDeepSeek([
    {
      role: 'system',
      content: '你是玄鉴安全智能体的应急响应专家，擅长根据威胁分析结果制定标准化的处置方案。方案应具体可操作。'
    },
    { role: 'user', content: prompt }
  ], { temperature: 0.3, maxTokens: 1500 });

  const content = response.data?.choices?.[0]?.message?.content;
  if (!content) throw new Error('LLM响应为空');

  let parsed;
  try {
    const clean = content.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim();
    parsed = JSON.parse(clean);
    logger.info(`[LLM处置建议] JSON解析成功: priority=${parsed.priority}, escalation=${parsed.escalation_needed}`);
  } catch {
    parsed = extractLLMJSON(content);
    logger.info(`[LLM处置建议] JSON解析失败，降级到文本提取: ${JSON.stringify(parsed)}`);
  }

  return {
    priority: parsed.priority || (threatLevel === 'critical' || threatLevel === 'high' ? 'immediate' : 'normal'),
    containment_steps: Array.isArray(parsed.containment_steps) ? parsed.containment_steps : [],
    eradication_steps: Array.isArray(parsed.eradication_steps) ? parsed.eradication_steps : [],
    recovery_steps: Array.isArray(parsed.recovery_steps) ? parsed.recovery_steps : [],
    monitoring_suggestions: Array.isArray(parsed.monitoring_suggestions) ? parsed.monitoring_suggestions : [],
    prevention_recommendations: Array.isArray(parsed.prevention_recommendations) ? parsed.prevention_recommendations : [],
    escalation_needed: parsed.escalation_needed === true,
    escalation_reason: parsed.escalation_reason || ''
  };
}

/**
 * 规则降级分析（LLM 不可用时）
 */
function generateFallbackAnalysis(file, hashes, engineResults, decision) {
  const maliciousEngines = Object.values(engineResults || {})
    .filter((e) => e.verdict === 'malicious' || e.verdict === 'poisoned');

  return {
    threat_classification: maliciousEngines.length > 0 ? 'unknown' : 'clean',
    threat_family: 'unknown',
    threat_level: decision.verdict === 'malicious' ? 'high' : (decision.verdict === 'suspicious' ? 'medium' : 'low'),
    confidence: decision.confidence,
    analysis_reasoning: `规则引擎判定: ${decision.primaryEngine} 给出 ${decision.verdict} 结论，置信度 ${(decision.confidence * 100).toFixed(0)}%。${maliciousEngines.length > 0 ? `检测到 ${maliciousEngines.length} 个引擎标记为恶意。` : '未发现明确恶意特征。'}`,
    behavioral_indicators: maliciousEngines.map((e) => e.detail).filter(Boolean),
    ioc_indicators: [],
    similar_threats: maliciousEngines.map((e) => e.threatName).filter(Boolean)
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
  analyzeThreatWithLLM,
  generateRemediationPlan
};
