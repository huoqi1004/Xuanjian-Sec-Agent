/**
 * 模型幻觉检测器（HallucinationDetector）
 * 三层检测：引用溯源验证 + 数值一致性检查 + 置信度分级
 */
const logger = require('../utils/logger');

/**
 * 层 1：引用溯源验证
 * 验证 LLM 输出中的引用是否指向实际检索到的知识库文档
 * @param {string} llmContent - LLM 生成的回复
 * @param {Array} retrievedDocs - 实际检索到的知识库文档 [{title, content, id}]
 * @returns {{ valid, invalid_citations, citation_rate }}
 */
function verifyCitations(llmContent, retrievedDocs) {
  if (!retrievedDocs || retrievedDocs.length === 0) {
    return { valid: true, invalid_citations: [], citation_rate: 1.0 };
  }

  const docIds = new Set(retrievedDocs.map(d => d.id));
  const docTitles = new Set(retrievedDocs.map(d => d.title));

  // 提取 LLM 输出中的引用标记
  const citations = llmContent.match(/\[DOC:(\d+)\]/g) || [];
  const titleCitations = llmContent.match(/\[TRUSTED_DOC\]\s*([^:]+)/g) || [];

  const invalidById = citations
    .map(m => m.replace('[DOC:', '').replace(']', ''))
    .filter(id => !docIds.has(parseInt(id, 10)));

  const invalidByTitle = titleCitations
    .map(m => m.replace('[TRUSTED_DOC] ', '').trim())
    .filter(title => !docTitles.has(title));

  const allInvalid = [...new Set([...invalidById, ...invalidByTitle])];
  const citationRate = allInvalid.length === 0 ? 1.0
    : Math.max(0, 1 - allInvalid.length / Math.max(1, citations.length + titleCitations.length));

  logger.debug(`[Hallucination] 引用验证: total=${citations.length + titleCitations.length}, invalid=${allInvalid.length}, rate=${citationRate.toFixed(2)}`);

  return { valid: allInvalid.length === 0, invalid_citations: allInvalid, citation_rate: citationRate };
}

/**
 * 层 2：数值一致性检查
 * 检测 LLM 是否编造了超出源数据范围的数值
 * @param {string} llmContent - LLM 输出
 * @param {Object} sourceData - 源数据结构化数据 {maxValues: {alert_count: 100, ...}}
 * @returns {Array<{value, reason}>} 可疑数值列表
 */
function checkNumericConsistency(llmContent, sourceData) {
  if (!sourceData) return [];

  const findings = [];
  // 提取所有百分比
  const percentMatches = llmContent.match(/\d+(\.\d+)?%/g) || [];
  for (const match of percentMatches) {
    const val = parseFloat(match);
    if (val > 100) {
      findings.push({ value: match, reason: '百分比超过 100%' });
    }
    // 检查是否超出源数据合理范围
    for (const [key, maxVal] of Object.entries(sourceData.maxValues || {})) {
      if (val > maxVal * 2) {
        findings.push({ value: match, reason: `超出 ${key} 合理范围(> ${maxVal * 2})` });
      }
    }
  }

  // 提取绝对数值
  const numberMatches = llmContent.match(/\b(\d{4,})\b/g) || [];
  for (const match of numberMatches) {
    const val = parseInt(match, 10);
    for (const [key, maxVal] of Object.entries(sourceData.maxValues || {})) {
      if (val > maxVal * 5) {
        findings.push({ value: match, reason: `数值 ${val} 远超 ${key} 上限 ${maxVal}` });
      }
    }
  }

  return findings;
}

/**
 * 层 3：置信度分级
 * @param {number} citationRate - 引用验证通过率
 * @param {Array} numericFindings - 数值异常列表
 * @returns {{level, action, warning}}
 */
function assessConfidence(citationRate, numericFindings) {
  const numericScore = numericFindings.length > 0 ? 0.3 : 1.0;
  const overallScore = citationRate * 0.6 + numericScore * 0.4;

  let level, action, warning;
  if (overallScore >= 0.7) {
    level = 'high'; action = 'display'; warning = null;
  } else if (overallScore >= 0.4) {
    level = 'medium'; action = 'show_with_warning'; warning = '该回答部分内容未经知识库验证，请交叉核对原始数据';
  } else {
    level = 'low'; action = 'hide_and_show_raw_data'; warning = 'AI 分析置信度过低，已切换为原始数据展示模式';
  }

  return { level, action, score: overallScore, warning };
}

/**
 * 主检测流程
 * @param {string} llmContent - LLM 输出内容
 * @param {Array} retrievedDocs - 检索到的知识库文档
 * @param {Object} sourceData - 源数据结构化数据
 * @returns {{ is_hallucination, confidence, action, warning, sanitized_content }}
 */
function detectHallucination(llmContent, retrievedDocs, sourceData) {
  if (typeof llmContent !== 'string') return { is_hallucination: false, confidence: 0, action: 'display' };

  const citationCheck = verifyCitations(llmContent, retrievedDocs || []);
  const numericCheck = checkNumericConsistency(llmContent, sourceData);
  const confidence = assessConfidence(citationCheck.citation_rate, numericCheck);

  let sanitized = llmContent;
  if (confidence.action === 'show_with_warning' && confidence.warning) {
    sanitized = `[⚠️ ${confidence.warning}]\n${llmContent}`;
  }

  const isHallucination = confidence.level === 'low';

  logger.debug(`[Hallucination] level=${confidence.level}, score=${confidence.score.toFixed(2)}, is_hallucination=${isHallucination}`);

  return {
    is_hallucination: isHallucination,
    confidence: confidence.score,
    action: confidence.action,
    warning: confidence.warning,
    citation_rate: citationCheck.citation_rate,
    numeric_findings: numericCheck,
    sanitized_content: sanitized,
  };
}

module.exports = { detectHallucination, verifyCitations, checkNumericConsistency, assessConfidence };
