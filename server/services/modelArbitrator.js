/**
 * Phase 4.2: 多模型混合仲裁服务
 * 功能：
 * 1. 并行调用多个 LLM 后端（Agnes + 备选模型）
 * 2. 对比输出一致性，识别高置信度答案
 * 3. 当模型间分歧较大时触发幻觉预警
 * 4. 记录投票历史供审计
 */
const axios = require('axios');
const logger = require('../utils/logger');
const { getDb } = require('../db/database');
const { config } = require('../config');
const metrics = require('../utils/metrics');

/**
 * 已注册的 LLM 后端
 * 结构: { id, name, apiKey, apiBase, model, enabled }
 */
const registeredModels = new Map([
  ['agnes', {
    id: 'agnes',
    name: 'Agnes-2.5-Flash',
    apiKey: config.agnes.apiKey,
    apiBase: config.agnes.apiBase,
    model: config.agnes.model || 'agnes-2.5-flash',
    enabled: !!config.agnes.apiKey
  }]
]);

/**
 * 注册额外的 LLM 后端
 */
function registerModel(id, config) {
  registeredModels.set(id, {
    id,
    name: config.name || id,
    apiKey: config.apiKey,
    apiBase: config.apiBase || 'https://api.openai.com/v1',
    model: config.model || 'gpt-4',
    enabled: !!config.apiKey
  });
  logger.info(`[ModelArb] 注册模型: ${config.name || id} (${config.model})`);
}

/**
 * 调用单个 LLM 后端
 */
async function callLLM(modelId, messages, options = {}) {
  const model = registeredModels.get(modelId);
  if (!model || !model.enabled) {
    throw new Error(`模型 ${modelId} 未启用`);
  }

  const startTime = Date.now();
  try {
    const resp = await axios.post(
      `${model.apiBase}/chat/completions`,
      {
        model: model.model,
        messages,
        max_tokens: options.maxTokens || config.agnes.maxTokens || 4096,
        temperature: options.temperature ?? 0.3
      },
      {
        timeout: options.timeout || 60000,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${model.apiKey}`
        }
      }
    );

    const content = resp.data?.choices?.[0]?.message?.content || '';
    const latency = Date.now() - startTime;
    metrics.inc('model_call_total', { model: modelId }, 1);
    metrics.observe('model_call_latency_ms', latency, { model: modelId });

    return {
      modelId,
      modelName: model.name,
      content,
      latency,
      success: true,
      raw: resp.data
    };
  } catch (e) {
    const latency = Date.now() - startTime;
    logger.warn(`[ModelArb] ${modelId} 调用失败: ${e.message} (${latency}ms)`);
    return {
      modelId,
      modelName: model.name,
      content: null,
      latency,
      success: false,
      error: e.message
    };
  }
}

/**
 * 计算两个文本的相似度（简单词重叠）
 */
function textSimilarity(a, b) {
  if (!a || !b) return 0;
  const wordsA = new Set(a.toLowerCase().replace(/[^\w\u4e00-\u9fff]/g, ' ').split(/\s+/).filter(Boolean));
  const wordsB = new Set(b.toLowerCase().replace(/[^\w\u4e00-\u9fff]/g, ' ').split(/\s+/).filter(Boolean));
  let overlap = 0;
  for (const w of wordsA) {
    if (wordsB.has(w)) overlap++;
  }
  const union = new Set([...wordsA, ...wordsB]).size;
  return union > 0 ? overlap / union : 0;
}

/**
 * 多模型并行调用 + 仲裁
 * @param {Array} messages - 对话消息
 * @param {Object} options - { models: ['agnes', ...], minConsensus: 0.6, maxModels: 3 }
 * @returns {Object} { finalAnswer, confidence, votes, consensus }
 */
async function arbitrate(messages, options = {}) {
  const enabledModels = [...registeredModels.values()]
    .filter(m => m.enabled)
    .slice(0, options.maxModels || 3);

  if (enabledModels.length === 0) {
    throw new Error('没有可用的 LLM 后端');
  }

  // 并行调用所有模型
  logger.info(`[ModelArb] 并行调用 ${enabledModels.length} 个模型进行仲裁`);
  metrics.inc('model_arbitrate_total', 1);

  const results = await Promise.allSettled(
    enabledModels.map(m => callLLM(m.id, messages, options))
  );

  const votes = results
    .filter(r => r.status === 'fulfilled' && r.value.success)
    .map(r => r.value);

  if (votes.length === 0) {
    const failures = results.filter(r => r.status === 'rejected' || !r.value.success);
    throw new Error(`所有模型调用失败: ${failures.map(f => f.status === 'rejected' ? f.reason?.message : f.value?.error).join(', ')}`);
  }

  // 计算两两相似度，取最高共识
  const minConsensus = options.minConsensus ?? 0.6;
  let bestConsensus = 0;
  let dominantAnswer = votes[0].content;
  let dominantModel = votes[0].modelId;

  for (let i = 0; i < votes.length; i++) {
    let agreeCount = 0;
    for (let j = 0; j < votes.length; j++) {
      if (i !== j) {
        const sim = textSimilarity(votes[i].content, votes[j].content);
        if (sim >= minConsensus) agreeCount++;
      }
    }
    const consensus = agreeCount / (votes.length - 1);
    if (consensus > bestConsensus) {
      bestConsensus = consensus;
      dominantAnswer = votes[i].content;
      dominantModel = votes[i].modelId;
    }
  }

  // 检测分歧（幻觉预警）
  const avgLatency = votes.reduce((s, v) => s + v.latency, 0) / votes.length;
  const hasDivergence = bestConsensus < minConsensus;

  const voteRecords = votes.map(v => ({
    model_id: v.modelId,
    model_name: v.modelName,
    latency_ms: v.latency,
    content_preview: v.content.substring(0, 100)
  }));

  // 持久化投票记录
  try {
    const db = getDb();
    const convId = messages.find(m => m.role === 'user')?.conversation_id || 'arbitrate';
    for (const v of votes) {
      db.prepare(
        `INSERT INTO model_votes (conversation_id, query, model_name, response, confidence, verdict, latency_ms, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      ).run(
        convId,
        messages[messages.length - 1]?.content?.substring(0, 500) || '',
        v.modelName,
        v.content?.substring(0, 2000) || '',
        bestConsensus,
        hasDivergence ? 'divergent' : 'consensus',
        v.latency
      );
    }
  } catch (e) {
    logger.warn('[ModelArb] 投票记录入库失败:', e.message);
  }

  const result = {
    finalAnswer: dominantAnswer,
    confidence: bestConsensus,
    consensus: hasDivergence ? 'low' : 'high',
    dominantModel,
    votes: voteRecords,
    avgLatency: Math.round(avgLatency),
    hasDivergence,
    hallucinationWarning: hasDivergence
      ? `模型间输出分歧较大（共识度=${bestConsensus.toFixed(2)}），可能存在幻觉。建议人工复核。`
      : null
  };

  logger.info(
    `[ModelArb] 仲裁完成: consensus=${bestConsensus.toFixed(2)} | dominant=${dominantModel} | latency=${result.avgLatency}ms | divergence=${hasDivergence}`
  );
  return result;
}

/**
 * 单模型模式（优先模式，仲裁仅作为备份）
 * 正常路径使用 agnes，仅当 agnes 不可用时启用仲裁
 */
async function chatWithFallback(messages, options = {}) {
  const agnes = registeredModels.get('agnes');
  if (agnes && agnes.enabled) {
    try {
      const result = await callLLM('agnes', messages, options);
      if (result.success && result.content) {
        return { answer: result.content, model: result.modelName, fallback: false };
      }
    } catch (e) {
      logger.warn('[ModelArb] Agnes 调用失败，尝试仲裁:', e.message);
    }
  }

  // Agnes 不可用，启用多模型仲裁
  logger.info('[ModelArb] Agnes 不可用，启用多模型仲裁');
  const arbResult = await arbitrate(messages, options);
  return {
    answer: arbResult.finalAnswer,
    model: arbResult.dominantModel,
    fallback: true,
    confidence: arbResult.confidence,
    warning: arbResult.hallucinationWarning
  };
}

/**
 * 获取已注册模型列表
 */
function getRegisteredModels() {
  return [...registeredModels.values()].map(m => ({
    id: m.id,
    name: m.name,
    model: m.model,
    enabled: m.enabled
  }));
}

module.exports = {
  registerModel,
  arbitrate,
  chatWithFallback,
  callLLM,
  getRegisteredModels,
  textSimilarity
};
