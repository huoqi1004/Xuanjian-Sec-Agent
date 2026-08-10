/**
 * LLM 行为分析引擎（BehavioralAnalyzer）
 * 检测：模型窃取、对抗探测、API 滥用、上下文中毒
 */
const logger = require('../utils/logger');

// 查询追踪：userId -> [{ts, tokens, queryHash}]
const queryTracker = new Map();
// 用户级限流窗口
const WINDOW_MS = 60_000; // 1 分钟
const MAX_QUERIES_PER_WINDOW = 20;
const MAX_TOKENS_PER_WINDOW = 50_000;

/**
 * 分析用户查询行为，返回是否需要拦截
 */
function analyzeBehavior(userId, query) {
  if (!userId || typeof query !== 'string') return { alert: null, action: 'allow' };

  const now = Date.now();
  const tokens = estimateTokens(query);
  const queryHash = simpleHash(query);

  // 更新追踪记录
  let history = queryTracker.get(userId) || [];
  history = history.filter(h => now - h.ts < WINDOW_MS * 3); // 清理 3 分钟前的记录
  history.push({ ts: now, tokens, queryHash });
  queryTracker.set(userId, history);

  const recent = history.filter(h => now - h.ts < WINDOW_MS);

  // 检测 1：高频查询（疑似模型窃取/枚举）
  if (recent.length > MAX_QUERIES_PER_WINDOW) {
    logger.warn(`[Behavior] 高频查询: userId=${userId}, ${recent.length}次/分钟`);
    return { alert: 'high_frequency', action: 'throttle', details: `频率: ${recent.length}次/分钟` };
  }

  // 检测 2：Token 耗尽攻击（单次或短时间内大量 token）
  const totalTokens = recent.reduce((s, h) => s + h.tokens, 0);
  if (totalTokens > MAX_TOKENS_PER_WINDOW) {
    logger.warn(`[Behavior] Token 超限: userId=${userId}, ${totalTokens} tokens/分钟`);
    return { alert: 'token_flood', action: 'throttle', details: `token: ${totalTokens}/min` };
  }

  // 检测 3：模式化查询（对抗样本探测）
  // 如果最近 20 条查询中，unique pattern 占比 < 30%，疑似探测
  if (recent.length >= 10) {
    const uniqueHashes = new Set(recent.map(h => h.queryHash)).size;
    const uniquenessRatio = uniqueHashes / recent.length;
    if (uniquenessRatio < 0.3) {
      logger.warn(`[Behavior] 模式化查询疑似对抗探测: userId=${userId}, uniqueness=${uniquenessRatio.toFixed(2)}`);
      return { alert: 'pattern_probe', action: 'block_and_alert', details: `独特模式占比 ${uniquenessRatio.toFixed(0)}%` };
    }
  }

  // 检测 4：超长输入（上下文中毒）
  if (tokens > 4000) {
    logger.warn(`[Behavior] 超长输入疑似注入: userId=${userId}, tokens=${tokens}`);
    return { alert: 'long_input', action: 'reject', details: `tokens: ${tokens}` };
  }

  return { alert: null, action: 'allow' };
}

/**
 * 重置指定用户的追踪记录（登出时调用）
 */
function resetUser(userId) {
  queryTracker.delete(userId);
}

/**
 * 清理过期记录（定时调用）
 */
function cleanup() {
  const now = Date.now();
  for (const [userId, history] of queryTracker.entries()) {
    const filtered = history.filter(h => now - h.ts < WINDOW_MS * 3);
    if (filtered.length === 0) {
      queryTracker.delete(userId);
    } else {
      queryTracker.set(userId, filtered);
    }
  }
}

/**
 * 简单的字符串哈希（用于模式检测，不追求加密安全）
 */
function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // 转为 32 位整数
  }
  return hash.toString(16);
}

/**
 * 粗略 token 估算
 */
function estimateTokens(text) {
  if (typeof text !== 'string') return 0;
  const cnChars = (text.match(/[\u4e00-\u9fff]/g) || []).length;
  const enChars = text.length - cnChars;
  return Math.ceil(cnChars / 1.5 + enChars / 4);
}

module.exports = { analyzeBehavior, resetUser, cleanup };
