/**
 * 提示词注入检测器（PromptGuard）
 * 检测用户输入中的越狱、指令覆盖、编码绕过等攻击模式
 */
const logger = require('../utils/logger');

const INJECTION_PATTERNS = [
  // 经典 ignore/disregard 模式（高危，直接拦截）
  { name: 'ignore_previous', regex: /ignore\s+(all\s+)?previous\s+(instructions|prompts|messages|system)/i, weight: 0.55 },
  { name: 'disregard', regex: /disregard\s+(all\s+)?(?:the\s+)?(?:previous\s+)?(?:instructions|prompt|security)/i, weight: 0.55 },
  { name: 'system_override', regex: /(?:system|admin|root)\s*(?:override|bypass|disabl|unlock)/i, weight: 0.5 },
  // 角色扮演越狱（高危）
  { name: 'roleplay_jailbreak', regex: /(?:pretend|act\s+as|roleplay|扮演|假装|假设).*?(?:不|无|没有)?.*(?:限制|规则|安全|道德|审核)/i, weight: 0.5 },
  { name: 'new_identity', regex: /(?:you|你)\s+(?:are|is|变成|是)\s+(?:now|no\s+longer)?(?:\s*\(DAN\)|DAN|dev|debug|test|admin|godmode|unlimited)/i, weight: 0.55 },
  // 数据提取攻击
  { name: 'data_extraction', regex: /(?:reveal|output|print|泄露|输出|show|display).*(?:system\s+prompt|internal\s+instructions|original\s+prompt|your\s+rules)/i, weight: 0.5 },
  // 编码绕过
  { name: 'encoding_bypass', regex: /(?:base64|rot13|hex|unicode|utf-?8)\s*[:=]\s*[A-Za-z0-9+\/=]{10,}/i, weight: 0.3 },
  { name: 'new_line_inject', regex: /\n\s*(?:you\s+are|ignore|act\s+as|system\s+override|new\s+rule)/i, weight: 0.5 },
  { name: 'new_line_inject_cn', regex: /\n\s*(?:你是|忽略|你变成|请忽略|请忽略所有)/i, weight: 0.55 },
  // 中文越狱关键词（高危，直接拦截）
  { name: 'cn_jailbreak_ignore', regex: /(?:忽略|忘记|屏蔽|覆盖|解除|抛弃).*(?:限制|规则|安全|禁止|道德|前)/i, weight: 0.55 },
  { name: 'cn_jailbreak_identity', regex: /(?:你是|你变成|你现在是|扮演).*(?:无限制|自由|上帝|管理员|DEV)/i, weight: 0.55 },
  { name: 'cn_jailbreak_role', regex: /(?:扮演|假设|假设你).*(?:程序员|黑客|pentester|渗透测试).*(?:不需要|不用|不必).*(?:安全|审核|限制)/i, weight: 0.45 },
  // 高级对抗模式
  { name: 'dream_mode', regex: /(?:in\s+a|处于)?.*(?:dream|幻想|假设).*(?:world|情境|场景).*(?:you\s+are|你可以)/i, weight: 0.3 },
  { name: 'focus_game', regex: /(?:focus|专注|专注于).*(?:word|单词|text|文本).*(?:ignore|忽略|不顾)/i, weight: 0.3 },
  { name: 'pastebin_escape', regex: /PASTEBIN\s*ESCAPE/i, weight: 0.6 },
  { name: 'grandma_escape', regex: /(?:grandma|奶奶).*(?:extract|输出|泄露)/i, weight: 0.4 },
  { name: 'dad_joke_escape', regex: /(?:dad|父亲).*(?:tell|讲).*(?:joke|笑话).*(?:about|关于).*(?:malware|virus|hack)/i, weight: 0.3 },
  { name: 'tree_of_thoughts', regex: /(?:tree\s+of\s+thoughts|思维树).*(?:exploit|漏洞|攻击)/i, weight: 0.3 },
  { name: 'fictional_tutorial', regex: /(?:write|写).*(?:a\s+)?(?:fictional|虚构).*(?:tutorial|教程).*(?:about|关于).*(?:hacking|恶意软件)/i, weight: 0.3 },
];

// 零宽字符检测
const ZERO_WIDTH_CHARS = /[\u200B\u200C\u200D\uFEFF\uFFF9-\uFFFC]/;

/**
 * 检测提示词注入攻击
 * @param {string} message - 用户输入
 * @returns {Object} { is_attack, score, matched_patterns, sanitized_message, action }
 */
function detectPromptInjection(message) {
  if (typeof message !== 'string' || !message.trim()) {
    return { is_attack: false, score: 0, matched_patterns: [], sanitized_message: message, action: 'allow' };
  }

  const matched = [];
  let totalScore = 0;

  for (const { name, regex, weight } of INJECTION_PATTERNS) {
    if (regex.test(message)) {
      matched.push({ name, weight });
      totalScore = Math.min(1.0, totalScore + weight);
    }
  }

  // 检测零宽字符（编码混淆）
  if (ZERO_WIDTH_CHARS.test(message)) {
    matched.push({ name: 'zero_width_encoding', weight: 0.3 });
    totalScore = Math.min(1.0, totalScore + 0.3);
    logger.warn('[PromptGuard] 检测到零宽字符（可能为编码混淆攻击）');
  }

  // 检测异常长的连续指令块（>500字符无换行，疑似注入块）
  const longBlocks = message.match(/.{500,}/g);
  if (longBlocks && longBlocks.length === 1 && totalScore === 0) {
    // 单条超长无换行消息，可能是人工构造的注入
    totalScore = Math.min(1.0, totalScore + 0.15);
    matched.push({ name: 'suspicious_long_block', weight: 0.15 });
  }

  let action = 'allow';
  if (totalScore >= 0.7) action = 'reject';
  else if (totalScore >= 0.4) action = 'sanitize';
  else if (totalScore > 0) action = 'warn';

  const sanitized = action === 'sanitize' ? stripInjectionAttempts(message) : message;

  if (matched.length > 0) {
    logger.debug(
      `[PromptGuard] score=${totalScore.toFixed(2)}, action=${action}, patterns=[${matched.map(m => m.name).join(', ')}]`
    );
  }

  return {
    is_attack: totalScore >= 0.7,
    score: totalScore,
    matched_patterns: matched,
    sanitized_message: sanitized,
    action,
  };
}

/**
 * 剥离注入指令，保留用户原始意图
 */
function stripInjectionAttempts(text) {
  // 移除已知注入模式
  let cleaned = text;
  for (const { regex } of INJECTION_PATTERNS) {
    cleaned = cleaned.replace(regex, '');
  }
  // 移除零宽字符
  cleaned = cleaned.replace(ZERO_WIDTH_CHARS, '');
  // 移除换行后的指令块
  cleaned = cleaned.replace(/\n\s*(?:you\s+are|ignore|act\s+as|system\s+override)[^\n]*/gi, '');
  return cleaned.trim();
}

/**
 * 检查知识库文档是否安全（入库前）
 */
function scanKnowledgeDoc(doc) {
  if (typeof doc.content !== 'string') return { approved: false, reason: '非字符串内容' };

  const injection = detectPromptInjection(doc.content);
  if (injection.is_attack) {
    return { approved: false, reason: `内容包含注入模式(score=${injection.score.toFixed(2)})` };
  }

  // 超长文档检查
  if (doc.content.length > 8000) {
    return { approved: false, reason: `内容超长(${doc.content.length}字符)，需人工审核` };
  }

  // 可疑链接检查
  const urls = doc.content.match(/https?:\/\/\S+/g) || [];
  const suspiciousUrls = urls.filter(u => !/^(https?:\/\/)?(localhost|127\.0\.0\.1|docs\.google\.com|github\.com)/i.test(u));
  if (suspiciousUrls.length > 0) {
    logger.warn(`[PromptGuard/KB] 文档包含可疑外链: ${suspiciousUrls.slice(0, 3).join(', ')}`);
  }

  return { approved: true, warnings: suspiciousUrls.length > 0 ? ['包含外部链接'] : [] };
}

module.exports = { detectPromptInjection, scanKnowledgeDoc, stripInjectionAttempts };
