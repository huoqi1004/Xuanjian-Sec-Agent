/**
 * 输入安全校验器（InputValidator）
 * 防护：长度超限、控制字符、Unicode 混淆、上下文中毒
 */
const logger = require('../utils/logger');

const MAX_INPUT_CHARS = 8000;  // 字符数上限（约 4096 tokens）
const MAX_INPUT_BYTES = 32000; // 字节上限（UTF-8）

/**
 * 校验并清洗用户输入
 * @param {string} text - 原始输入
 * @returns {{ valid: boolean, reason?: string, sanitized: string }}
 */
function validateInput(text) {
  if (typeof text !== 'string') {
    return { valid: false, reason: '非字符串输入', sanitized: '' };
  }

  const trimmed = text.trim();
  if (!trimmed) {
    return { valid: false, reason: '空输入', sanitized: '' };
  }

  // 字节长度检查
  const bytes = Buffer.byteLength(trimmed, 'utf-8');
  if (bytes > MAX_INPUT_BYTES) {
    logger.warn(`[InputValidator] 输入超长: ${bytes} bytes > ${MAX_INPUT_BYTES}`);
    return { valid: false, reason: `输入过长（${bytes} 字节，上限 ${MAX_INPUT_BYTES}）`, sanitized: '' };
  }

  // 字符数检查
  if (trimmed.length > MAX_INPUT_CHARS) {
    logger.warn(`[InputValidator] 字符数超限: ${trimmed.length}`);
    return { valid: false, reason: `输入过长（${trimmed.length} 字符，上限 ${MAX_INPUT_CHARS}）`, sanitized: '' };
  }

  // 移除危险控制字符（保留换行和制表符用于可读性）
  const cleaned = trimmed.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');

  // 检测 Unicode 混淆（零宽字符、方向控制字符）
  const ZERO_WIDTH = /[\u200B\u200C\u200D\uFEFF\uFFF9-\uFFFC\u202A-\u202E\u2066-\u2069]/;
  if (ZERO_WIDTH.test(cleaned)) {
    logger.warn('[InputValidator] 检测到 Unicode 混淆字符（可能为编码绕过攻击）');
    return { valid: false, reason: '检测到异常字符编码（Unicode 混淆）', sanitized: '' };
  }

  // 检测重复字符注入（如 "aaaa..." 100+ 次，疑似 prompt injection padding）
  if (/(.)\1{99,}/.test(cleaned)) {
    logger.warn('[InputValidator] 检测到重复字符注入（疑似 padding attack）');
    return { valid: false, reason: '检测到异常重复字符模式', sanitized: '' };
  }

  return { valid: true, sanitized: cleaned };
}

/**
 * 估算 token 数量（粗略估算：中文约 1.5 字符/token，英文约 4 字符/token）
 */
function estimateTokens(text) {
  if (typeof text !== 'string') return 0;
  const cnChars = (text.match(/[\u4e00-\u9fff]/g) || []).length;
  const enChars = text.length - cnChars;
  return Math.ceil(cnChars / 1.5 + enChars / 4);
}

module.exports = { validateInput, estimateTokens, MAX_INPUT_CHARS, MAX_INPUT_BYTES };
