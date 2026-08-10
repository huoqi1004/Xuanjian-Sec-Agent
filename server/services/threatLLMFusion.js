/**
 * Phase 4.1: 威胁情报 LLM 融合服务
 * 功能：
 * 1. 从 Agnes API 拉取安全威胁更新
 * 2. 解析更新内容并生成防御策略建议
 * 3. 动态注入系统 Prompt（新增威胁知识段）
 * 4. 更新防御策略引擎（新增规则）
 */
const axios = require('axios');
const crypto = require('crypto');
const logger = require('../utils/logger');
const { getDb } = require('../db/database');
const { config } = require('../config');
const metrics = require('../utils/metrics');

const PROMPT_UPDATE_SYSMSG = `
=== THREAT_INTEL_UPDATED ===
当前安全威胁态势（由 LLM 动态更新）：
[等待首次拉取...]
=== END_THREAT_INTEL_UPDATED ===`;

// 内存中的动态系统提示片段
let dynamicPromptSegments = [];
let lastUpdateTimestamp = null;
let lastUpdateHash = null;

/**
 * 计算文本的 SHA-256 哈希（用于去重）
 */
function hashContent(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * 从 Agnes API 拉取最新安全威胁更新
 * 尝试调用专门的威胁情报分析端点，失败时降级为关键词查询
 */
async function fetchSecurityUpdates() {
  metrics.inc('threat_fusion_fetch_total', 1);

  try {
    // 尝试调用 Agnes API 的威胁情报分析端点
    const resp = await axios.post(
      `${config.agnes.apiBase}/chat/completions`,
      {
        model: config.agnes.model || 'agnes-2.5-flash',
        messages: [
          {
            role: 'system',
            content: `你是一个网络安全威胁情报分析师。请分析当前最新的安全威胁态势，重点关注：
1. 最近7天内新出现的恶意IP、C2域名、漏洞利用
2. 针对AI系统的新型攻击手法（越狱、投毒、幻觉诱导）
3. 新型恶意软件传播方式
请返回JSON格式：{"threats":[{"type":"ip|domain|cve|technique","value":"...","severity":"critical|high|medium|low","description":"..."}]}`
          },
          { role: 'user', content: '请提供最新的安全威胁情报摘要，限300字以内。' }
        ],
        max_tokens: 800,
        temperature: 0.3
      },
      { timeout: 30000, headers: { 'Authorization': `Bearer ${config.agnes.apiKey}` } }
    );

    const content = resp.data?.choices?.[0]?.message?.content || '';
    return parseThreatUpdates(content);
  } catch (e) {
    logger.warn(`[ThreatFusion] Agnes API 拉取失败: ${e.message}，使用内置知识库`);
    metrics.inc('threat_fusion_fetch_fail', 1);
    return generateFallbackUpdates();
  }
}

/**
 * 解析 LLM 返回的威胁情报 JSON
 */
function parseThreatUpdates(text) {
  const updates = [];
  try {
    // 尝试提取 JSON
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      updates.push(...(parsed.threats || []));
    }
  } catch (e) {
    // 非 JSON 格式，提取关键词
    updates.push({
      type: 'general',
      value: 'security_update',
      severity: 'medium',
      description: text.substring(0, 200)
    });
  }

  // 始终包含 AI 对抗攻击的固定威胁模式
  const aiAttackPatterns = [
    { type: 'technique', value: 'prompt_jailbreak', severity: 'high', description: 'Prompt注入/越狱攻击持续增加，包括DAN、角色扮演、编码绕过' },
    { type: 'technique', value: 'rag_poisoning', severity: 'high', description: 'RAG知识库投毒攻击：向向量库注入恶意文档诱导LLM输出有害内容' },
    { type: 'technique', value: 'hallucination诱导', severity: 'medium', description: '诱导LLM输出虚假CVE编号、伪造漏洞报告' },
    { type: 'technique', value: 'token_flooding', severity: 'medium', description: 'Token洪水攻击：发送超长输入消耗API配额' }
  ];
  updates.push(...aiAttackPatterns);
  return updates;
}

/**
 * 降级：返回内置威胁情报
 */
function generateFallbackUpdates() {
  return [
    { type: 'technique', value: 'prompt_jailbreak', severity: 'high', description: 'Prompt注入攻击持续活跃，重点关注DAN、角色伪装、编码绕过' },
    { type: 'technique', value: 'rag_poisoning', severity: 'high', description: 'RAG知识库投毒：攻击者通过编辑知识库注入恶意指令' },
    { type: 'technique', value: 'hallucination', severity: 'medium', description: 'LLM幻觉攻击：伪造CVE编号、数据、漏洞链接' },
    { type: 'ip', value: '已知恶意IP池', severity: 'medium', description: 'Shodan/AbuseIPDB 恶意IP排行榜实时更新' }
  ];
}

/**
 * 将威胁更新转换为动态系统提示片段
 */
function buildPromptSegment(updates) {
  const threatList = updates.map(u =>
    `• [${u.severity.toUpperCase()}] ${u.type.toUpperCase()}: ${u.value} — ${u.description}`
  ).join('\n');

  return `
=== ACTIVE_THREAT_INTEL ===
威胁情报更新时间: ${new Date().toISOString()}
当前活跃攻击模式:
${threatList}
=== END_ACTIVE_THREAT_INTEL ===
重要：当用户请求涉及上述攻击手法时，必须拒绝并提供安全替代方案。`;
}

/**
 * 执行威胁情报融合：拉取 → 解析 → 更新系统提示
 */
async function syncThreatIntelligence() {
  logger.info('[ThreatFusion] 开始同步威胁情报...');
  metrics.inc('threat_fusion_sync_total', 1);

  const updates = await fetchSecurityUpdates();
  const promptSegment = buildPromptSegment(updates);
  const currentHash = hashContent(promptSegment);

  // 去重：如果内容未变化则跳过
  if (currentHash === lastUpdateHash) {
    logger.info('[ThreatFusion] 威胁情报无变化，跳过更新');
    return { updated: false, update_count: 0 };
  }

  // 持久化到数据库
  const db = getDb();
  try {
    db.prepare(`INSERT INTO llm_security_updates (update_type, title, content, severity, applied, source, version, created_at)
                VALUES (?, ?, ?, ?, 1, ?, ?, datetime('now'))`)
      .run('threat_intel', `威胁情报更新 ${updates.length} 条`, promptSegment, 'medium', 'agnes_api', '1.0');
  } catch (e) {
    logger.warn('[ThreatFusion] 安全更新入库失败:', e.message);
  }

  // 更新内存中的动态提示
  lastUpdateTimestamp = Date.now();
  lastUpdateHash = currentHash;
  dynamicPromptSegments = [promptSegment];

  logger.info(`[ThreatFusion] 威胁情报同步完成: ${updates.length} 条更新`);
  metrics.inc('threat_fusion_sync_success', 1);
  return { updated: true, update_count: updates.length };
}

/**
 * 获取当前动态系统提示片段
 */
function getDynamicPromptSegments() {
  return dynamicPromptSegments;
}

/**
 * 获取上次更新时间
 */
function getLastUpdateTimestamp() {
  return lastUpdateTimestamp;
}

/**
 * 手动触发拉取（供管理员调用）
 */
async function manualFetch() {
  return await syncThreatIntelligence();
}

/**
 * 从数据库加载已应用的威胁更新（启动时恢复）
 */
function loadAppliedUpdates() {
  try {
    const db = getDb();
    const rows = db.prepare(
      'SELECT content FROM llm_security_updates WHERE applied = 1 ORDER BY id DESC LIMIT 1'
    ).all();
    if (rows.length > 0) {
      const content = rows[0].content;
      lastUpdateHash = hashContent(content);
      lastUpdateTimestamp = Date.now();
      dynamicPromptSegments = [content];
      logger.info('[ThreatFusion] 从数据库恢复最新威胁情报提示片段');
    }
  } catch (e) {
    logger.warn('[ThreatFusion] 加载历史更新失败:', e.message);
  }
}

module.exports = {
  syncThreatIntelligence,
  manualFetch,
  getDynamicPromptSegments,
  getLastUpdateTimestamp,
  loadAppliedUpdates,
  hashContent
};
