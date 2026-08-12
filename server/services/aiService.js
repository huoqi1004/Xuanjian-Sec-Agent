const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { config } = require('../config');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');
const { sanitizeXSS } = require('../utils/security');
const { detectPromptInjection, scanKnowledgeDoc } = require('./promptGuard');
const { validateInput } = require('./inputValidator');
const { analyzeBehavior } = require('./behavioralAnalyzer');
const { detectHallucination } = require('./hallucinationDetector');

/**
 * Agnes LLM API 客户端
 */
const agnesClient = axios.create({
  baseURL: config.agnes.apiBase,
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${config.agnes.apiKey}`
  }
});

/**
 * 对话历史存储（内存）
 * 使用 LRU 策略：最多保留 MAX_CONVERSATIONS 个会话，超出时淘汰最早创建的
 */
const MAX_CONVERSATIONS = 500;
const conversationHistory = new Map();

const MAX_HISTORY_LENGTH = 20;

/**
 * 清理最旧的会话（LRU 淘汰）
 */
function _evictOldestConversation() {
  if (conversationHistory.size <= MAX_CONVERSATIONS) return;
  const oldestKey = [...conversationHistory.keys()].sort((a, b) => {
    const aAge = conversationHistory.get(a)._createdAt || 0;
    const bAge = conversationHistory.get(b)._createdAt || 0;
    return aAge - bAge;
  })[0];
  logger.info(`[aiService] 会话数超限(${conversationHistory.size}/${MAX_CONVERSATIONS})，淘汰最旧会话: ${oldestKey}`);
  conversationHistory.delete(oldestKey);
}

/**
 * 保存对话历史（内存缓存 + 落库持久化，对应 ROADMAP 4.15）
 * assistant 消息自动进行 XSS 净化
 */
function saveHistory(conversationId, message) {
  try {
    const { getDb } = require('../db/database');
    const db = getDb();
    let content = typeof message.content === 'string' ? message.content : JSON.stringify(message.content);
    // assistant 角色内容需净化 XSS，防止 LLM 返回恶意脚本
    if (message.role === 'assistant') {
      content = sanitizeXSS(content);
    }
    db.prepare('INSERT INTO chat_history (conversation_id, role, content) VALUES (?, ?, ?)')
      .run(conversationId, message.role || 'user', content || '');
  } catch (err) {
    logger.warn('对话历史落库失败:', err.message);
  }

  // 保存消息
  if (!conversationHistory.has(conversationId)) {
    conversationHistory.set(conversationId, {
      messages: [],
      _createdAt: Date.now(),
    });
    _evictOldestConversation();
  }
  const conv = conversationHistory.get(conversationId);
  conv.messages.push(message);

  if (conv.messages.length > MAX_HISTORY_LENGTH) {
    conv.messages = conv.messages.slice(-MAX_HISTORY_LENGTH);
  }
}

/**
 * 获取对话历史（内存缓存优先，缓存未命中时从数据库恢复）
 */
function getHistory(conversationId) {
  if (conversationHistory.has(conversationId)) {
    return conversationHistory.get(conversationId);
  }
  try {
    const { getDb } = require('../db/database');
    const db = getDb();
    const rows = db.all('SELECT * FROM chat_history WHERE conversation_id = ? ORDER BY id ASC', conversationId);
    const history = rows.map((r) => ({
      role: r.role,
      content: (() => {
        try { return JSON.parse(r.content); } catch (e) { return r.content; }
      })()
    }));
    conversationHistory.set(conversationId, history.slice(-MAX_HISTORY_LENGTH));
    return history;
  } catch (err) {
    return [];
  }
}

/**
 * 清除对话历史（内存 + 数据库）
 */
function clearHistory(conversationId) {
  conversationHistory.delete(conversationId);
  try {
    const { getDb } = require('../db/database');
    const db = getDb();
    db._deleteRows('chat_history', (r) => r.conversation_id === conversationId);
  } catch (err) {
    logger.warn('清除对话历史落库失败:', err.message);
  }
}

/**
 * 定义可用工具（Skill技术）
 */
const tools = [
  {
    type: 'function',
    function: {
      name: 'get_threat_intel',
      description: '多源威胁情报聚合查询，支持微步TI、Shodan、AbuseIPDB、VirusTotal等7个数据源',
      parameters: {
        type: 'object',
        properties: {
          iocType: { type: 'string', enum: ['ip', 'domain', 'hash', 'url'], description: 'IOC类型' },
          value: { type: 'string', description: '要查询的IOC值（IP地址/域名/文件哈希/URL）' }
        },
        required: ['iocType', 'value']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'query_shodan',
      description: '查询Shodan获取IP的端口、服务、漏洞信息',
      parameters: {
        type: 'object',
        properties: {
          ip: { type: 'string', description: '目标IP地址' }
        },
        required: ['ip']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'query_abuseipdb',
      description: '查询AbuseIPDB获取IP信誉和滥用报告',
      parameters: {
        type: 'object',
        properties: {
          ip: { type: 'string', description: '目标IP地址' }
        },
        required: ['ip']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'query_virustotal',
      description: '查询VirusTotal获取IP/域名/文件的恶意检测统计',
      parameters: {
        type: 'object',
        properties: {
          iocType: { type: 'string', enum: ['ip', 'domain', 'hash'], description: 'IOC类型' },
          value: { type: 'string', description: '要查询的值' }
        },
        required: ['iocType', 'value']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'get_scan_results',
      description: '获取端口扫描结果',
      parameters: {
        type: 'object',
        properties: {
          task_id: { type: 'string', description: '扫描任务ID' }
        },
        required: ['task_id']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'get_alert_summary',
      description: '获取安全告警摘要',
      parameters: {
        type: 'object',
        properties: {
          severity: { type: 'string', description: '告警级别过滤: critical, high, medium, low' },
          limit: { type: 'integer', description: '返回数量限制' }
        }
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'get_baseline_results',
      description: '获取基线检查结果',
      parameters: {
        type: 'object',
        properties: {
          task_id: { type: 'string', description: '基线检查任务ID' }
        },
        required: ['task_id']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'analyze_virus_hash',
      description: '分析文件哈希是否为恶意软件',
      parameters: {
        type: 'object',
        properties: {
          hash: { type: 'string', description: '文件哈希值 (MD5或SHA256)' }
        },
        required: ['hash']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'generate_security_report',
      description: '生成安全报告',
      parameters: {
        type: 'object',
        properties: {
          type: { type: 'string', description: '报告类型: daily, weekly, monthly' }
        }
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'analyze_alerts',
      description: '分析安全告警',
      parameters: {
        type: 'object',
        properties: {
          severity: { type: 'string', description: '告警级别过滤' },
          limit: { type: 'integer', description: '分析数量' }
        }
      }
    }
  }
];

/**
 * 支持的指令列表
 */
const commands = {
  'help': {
    description: '显示帮助信息',
    example: 'help',
    action: () => ({
      success: true,
      content: `玄鉴安全智能体助手 - 可用命令列表：

📊 报告生成:
- report daily/weekly/monthly - 生成安全报告
- scan report <task_id> - 生成扫描报告
- baseline report - 生成基线检查报告

🔍 威胁情报:
- threat intel <type> <value> - 查询威胁情报（type: ip/domain/hash/cve）
- analyze hash <hash_value> - 分析文件哈希

⚠️ 告警管理:
- alerts - 查看告警摘要
- alerts <severity> - 按级别查看告警（critical/high/medium/low）
- analyze alerts - 分析告警数据

🔧 系统操作:
- health - 检查系统健康状态
- clear history - 清除对话历史

💬 自然语言:
直接输入问题或需求，我会为您提供专业的安全分析和建议。
`
    })
  },
  'health': {
    description: '检查系统健康状态',
    example: 'health',
    action: async () => {
      const db = require('../db/database').getDb();
      const alerts = db.all('SELECT * FROM alert_records');
      const policies = db.all('SELECT * FROM auto_policies WHERE enabled = 1');
      const intel = db.all('SELECT * FROM threat_intel');
      
      return {
        success: true,
        content: `系统健康状态检查：

📊 安全概览:
- 告警总数: ${alerts.length} 条
- 活跃策略: ${policies.length} 个
- 威胁情报: ${intel.length} 条

⚠️ 严重告警:
${alerts.filter(a => a.severity === 'critical').slice(0, 3).map(a => `  - ${a.description}`).join('\n') || '  无'}

✅ 系统状态: 运行正常`
      };
    }
  },
  'clear': {
    description: '清除对话历史',
    example: 'clear history',
    action: (conversationId) => {
      clearHistory(conversationId);
      return {
        success: true,
        content: '对话历史已清除'
      };
    }
  }
};

/**
 * 指令解析器
 */
function parseCommand(message) {
  const lowerMsg = message.toLowerCase().trim();
  const originalMsg = message.trim();
  logger.debug(`[parseCommand] 原始消息: "${originalMsg}"`);

  if (lowerMsg === 'help' || originalMsg === '帮助' || originalMsg === '帮助信息') {
    logger.debug('[parseCommand] 匹配命令: help');
    return { command: 'help', params: [] };
  }

  if (lowerMsg === 'health' || originalMsg === '健康' || originalMsg === '系统健康' || originalMsg === '健康检查') {
    logger.debug('[parseCommand] 匹配命令: health');
    return { command: 'health', params: [] };
  }

  if (lowerMsg === 'clear history' || originalMsg === '清除历史' || originalMsg === '清空对话') {
    logger.debug('[parseCommand] 匹配命令: clear');
    return { command: 'clear', params: ['history'] };
  }

  if (lowerMsg.startsWith('report ') ||
      originalMsg.startsWith('安全日报') ||
      originalMsg.startsWith('安全周报') ||
      originalMsg.startsWith('安全月报') ||
      originalMsg.startsWith('报告') ||
      originalMsg === '安全日报' ||
      originalMsg === '安全周报' ||
      originalMsg === '安全月报') {
    let type = 'daily';
    if (lowerMsg.startsWith('report ')) {
      type = lowerMsg.split(' ')[1] || 'daily';
    } else if (originalMsg.includes('周报') || originalMsg.includes('weekly')) {
      type = 'weekly';
    } else if (originalMsg.includes('月报') || originalMsg.includes('monthly')) {
      type = 'monthly';
    } else if (originalMsg.includes('日报') || originalMsg.includes('daily')) {
      type = 'daily';
    }
    logger.debug(`[parseCommand] 匹配命令: report, type=${type}`);
    return { command: 'report', params: [type] };
  }

  if (lowerMsg.startsWith('alerts') || originalMsg.startsWith('告警')) {
    const match = originalMsg.match(/告警\s*(\w+)/);
    const severity = match ? match[1] : '';
    logger.debug(`[parseCommand] 匹配命令: alerts, severity="${severity}"`);
    return { command: 'alerts', params: severity ? [severity] : [] };
  }

  if (lowerMsg.startsWith('threat intel ') || originalMsg.includes('威胁情报')) {
    if (lowerMsg.startsWith('threat intel ')) {
      const parts = lowerMsg.split(' ');
      const iocType = parts[2] || '';
      const value = parts.slice(3).join(' ') || '';
      logger.debug(`[parseCommand] 匹配命令: threat_intel (英文指令), iocType="${iocType}", value="${value}", parts=[${parts.join(', ')}]`);
      return { command: 'threat_intel', params: [iocType, value] };
    }
    // 中文自然语言：提取 IP/域名/哈希
    const ipMatch = originalMsg.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    const domainMatch = originalMsg.match(/([a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,})/);
    const hashMatch = originalMsg.match(/([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})/);
    let iocType = '';
    let value = '';
    if (ipMatch) { iocType = 'ip'; value = ipMatch[1]; }
    else if (hashMatch) { iocType = 'hash'; value = hashMatch[1]; }
    else if (domainMatch) { iocType = 'domain'; value = domainMatch[1]; }
    logger.debug(`[parseCommand] 匹配命令: threat_intel (中文自然语言), iocType="${iocType}", value="${value}", ipMatch=${ipMatch ? `"${ipMatch[1]}"` : 'null'}, hashMatch=${hashMatch ? `"${hashMatch[1]}"` : 'null'}, domainMatch=${domainMatch ? `"${domainMatch[1]}"` : 'null'}`);
    if (!value) {
      logger.warn('[parseCommand] 威胁情报命令未提取到有效的 IOC 值（IP/域名/哈希）');
    }
    return { command: 'threat_intel', params: [iocType, value] };
  }

  if (lowerMsg.startsWith('analyze hash ') || originalMsg.includes('分析哈希')) {
    const hash = lowerMsg.startsWith('analyze hash ')
      ? lowerMsg.replace('analyze hash ', '')
      : (originalMsg.replace('分析哈希', '').trim() || '');
    logger.debug(`[parseCommand] 匹配命令: analyze_hash, hash="${hash}"`);
    return { command: 'analyze_hash', params: [hash] };
  }

  if (lowerMsg.startsWith('alerts')) {
    const parts = lowerMsg.split(' ');
    const severity = parts[1] || '';
    logger.debug(`[parseCommand] 匹配命令: alerts, severity="${severity}"`);
    return { command: 'alerts', params: [severity] };
  }

  if (lowerMsg.startsWith('analyze alerts')) {
    logger.debug('[parseCommand] 匹配命令: analyze_alerts');
    return { command: 'analyze_alerts', params: [] };
  }

  logger.debug('[parseCommand] 未匹配任何命令，返回 null（将走 LLM 工具调用路径）');
  return null;
}

/**
 * 工具执行器
 */
async function executeTool(toolName, params) {
  // 兼容壳：转发到工具注册表（N-25 Task A4）
  const { executeToolByName } = require('../agents/tools/registry');
  const { registerBuiltinTools } = require('../agents/tools');
  registerBuiltinTools();
  try {
    return await executeToolByName(toolName, params);
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * 获取仪表板数据
 */
function getDashboardData() {
  const { getDb } = require('../db/database');
  const db = getDb();
  
  const alerts = db.all('SELECT * FROM alert_records ORDER BY created_at DESC LIMIT 20');
  const scanTasks = db.all('SELECT * FROM scan_tasks ORDER BY created_at DESC LIMIT 10');
  const intel = db.all('SELECT * FROM threat_intel LIMIT 15');
  const policies = db.all('SELECT * FROM auto_policies WHERE enabled = 1');
  
  return {
    alerts,
    scanTasks,
    threatIntel: intel,
    policies,
    summary: {
      totalAlerts: alerts.length,
      criticalAlerts: alerts.filter(a => a.severity === 'critical').length,
      highAlerts: alerts.filter(a => a.severity === 'high').length,
      scanTasksCount: scanTasks.length,
      threatIntelCount: intel.length,
      activePolicies: policies.length
    }
  };
}

/**
 * 生成病毒查杀报告（多引擎查杀数据 → LLM 报告）
 */
async function generateVirusReport(data) {
  const { fileName, fileSize, hashes, engineSummary, decision, scanTime, totalTime } = data;

  const prompt = `请根据以下病毒查杀数据生成一份专业的查杀报告（Markdown格式）：

## 文件信息
- 文件名: ${fileName}
- 文件大小: ${fileSize < 1048576 ? (fileSize / 1024).toFixed(1) + ' KB' : (fileSize / 1048576).toFixed(1) + ' MB'}
- MD5: ${hashes.md5}
- SHA256: ${hashes.sha256}

## 各引擎扫描结果
${engineSummary.map(e => `- **${e.engine}**: ${e.verdict} (置信度 ${(e.confidence * 100).toFixed(0)}%, 耗时 ${e.responseTime}) - ${e.detail}`).join('\n')}

## 最终判定
- 结论: ${decision.verdict === 'malicious' ? '恶意' : (decision.verdict === 'suspicious' ? '疑似' : '安全')}
- 置信度: ${(decision.confidence * 100).toFixed(1)}%
- 主要判定引擎: ${decision.primaryEngine}
- 处置建议: ${decision.recommendation}
- 扫描耗时: ${totalTime}s

请生成一份结构化的查杀报告，包含：
1. 报告摘要（简明扼要）
2. 文件信息汇总
3. 多引擎检测结果分析
4. 风险评估与处置建议
5. 附录（各引擎详细信息）

报告风格要专业、简洁，适合提交给安全团队审阅。`;

  const response = await callDeepSeek([
    { role: 'system', content: '你是玄鉴安全智能体病毒查杀报告专家，擅长生成专业的安全查杀报告。请输出Markdown格式的报告。' },
    { role: 'user', content: prompt }
  ], { maxTokens: 4096, temperature: 0.3 });

  return response.data?.choices?.[0]?.message?.content || null;
}

/**
 * RAG 知识库检索（调用 Python AI 服务的本地向量检索）
 * @returns {Promise<Array>} [{id,title,content,category,severity,score}]，失败返回空数组（降级）
 */
async function searchKnowledge(query, topK = 5) {
  try {
    const resp = await axios.post(
      `${config.aiService.url}/api/knowledge/search`,
      { query, top_k: topK },
      { timeout: 8000 }
    );
    const body = resp.data;
    if (body && body.code === 0 && Array.isArray(body.data)) {
      return body.data;
    }
    return [];
  } catch (err) {
    logger.warn(`[RAG] 知识库检索失败（已降级）: ${err.message.substring(0, 100)}`);
    return [];
  }
}

/**
 * 调用 Agnes LLM
 */
async function callDeepSeek(messages, options = {}) {
  metrics.inc('ai_calls_total', { provider: 'agnes' }, 1, 'AI 调用次数');

  // Token 预算控制：防止上下文过长导致 DoS 或上下文中毒
  const MAX_CONTEXT_TOKENS = 16000;
  const totalTokens = estimateTokensForMessages(messages);
  if (totalTokens > MAX_CONTEXT_TOKENS) {
    logger.warn(`[LLM-Token] 上下文超限: ${totalTokens} tokens > ${MAX_CONTEXT_TOKENS}，执行截断`);
    messages = truncateMessagesToBudget(messages, MAX_CONTEXT_TOKENS);
  }
  try {
    const requestBody = {
      model: config.agnes.model,
      messages: messages,
      max_tokens: options.maxTokens || config.agnes.maxTokens,
      temperature: options.temperature || 0.7,
      ...(options.tools ? { tools: options.tools } : {}),
      ...(options.tool_choice ? { tool_choice: options.tool_choice } : {})
    };

    const response = await agnesClient.post('/chat/completions', requestBody);
    return { success: true, data: response.data };
  } catch (err) {
    metrics.inc('ai_calls_failed_total', { provider: 'agnes' }, 1, 'AI 调用失败次数');
    logger.error('Agnes API 调用失败:', err.response?.data || err.message);
    return { success: false, error: err.response?.data?.error?.message || err.message };
  }
}

/**
 * 解析 <function_calls> XML 格式的工具调用
 */
function parseFunctionCalls(jsonStr) {
  try {
    const arr = JSON.parse(jsonStr);
    return arr.map((item, idx) => ({
      id: `call_${Date.now()}_${idx}`,
      type: 'function',
      function: {
        name: item.name,
        arguments: JSON.stringify(item.parameters || {})
      }
    }));
  } catch {
    return null;
  }
}

/**
 * 带工具调用的对话（Skill技术核心）
 */
async function chatWithTools(userMessage, context = {}) {
  try {
    let systemPrompt = `
你是玄鉴安全智能体，一个专业的网络安全AI助手，基于Agnes模型驱动。你的任务是帮助用户分析安全数据、生成安全报告和提供安全建议。

你可以使用以下工具：
- get_threat_intel: 多源威胁情报聚合查询（微步TI、Shodan、AbuseIPDB、VirusTotal、Google Safe Browsing等7个数据源）
- query_shodan: 查询Shodan获取IP的端口、服务、漏洞信息
- query_abuseipdb: 查询AbuseIPDB获取IP信誉和滥用报告
- query_virustotal: 查询VirusTotal获取IP/域名/文件的恶意检测统计
- analyze_virus_hash: 通过360、卡巴斯基、VirusTotal等多引擎分析文件哈希
- scan_file_with_ai: AI驱动智能文件查杀（支持7引擎并行扫描）
- get_scan_results: 获取端口扫描结果
- get_alert_summary: 获取安全告警摘要
- get_baseline_results: 获取基线检查结果
- generate_security_report: 生成安全报告
- analyze_alerts: 分析安全告警

如果需要调用工具，请输出工具调用指令。

输出格式：
如果需要调用工具：
<function_calls>[{"name":"工具名称","parameters":{"参数名":"参数值"}}]</function_calls>

如果不需要调用工具，可以直接回答用户问题。
`.trim();

    // RAG 增强：检索内部知识库，将相关条目注入 system prompt 供回答引用
    // 知识库内容与 system prompt 严格隔离，防止知识库投毒影响核心指令
    try {
      const kbHits = await searchKnowledge(userMessage, 3);
      if (kbHits.length > 0) {
        // 入库前安全检查（防御知识库投毒）
        const safeHits = [];
        for (const hit of kbHits) {
          const scan = scanKnowledgeDoc(hit);
          if (scan.approved) {
            safeHits.push(hit);
          } else {
            logger.warn(`[AI-Security] RAG 知识库文档被拒绝: title=${hit.title}, reason=${scan.reason}`);
          }
        }
        if (safeHits.length > 0) {
          // 使用明确分隔符隔离知识库内容，LLM 需标注引用来源
          const kbSection = `\n\n=== KNOWLEDGE_BASE ===\n以下知识来自内部知识库（已安全扫描），回答时请引用并标注来源 [DOC:ID]：\n${safeHits.map((h, i) => `[DOC:${i+1}] ${h.title}:\n${h.content}`).join('\n\n')}\n=== END_KNOWLEDGE_BASE ===`;
          systemPrompt += kbSection;
        }
      }
    } catch (e) {
      // RAG 检索失败不影响主流程
    }

    const messages = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userMessage }
    ];

    const response = await callDeepSeek(messages, { tools });
    
    if (!response.success) {
      return { success: false, error: response.error || 'Agnes API 调用失败' };
    }
    
    const choice = response.data?.choices?.[0];
    if (!choice) {
      return { success: false, error: 'API响应异常' };
    }

    const toolCalls = choice.message?.tool_calls;
    // 兼容 <function_calls> XML 格式（部分 LLM 返回此格式而非 OpenAI tool_calls）
    const functionCallsMatch = choice.message?.content?.match(/<function_calls>\s*(\[.*?\])\s*<\/function_calls>/s);
    const parsedToolCalls = toolCalls || (functionCallsMatch ? parseFunctionCalls(functionCallsMatch[1]) : []);
    if (parsedToolCalls && parsedToolCalls.length > 0) {
      const toolResults = [];

      for (const toolCall of parsedToolCalls) {
        let args;
        try {
          args = JSON.parse(toolCall.function?.arguments || JSON.stringify(toolCall.parameters || {}));
        } catch (parseErr) {
          toolResults.push({
            tool_call_id: toolCall.id || `call_${Date.now()}`,
            tool_name: toolCall.function?.name || toolCall.name,
            result: { success: false, error: '参数解析失败: ' + parseErr.message }
          });
          continue;
        }
        const result = await executeTool(toolCall.function?.name || toolCall.name, args);
        toolResults.push({
          tool_call_id: toolCall.id || `call_${Date.now()}`,
          tool_name: toolCall.function?.name || toolCall.name,
          result: result
        });
      }

      messages.push(choice.message);
      
      for (const toolResult of toolResults) {
        messages.push({
          role: 'tool',
          content: JSON.stringify(toolResult),
          tool_call_id: toolResult.tool_call_id
        });
      }

      const finalResponse = await callDeepSeek(messages);
      if (!finalResponse.success) {
        logger.warn('工具调用后 LLM 二次回复失败，降级使用工具结果生成回复:', finalResponse.error);
        // 降级：从工具结果直接构造回复，避免整体失败
        const failedTools = toolResults.filter(r => !r.result?.success);
        if (failedTools.length > 0) {
          const toolErrorList = failedTools.map(r => `• ${r.tool_name}: ${r.result?.error || '执行失败'}`).join('\n');
          return {
            success: true,
            content: `已尝试执行工具，但部分工具调用失败：\n\n${toolErrorList}\n\n\n\n如需进一步分析，请检查相关 API Key 配置。`,
            tool_results: toolResults
          };
        }
        return { success: false, error: finalResponse.error || 'Agnes API 调用失败', tool_results: toolResults };
      }
      
      return {
        success: true,
        content: finalResponse.data?.choices?.[0]?.message?.content || '处理完成',
        tool_results: toolResults
      };
    }

    let rawContent = choice.message?.content || '无响应';

    // 幻觉检测：验证 LLM 输出是否编造了知识库引用
    if (rawContent) {
      try {
        const kbHits = await searchKnowledge(userMessage, 3);
        const hallucinationCheck = detectHallucination(rawContent, kbHits, null);
        if (hallucinationCheck.is_hallucination) {
          logger.warn(`[AI-Security] 检测到模型幻觉: score=${hallucinationCheck.confidence.toFixed(2)}, action=${hallucinationCheck.action}`);
          rawContent = `[⚠️ AI 分析置信度较低，建议人工核实] ${rawContent}`;
        } else if (hallucinationCheck.warning) {
          rawContent = `[ℹ️ ${hallucinationCheck.warning}]\n${rawContent}`;
        }
      } catch (e) {
        logger.warn('[AI-Security] 幻觉检测失败（降级处理）:', e.message);
      }
    }

    // XSS 净化（assistant 输出安全）
    const safeContent = sanitizeXSS(rawContent);

    return {
      success: true,
      content: safeContent,
      tool_results: []
    };
  } catch (err) {
    logger.error('chatWithTools 异常:', err.message);
    return { success: false, error: 'AI处理异常: ' + err.message };
  }
}

/**
 * AI安全助手对话
 */
async function chatAssistant(conversationId, userMessage) {
  // ① 输入安全校验（长度/控制字符/Unicode 混淆）
  const inputCheck = validateInput(userMessage);
  if (!inputCheck.valid) {
    logger.warn(`[AI-Security] 输入校验失败: ${inputCheck.reason}, conversationId=${conversationId}`);
    return { success: false, content: `⚠️ ${inputCheck.reason}` };
  }
  userMessage = inputCheck.sanitized;

  // ② 行为分析（防模型窃取/高频探测/上下文中毒）
  const behavior = analyzeBehavior(conversationId, userMessage);
  if (behavior.action === 'block_and_alert') {
    logger.warn(`[AI-Security] 行为异常阻断: userId=${conversationId}, alert=${behavior.alert}, ${behavior.details}`);
    return { success: false, content: '⚠️ 请求异常，已触发安全告警，请联系管理员' };
  }
  if (behavior.action === 'reject') {
    logger.warn(`[AI-Security] 输入拒绝: userId=${conversationId}, alert=${behavior.alert}, ${behavior.details}`);
    return { success: false, content: '⚠️ 输入内容不符合安全规范，请简化您的提问' };
  }
  if (behavior.action === 'throttle') {
    logger.warn(`[AI-Security] 频率限制: userId=${conversationId}, alert=${behavior.alert}`);
    return { success: false, content: '⚠️ 请求过于频繁，请稍后再试' };
  }

  // ③ 提示词注入检测
  const injectionCheck = detectPromptInjection(userMessage);
  if (injectionCheck.is_attack) {
    logger.warn(`[AI-Security] 提示词注入检测: score=${injectionCheck.score.toFixed(2)}, patterns=[${injectionCheck.matched_patterns.map(p => p.name).join(', ')}]`);
    return { success: false, content: '⚠️ 您的输入包含疑似注入指令，已拒绝处理' };
  }
  if (injectionCheck.action === 'sanitize') {
    userMessage = injectionCheck.sanitized_message;
    logger.info(`[AI-Security] 提示词注入已净化，继续处理`);
  }

  const parsedCommand = parseCommand(userMessage);
  
  if (parsedCommand) {
    const { command, params } = parsedCommand;
    
    if (command === 'help') {
      saveHistory(conversationId, { role: 'user', content: userMessage });
      const result = commands.help.action();
      saveHistory(conversationId, { role: 'assistant', content: result.content });
      return result;
    }
    
    if (command === 'health') {
      saveHistory(conversationId, { role: 'user', content: userMessage });
      const result = await commands.health.action();
      saveHistory(conversationId, { role: 'assistant', content: result.content });
      return result;
    }
    
    if (command === 'clear') {
      const result = commands.clear.action(conversationId);
      return result;
    }
    
    if (command === 'report') {
      saveHistory(conversationId, { role: 'user', content: userMessage });
      const reportType = params[0] || 'daily';
      try {
        const report = await generateSecurityReport(getDashboardData(), reportType);
        saveHistory(conversationId, { role: 'assistant', content: report });
        return { success: true, content: report, is_report: true };
      } catch (err) {
        logger.error('报告生成失败:', err.message);
        const errorMsg = '❌ 报告生成失败：' + err.message;
        saveHistory(conversationId, { role: 'assistant', content: errorMsg });
        return { success: false, content: errorMsg };
      }
    }
    
    if (command === 'threat_intel') {
      saveHistory(conversationId, { role: 'user', content: userMessage });
      const [type, value] = params;
      const result = await executeTool('get_threat_intel', { iocType: type, value });
      let content;
      if (result.success && result.data) {
        const d = result.data;
        const sources = Array.isArray(d.sources)
          ? d.sources.map((s, i) => `  ${i + 1}. [${s.source}] ${s.verdict || 'unknown'}`).join('\n')
          : '  (无来源数据)';
        content = `威胁情报查询结果（${type || '未知类型'}: ${value}）\n\n风险等级: ${d.riskLevel || 'unknown'}\n风险评分: ${d.riskScore ?? 'N/A'}\n摘要: ${d.summary || '无'}\n\n来源:\n${sources}`;
      } else {
        content = result.error ? `查询失败: ${result.error}` : '无结果';
      }
      saveHistory(conversationId, { role: 'assistant', content });
      return { success: result.success, content };
    }
    
    if (command === 'analyze_hash') {
      saveHistory(conversationId, { role: 'user', content: userMessage });
      const [hash] = params;
      const result = await executeTool('analyze_virus_hash', { hash });
      let content;
      if (result.success && result.data) {
        const d = result.data;
        if (d.threat_name) {
          content = `⚠️ 检测到恶意软件：\n- 威胁名称: ${d.threat_name}\n- 严重级别: ${d.severity}\n- 来源: ${d.source}`;
        } else if (d.hash) {
          const sources = Array.isArray(d.sources) ? d.sources : [];
          const threatEntries = sources.filter(s => s.verdict === 'malicious' || s.verdict === 'high_risk');
          content = threatEntries.length > 0
            ? `⚠️ 检测到恶意软件：\n- 哈希: ${d.hash}\n- 威胁来源: ${threatEntries.map(s => s.source).join(', ')}`
            : `✅ 未在已知威胁数据库中找到该哈希: ${d.hash}`;
        } else {
          content = `✅ 哈希分析完成: ${hash}`;
        }
      } else {
        content = result.error ? `查询失败: ${result.error}` : '无结果';
      }
      saveHistory(conversationId, { role: 'assistant', content });
      return { success: result.success, content };
    }
    
    if (command === 'alerts') {
      saveHistory(conversationId, { role: 'user', content: userMessage });
      const [severity] = params;
      const result = await executeTool('get_alert_summary', { severity, limit: 10 });
      const content = result.success 
        ? `找到 ${result.data.length} 条告警：\n\n${result.data.map((alert, i) => `${i+1}. [${alert.severity.toUpperCase()}] ${alert.description}`).join('\n')}`
        : `查询失败: ${result.error}`;
      saveHistory(conversationId, { role: 'assistant', content });
      return { success: result.success, content };
    }
    
    if (command === 'analyze_alerts') {
      saveHistory(conversationId, { role: 'user', content: userMessage });
      const result = await executeTool('analyze_alerts', { limit: 20 });
      const content = result.success ? result.data : '告警分析失败: ' + (result.error || '未知错误');
      saveHistory(conversationId, { role: 'assistant', content });
      return { success: result.success, content };
    }
  }
  
  saveHistory(conversationId, { role: 'user', content: userMessage });
  
  const result = await chatWithTools(userMessage);
  
  if (result.success) {
    saveHistory(conversationId, { role: 'assistant', content: result.content });
  }
  
  return result;
}

/**
 * 调用 Python AI 微服务进行文件检测（multipart 上传）
 * @param {string} endpoint - /api/detect/malware 或 /api/detect/poisoning
 * @param {string} filePath - 本地文件路径
 * @returns {Object|null} Python 服务返回的检测结果；调用失败返回 null
 */
async function callAiServiceFileDetection(endpoint, filePath, fileBuffer = null) {
  metrics.inc('ai_calls_total', { provider: 'python' }, 1, 'AI 调用次数');
  try {
    if (!fileBuffer) {
      if (!fs.existsSync(filePath)) throw new Error('文件不存在');
      fileBuffer = fs.readFileSync(filePath);
    }
    const boundary = '----XuanJian' + Date.now() + Math.random().toString(16).slice(2);
    const filename = path.basename(filePath).replace(/[^a-zA-Z0-9._-]/g, '_');

    const body = Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`),
      fileBuffer,
      Buffer.from(`\r\n--${boundary}--\r\n`)
    ]);

    const resp = await axios.post(`${config.aiService.url}${endpoint}`, body, {
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
      timeout: 120000,
      maxBodyLength: 110 * 1024 * 1024,
      maxContentLength: 110 * 1024 * 1024
    });
    return resp.data || null;
  } catch (err) {
    metrics.inc('ai_calls_failed_total', { provider: 'python' }, 1, 'AI 调用失败次数');
    logger.warn(`[AI服务] 调用 ${endpoint} 失败: ${err.message}`);
    return null;
  }
}

/**
 * 本地降级检测：Python AI 服务不可用时，使用轻量规则（熵值 + 可执行头 + 可疑字符串）
 * @returns {Object} 与 Python 服务结构一致的检测结果
 */
function degradeMalwareDetect(filePath, fileBuffer = null) {
  try {
    const data = fileBuffer || fs.readFileSync(filePath);
    const entropy = calculateEntropy(data);
    let score = 0;
    const anomalies = [];

    if (entropy > 7.5) { score += 0.35; anomalies.push('文件熵值异常偏高，可能经过加密或混淆'); }
    else if (entropy > 6.5) { score += 0.15; anomalies.push('文件熵值较高'); }

    if (data.length >= 2 && data[0] === 0x4d && data[1] === 0x5a) {
      score += 0.2; anomalies.push('PE 可执行文件');
    }

    const suspiciousBytes = ['powershell', 'WScript.Shell', 'CreateObject', 'RegWrite', 'cmd.exe', 'keylog', 'GetAsyncKeyState'];
    let hit = 0;
    for (const s of suspiciousBytes) {
      if (data.includes(s)) hit++;
    }
    if (hit > 0) { score += Math.min(0.3, hit * 0.15); anomalies.push(`命中 ${hit} 个可疑行为特征`); }

    return {
      is_malicious: score > 0.5,
      score: Math.min(score, 1),
      method: 'local_rule_degraded',
      model_version: null,
      rule_score: Math.min(score, 1),
      model_probability: null,
      anomalies
    };
  } catch (err) {
    logger.error(`[AI服务] 本地降级检测失败: ${err.message}`);
    return { is_malicious: false, score: 0, method: 'degraded_error', anomalies: ['降级检测失败'] };
  }
}

function calculateEntropy(data) {
  if (!data || data.length === 0) return 0;
  const freq = new Map();
  for (const byte of data) freq.set(byte, (freq.get(byte) || 0) + 1);
  let entropy = 0;
  const len = data.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * AI恶意代码检测
 * 优先调用 Python AI 微服务（真实 PE 特征 + 规则引擎/GBDT），失败时降级本地规则。
 * 不再使用 LLM 基于文件名/大小进行不可靠分析。
 */
async function detectMalware(filePath, fileBuffer = null) {
  const result = await callAiServiceFileDetection('/api/detect/malware', filePath, fileBuffer);
  if (result && typeof result.is_malicious === 'boolean') {
    return {
      is_malicious: result.is_malicious,
      score: result.score || 0,
      method: result.method || 'python_rule_engine',
      model_version: result.model_version || null,
      rule_score: result.rule_score,
      model_probability: result.model_probability,
      anomalies: result.anomalies || []
    };
  }
  logger.warn('[AI服务] Python 恶意检测不可用，使用本地降级规则');
  return degradeMalwareDetect(filePath, fileBuffer);
}

/**
 * AI威胁情报分析
 */
async function analyzeThreatIntel(iocData) {
  try {
    const systemPrompt = `
你是威胁情报分析专家。请分析以下威胁指标(IOC)数据：

${JSON.stringify(iocData, null, 2)}

请提供：
1. 威胁评估
2. 关联分析
3. 处置建议
`.trim();

    const messages = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: '请进行威胁情报分析' }
    ];

    const response = await callDeepSeek(messages);
    return {
      success: true,
      content: response.data?.choices?.[0]?.message?.content || '分析完成'
    };
  } catch (err) {
    logger.error('威胁情报分析失败:', err.message);
    throw err;
  }
}

/**
 * AI安全报告生成
 */
async function generateSecurityReport(dashboard, reportType = 'weekly') {
  try {
    const reportTemplates = {
      daily: '生成一份简要的每日安全报告',
      weekly: '生成一份详细的周安全报告，包括威胁趋势分析、漏洞统计和改进建议',
      monthly: '生成一份全面的月度安全报告，包括趋势分析、风险评估和战略建议'
    };

    const systemPrompt = `
你是专业的安全报告生成专家。请根据以下安全仪表板数据生成${reportTemplates[reportType] || '安全报告'}：

仪表板数据：
${JSON.stringify(dashboard, null, 2)}

报告要求：
1. 数据准确引用
2. 分析深入透彻
3. 建议切实可行
4. 格式专业美观
`.trim();

    const messages = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: '请生成安全报告' }
    ];

    const response = await callDeepSeek(messages, { maxTokens: 4096 });
    return response.data?.choices?.[0]?.message?.content || '报告生成完成';
  } catch (err) {
    logger.error('安全报告生成失败:', err.message);
    throw err;
  }
}

/**
 * AI基线检查报告润色
 */
async function generateBaselineReport(checkResults) {
  try {
    const systemPrompt = `
你是安全合规专家。请根据以下基线检查结果生成专业的合规报告：

检查结果：
${JSON.stringify(checkResults, null, 2)}

报告要求：
1. 列出所有检查项及其状态
2. 分析不合规项的风险
3. 提供具体的整改建议
4. 生成合规评分
`.trim();

    const messages = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: '请生成基线检查报告' }
    ];

    const response = await callDeepSeek(messages);
    return response.data?.choices?.[0]?.message?.content || '报告生成完成';
  } catch (err) {
    logger.error('基线报告生成失败:', err.message);
    throw err;
  }
}

/**
 * AI扫描报告生成
 */
async function generateScanReport(scanData) {
  try {
    const systemPrompt = `
你是网络安全扫描分析专家。请根据以下端口扫描结果生成专业的安全分析报告：

扫描数据：
${JSON.stringify(scanData, null, 2)}

报告要求：
1. 分析开放端口和服务
2. 识别潜在漏洞和风险
3. 提供安全加固建议
4. 生成风险评分
`.trim();

    const messages = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: '请生成扫描报告' }
    ];

    const response = await callDeepSeek(messages);
    return response.data?.choices?.[0]?.message?.content || '报告生成完成';
  } catch (err) {
    logger.error('扫描报告生成失败:', err.message);
    throw err;
  }
}

/**
 * AI告警分析
 */
async function analyzeAlerts(alerts) {
  try {
    const systemPrompt = `
你是安全运营中心(SOC)分析师。请根据以下告警数据进行分析：

告警数据：
${JSON.stringify(alerts, null, 2)}

请提供：
1. 告警聚合分析
2. 威胁等级评估
3. 响应优先级建议
4. 根因分析（如果可能）
`.trim();

    const messages = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: '请分析告警数据' }
    ];

    const response = await callDeepSeek(messages);
    return {
      success: true,
      content: response.data?.choices?.[0]?.message?.content || '分析完成'
    };
  } catch (err) {
    logger.error('告警分析失败:', err.message);
    throw err;
  }
}

/**
 * AI投毒检测
 * 优先调用 Python AI 微服务（统计规则引擎，检测模型权重/训练数据/供应链投毒），失败时降级。
 * 不再使用 LLM 基于文件名/大小进行不可靠分析。
 */
async function detectPoisoning(filePath) {
  const result = await callAiServiceFileDetection('/api/detect/poisoning', filePath);
  if (result && typeof result.is_poisoned === 'boolean') {
    return {
      is_poisoned: result.is_poisoned,
      poisoning_probability: result.poisoning_probability || result.score || 0,
      method: result.method || 'python_statistical_engine',
      isolation_forest_anomaly: result.isolation_forest_anomaly || false,
      isolation_forest_score: result.isolation_forest_score,
      anomalies: result.anomalies || []
    };
  }
  logger.warn('[AI服务] Python 投毒检测不可用，返回低风险判定');
  return {
    is_poisoned: false,
    poisoning_probability: 0,
    method: 'degraded',
    isolation_forest_anomaly: false,
    isolation_forest_score: null,
    anomalies: ['AI 投毒检测服务不可用，已降级']
  };
}

/**
 * AI等保测评报告生成
 */
async function generateDjppReport(djppData) {
  try {
    const { level, taskName, stats, results } = djppData;
    const levelNames = {
      1: '第一级',
      2: '第二级',
      3: '第三级',
      4: '第四级',
      5: '第五级'
    };

    const systemPrompt = `
你是专业的等级保护测评专家。请根据以下测评数据生成符合《信息安全等级保护基本要求》的专业测评报告。

测评任务: ${taskName}
测评级别: ${levelNames[level]}级

测评统计:
- 总检查项: ${stats.total}
- 通过: ${stats.pass}
- 失败: ${stats.fail}
- 警告: ${stats.warning}
- 合规率: ${stats.complianceRate}%

详细结果:
${results.slice(0, 30).map(r => `${r.check_code} [${r.status}] - ${r.check_name}`).join('\n')}

请生成：
1. 测评概要（包含基本信息、测评范围、测评依据）
2. 测评结果汇总（合规率统计、风险等级分布）
3. 详细测评分析（按安全类别的分析）
4. 风险评估（高/中/低风险项分析）
5. 整改建议（具体、可操作的建议）
6. 总体评价和后续建议
`.trim();

    const messages = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: '请生成等级保护测评报告' }
    ];

    const response = await callDeepSeek(messages, { maxTokens: 4000 });
    return response.data?.choices?.[0]?.message?.content || '报告生成完成';
  } catch (err) {
    logger.error('等保报告生成失败:', err.message);
    throw err;
  }
}

/**
 * 健康检查
 */
async function healthCheck() {
  try {
    const testMessages = [{ role: 'user', content: 'hello' }];
    const response = await callDeepSeek(testMessages, { maxTokens: 10 });
    return { status: 'healthy', data: { model: response.model || 'agnes-2.5-flash' } };
  } catch (err) {
    return { status: 'unavailable', error: err.message };
  }
}

/**
 * 粗略 token 估算（中文约 1.5 字符/token，英文约 4 字符/token）
 */
function estimateTokens(text) {
  if (typeof text !== 'string') return 0;
  const cnChars = (text.match(/[\u4e00-\u9fff]/g) || []).length;
  const enChars = text.length - cnChars;
  return Math.ceil(cnChars / 1.5 + enChars / 4);
}

/**
 * Token 估算缓存（避免高频重复计算）
 * key: messages 的 JSON 字符串哈希，value: token 数
 */
const _tokenEstimateCache = new Map();
const MAX_TOKEN_CACHE = 1000;

/**
 * 计算消息列表的总 token 估算值（带简单缓存）
 */
function estimateTokensForMessages(messages) {
  if (!Array.isArray(messages)) return 0;
  // 用引用 ID 做缓存 key（messages 对象不变时复用结果）
  const cacheKey = messages.length + ':' + messages.map(m => m.content?.length || 0).join(',');
  const cached = _tokenEstimateCache.get(cacheKey);
  if (cached !== undefined) return cached;

  const total = messages.reduce((sum, m) => sum + estimateTokens(m.content || ''), 0);

  // LRU 淘汰：超出上限时移除最旧的条目
  if (_tokenEstimateCache.size >= MAX_TOKEN_CACHE) {
    const firstKey = _tokenEstimateCache.keys().next().value;
    _tokenEstimateCache.delete(firstKey);
  }
  _tokenEstimateCache.set(cacheKey, total);
  return total;
}

/**
 * 将消息列表截断到 token 预算内
 * 保留 system prompt（索引0）和最新2条消息，丢弃中间历史
 */
function truncateMessagesToBudget(messages, maxTokens) {
  if (!Array.isArray(messages) || messages.length <= 3) return messages;

  // 保留 system prompt，丢弃中间历史，保留最后1条用户消息
  const systemMsg = messages[0];
  const keepMessages = messages.slice(-2); // 保留最后2条（用户+assistant）
  const truncated = [systemMsg, ...keepMessages];

  const total = estimateTokensForMessages(truncated);
  if (total <= maxTokens) return truncated;

  // 如果仍超限，仅保留 system + 最新消息
  return [systemMsg, keepMessages[keepMessages.length - 1]];
}

/**
 * 调用 AI 微服务的 GAN 分析接口
 * 复用 callAiServiceFileDetection，路径为 /api/gan/anomaly
 */
async function callGANAnalysis(filePath, fileBuffer = null) {
  const start = Date.now();
  try {
    const result = await callAiServiceFileDetection('/api/gan/anomaly', filePath, fileBuffer);
    const elapsed = Date.now() - start;
    logger.info(`[aiService.GAN] GAN分析完成: ${filePath} | ${elapsed}ms | is_anomaly=${result?.is_anomaly}`);
    return result;
  } catch (error) {
    logger.warn(`[aiService.GAN] GAN分析失败: ${error.message}`);
    return {
      is_anomaly: false,
      reconstruction_error: 0,
      anomaly_score: 0,
      confidence: 0,
      model_version: 'error',
      error: error.message
    };
  }
}

/**
 * 调用 AI 微服务的 JSON 接口（非文件上传）
 */
async function callAiServiceJson(endpoint) {
  try {
    const resp = await axios.get(`${config.aiService.url}${endpoint}`, { timeout: 10000 });
    return resp.data;
  } catch (error) {
    logger.warn(`[aiService.JSON] 调用 ${endpoint} 失败: ${error.message}`);
    return { code: 1, message: error.message, data: null };
  }
}

module.exports = {
  detectMalware,
  detectPoisoning,
  generateSecurityReport,
  getDashboardData,
  generateBaselineReport,
  generateVirusReport,
  generateScanReport,
  generateDjppReport,
  analyzeThreatIntel,
  analyzeAlerts,
  chatWithTools,
  chatAssistant,
  getHistory,
  clearHistory,
  healthCheck,
  callDeepSeek,
  searchKnowledge,
  executeTool,
  callGANAnalysis,
  callAiServiceJson,
  // AI 安全能力（供外部调用）
  detectPromptInjection,
  validateInput,
  analyzeBehavior,
  detectHallucination,
  scanKnowledgeDoc,
};