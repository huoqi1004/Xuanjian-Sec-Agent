const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');
const aiService = require('../services/aiService');
const kbIntegrity = require('../services/kbIntegrityService');
const threatLLMFusion = require('../services/threatLLMFusion');
const modelArb = require('../services/modelArbitrator');
const diffPrivacy = require('../services/diffPrivacyService');
const wasmSandbox = require('../services/wasmSandboxService');
const logger = require('../utils/logger');

router.use(authMiddleware);

router.post('/chat', auditLog('ai_chat'), async (req, res) => {
  try {
    const { message, conversation_id = 'default' } = req.body;
    
    if (!message) {
      return res.status(400).json({ code: -1, message: '消息内容不能为空' });
    }

    const result = await aiService.chatAssistant(conversation_id, message);
    
    if (result.success) {
      res.json({
        code: 0,
        message: 'success',
        data: {
          content: result.content,
          is_report: result.is_report || false,
          conversation_id: conversation_id
        }
      });
    } else {
      res.json({
        code: -1,
        message: result.error || '处理失败',
        data: { content: result.content }
      });
    }
  } catch (err) {
    logger.error('AI聊天失败:', err.message);
    res.status(500).json({ code: -1, message: '服务器内部错误' });
  }
});

router.get('/history/:conversation_id', async (req, res) => {
  try {
    const { conversation_id } = req.params;
    const history = aiService.getHistory(conversation_id);
    
    res.json({
      code: 0,
      message: 'success',
      data: {
        conversation_id,
        messages: history
      }
    });
  } catch (err) {
    logger.error('获取对话历史失败:', err.message);
    res.status(500).json({ code: -1, message: '服务器内部错误' });
  }
});

router.delete('/history/:conversation_id', async (req, res) => {
  try {
    const { conversation_id } = req.params;
    aiService.clearHistory(conversation_id);
    
    res.json({
      code: 0,
      message: '对话历史已清除'
    });
  } catch (err) {
    logger.error('清除对话历史失败:', err.message);
    res.status(500).json({ code: -1, message: '服务器内部错误' });
  }
});

router.post('/report/security', auditLog('ai_report_security'), async (req, res) => {
  try {
    const { type = 'daily' } = req.body;
    const { getDb } = require('../db/database');
    const db = getDb();
    
    const alerts = db.all('SELECT * FROM alert_records ORDER BY created_at DESC LIMIT 20');
    const scanTasks = db.all('SELECT * FROM scan_tasks ORDER BY created_at DESC LIMIT 10');
    const intel = db.all('SELECT * FROM threat_intel LIMIT 15');
    const policies = db.all('SELECT * FROM auto_policies WHERE enabled = 1');
    
    const dashboard = {
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
    
    const report = await aiService.generateSecurityReport(dashboard, type);
    
    res.json({
      code: 0,
      message: '安全报告生成成功',
      data: {
        content: report,
        type: type,
        generated_at: new Date().toISOString()
      }
    });
  } catch (err) {
    logger.error('安全报告生成失败:', err.message);
    res.status(500).json({ code: -1, message: '报告生成失败' });
  }
});

router.post('/report/scan', auditLog('ai_report_scan'), async (req, res) => {
  try {
    const { task_id } = req.body;
    const { getDb } = require('../db/database');
    const db = getDb();
    
    const scanData = db.all('SELECT * FROM scan_results WHERE task_id = ?', [task_id]);
    if (scanData.length === 0) {
      return res.status(404).json({ code: -1, message: '未找到扫描任务' });
    }
    
    const report = await aiService.generateScanReport(scanData);
    
    res.json({
      code: 0,
      message: '扫描报告生成成功',
      data: {
        content: report,
        task_id: task_id,
        generated_at: new Date().toISOString()
      }
    });
  } catch (err) {
    logger.error('扫描报告生成失败:', err.message);
    res.status(500).json({ code: -1, message: '报告生成失败' });
  }
});

router.post('/report/baseline', async (req, res) => {
  try {
    const { task_id } = req.body;
    const { getDb } = require('../db/database');
    const db = getDb();
    
    const baselineData = task_id 
      ? db.all('SELECT * FROM baseline_results WHERE task_id = ?', [task_id])
      : db.all('SELECT * FROM baseline_results ORDER BY created_at DESC LIMIT 50');
    
    const report = await aiService.generateBaselineReport(baselineData);
    
    res.json({
      code: 0,
      message: '基线检查报告生成成功',
      data: {
        content: report,
        generated_at: new Date().toISOString()
      }
    });
  } catch (err) {
    logger.error('基线报告生成失败:', err.message);
    res.status(500).json({ code: -1, message: '报告生成失败' });
  }
});

router.post('/analyze/threat', auditLog('ai_analyze_threat'), async (req, res) => {
  try {
    const { ioc_data } = req.body;
    const result = await aiService.analyzeThreatIntel(ioc_data);
    
    res.json({
      code: 0,
      message: '威胁情报分析完成',
      data: {
        content: result.content
      }
    });
  } catch (err) {
    logger.error('威胁情报分析失败:', err.message);
    res.status(500).json({ code: -1, message: '分析失败' });
  }
});

router.post('/analyze/alerts', async (req, res) => {
  try {
    const { severity, limit = 20 } = req.body;
    const { getDb } = require('../db/database');
    const db = getDb();
    
    let query = 'SELECT * FROM alert_records ORDER BY created_at DESC LIMIT ?';
    const alerts = db.all(query, [limit]);
    
    const result = await aiService.analyzeAlerts(alerts);
    
    res.json({
      code: 0,
      message: '告警分析完成',
      data: {
        content: result.content,
        analyzed_count: alerts.length
      }
    });
  } catch (err) {
    logger.error('告警分析失败:', err.message);
    res.status(500).json({ code: -1, message: '分析失败' });
  }
});

router.post('/detect/malware', async (req, res) => {
  try {
    const { file_path } = req.body;
    const result = await aiService.detectMalware(file_path);
    
    res.json({
      code: 0,
      message: '恶意软件检测完成',
      data: result
    });
  } catch (err) {
    logger.error('恶意软件检测失败:', err.message);
    res.status(500).json({ code: -1, message: '检测失败' });
  }
});

router.get('/health', async (req, res) => {
  try {
    const result = await aiService.healthCheck();
    
    if (result.status === 'healthy') {
      res.json({
        code: 0,
        message: '健康检查完成',
        data: result
      });
    } else {
      res.json({
        code: -1,
        message: 'AI服务不可用',
        data: result
      });
    }
  } catch (err) {
    logger.error('健康检查失败:', err.message);
    res.status(500).json({ code: -1, message: '健康检查失败' });
  }
});

/* ---------------- 多步规划 Agent（4.13） ---------------- */

router.post('/agent/run', async (req, res) => {
  try {
    const { task } = req.body;
    if (!task || !String(task).trim()) {
      return res.status(400).json({ code: -1, message: '任务描述不能为空' });
    }
    const agentService = require('../services/agentService');
    const result = await agentService.runAgent(task, { userId: req.user?.id });
    if (!result.success) {
      return res.status(400).json({ code: -1, message: result.error || 'Agent 执行失败' });
    }
    res.json({ code: 0, message: 'Agent 执行完成', data: result });
  } catch (err) {
    logger.error('Agent 执行失败:', err.message);
    res.status(500).json({ code: -1, message: 'Agent 执行失败: ' + err.message });
  }
});

router.post('/agent/confirm', async (req, res) => {
  try {
    const { confirmation_id, decision = 'approve' } = req.body;
    if (!confirmation_id) {
      return res.status(400).json({ code: -1, message: '缺少 confirmation_id' });
    }
    const agentService = require('../services/agentService');
    const result = await agentService.confirmExecution(confirmation_id, decision);
    if (!result.success) {
      return res.status(400).json({ code: -1, message: result.error });
    }
    res.json({ code: 0, message: '确认处理完成', data: result.data });
  } catch (err) {
    logger.error('Agent 确认失败:', err.message);
    res.status(500).json({ code: -1, message: '确认处理失败: ' + err.message });
  }
});

router.get('/agent/pending', async (req, res) => {
  try {
    const agentService = require('../services/agentService');
    res.json({ code: 0, message: '获取成功', data: agentService.getPendingConfirmations() });
  } catch (err) {
    res.status(500).json({ code: -1, message: '获取失败' });
  }
});

/* ---------------- 多 Agent 工作台数据（N-25） ---------------- */

router.get('/agent/tools', async (req, res) => {
  try {
    const { listTools } = require('../agents/tools/registry');
    const { registerBuiltinTools } = require('../agents/tools');
    registerBuiltinTools();
    res.json({ code: 0, message: '获取成功', data: listTools() });
  } catch (err) {
    res.status(500).json({ code: -1, message: '获取工具目录失败' });
  }
});

router.get('/agent/plan', async (req, res) => {
  try {
    // 计划解析预览：不入库、不执行，供前端先渲染步骤
    const { task } = req.query;
    if (!task) return res.status(400).json({ code: -1, message: '缺少 task 参数' });
    const agentService = require('../services/agentService');
    let plan;
    try {
      plan = await agentService.planWithLLM(String(task));
    } catch (err) {
      plan = agentService.buildFallbackPlan(String(task));
    }
    res.json({ code: 0, message: '计划生成成功', data: plan });
  } catch (err) {
    res.status(500).json({ code: -1, message: '计划生成失败' });
  }
});

/* ---------------- 安全运营 Copilot（4.15） ---------------- */

router.post('/copilot/triage', async (req, res) => {
  try {
    const { limit = 50 } = req.body;
    const copilotService = require('../services/copilotService');
    const result = await copilotService.triageAlerts(parseInt(limit));
    res.json({ code: 0, message: '告警研判完成', data: result });
  } catch (err) {
    logger.error('告警研判失败:', err.message);
    res.status(500).json({ code: -1, message: '研判失败: ' + err.message });
  }
});

router.post('/copilot/patrol', async (req, res) => {
  try {
    const { target, ports } = req.body;
    const copilotService = require('../services/copilotService');
    const result = await copilotService.runProactivePatrol({ target, ports, userId: req.user?.id });
    res.json({ code: 0, message: '主动巡检完成', data: result });
  } catch (err) {
    logger.error('主动巡检失败:', err.message);
    res.status(500).json({ code: -1, message: '巡检失败: ' + err.message });
  }
});

/* ---------------- 知识库 RAG（4.14） ---------------- */

router.post('/knowledge/search', async (req, res) => {
  try {
    const { query, top_k = 5 } = req.body;
    if (!query) {
      return res.status(400).json({ code: -1, message: 'query 不能为空' });
    }
    const results = await aiService.searchKnowledge(query, top_k);
    res.json({ code: 0, message: '检索成功', data: results });
  } catch (err) {
    res.status(500).json({ code: -1, message: '检索失败' });
  }
});

router.get('/knowledge', async (req, res) => {
  try {
    const axios = require('axios');
    const { config } = require('../config');
    const resp = await axios.get(`${config.aiService.url}/api/knowledge`, {
      params: { category: req.query.category, limit: req.query.limit, offset: req.query.offset },
      timeout: 8000
    });
    res.json({ code: 0, message: '获取成功', data: resp.data?.data });
  } catch (err) {
    logger.error('知识库列表失败:', err.message);
    res.status(500).json({ code: -1, message: '获取知识库失败（AI 服务不可用）' });
  }
});

router.post('/knowledge/add', auditLog('kb_add'), async (req, res) => {
  try {
    const { title, content, category, source } = req.body;
    if (!title || !content) {
      return res.status(400).json({ code: -1, message: 'title 和 content 不能为空' });
    }
    const result = kbIntegrity.addDocument({ title, content, category, source });
    if (!result.approved) {
      return res.json({ code: -1, message: result.reason || '文档未通过安全扫描' });
    }
    res.json({ code: 0, message: '文档入库成功', data: { id: result.id, hash: result.hash, warnings: result.warnings } });
  } catch (err) {
    logger.error('知识库添加失败:', err.message);
    res.status(500).json({ code: -1, message: '添加失败: ' + err.message });
  }
});

router.get('/knowledge/integrity', async (req, res) => {
  try {
    const anomalies = kbIntegrity.verifyIntegrity();
    res.json({
      code: 0,
      message: anomalies.length > 0 ? '发现异常' : '完整性正常',
      data: { anomaly_count: anomalies.length, anomalies }
    });
  } catch (err) {
    logger.error('知识库完整性校验失败:', err.message);
    res.status(500).json({ code: -1, message: '校验失败: ' + err.message });
  }
});

router.get('/knowledge/docs', async (req, res) => {
  try {
    const docs = kbIntegrity.listDocuments();
    const stats = kbIntegrity.getCategoryStats();
    res.json({ code: 0, message: 'success', data: { documents: docs, category_stats: stats } });
  } catch (err) {
    logger.error('知识库列表失败:', err.message);
    res.status(500).json({ code: -1, message: '获取失败: ' + err.message });
  }
});

// ── 威胁知识库管理 ─────────────────────────────────────────
router.get('/knowledge/stats', async (req, res) => {
  try {
    const axios = require('axios');
    const { config } = require('../config');
    const resp = await axios.get(`${config.aiService.url}/api/knowledge/stats`, { timeout: 5000 });
    res.json({ code: 0, message: '统计成功', data: resp.data?.data });
  } catch (err) {
    logger.warn('[RAG] 知识库统计请求失败（AI服务不可用）:', err.message.substring(0, 100));
    res.status(500).json({ code: -1, message: '统计失败（AI服务不可用）' });
  }
});

router.post('/knowledge/sync', auditLog('kb_sync'), async (req, res) => {
  try {
    const axios = require('axios');
    const { config } = require('../config');
    const resp = await axios.post(`${config.aiService.url}/api/knowledge/sync`, {}, { timeout: 15000 });
    res.json({ code: 0, message: '同步成功', data: resp.data?.data });
  } catch (err) {
    logger.error('知识库同步失败:', err.message);
    res.status(500).json({ code: -1, message: '同步失败: ' + err.message });
  }
});

// ── Phase 4: 威胁情报 LLM 融合 ──────────────────────────────
router.post('/threat-fusion/sync', auditLog('threat_fusion_sync'), async (req, res) => {
  try {
    const result = await threatLLMFusion.manualFetch();
    res.json({ code: 0, message: result.updated ? '威胁情报已更新' : '情报无变化', data: result });
  } catch (err) {
    logger.error('威胁情报同步失败:', err.message);
    res.status(500).json({ code: -1, message: '同步失败: ' + err.message });
  }
});

router.get('/threat-fusion/status', async (req, res) => {
  try {
    res.json({
      code: 0,
      data: {
        last_update: threatLLMFusion.getLastUpdateTimestamp(),
        segments_count: threatLLMFusion.getDynamicPromptSegments().length
      }
    });
  } catch (err) {
    res.status(500).json({ code: -1, message: err.message });
  }
});

// ── Phase 4: 多模型混合仲裁 ────────────────────────────────
router.post('/arbitrate', auditLog('model_arbitrate'), async (req, res) => {
  try {
    const { messages, models, minConsensus } = req.body;
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ code: -1, message: 'messages 为必填数组' });
    }
    const result = await modelArb.arbitrate(messages, { models, minConsensus });
    res.json({ code: 0, message: '仲裁完成', data: result });
  } catch (err) {
    logger.error('模型仲裁失败:', err.message);
    res.status(500).json({ code: -1, message: '仲裁失败: ' + err.message });
  }
});

router.get('/models', async (req, res) => {
  try {
    res.json({ code: 0, data: { models: modelArb.getRegisteredModels() } });
  } catch (err) {
    res.status(500).json({ code: -1, message: err.message });
  }
});

// ── Phase 4: 差分隐私投毒检测 ──────────────────────────────
router.post('/knowledge/add-dp', auditLog('kb_add_dp'), async (req, res) => {
  try {
    const { title, content, category, source, epsilon, sensitivity } = req.body;
    if (!title || !content) {
      return res.status(400).json({ code: -1, message: 'title 和 content 不能为空' });
    }
    const result = diffPrivacy.addDocumentWithDP({ title, content, category, source, epsilon, sensitivity });
    if (!result.approved) {
      return res.json({ code: -1, message: result.reason || '文档未通过安全扫描' });
    }
    res.json({
      code: 0, message: '文档入库成功（差分隐私保护）',
      data: { id: result.id, anomaly_score: result.anomaly_score, is_anomaly: result.is_anomaly, dp_params: result.dp_params }
    });
  } catch (err) {
    logger.error('差分隐私入库失败:', err.message);
    res.status(500).json({ code: -1, message: '入库失败: ' + err.message });
  }
});

router.get('/privacy/audit', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    res.json({ code: 0, data: { logs: diffPrivacy.getPrivacyAuditLog(limit) } });
  } catch (err) {
    res.status(500).json({ code: -1, message: err.message });
  }
});

router.post('/privacy/detect', auditLog('privacy_detect'), async (req, res) => {
  try {
    const threshold = parseFloat(req.body.threshold) || 0.7;
    const result = diffPrivacy.detectPoisoningDocs(threshold);
    res.json({ code: 0, message: result.detected_count > 0 ? '发现异常' : '检测正常', data: result });
  } catch (err) {
    logger.error('投毒检测失败:', err.message);
    res.status(500).json({ code: -1, message: '检测失败: ' + err.message });
  }
});

// ── Phase 4: WebAssembly 沙箱 ──────────────────────────────
router.post('/sandbox/wasm', auditLog('wasm_sandbox'), async (req, res) => {
  try {
    const { filePath } = req.body;
    if (!filePath) {
      return res.status(400).json({ code: -1, message: 'filePath 不能为空' });
    }
    const result = await wasmSandbox.analyzeWithWasmSandbox(filePath);
    res.json({ code: 0, message: '分析完成', data: result });
  } catch (err) {
    logger.error('WASM沙箱分析失败:', err.message);
    res.status(500).json({ code: -1, message: '分析失败: ' + err.message });
  }
});

router.get('/sandbox/wasm/history', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    res.json({ code: 0, data: { logs: wasmSandbox.getAnalysisHistory(limit) } });
  } catch (err) {
    res.status(500).json({ code: -1, message: err.message });
  }
});

router.get('/sandbox/wasm/stats', async (req, res) => {
  try {
    res.json({ code: 0, data: wasmSandbox.getStats() });
  } catch (err) {
    res.status(500).json({ code: -1, message: err.message });
  }
});

module.exports = router;