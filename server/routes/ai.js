const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../middleware/auth');
const aiService = require('../services/aiService');
const logger = require('../utils/logger');

router.use(authMiddleware);

router.post('/chat', async (req, res) => {
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
        message: result.error || '处理失败'
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

router.post('/report/security', async (req, res) => {
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

router.post('/report/scan', async (req, res) => {
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

router.post('/analyze/threat', async (req, res) => {
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

module.exports = router;