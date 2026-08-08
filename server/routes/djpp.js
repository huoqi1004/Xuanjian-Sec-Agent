const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../middleware/auth');
const { tenantScope } = require('../middleware/tenant');
const djppService = require('../services/djppService');
const logger = require('../utils/logger');

router.get('/test', (req, res) => {
  const db = require('../db/database').getDb();
  const tasks = db.prepare('SELECT * FROM djpp_tasks').all();
  const levels = db.prepare('SELECT * FROM djpp_levels').all();
  res.json({ code: 0, data: { tasks: tasks.length, levels: levels.length, taskList: tasks } });
});

router.use(authMiddleware);
// N-01/N-02：注入租户上下文，列表/详情按组织与对象级过滤
router.use(tenantScope);

router.get('/levels', (req, res) => {
  try {
    const levels = djppService.getLevels();
    res.json({ code: 0, data: levels });
  } catch (err) {
    logger.error('获取等保级别获取失败:', err);
    res.status(500).json({ code: -1, message: '获取失败' });
  }
});

router.get('/levels/:level/categories', (req, res) => {
  try {
    const levelId = parseInt(req.params.level);
    const categories = djppService.getCategories(levelId);
    res.json({ code: 0, data: categories });
  } catch (err) {
    logger.error('获取等保类别获取失败:', err);
    res.status(500).json({ code: -1, message: '获取失败' });
  }
});

router.get('/categories/:categoryId/checks', (req, res) => {
  try {
    const categoryId = parseInt(req.params.categoryId);
    const checks = djppService.getChecks(categoryId);
    res.json({ code: 0, data: checks });
  } catch (err) {
    logger.error('获取等保检查项获取失败:', err);
    res.status(500).json({ code: -1, message: '获取失败' });
  }
});

router.get('/levels/:level/checks', (req, res) => {
  try {
    const level = parseInt(req.params.level);
    const checks = djppService.getLevelChecks(level);
    res.json({ code: 0, data: checks });
  } catch (err) {
    logger.error('获取等保级别检查项获取失败:', err);
    res.status(500).json({ code: -1, message: '获取失败' });
  }
});

router.post('/tasks', (req, res) => {
  try {
    const { level, name, description } = req.body;
    const userId = req.user?.id || 1;
    
    if (!level || !name) {
      return res.status(400).json({ code: -1, message: '参数不完整' });
    }

    const result = djppService.startTask(level, name, description, userId);
    res.json({ code: 0, data: result });
  } catch (err) {
    logger.error('创建等保测评任务失败:', err);
    res.status(500).json({ code: -1, message: '创建失败' });
  }
});

router.get('/tasks', (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 20;
    
    const result = djppService.getTasks(page, pageSize, req.tenant);
    res.json({ code: 0, data: result });
  } catch (err) {
    logger.error('获取等保测评任务列表失败:', err);
    res.status(500).json({ code: -1, message: '获取失败' });
  }
});

router.get('/tasks/:taskId', (req, res) => {
  try {
    const { taskId } = req.params;
    const detail = djppService.getTaskDetail(taskId, req.tenant);
    
    if (!detail) {
      return res.status(404).json({ code: -1, message: '任务不存在或无权访问' });
    }
    
    res.json({ code: 0, data: detail });
  } catch (err) {
    logger.error('获取等保测评任务详情失败:', err);
    res.status(500).json({ code: -1, message: '获取失败' });
  }
});

router.post('/tasks/:taskId/report', async (req, res) => {
  try {
    const { taskId } = req.params;
    
    try {
      const report = await djppService.generateReport(taskId);
      res.json({ code: 0, data: report });
    } catch (reportErr) {
      logger.error('生成等保报告失败:', reportErr);
      res.status(500).json({ code: -1, message: '报告生成失败' });
    }
  } catch (err) {
    logger.error('等保报告请求失败:', err);
    res.status(500).json({ code: -1, message: '请求失败' });
  }
});

router.get('/reports', (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.pageSize) || 20;
    
    const result = djppService.getReports(page, pageSize, req.tenant);
    res.json({ code: 0, data: result });
  } catch (err) {
    logger.error('获取等保报告列表失败:', err);
    res.status(500).json({ code: -1, message: '获取失败' });
  }
});

router.delete('/reports/:reportId', (req, res) => {
  try {
    const { reportId } = req.params;
    const deleted = djppService.deleteReport(reportId, req.tenant);
    
    if (!deleted) {
      return res.status(404).json({ code: -1, message: '报告不存在或无权删除' });
    }
    
    res.json({ code: 0, message: '删除成功' });
  } catch (err) {
    logger.error('删除等保报告失败:', err);
    res.status(500).json({ code: -1, message: '删除失败' });
  }
});

module.exports = router;
