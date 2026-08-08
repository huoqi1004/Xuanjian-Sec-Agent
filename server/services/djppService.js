const { getDb } = require('../db/database');
const { generateId } = require('../utils/helpers');
const { execSync } = require('child_process');
const aiService = require('./aiService');
const logger = require('../utils/logger');

function getLevels() {
  const db = getDb();
  return db.prepare('SELECT * FROM djpp_levels ORDER BY level').all();
}

function getCategories(levelId) {
  const db = getDb();
  return db.prepare('SELECT * FROM djpp_categories WHERE level_id = ? ORDER BY category_code').all(levelId);
}

function getChecks(categoryId) {
  const db = getDb();
  return db.prepare('SELECT * FROM djpp_checks WHERE category_id = ? ORDER BY check_code').all(categoryId);
}

function getLevelChecks(level) {
  const db = getDb();
  return db.prepare(`
    SELECT c.*, cat.category_name, cat.level_id 
    FROM djpp_checks c 
    JOIN djpp_categories cat ON c.category_id = cat.id 
    WHERE cat.level_id = ?
    ORDER BY cat.category_code, c.check_code
  `).all(level);
}

function startTask(level, name, description, userId) {
  const db = getDb();
  const taskId = generateId();

  db.prepare(`
    INSERT INTO djpp_tasks (id, level, name, description, status, progress, created_by, started_at) 
    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).run(taskId, level, name, description, 'running', 0, userId);

  const checks = getLevelChecks(level);
  const totalChecks = checks.length;

  (async () => {
    try {
      let completed = 0;
      for (const check of checks) {
        const result = executeCheck(check);
        db.prepare(`
          INSERT INTO djpp_results (task_id, check_id, check_code, check_name, category_name, actual_value, status, evidence, comment, severity)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          taskId,
          check.id,
          check.check_code,
          check.check_name,
          check.category_name,
          result.actualValue,
          result.status,
          result.evidence,
          result.comment,
          check.severity
        );
        completed++;
        const progress = Math.round((completed / totalChecks) * 100);
        db.prepare('UPDATE djpp_tasks SET progress = ? WHERE id = ?').run(progress, taskId);
      }

      db.prepare(`
        UPDATE djpp_tasks 
        SET status = 'completed', completed_at = datetime('now')
        WHERE id = ?
      `).run(taskId);

      logger.info(`等保测评任务 ${taskId} 完成，级别: ${level}`);

      try {
        const report = await generateReport(taskId);
        logger.info(`等保测评任务 ${taskId} 报告已生成，报告ID: ${report.reportId}`);
      } catch (reportErr) {
        logger.error(`等保测评任务 ${taskId} 报告生成失败:`, reportErr.message);
      }
    } catch (err) {
      logger.error(`等保测评任务 ${taskId} 失败:`, err.message);
      db.prepare(`
        UPDATE djpp_tasks 
        SET status = 'failed'
        WHERE id = ?
      `).run(taskId);
    }
  })();

  return { taskId, status: 'running' };
}

function executeCheck(check) {
  try {
    if (!check.check_command) {
      return {
        status: 'warning',
        actualValue: '无检查命令',
        evidence: '检查项缺少执行命令',
        comment: '需要手动检查'
      };
    }

    const result = execSync(check.check_command, {
      timeout: 15000,
      encoding: 'utf-8'
    }).trim();

    const expected = check.expected_value || '';
    let passed = false;

    if (expected === '0') {
      passed = result === '0' || parseInt(result) === 0;
    } else if (expected === '1') {
      passed = result === '1' || parseInt(result) >= 1;
    } else if (expected === 'active' || expected === 'exist') {
      passed = result.includes(expected);
    } else {
      passed = result === expected;
    }

    return {
      status: passed ? 'pass' : 'fail',
      actualValue: result.substring(0, 500),
      evidence: `执行命令: ${check.check_command.substring(0, 100)}\n结果: ${result.substring(0, 300)}`,
      comment: passed ? '符合要求' : `期望: ${expected}, 实际: ${result.substring(0, 50)}`
    };
  } catch (err) {
    return {
      status: 'warning',
      actualValue: `命令执行失败: ${err.message.substring(0, 100)}`,
      evidence: err.stack ? err.stack.substring(0, 300) : '无详细堆栈',
      comment: '检查执行异常，建议手动复核'
    };
  }
}

function getTasks(page = 1, pageSize = 20, tenant) {
  const db = getDb();

  const tasks = db.prepare(`
    SELECT t.*, u.username as created_by_name 
    FROM djpp_tasks t 
    LEFT JOIN users u ON t.created_by = u.id 
  `).all();

  const { inOrg } = require('../utils/tenantHelpers');
  const filtered = inOrg(tasks, tenant, 'created_by')
    .sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));
  const offset = (page - 1) * pageSize;

  return { tasks: filtered.slice(offset, offset + pageSize), total: filtered.length, page, pageSize };
}

function getTaskDetail(taskId, tenant) {
  const db = getDb();
  const task = db.prepare('SELECT * FROM djpp_tasks WHERE id = ?').get(taskId);
  if (!task) return null;
  if (!require('../utils/tenantHelpers').isOwner(tenant, task, 'created_by')) return null;

  const results = db.prepare('SELECT * FROM djpp_results WHERE task_id = ? ORDER BY id').all(taskId);

  const stats = {
    total: results.length,
    pass: results.filter(r => r.status === 'pass').length,
    fail: results.filter(r => r.status === 'fail').length,
    warning: results.filter(r => r.status === 'warning').length
  };

  stats.complianceRate = results.length > 0 
    ? ((stats.pass / results.length) * 100).toFixed(1) 
    : '0.0';

  return { task, results, stats };
}

async function generateReport(taskId) {
  const db = getDb();
  const detail = getTaskDetail(taskId);
  
  if (!detail) {
    throw new Error('任务不存在');
  }

  const { task, results, stats } = detail;

  let aiAnalysis = '';
  try {
    aiAnalysis = await aiService.generateDjppReport({
      level: task.level,
      taskName: task.name,
      stats,
      results
    });
  } catch (err) {
    logger.warn('AI等保报告生成失败，使用默认模板:', err.message);
    aiAnalysis = generateDefaultReport(task, stats, results);
  }

  const reportContent = {
    taskId,
    level: task.level,
    taskName: task.name,
    generatedAt: new Date().toISOString(),
    stats,
    aiAnalysis,
    details: results.map(r => ({
      category: r.category_name,
      checkCode: r.check_code,
      checkName: r.check_name,
      status: r.status,
      severity: r.severity,
      actual: r.actual_value,
      evidence: r.evidence,
      comment: r.comment
    }))
  };

  const reportId = generateId();
  db.prepare(`
    INSERT INTO reports (id, title, type, content, generated_by, created_at) 
    VALUES (?, ?, ?, ?, ?, datetime('now'))
  `).run(
    reportId, 
    `${task.name} - 等级保护${task.level}级测评报告`, 
    'djpp', 
    JSON.stringify(reportContent), 
    task.created_by
  );

  return { reportId, ...reportContent };
}

function generateDefaultReport(task, stats, results) {
  const levelName = {
    1: '第一级',
    2: '第二级', 
    3: '第三级',
    4: '第四级',
    5: '第五级'
  };

  const severityIssues = {
    critical: results.filter(r => r.status === 'fail' && r.severity === 'critical').length,
    high: results.filter(r => r.status === 'fail' && r.severity === 'high').length,
    medium: results.filter(r => r.status === 'fail' && r.severity === 'medium').length
  };

  return `
# 等级保护${levelName[task.level]}测评报告

## 测评概要
- 测评任务: ${task.name}
- 测评级别: ${levelName[task.level]}
- 开始时间: ${task.started_at}
- 完成时间: ${task.completed_at}

## 测评结果
- 总检查项: ${stats.total}
- 通过: ${stats.pass}
- 失败: ${stats.fail}
- 警告: ${stats.warning}
- 合规率: ${stats.complianceRate}%

## 风险概览
- 严重风险: ${severityIssues.critical}项
- 高风险: ${severityIssues.high}项
- 中风险: ${severityIssues.medium}项

## 整改建议
1. 优先处理严重风险项，立即进行整改
2. 高风险项应在7个工作日内落实整改措施
3. 中风险项应制定整改计划，逐步落实
4. 定期进行复测，确保持续合规
  `.trim();
}

function getReports(page = 1, pageSize = 20, tenant) {
  const db = getDb();

  // N-02：全量取本组织报告后内存过滤（reports.generated_by 归属）
  const reports = db.prepare(`
    SELECT r.*, u.username as generated_by_name 
    FROM reports r 
    LEFT JOIN users u ON r.generated_by = u.id 
    WHERE r.type = 'djpp'
  `).all();

  const { inOrg } = require('../utils/tenantHelpers');
  const filtered = inOrg(reports, tenant, 'generated_by')
    .sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));
  const offset = (page - 1) * pageSize;

  return { reports: filtered.slice(offset, offset + pageSize), total: filtered.length, page, pageSize };
}

function deleteReport(reportId, tenant) {
  const db = getDb();
  const report = db.prepare('SELECT * FROM reports WHERE id = ? AND type = ?').get(reportId, 'djpp');
  if (!report) return false;
  // N-01：对象级校验，非管理员仅可删除本人生成的报告
  if (!require('../utils/tenantHelpers').isOwner(tenant, report, 'generated_by')) return false;
  const result = db.prepare('DELETE FROM reports WHERE id = ?').run(reportId);
  return result.changes > 0;
}

module.exports = {
  getLevels,
  getCategories,
  getChecks,
  getLevelChecks,
  startTask,
  getTasks,
  getTaskDetail,
  generateReport,
  getReports,
  deleteReport
};
