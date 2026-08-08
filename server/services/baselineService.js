const { getDb } = require('../db/database');
const { generateId } = require('../utils/helpers');
const { execSync } = require('child_process');
const aiService = require('./aiService');
const logger = require('../utils/logger');

/**
 * 获取基线策略列表
 */
function getPolicies() {
  const db = getDb();
  const policies = db.prepare('SELECT * FROM baseline_policies ORDER BY id').all();

  return policies.map(policy => ({
    ...policy,
    checks: JSON.parse(policy.checks || '[]')
  }));
}

/**
 * 启动基线检查
 */
function runCheck(policy_id, host_id, user_id) {
  const db = getDb();
  const taskId = generateId();

  const policy = db.prepare('SELECT * FROM baseline_policies WHERE id = ?').get(policy_id);
  if (!policy) {
    throw new Error('基线策略不存在');
  }

  const checks = JSON.parse(policy.checks || '[]');

  // 异步执行检查（模拟）
  (async () => {
    try {
      const insertResult = db.prepare(`
        INSERT INTO baseline_results (task_id, host_id, check_id, check_name, expected_value, actual_value, status, severity, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      for (const check of checks) {
        // 执行本地系统命令进行真实检查
        const result = executeLocalCheck(check);

        insertResult.run(
          taskId,
          host_id || 'local',
          check.id,
          check.name,
          check.expected_value || check.pattern,
          result.actual_value,
          result.status,
          result.severity || check.severity,
          result.remediation || check.remediation
        );
      }

      logger.info(`基线检查任务 ${taskId} 完成，策略: ${policy.name}`);
    } catch (err) {
      logger.error(`基线检查任务 ${taskId} 失败:`, err.message);
    }
  })();

  return {
    task_id: taskId,
    policy_id,
    policy_name: policy.name,
    host_id: host_id || 'local',
    check_count: checks.length,
    status: 'running'
  };
}

/**
 * 执行本地基线检查（真实执行系统命令）
 */
function executeLocalCheck(check) {
  try {
    if (!check.check_command) {
      return { status: 'warn', actual_value: '无检查命令', severity: 'low', remediation: check.remediation || '请配置检查命令' };
    }

    const result = execSync(check.check_command, {
      timeout: 10000,
      encoding: 'utf-8',
      shell: '/bin/bash'
    }).trim();

    const expected = check.expected_value || '';
    const operator = check.operator || 'equals';
    let passed = false;

    switch (operator) {
      case 'regex':
        try { passed = new RegExp(expected).test(result); } catch(e) { passed = false; }
        break;
      case 'contains':
        passed = result.includes(expected);
        break;
      case 'not_equals':
        passed = result !== expected;
        break;
      case 'range': {
        const [min, max] = expected.split('-').map(Number);
        const num = parseFloat(result);
        passed = !isNaN(num) && num >= min && num <= max;
        break;
      }
      case 'equals':
      default:
        passed = result === expected;
        break;
    }

    return {
      status: passed ? 'pass' : 'fail',
      actual_value: result.substring(0, 500),
      severity: passed ? 'low' : (check.severity || 'medium'),
      remediation: check.remediation || (passed ? '' : `当前值: ${result}，期望: ${expected}`)
    };
  } catch (error) {
    return {
      status: 'warn',
      actual_value: `命令执行失败: ${error.message.substring(0, 200)}`,
      severity: check.severity || 'medium',
      remediation: check.remediation || '无法执行检查命令，请确认系统环境'
    };
  }
}

/**
 * 获取检查结果
 */
function getResults(taskId) {
  const db = getDb();
  const results = db.prepare('SELECT * FROM baseline_results WHERE task_id = ? ORDER BY id').all(taskId);

  // 统计
  const stats = {
    total: results.length,
    pass: results.filter(r => r.status === 'pass').length,
    fail: results.filter(r => r.status === 'fail').length,
    warn: results.filter(r => r.status === 'warn').length,
    compliance_rate: results.length > 0
      ? ((results.filter(r => r.status === 'pass').length / results.length) * 100).toFixed(1)
      : '0.0'
  };

  // 按严重程度分类
  const bySeverity = {
    critical: results.filter(r => r.severity === 'critical'),
    high: results.filter(r => r.severity === 'high'),
    medium: results.filter(r => r.severity === 'medium'),
    low: results.filter(r => r.severity === 'low')
  };

  return { results, stats, bySeverity };
}

/**
 * 生成合规报告
 */
async function generateReport(taskId) {
  const db = getDb();
  const results = getResults(taskId);

  if (results.results.length === 0) {
    throw new Error('没有可用的检查结果');
  }

  // 尝试调用AI服务润色报告
  let aiSummary = '';
  try {
    aiSummary = await aiService.generateBaselineReport(results);
  } catch (err) {
    logger.warn('AI报告生成失败，使用默认模板:', err.message);
    aiSummary = generateDefaultSummary(results);
  }

  const report = {
    task_id: taskId,
    generated_at: new Date().toISOString(),
    summary: aiSummary,
    statistics: results.stats,
    failed_checks: results.results.filter(r => r.status === 'fail').map(r => ({
      check_id: r.check_id,
      check_name: r.check_name,
      severity: r.severity,
      remediation: r.remediation
    })),
    warning_checks: results.results.filter(r => r.status === 'warn').map(r => ({
      check_id: r.check_id,
      check_name: r.check_name,
      severity: r.severity,
      remediation: r.remediation
    }))
  };

  return report;
}

/**
 * 生成默认报告摘要
 */
function generateDefaultSummary(results) {
  const { stats } = results;
  return `基线安全检查报告

检查时间: ${new Date().toLocaleString()}
总检查项: ${stats.total}
通过: ${stats.pass} 项
失败: ${stats.fail} 项
警告: ${stats.warn} 项
合规率: ${stats.compliance_rate}%

总体评估: ${parseFloat(stats.compliance_rate) >= 80 ? '安全状况良好' : parseFloat(stats.compliance_rate) >= 60 ? '存在安全风险，建议整改' : '安全状况较差，需立即整改'}

建议:
1. 优先处理严重(Critical)和高(High)级别的失败项
2. 对警告(Warn)项进行评估并制定改进计划
3. 定期进行基线检查，确保持续合规`;
}

function getPolicyById(id) {
  const db = getDb();
  return db.prepare('SELECT * FROM baseline_policies WHERE id = ?').get(id);
}

module.exports = {
  getPolicies,
  getPolicyById,
  runCheck,
  getResults,
  generateReport
};
