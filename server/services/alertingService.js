/**
 * 玄鉴安全智能体 - 系统健康检查与告警规则
 *
 * 周期性巡检：AI 服务可达性、进程内存占用、任务队列积压，
 * 不达标时生成 system_health 告警（幂等去重），并维护最近一次快照
 * 供 /api/health 与 /metrics 引用。
 */

const axios = require('axios');
const os = require('os');
const { getDb } = require('../db/database');
const { config } = require('../config');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');
const { getQueue } = require('./queue');

// 最近一次健康检查快照（写入时深拷贝，防止并发修改）
let lastCheck = {
  ts: null,
  aiOk: false,
  aiLatencyMs: 0,
  memUsageRatio: 0,
  checks: []
};

/** 原子写入 lastCheck 快照（防止并发健康检查写入覆盖） */
function updateLastCheck(updates) {
  lastCheck = { ...lastCheck, ...updates };
}

function upsertSystemAlert(db, relatedAsset, severity, confidence, description) {
  const existing = db.prepare("SELECT * FROM alert_records WHERE alert_type = 'system_health'").all();
  const duplicated = existing.some((a) => a.description === description && a.status === 'new');
  if (duplicated) return false;

  db.prepare(
    'INSERT INTO alert_records (related_asset, alert_type, severity, confidence, description, status) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(relatedAsset, 'system_health', severity, confidence, description, 'new');

  metrics.inc('system_health_alerts_total', { severity }, 1, '系统健康告警总数');
  return true;
}

async function checkAiService() {
  const url = `${config.aiService.url}/health`;
  const start = Date.now();
  try {
    const resp = await axios.get(url, { timeout: 3000, validateStatus: () => true });
    const latency = Date.now() - start;
    const ok = resp.status < 500;
    metrics.setGauge('system_health_ai_service', {}, ok ? 1 : 0, 'AI 服务可达性(0/1)');
    metrics.observe('ai_service_health_latency', {}, latency / 1000, 'AI 健康检查延迟', { unit: 'seconds' });
    if (!ok) {
      upsertSystemAlert(db(), config.aiService.url, 'high', 0.8, `系统健康: AI服务异常响应 HTTP ${resp.status} (${config.aiService.url})`);
    }
    return { ok, latency, detail: `HTTP ${resp.status}` };
  } catch (err) {
    metrics.setGauge('system_health_ai_service', {}, 0, 'AI 服务可达性(0/1)');
    upsertSystemAlert(db(), config.aiService.url, 'high', 0.8, `系统健康: AI服务不可达 (${config.aiService.url})`);
    return { ok: false, latency: Date.now() - start, detail: err.message.substring(0, 120) };
  }
}

function db() {
  return getDb();
}

/**
 * 执行一轮系统健康巡检
 */
async function checkSystemHealth() {
  const checks = [];

  // 1. AI 服务可达性
  const ai = await checkAiService();
  checks.push({ name: 'ai_service', ok: ai.ok, detail: ai.detail });
  updateLastCheck({ aiOk: ai.ok, aiLatencyMs: ai.latency });

  // 2. 进程内存占用（RSS / 物理内存）
  const memUsageRatio = process.memoryUsage().rss / os.totalmem();
  metrics.setGauge('system_health_mem_usage_ratio', {}, memUsageRatio, '进程内存占用率');
  const memOk = memUsageRatio < 0.85;
  checks.push({
    name: 'memory',
    ok: memOk,
    detail: `RSS 占用 ${(memUsageRatio * 100).toFixed(1)}%`
  });
  if (!memOk) {
    upsertSystemAlert(db(), 'server', 'critical', 0.9, `系统健康: 内存占用率超阈值 ${(memUsageRatio * 100).toFixed(1)}%`);
  }
  updateLastCheck({ memUsageRatio });

  // 3. 任务队列积压
  const queueStats = getQueue().stats();
  metrics.setGauge('queue_waiting_jobs', {}, queueStats.waiting, '队列等待任务数');
  const queueOk = queueStats.depth < 100;
  checks.push({ name: 'queue', ok: queueOk, detail: `深度 ${queueStats.depth}` });
  if (!queueOk) {
    upsertSystemAlert(db(), 'task-queue', 'warning', 0.7, `系统健康: 任务队列积压 ${queueStats.depth}`);
  }

  // 4. AI 调用失败率
  const aiTotal = metrics.get('ai_calls_total', { provider: 'deepseek' });
  const aiFailed = metrics.get('ai_calls_failed_total', { provider: 'deepseek' });
  const failRate = aiTotal > 0 ? aiFailed / aiTotal : 0;
  metrics.setGauge('ai_call_failure_rate', {}, failRate, 'AI 调用失败率');
  const failRateOk = aiTotal === 0 || failRate < (parseFloat(process.env.AI_FAILURE_RATE_THRESHOLD) || 0.5);
  checks.push({ name: 'ai_failure_rate', ok: failRateOk, detail: `失败率 ${(failRate * 100).toFixed(1)}% (${aiFailed}/${aiTotal})` });
  if (!failRateOk) {
    upsertSystemAlert(db(), 'ai-service', 'warning', 0.8, `系统健康: AI 调用失败率 ${(failRate * 100).toFixed(1)}% 超过阈值`);
  }

  updateLastCheck({ ts: new Date().toISOString(), checks });

  if (!ai.ok || !memOk || !queueOk || !failRateOk) {
    logger.warn(`[健康巡检] 存在异常项: ${checks.filter((c) => !c.ok).map((c) => c.name).join(', ')}`);
  }
  return { ts: lastCheck.ts, checks };
}

function getLastHealthCheck() {
  return lastCheck;
}

module.exports = { checkSystemHealth, getLastHealthCheck };
