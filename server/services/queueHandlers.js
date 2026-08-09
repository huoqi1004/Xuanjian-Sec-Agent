/**
 * 玄鉴安全智能体 - 统一任务队列处理器注册中心（N-07）
 *
 * 注册三类异步任务的处理器：
 * - threat_intel_collect  威胁情报采集（server.js 定时任务触发）
 * - report_generate       报告生成（定时周报 / 手动接口触发）
 * - defense_actions       防御策略动作执行（evaluatePolicies 触发）
 *
 * 注意：为避免循环依赖，本模块内部按需 require 各 service；
 * 各 service 不应反向 require 本模块。
 */
const logger = require('../utils/logger');
const { getQueue } = require('./queue');

/**
 * 注册处理器到指定队列（默认当前单例），幂等，重复调用安全
 */
function registerHandlers(queue = getQueue()) {
  // 威胁情报采集
  queue.process('threat_intel_collect', async (job) => {
    const situationalService = require('./situationalService');
    await situationalService.collectThreatIntel();
    return { collected: true };
  });

  // 报告生成
  queue.process('report_generate', async (job) => {
    const { title, type, time_range, userId } = job.data;
    const situationalService = require('./situationalService');
    return situationalService.generateReport(title, type, time_range, userId);
  });

  // 防御策略动作执行
  queue.process('defense_actions', async (job) => {
    const { policy, facts } = job.data;
    const defenseService = require('./defenseService');
    await defenseService.executePolicyActions(policy, facts);
    return { executed: true };
  });
}

// 模块加载即注册到当前队列单例（server.js 启动时 require 本模块即完成接入）
registerHandlers();

// 周报生成完成后推送通知（仅定时周报 job.data.notify === true 时触发，保持原定时任务推送行为）
getQueue().on('completed:report_generate', (job) => {
  if (!job.data || !job.data.notify || !job.result) return;
  const notifyService = require('./notifyService');
  notifyService.send({
    channel: 'all',
    message: `安全态势周报已生成：${job.result.title}（报告ID ${job.result.id}）`,
    severity: 'medium'
  })
    .then(() => logger.info(`定时周报已生成并推送: ${job.result.title}`))
    .catch((err) => logger.error('定时周报推送失败:', err.message));
});

module.exports = { registerHandlers };
