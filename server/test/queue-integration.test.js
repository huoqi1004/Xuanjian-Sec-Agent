/**
 * N-07 统一任务队列接入集成测试
 * 验证威胁情报采集 / 报告生成 / 防御策略动作三类处理器已注册并可执行
 */
const { getQueue, resetQueue } = require('../services/queue');
const { resetForTest } = require('../db/database');

beforeEach(() => {
  resetForTest();
  resetQueue();
  // 显式注册处理器到新建的队列单例（幂等；Jest 模块缓存下重复 require 不会重新执行注册逻辑）
  const { registerHandlers } = require('../services/queueHandlers');
  registerHandlers();
});

test('threat_intel_collect 处理器已注册并可执行', async () => {
  const q = getQueue();
  // 直接调用处理器（避免真实外网请求）：从 q.handlers 拿 handler 执行
  const handler = q.handlers.get('threat_intel_collect');
  expect(typeof handler).toBe('function');
  // collectThreatIntel 会请求外网，用 jest 拦截
  const situationalService = require('../services/situationalService');
  jest.spyOn(situationalService, 'collectThreatIntel').mockResolvedValue({ newCount: 0 });
  const r = await handler({ name: 'threat_intel_collect', data: {} });
  expect(r).toBeTruthy();
  expect(r.collected).toBe(true);
  situationalService.collectThreatIntel.mockRestore();
});

test('report_generate 处理器已注册', async () => {
  const q = getQueue();
  expect(q.handlers.has('report_generate')).toBe(true);
});

test('defense_actions 处理器已注册', async () => {
  const q = getQueue();
  expect(q.handlers.has('defense_actions')).toBe(true);
});

test('queue.add 可入队并统计', async () => {
  const q = getQueue();
  // 拦截外网调用，避免入队后真实执行网络请求
  const situationalService = require('../services/situationalService');
  jest.spyOn(situationalService, 'collectThreatIntel').mockResolvedValue({ newCount: 0 });
  q.add('threat_intel_collect', {}, { attempts: 1 });
  const s = q.stats();
  expect(s.driver).toBe('memory');
  expect(typeof s.waiting).toBe('number');
  situationalService.collectThreatIntel.mockRestore();
});
