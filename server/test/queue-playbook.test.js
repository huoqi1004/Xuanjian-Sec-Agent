/**
 * N-07 Task B：剧本执行接入队列（playbook_run）+ 队列可观测性（积压/重试指标）
 * 验证：
 * - playbook_run 处理器已注册
 * - playbookService.execute 默认入队返回 { queued: true, run_id }
 * - queue.add 队列深度统计可用
 */
const { getQueue, resetQueue } = require('../services/queue');
const { getDb, resetForTest } = require('../db/database');
const playbookService = require('../services/playbookService');

beforeEach(() => {
  resetForTest();
  resetQueue();
  // 显式注册处理器到新建的队列单例（幂等；Jest 模块缓存下重复 require 不会重新执行注册逻辑）
  const { registerHandlers } = require('../services/queueHandlers');
  registerHandlers();
});

test('playbook_run 处理器已注册', () => {
  expect(getQueue().handlers.has('playbook_run')).toBe(true);
});

test('execute 默认入队返回 queued', async () => {
  // 需要一个启用的剧本：优先取库中已有，无则 seed 3 个模板后取第一个
  const db = getDb();
  let pb = db.prepare('SELECT * FROM playbooks WHERE enabled = 1 LIMIT 1').get();
  if (!pb) {
    playbookService.seedTemplates();
    pb = db.prepare('SELECT * FROM playbooks WHERE enabled = 1 LIMIT 1').get();
  }
  expect(pb).toBeTruthy();
  const r = await playbookService.execute(pb.id, { ip: '10.0.0.1', severity: 'high' }, { userId: 1 });
  expect(r.queued).toBe(true);
  expect(r.run_id).toBeTruthy();
});

test('queue.add 队列深度统计可用', () => {
  const q = getQueue();
  // 拦截外网调用，避免入队后真实执行网络请求（与 queue-integration 一致）
  const situationalService = require('../services/situationalService');
  jest.spyOn(situationalService, 'collectThreatIntel').mockResolvedValue({ newCount: 0 });
  q.add('threat_intel_collect', {}, { attempts: 1 });
  const s = q.stats();
  expect(typeof s.waiting).toBe('number');
  situationalService.collectThreatIntel.mockRestore();
});
