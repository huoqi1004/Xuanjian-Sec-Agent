// -*- coding: utf-8 -*-
/**
 * GAN 模型版本管理 + 监控指标 集成测试
 *
 * 测试范围：
 * - version_manager.py: 模型注册/部署/清理/摘要
 * - metrics_collector.py: 指标记录/查询/清理
 * - ganVersionService.js: Node 端集成
 *
 * 运行:
 *   pytest ai-service/test/test_gan_version_metrics.py -v
 *   cd server && npx jest test/gan_version_metrics.test.js
 */

const { expect, test, describe, beforeAll, afterAll } = require('@jest/globals');
const fs = require('fs');
const path = require('path');

// ──────────────────────────────────────────────────────────────
// Python 模块测试（通过 subprocess 调用）
// ──────────────────────────────────────────────────────────────

describe('GAN 模型版本管理 (Python)', () => {
  const pythonTestScript = path.join(__dirname, '..', '..', 'ai-service', 'test', 'test_gan_version_metrics.py');

  test('Python 测试文件存在', () => {
    expect(fs.existsSync(pythonTestScript)).toBe(true);
  });

  test('version_manager.py 可导入', async () => {
    const { execSync } = require('child_process');
    try {
      const result = execSync(
        'python -c "from gan.version_manager import GANVersionManager, MODEL_TYPE_ANOMALY, MODEL_TYPE_ADV; print(\'OK\')"',
        { cwd: path.join(__dirname, '..', '..', 'ai-service'), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      );
      expect(result.trim()).toBe('OK');
    } catch (e) {
      fail(`导入失败: ${e.stderr?.toString() || e.message}`);
    }
  });

  test('metrics_collector.py 可导入', async () => {
    const { execSync } = require('child_process');
    try {
      const result = execSync(
        'python -c "from gan.metrics_collector import GANMetricsCollector; print(\'OK\')"',
        { cwd: path.join(__dirname, '..', '..', 'ai-service'), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      );
      expect(result.trim()).toBe('OK');
    } catch (e) {
      fail(`导入失败: ${e.stderr?.toString() || e.message}`);
    }
  });
});

// ──────────────────────────────────────────────────────────────
// Node.js 服务测试
// ──────────────────────────────────────────────────────────────

describe('GANVersionService (Node.js)', () => {
  test('ganVersionService.js 可加载', () => {
    const GANVersionService = require('../../server/services/ganVersionService');
    expect(typeof GANVersionService).toBe('function');

    const service = new GANVersionService({
      callAiServiceJson: async () => ({ code: 0, data: null }),
      callAiServiceFileDetection: async () => null,
    });
    expect(service).toBeDefined();
  });

  test('recordScanMetric 方法存在', () => {
    const GANVersionService = require('../../server/services/ganVersionService');
    const service = new GANVersionService({
      callAiServiceJson: async () => ({ code: 0, data: null }),
      callAiServiceFileDetection: async () => null,
    });
    expect(typeof service.recordScanMetric).toBe('function');
  });
});

describe('multiEngineScanService GAN 指标记录', () => {
  test('multiEngineScanService 可加载（含 GAN 方法）', () => {
    const ms = require('../../server/services/multiEngineScanService');
    // ms 是单例实例，不是类，直接检查实例方法
    expect(typeof ms._recordGANMetrics).toBe('function');
    expect(typeof ms._scanGANCHomaly).toBe('function');
    expect(typeof ms._ganVoteMerge).toBe('function');
  });
});
