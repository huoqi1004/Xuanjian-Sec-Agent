const metrics = require('../utils/metrics');

describe('Prometheus 指标收集器', () => {
  test('Counter 累加与渲染', () => {
    metrics.inc('test_counter', { method: 'GET' }, 2, '测试计数器');
    metrics.inc('test_counter', { method: 'GET' }, 3, '测试计数器');
    metrics.inc('test_counter', { method: 'POST' }, 1, '测试计数器');
    const out = metrics.render();
    expect(out).toContain('# TYPE test_counter counter');
    expect(out).toContain('test_counter{method="GET"} 5');
    expect(out).toContain('test_counter{method="POST"} 1');
  });

  test('Gauge 设置当前值', () => {
    metrics.setGauge('test_gauge', {}, 42, '测试仪表');
    expect(metrics.render()).toContain('test_gauge 42');
  });

  test('Histogram 输出 bucket/sum/count', () => {
    metrics.observe('test_hist', {}, 0.3, '测试直方图');
    metrics.observe('test_hist', {}, 0.3, '测试直方图');
    const out = metrics.render();
    expect(out).toContain('# TYPE test_hist histogram');
    expect(out).toContain('test_hist_count 2');
    expect(out).toContain('test_hist_sum 0.6');
    expect(out).toContain('test_hist_bucket');
    expect(out).toContain('le="+Inf"');
  });

  test('内置进程指标存在', () => {
    const out = metrics.render();
    expect(out).toContain('nodejs_process_uptime_seconds');
    expect(out).toContain('nodejs_process_memory_bytes');
    expect(out).toContain('service="xuanjian-security-agent"');
  });
});
