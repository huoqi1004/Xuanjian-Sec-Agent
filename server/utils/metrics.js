/**
 * 玄鉴安全智能体 - Prometheus 指标收集器（轻量实现，无需外部依赖）
 *
 * 支持 Counter（计数器）/ Gauge（仪表）/ Histogram（直方图）三类指标，
 * 输出 Prometheus 文本格式，供 /metrics 端点暴露后由 Prometheus 抓取。
 */

const os = require('os');

// 指标注册表: name -> { type, help, unit, values: Map(labelsKey -> value), buckets? }
const registry = new Map();

function labelsKey(labels) {
  if (!labels || Object.keys(labels).length === 0) return '';
  return Object.keys(labels)
    .sort()
    .map((k) => `${k}="${String(labels[k]).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`)
    .join(',');
}

function getOrCreate(name, type, help, opts = {}) {
  let entry = registry.get(name);
  if (!entry) {
    entry = { name, type, help, unit: opts.unit || '', values: new Map(), buckets: opts.buckets || null };
    registry.set(name, entry);
  }
  return entry;
}

/**
 * Counter 累加计数
 */
function inc(name, labels = {}, delta = 1, help = '', opts = {}) {
  const entry = getOrCreate(name, 'counter', help, opts);
  const key = labelsKey(labels);
  entry.values.set(key, (entry.values.get(key) || 0) + delta);
}

/**
 * Gauge 设置当前值
 */
function setGauge(name, labels = {}, value = 0, help = '', opts = {}) {
  const entry = getOrCreate(name, 'gauge', help, opts);
  const key = labelsKey(labels);
  entry.values.set(key, Number(value) || 0);
}

function incGauge(name, labels = {}, delta = 1, help = '', opts = {}) {
  const entry = getOrCreate(name, 'gauge', help, opts);
  const key = labelsKey(labels);
  entry.values.set(key, (entry.values.get(key) || 0) + delta);
}

/**
 * 读取指定指标（counter/gauge）当前值，按标签取数；未注册或不存在时返回 0。
 * 兼容无标签指标（labels 为空对象）与带标签指标，如 get('ai_calls_total', { provider: 'deepseek' })。
 */
function get(name, labels = {}) {
  const entry = registry.get(name);
  if (!entry) return 0;
  if (entry.type !== 'counter' && entry.type !== 'gauge') return 0;
  const key = labelsKey(labels);
  return entry.values.get(key) || 0;
}

/**
 * Histogram 观测值（输出 _sum/_count/_bucket，Prometheus 直方图格式）
 */
function observe(name, labels = {}, value = 0, help = '', opts = {}) {
  const buckets = opts.buckets || [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
  const entry = getOrCreate(name, 'histogram', help, { unit: opts.unit || '', buckets });
  const key = labelsKey(labels);
  const agg = entry.values.get(key) || { count: 0, sum: 0, buckets: new Array(buckets.length + 1).fill(0) };
  agg.count += 1;
  agg.sum += Number(value) || 0;
  for (let i = 0; i < buckets.length; i++) {
    if ((Number(value) || 0) <= buckets[i]) agg.buckets[i] += 1;
  }
  agg.buckets[buckets.length] += 1; // +Inf
  entry.values.set(key, agg);
}

function escapeHelp(help) {
  return String(help || '').replace(/\\/g, '\\\\').replace(/\n/g, '\\n');
}

/**
 * 渲染 Prometheus 文本格式（含内置进程指标）
 */
function render() {
  const lines = [];

  for (const entry of registry.values()) {
    const baseName = entry.unit ? `${entry.name}_${entry.unit}` : entry.name;
    lines.push(`# HELP ${baseName} ${escapeHelp(entry.help)}`);
    lines.push(`# TYPE ${baseName} ${entry.type}`);

    for (const [key, value] of entry.values.entries()) {
      const suffix = key ? `{${key}}` : '';
      if (entry.type === 'counter' || entry.type === 'gauge') {
        lines.push(`${baseName}${suffix} ${value}`);
      } else if (entry.type === 'histogram') {
        const buckets = entry.buckets || [];
        for (let i = 0; i < buckets.length; i++) {
          lines.push(`${baseName}_bucket{${key ? `${key},` : ''}le="${buckets[i]}"} ${value.buckets[i]}`);
        }
        lines.push(`${baseName}_bucket{${key ? `${key},` : ''}le="+Inf"} ${value.buckets[value.buckets.length - 1]}`);
        lines.push(`${baseName}_sum${suffix} ${value.sum}`);
        lines.push(`${baseName}_count${suffix} ${value.count}`);
      }
    }
  }

  // 内置进程指标
  const mem = process.memoryUsage();
  lines.push('# HELP nodejs_process_memory_bytes Node.js 进程内存占用');
  lines.push('# TYPE nodejs_process_memory_bytes gauge');
  lines.push(`nodejs_process_memory_bytes{type="rss"} ${mem.rss}`);
  lines.push(`nodejs_process_memory_bytes{type="heapTotal"} ${mem.heapTotal}`);
  lines.push(`nodejs_process_memory_bytes{type="heapUsed"} ${mem.heapUsed}`);
  lines.push(`nodejs_process_memory_bytes{type="external"} ${mem.external || 0}`);

  lines.push('# HELP nodejs_process_uptime_seconds Node.js 进程运行时长');
  lines.push('# TYPE nodejs_process_uptime_seconds gauge');
  lines.push(`nodejs_process_uptime_seconds ${process.uptime()}`);

  lines.push('# HELP nodejs_os_memory_bytes 操作系统内存总量');
  lines.push('# TYPE nodejs_os_memory_bytes gauge');
  lines.push(`nodejs_os_memory_bytes ${os.totalmem()}`);
  lines.push(`nodejs_os_free_memory_bytes ${os.freemem()}`);
  lines.push('# HELP nodejs_os_cpu_count CPU 核数');
  lines.push('# TYPE nodejs_os_cpu_count gauge');
  lines.push(`nodejs_os_cpu_count ${os.cpus().length}`);

  lines.push('# HELP nodejs_version_info Node.js 版本');
  lines.push('# TYPE nodejs_version_info gauge');
  lines.push(`nodejs_version_info{version="${process.versions.node}",service="xuanjian-security-agent"} 1`);

  return lines.join('\n') + '\n';
}

module.exports = { inc, setGauge, incGauge, observe, get, render, registry };
