/**
 * 玄鉴安全智能体 - 请求指标与链路追踪中间件
 *
 * 职责：
 * 1. 注入/透传 X-Request-Id（traceId），供全链路日志关联
 * 2. 统计 HTTP 请求数、状态码分布、耗时直方图（Prometheus）
 */

const metrics = require('../utils/metrics');
const logger = require('../utils/logger');

function metricsMiddleware(req, res, next) {
  const start = process.hrtime.bigint();

  // 链路追踪 ID：优先透传调用方传入的 X-Request-Id，否则生成新 ID
  const traceId = req.headers['x-request-id'] || logger.newTraceId();
  req.traceId = traceId;
  res.setHeader('X-Request-Id', traceId);
  req.log = logger.child({ traceId });

  // 统计计数（不含 /metrics 自身，避免抓取循环放大）
  const route = req.path;
  const labelRoute = route === '/metrics' ? '/metrics' : route;

  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
    metrics.inc('http_requests_total', { method: req.method, path: labelRoute, status: res.statusCode }, 1, 'HTTP 请求总数');
    metrics.observe('http_request_duration', { method: req.method, path: labelRoute }, durationMs / 1000, 'HTTP 请求耗时', { unit: 'seconds' });
    metrics.inc('http_requests_total', { method: 'ALL', path: 'ALL', status: 'ALL' }, 1, 'HTTP 请求总数');
  });

  next();
}

module.exports = metricsMiddleware;
