const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');
const logConfig = require('../config/logging');

const LOG_DIR = logConfig.getConfig().logDir;
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

const LOG_FILE = path.join(LOG_DIR, logConfig.getConfig().appLog);
const SERVER_LOG_FILE = path.join(LOG_DIR, logConfig.getConfig().serverLog);
const ERROR_LOG_FILE = path.join(LOG_DIR, logConfig.getConfig().errorLog);

const LOG_LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
};

const config = logConfig.getConfig();
const currentLevel = LOG_LEVELS[config.level] ?? LOG_LEVELS.debug;
// LOG_FORMAT=json 输出结构化日志（便于 Loki/ELK 采集）；默认人类可读文本
const jsonMode = (config.format || 'text') === 'json';

function formatTime(date) {
  const pad = (n) => n.toString().padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function serializeArg(arg) {
  if (typeof arg === 'object' && arg !== null) {
    try { return JSON.stringify(arg); }
    catch { return String(arg); }
  }
  return String(arg);
}

function log(level, args, context) {
  if (LOG_LEVELS[level] < currentLevel) return;

  const timestamp = new Date().toISOString();
  const contextObj = context || {};

  if (jsonMode) {
    const line = JSON.stringify({
      level,
      time: timestamp,
      msg: args.map(serializeArg).join(' '),
      service: 'xuanjian-security-agent',
      ...contextObj
    }) + '\n';

    if (level === 'error') console.error(line.trim());
    else if (level === 'warn') console.warn(line.trim());
    else console.log(line.trim());

    // 同时写入 server.log（系统运行日志）
    try {
      const targetFile = level === 'error' ? ERROR_LOG_FILE : SERVER_LOG_FILE;
      fs.appendFileSync(targetFile, line, 'utf8');
    } catch (e) {}
    // 写入 app.log（应用日志）
    try { fs.appendFileSync(LOG_FILE, line, 'utf8'); } catch (e) {}
    return;
  }

  const ts = formatTime(new Date());
  const ctx = context && Object.keys(context).length > 0 ? ` ${Object.entries(context).map(([k, v]) => `${k}=${v}`).join(' ')}` : '';
  const message = args.map(serializeArg).join(' ');
  const logLine = `[${ts}] [${level.toUpperCase()}]${ctx} ${message}\n`;

  if (level === 'error') console.error(logLine.trim());
  else if (level === 'warn') console.warn(logLine.trim());
  else console.log(logLine.trim());

  // 同时写入 server.log（系统运行日志）
  try {
    const targetFile = level === 'error' ? ERROR_LOG_FILE : SERVER_LOG_FILE;
    fs.appendFileSync(targetFile, logLine, 'utf8');
  } catch (e) {}
  // 写入 app.log（应用日志）
  try { fs.appendFileSync(LOG_FILE, logLine, 'utf8'); } catch (e) {}
}

/**
 * 创建绑定上下文（如 traceId/requestId）的子 logger，保持 API 与顶层 logger 一致
 */
function child(context) {
  return createLogger({ ...(context || {}) });
}

function createLogger(baseContext) {
  return {
    debug: (...args) => log('debug', args, baseContext),
    info: (...args) => log('info', args, baseContext),
    warn: (...args) => log('warn', args, baseContext),
    error: (...args) => log('error', args, baseContext),
    child: (context) => createLogger({ ...(baseContext || {}), ...(context || {}) })
  };
}

/**
 * 生成请求级 traceId，并挂到 req 对象（配合 metrics 中间件做全链路关联）
 */
function newTraceId() {
  return randomUUID();
}

const logger = createLogger({});

module.exports = logger;
module.exports.child = child;
module.exports.newTraceId = newTraceId;
