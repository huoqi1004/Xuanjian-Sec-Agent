/**
 * 日志配置中心
 *
 * 用途：统一管理各服务模块的日志级别、性能监控阈值、输出格式
 * 使用方式：
 *   1. 直接设置环境变量（推荐，无需改代码）
 *      LOG_LEVEL=debug
 *      LOG_PERF_SERVICE=wasmSandbox,diffPrivacy
 *      LOG_PERF_SLOW_MS=50
 *   2. 或通过 server/config/index.js 的 config.log 字段
 *   3. 测试环境快速复用：复制 .env.test 到项目根目录
 */
require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });
const path = require('path');

// ── 默认配置 ──────────────────────────────────────────────
const DEFAULTS = {
  // 全局最低日志级别：debug | info | warn | error
  level: 'debug',

  // 日志文件路径
  logDir: path.resolve(__dirname, '../../logs'),
  appLog: 'app.log',
  serverLog: 'server.log',
  errorLog: 'server_err.log',

  // 日志格式：text（人类可读）| json（结构化，供 Loki/ELK 采集）
  format: 'text',

  // 是否写入文件
  fileEnabled: true,

  // 是否输出到控制台
  consoleEnabled: true,

  // 性能监控阈值（毫秒）：超过此值才输出 WARN 级别的慢操作日志
  slowThresholdMs: 50,

  // 哪些服务开启性能日志（逗号分隔，空 = 全部）
  perfServices: '',

  // 是否记录函数入参/返回值（debug 模式下生效）
  traceArgs: false,

  // 采样率：0~1，1=全量记录，0.1=10%采样（用于高频日志降载）
  sampleRate: 1.0,

  // 日志行数上限（滚动截断，防止磁盘爆满）
  maxLinesPerFile: 1_000_000,
};

// ── 各服务模块的日志配置 ──────────────────────────────────
const SERVICE_CONFIG = {
  // WebAssembly 沙箱分析
  wasmSandbox: {
    defaultLevel: 'debug',
    enablePerf: true,
    // 慢操作阈值（毫秒）
    slowThresholdMs: 30,
    // 性能指标监控点
    metrics: ['hashFile', 'loadWasmModule', 'heuristicAnalysis', 'insertDB'],
  },

  // 差分隐私投毒检测
  diffPrivacy: {
    defaultLevel: 'debug',
    enablePerf: true,
    slowThresholdMs: 20,
    metrics: ['laplaceNoise', 'applyDPNoise', 'detectPoisoningAnomaly', 'insertDB'],
  },

  // 提示词注入检测
  promptGuard: {
    defaultLevel: 'debug',
    enablePerf: true,
    slowThresholdMs: 10,
    metrics: ['detectPromptInjection', 'scanKnowledgeDoc'],
  },

  // 幻觉检测
  hallucinationDetector: {
    defaultLevel: 'info',
    enablePerf: false,
    slowThresholdMs: 100,
  },

  // 行为分析
  behavioralAnalyzer: {
    defaultLevel: 'info',
    enablePerf: false,
    slowThresholdMs: 50,
  },

  // 知识库完整性
  kbIntegrity: {
    defaultLevel: 'debug',
    enablePerf: true,
    slowThresholdMs: 200,
    metrics: ['verifyIntegrity', 'scanDoc', 'insertLog'],
  },

  // 多模型仲裁
  modelArbitrator: {
    defaultLevel: 'debug',
    enablePerf: true,
    slowThresholdMs: 500,
    metrics: ['callLLM', 'textSimilarity', 'arbitrate'],
  },

  // 威胁情报融合
  threatLLMFusion: {
    defaultLevel: 'info',
    enablePerf: true,
    slowThresholdMs: 1000,
    metrics: ['fetchSecurityUpdates', 'buildPromptSegment', 'syncThreatIntelligence'],
  },
};

/**
 * 解析环境变量，生成最终配置
 * 优先级：环境变量 > .env 文件 > DEFAULTS
 */
function parseConfig() {
  const raw = {
    level: process.env.LOG_LEVEL || DEFAULTS.level,
    logDir: process.env.LOG_DIR || DEFAULTS.logDir,
    appLog: process.env.LOG_APP_FILE || DEFAULTS.appLog,
    serverLog: process.env.LOG_SERVER_FILE || DEFAULTS.serverLog,
    errorLog: process.env.LOG_ERROR_FILE || DEFAULTS.errorLog,
    format: process.env.LOG_FORMAT || DEFAULTS.format,
    fileEnabled: process.env.LOG_FILE_ENABLED !== '0',
    consoleEnabled: process.env.LOG_CONSOLE_ENABLED !== '0',
    slowThresholdMs: parseInt(process.env.LOG_SLOW_THRESHOLD_MS) || DEFAULTS.slowThresholdMs,
    perfServices: (process.env.LOG_PERF_SERVICES || DEFAULTS.perfServices).toLowerCase(),
    traceArgs: process.env.LOG_TRACE_ARGS === '1',
    sampleRate: Math.min(1, Math.max(0, parseFloat(process.env.LOG_SAMPLE_RATE) || DEFAULTS.sampleRate)),
    maxLinesPerFile: parseInt(process.env.LOG_MAX_LINES) || DEFAULTS.maxLinesPerFile,
  };

  // 将 COMMA_SEPARATED 字符串转为 Set
  const perfServiceSet = new Set(
    raw.perfServices
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
  );

  // 构建最终配置对象
  const config = {
    ...DEFAULTS,
    ...raw,
    _perfServiceSet: perfServiceSet,
    _serviceConfigs: {},
  };

  // 合并各服务配置
  for (const [serviceName, svcCfg] of Object.entries(SERVICE_CONFIG)) {
    config._serviceConfigs[serviceName] = {
      ...svcCfg,
      // 服务级日志级别可被环境变量覆盖：LOG_LEVEL_wasmSandbox=info
      level: process.env[`LOG_LEVEL_${serviceName}`] || svcCfg.defaultLevel,
      // 服务级慢阈值可被覆盖：LOG_SLOW_wasmSandbox=20
      slowThresholdMs: parseInt(process.env[`LOG_SLOW_${serviceName}`]) || svcCfg.slowThresholdMs,
      // 是否开启该服务的性能日志
      enablePerf: perfServiceSet.size === 0
        ? svcCfg.enablePerf
        : perfServiceSet.has(serviceName.toLowerCase()),
    };
  }

  return config;
}

// ── 单例配置（启动时解析一次）────────────────────────────
let _config = null;

function getConfig() {
  if (!_config) {
    _config = parseConfig();
  }
  return _config;
}

/**
 * 强制重新解析配置（用于测试环境热重载）
 */
function reloadConfig() {
  _config = parseConfig();
  return _config;
}

/**
 * 判断某个服务是否开启了性能日志
 */
function isPerfEnabled(serviceName) {
  const cfg = getConfig()._serviceConfigs[serviceName];
  return cfg ? cfg.enablePerf : false;
}

/**
 * 获取某个服务的慢操作阈值（毫秒）
 */
function getSlowThreshold(serviceName) {
  const cfg = getConfig()._serviceConfigs[serviceName];
  if (!cfg) return getConfig().slowThresholdMs;
  return cfg.slowThresholdMs;
}

/**
 * 判断某个日志级别在当前配置下是否可见
 */
function isLevelVisible(level) {
  const levels = { debug: 0, info: 1, warn: 2, error: 3 };
  return (levels[level] ?? 0) >= (levels[getConfig().level] ?? 0);
}

/**
 * 生成测试环境预设配置（返回 env 变量字符串，可直接写入 .env.test）
 */
function generateTestEnv() {
  return `# ═══════════════════════════════════════════
# 玄鉴安全智能体 — 测试环境日志配置
# 生成时间: ${new Date().toISOString()}
# 用途: 复制到项目根目录作为 .env.test 使用
# ═══════════════════════════════════════════

# ── 日志基础配置 ──────────────────────────
# 全局日志级别: debug（详细）| info（标准）| warn（仅警告）| error（仅错误）
LOG_LEVEL=debug

# 日志格式: text（可读）| json（ELK/Loki 结构化采集）
LOG_FORMAT=text

# 启用文件日志
LOG_FILE_ENABLED=1
# 启用控制台输出
LOG_CONSOLE_ENABLED=1

# 日志文件路径（相对项目根目录）
LOG_DIR=./logs
LOG_APP_FILE=app.log
LOG_SERVER_FILE=server.log
LOG_ERROR_FILE=server_err.log

# ── 性能监控开关 ──────────────────────────
# 默认慢操作阈值（毫秒），低于此值不输出性能日志
LOG_SLOW_THRESHOLD_MS=50

# 启用性能日志的服务列表（逗号分隔，留空=使用各服务默认值）
# 可选服务: wasmSandbox, diffPrivacy, promptGuard, hallucinationDetector,
#           behavioralAnalyzer, kbIntegrity, modelArbitrator, threatLLMFusion
LOG_PERF_SERVICES=wasmSandbox,diffPrivacy,promptGuard,kbIntegrity,modelArbitrator

# ── 各服务独立配置（可按需覆盖）──────────
# LOG_LEVEL_wasmSandbox=debug
# LOG_LEVEL_diffPrivacy=debug
# LOG_SLOW_wasmSandbox=30
# LOG_SLOW_diffPrivacy=20

# ── 采样与追踪 ────────────────────────────
# 采样率: 1.0=全量, 0.1=10%, 0.01=1%
LOG_SAMPLE_RATE=1.0

# 是否记录函数入参/返回值（debug 模式生效，生产环境建议关闭）
LOG_TRACE_ARGS=0

# 单文件最大行数（超出后截断，防止磁盘爆满）
LOG_MAX_LINES=1000000
`;
}

module.exports = {
  getConfig,
  reloadConfig,
  isPerfEnabled,
  getSlowThreshold,
  isLevelVisible,
  generateTestEnv,
  DEFAULTS,
  SERVICE_CONFIG
};
