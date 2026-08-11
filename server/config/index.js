const { getDb } = require('../db/database');

const config = {
  port: parseInt(process.env.PORT) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  jwt: {
    secret: process.env.JWT_SECRET || 'xuanjian_security_agent_jwt_secret_key_2024',
    expiresIn: process.env.JWT_EXPIRES_IN || '24h'
  },
  db: {
    path: process.env.DB_PATH || './data/security.db',
    // N-06 数据层：shim(旧内存模拟器，默认) | sqlite | mysql | pg
    driver: process.env.DB_DRIVER || 'shim',
    host: process.env.DB_HOST || '127.0.0.1',
    port: process.env.DB_PORT || '3306',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    name: process.env.DB_NAME || 'xuanjian'
  },
  aiService: {
    url: process.env.AI_SERVICE_URL || 'http://localhost:5000'
  },
  deepseek: {
    apiKey: process.env.DEEPSEEK_API_KEY || '',
    apiBase: process.env.DEEPSEEK_API_BASE || 'https://api.deepseek.com',
    model: process.env.DEEPSEEK_MODEL || 'deepseek-chat',
    maxTokens: parseInt(process.env.DEEPSEEK_MAX_TOKENS) || 4096
  },
  agnes: {
    apiKey: process.env.ANGES_API_KEY || process.env.LLM_API_KEY || '',
    apiBase: process.env.ANGES_API_BASE || process.env.LLM_API_BASE || 'https://api.openai.com/v1',
    model: process.env.ANGES_MODEL || process.env.LLM_MODEL || 'agnes-2.5-flash',
    maxTokens: parseInt(process.env.ANGES_MAX_TOKENS) || 8192
  },
  virusTotal: {
    apiKey: process.env.VIRUSTOTAL_API_KEY || ''
  },
  virusScan: {
    enabled: process.env.VIRUS_SCAN_ENABLED === 'true',
    cron: process.env.VIRUS_SCAN_CRON || '0 3 * * *',
    watchDirs: (process.env.VIRUS_SCAN_WATCH_DIRS || './uploads,./data').split(',').map(s => s.trim()).filter(Boolean)
  },
  gan: {
    enabled: process.env.GAN_SCAN_ENABLED === 'true',
    anomalyThreshold: parseFloat(process.env.GAN_ANOMALY_THRESHOLD) || 0.02,
    weight: parseFloat(process.env.GAN_ENGINE_WEIGHT) || 0.3,
    timeoutMs: parseInt(process.env.GAN_SCAN_TIMEOUT_MS) || 20000,
    fallbackToRule: process.env.GAN_FALLBACK_TO_RULE !== 'false'
  },
  llm: {
    apiKey: process.env.LLM_API_KEY || '',
    apiBase: process.env.LLM_API_BASE || 'https://api.openai.com/v1',
    model: process.env.LLM_MODEL || 'gpt-4'
  },
  device: {
    heartbeatTimeout: parseInt(process.env.DEVICE_HEARTBEAT_TIMEOUT) || 60,
    tokenExpiry: parseInt(process.env.DEVICE_TOKEN_EXPIRY) || 86400
  },
  scan: {
    maxConcurrency: parseInt(process.env.SCAN_MAX_CONCURRENCY) || 100,
    timeout: parseInt(process.env.SCAN_TIMEOUT) || 5000,
    engine: process.env.SCAN_ENGINE || 'auto', // auto | nmap | masscan | node
    // N-04 扫描安全管控：目标 CIDR 白名单（逗号分隔）+ 大任务审批阈值
    allowedCidrs: (process.env.SCAN_ALLOWED_CIDRS || '127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16').split(',').map(s => s.trim()).filter(Boolean),
    approvalHostThreshold: parseInt(process.env.SCAN_APPROVAL_HOST_THRESHOLD) || 256
  },
  log: {
    level: process.env.LOG_LEVEL || 'debug',
    file: process.env.LOG_FILE || './logs/app.log'
  },
  threatIntel: {
    interval: parseInt(process.env.THREAT_INTEL_INTERVAL) || 30
  },
  bcrypt: {
    rounds: parseInt(process.env.BCRYPT_ROUNDS) || 10
  }
};

// 生产环境强制校验 JWT 密钥：禁止缺失、禁止使用默认值、禁止弱密钥
if (process.env.NODE_ENV === 'production') {
  const defaultSecrets = [
    'xuanjian_security_agent_jwt_secret_key_2024',
    'xuanguang_security_gpt_jwt_secret_key_2024'
  ];
  const secret = process.env.JWT_SECRET || '';
  if (!secret || defaultSecrets.includes(secret)) {
    throw new Error('[安全] 生产环境禁止使用默认 JWT_SECRET，请配置强随机密钥（生成命令: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"）');
  }
  if (secret.length < 32) {
    throw new Error('[安全] 生产环境 JWT_SECRET 长度必须 ≥ 32 字符');
  }
}

async function loadDbConfig() {
  try {
    const db = await getDb();
    const rows = db.prepare('SELECT key, value FROM sys_config').all();
    rows.forEach(row => {
      switch (row.key) {
        case 'ai_service_url':
          config.aiService.url = row.value;
          break;
        case 'virustotal_api_key':
          config.virusTotal.apiKey = row.value;
          break;
        case 'llm_api_key':
          config.llm.apiKey = row.value;
          break;
        case 'llm_api_base':
          config.llm.apiBase = row.value;
          break;
        case 'llm_model':
          config.llm.model = row.value;
          break;
        case 'scan_max_concurrency':
          config.scan.maxConcurrency = parseInt(row.value) || 100;
          break;
        case 'scan_timeout':
          config.scan.timeout = parseInt(row.value) || 5000;
          break;
        case 'device_heartbeat_timeout':
          config.device.heartbeatTimeout = parseInt(row.value) || 60;
          break;
        case 'threat_intel_interval':
          config.threatIntel.interval = parseInt(row.value) || 30;
          break;
        case 'defense_cooldown':
          config.defense = config.defense || {};
          config.defense.cooldown = parseInt(row.value) || 300;
          break;
        case 'max_upload_size':
          config.upload = config.upload || {};
          config.upload.maxSize = parseInt(row.value) || 104857600;
          break;
      }
    });
  } catch (err) {
    console.error('加载数据库配置失败:', err.message);
  }
}

function getConfig() {
  return config;
}

module.exports = { config, getConfig, loadDbConfig };