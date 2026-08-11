/**
 * 玄鉴安全智能体 - 多引擎协同安全评估系统
 * 主入口文件
 */

require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const nodeCron = require('node-cron');
const path = require('path');
const url = require('url');

const { config, loadDbConfig } = require('./config');
const logger = require('./utils/logger');
const metrics = require('./utils/metrics');
const metricsMiddleware = require('./middleware/metrics');
const { authMiddleware } = require('./middleware/auth');
const { initDatabase } = require('./db/init');
const { runMigrations } = require('./db/migrations');
const { closeDb, getDb } = require('./db/database');
const { serverError } = require('./utils/helpers');

async function startServer(options = {}) {
  const { listen = true } = options;
  try {
    await initDatabase();
    await runMigrations();
    await loadDbConfig();
    logger.info('数据库初始化完成');

    // 注册统一任务队列处理器（威胁情报采集/报告生成/防御策略动作）
    require('./services/queueHandlers');

    const app = express();

    app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "https://unpkg.com"],
          styleSrc: ["'self'", "https://unpkg.com", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          frameSrc: ["'self'"],
          frameAncestors: ["'self'"],
          baseUri: ["'self'"],
          formAction: ["'self'"]
        }
      },
      hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
      referrerPolicy: { source: 'same-origin' },
      crossOriginEmbedderPolicy: false
    }));

    // CORS 白名单（可通过环境变量 CORS_ORIGINS 扩展，逗号分隔）
    const allowedOrigins = (process.env.CORS_ORIGINS ||
      'http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174,http://localhost:5176,http://127.0.0.1:5176')
      .split(',').map(s => s.trim()).filter(Boolean);

    app.use(cors({
      origin: (origin, cb) => {
        // 允许无 Origin 的同源/非浏览器请求
        if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
        logger.warn(`[CORS] 拒绝跨域来源: ${origin}`);
        return cb(null, false);
      },
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
      credentials: true
    }));

    app.use(compression());
    app.use(express.json({ limit: '50mb' }));
    app.use(express.urlencoded({ extended: true, limit: '50mb' }));
    // 请求指标 + 链路追踪（X-Request-Id），置于路由之前
    app.use(metricsMiddleware);

    // 全局限流：适度收紧，防止 API 滥用
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 300,
      message: { code: 1, message: '请求过于频繁，请稍后再试', data: null },
      standardHeaders: true,
      legacyHeaders: false
    });
    app.use('/api/', limiter);

    // 认证接口独立严格限流（防暴力破解）
    const authLimiter = rateLimit({
      windowMs: 60 * 1000,
      max: 5,
      message: { code: 1, message: '登录尝试过于频繁，请 1 分钟后再试', data: null },
      standardHeaders: true,
      legacyHeaders: false
    });
    app.use('/api/auth/login', authLimiter);
    app.use('/api/auth/register', authLimiter);

    // 上传目录不再对外公开托管，避免上传的敏感/恶意文件被匿名访问
    // 静态资源优先使用 React 构建产物（frontend-react/dist），缺失时回退 frontend-app/dist，再回退旧版 frontend/
    const envFrontend = process.env.FRONTEND_DIR; // 显式指定前端目录
    const reactDist = path.join(__dirname, '../frontend-react/dist');
    const frontendDist = path.join(__dirname, '../frontend-app/dist');
    const legacyFrontend = path.join(__dirname, '../frontend');
    const staticDir = envFrontend
      ? path.resolve(process.cwd(), envFrontend)
      : [reactDist, frontendDist, legacyFrontend].find((d) => require('fs').existsSync(d));
    logger.info(`前端静态目录: ${staticDir}`);
    app.use(express.static(staticDir));

    const authRoutes = require('./routes/auth');
    const scanRoutes = require('./routes/scan');
    const baselineRoutes = require('./routes/baseline');
    const virusRoutes = require('./routes/virus');
    const situationalRoutes = require('./routes/situational');
    const defenseRoutes = require('./routes/defense');
    const deviceRoutes = require('./routes/device');
    const userRoutes = require('./routes/user');
    const configRoutes = require('./routes/config');
    const aiRoutes = require('./routes/ai');
    const djppRoutes = require('./routes/djpp');
    const intelRoutes = require('./routes/intel');
    const reportsRoutes = require('./routes/reports');
    const playbookRoutes = require('./routes/playbook');
    const adaptersRoutes = require('./routes/adapters');

    app.use('/api/auth', authRoutes);
    app.use('/api/scan', scanRoutes);
    app.use('/api/baseline', baselineRoutes);
    app.use('/api/virus', virusRoutes);
    app.use('/api/situational', situationalRoutes);
    app.use('/api/defense', defenseRoutes);
    app.use('/api/device', deviceRoutes);
    app.use('/api/user', userRoutes);
    app.use('/api/config', configRoutes);
    app.use('/api/ai', aiRoutes);
    app.use('/api/djpp', djppRoutes);
    app.use('/api/intel', intelRoutes);
    app.use('/api/reports', reportsRoutes);
    app.use('/api/playbook', playbookRoutes);
    app.use('/api/adapters', adaptersRoutes);

    app.get('/api/health', (req, res) => {
      const db = getDb();
      const queue = require('./services/queue').getQueue();
      const alerting = require('./services/alertingService');
      const health = alerting.getLastHealthCheck();
      const rowCount = (t) => (db._rawTable(t) || []).length;

      const dbHealth = {
        row_counts: {
          users: rowCount('users'),
          roles: rowCount('roles'),
          alerts: rowCount('alert_records'),
          scan_tasks: rowCount('scan_tasks'),
          threat_intel: rowCount('threat_intel'),
          edge_devices: rowCount('edge_devices')
        }
      };

      res.json({
        code: 0,
        message: '服务运行正常',
        data: {
          service: 'xuanjian-security-agent',
          version: '1.0.0',
          uptime: process.uptime(),
          timestamp: new Date().toISOString(),
          trace_id: req.traceId,
          queue: queue.stats(),
          health_check: health,
          db: dbHealth,
          node_env: config.nodeEnv,
          scan_engine: config.scan.engine
        }
      });
    });

    // Prometheus 指标端点（仅管理员可访问）
    app.get('/metrics', authMiddleware, (req, res) => {
      res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
      res.send(metrics.render());
    });

    app.get('/api/djpp-data-check', authMiddleware, (req, res) => {
      const { getDb } = require('./db/database');
      const db = getDb();
      const tasks = db.prepare('SELECT * FROM djpp_tasks').all();
      const levels = db.prepare('SELECT * FROM djpp_levels').all();
      const results = db.prepare('SELECT * FROM djpp_results').all();
      const reports = db.prepare('SELECT * FROM reports WHERE type = "djpp"').all();
      res.json({ 
        code: 0, 
        data: { 
          tasks: tasks.length, 
          levels: levels.length,
          results: results.length,
          reports: reports.length,
          taskList: tasks 
        } 
      });
    });

    app.use('/api/', (req, res) => {
      res.status(404).json({ code: 1, message: '接口不存在', data: null });
    });

    app.get('*', (req, res) => {
      res.sendFile(path.join(staticDir, 'index.html'));
    });

    app.use((err, req, res, next) => {
      logger.error('服务器错误:', err.stack || err.message);
      if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ code: 1, message: '请求数据格式错误', data: null });
      }
      // 生产环境不泄露内部错误信息
      const isDev = process.env.NODE_ENV !== 'production';
      const message = isDev ? (err.message || '服务器内部错误') : '服务器内部错误';
      serverError(res, message);
    });

    const server = http.createServer(app);

    const wss = new WebSocket.Server({ noServer: true });
    const frontendWss = new WebSocket.Server({ noServer: true });
    const frontendClients = new Set();

    server.on('upgrade', (request, socket, head) => {
      const pathname = url.parse(request.url).pathname;

      if (pathname === '/ws/device') {
        wss.handleUpgrade(request, socket, head, (ws) => {
          wss.emit('connection', ws, request);
        });
      } else if (pathname === '/ws/frontend') {
        frontendWss.handleUpgrade(request, socket, head, (ws) => {
          frontendWss.emit('connection', ws, request);
        });
      } else {
        socket.destroy();
      }
    });

    wss.on('connection', (ws, req) => {
      logger.info('WebSocket连接请求');

      const urlObj = new URL(req.url, `http://${req.headers.host}`);
      const deviceId = urlObj.searchParams.get('device_id');
      const token = urlObj.searchParams.get('token');

      if (!deviceId || !token) {
        logger.warn('WebSocket连接缺少设备ID或Token');
        ws.close(4001, '缺少设备认证信息');
        return;
      }

      const deviceService = require('./services/deviceService');
      deviceService.handleDeviceConnection(ws, deviceId, token);
    });

    frontendWss.on('connection', (ws) => {
      frontendClients.add(ws);
      logger.info(`前端WebSocket客户端已连接，当前连接数: ${frontendClients.size}`);

      ws.on('close', () => {
        frontendClients.delete(ws);
        logger.info(`前端WebSocket客户端已断开，当前连接数: ${frontendClients.size}`);
      });
      ws.on('error', (err) => {
        frontendClients.delete(ws);
        logger.error('前端WebSocket客户端错误:', err.message);
      });
    });

    function broadcastToFrontend(type, data) {
      const message = JSON.stringify({ type, data, timestamp: new Date().toISOString() });
      frontendClients.forEach(client => {
        try {
          if (client.readyState === WebSocket.OPEN) {
            client.send(message);
          }
        } catch (err) {
          frontendClients.delete(client);
        }
      });
    }

    app.set('broadcastToFrontend', broadcastToFrontend);

    const heartbeatInterval = setInterval(() => {
      wss.clients.forEach((ws) => {
        if (ws.isAlive === false) {
          return ws.terminate();
        }
        ws.isAlive = false;
        ws.ping().catch(() => { ws.isAlive = false; ws.terminate(); });
      });
    }, 30000);

    wss.on('close', () => {
      clearInterval(heartbeatInterval);
    });

    const threatIntelInterval = config.threatIntel.interval;
    const threatIntelCron = `*/${threatIntelInterval} * * * *`;
    nodeCron.schedule(threatIntelCron, () => {
      logger.info('执行定时任务: 威胁情报采集');
      try {
        const { getQueue } = require('./services/queue');
        getQueue().add('threat_intel_collect', {}, { attempts: 2, backoff: 5000 });
      } catch (err) {
        logger.error('威胁情报采集失败:', err.message);
      }
    });
    logger.info(`定时任务已配置: 威胁情报采集 (每${threatIntelInterval}分钟)`);

    nodeCron.schedule('* * * * *', () => {
      try {
        const deviceService = require('./services/deviceService');
        deviceService.checkHeartbeats().catch((err) => {
          logger.error('设备心跳检测失败:', err.message);
        });
      } catch (err) {
        logger.error('设备心跳检测失败:', err.message);
      }
    });
    logger.info('定时任务已配置: 设备心跳检测 (每分钟)');

    // 系统健康巡检（每 5 分钟），异常生成 system_health 告警
    nodeCron.schedule('*/5 * * * *', () => {
      const alertingService = require('./services/alertingService');
      alertingService.checkSystemHealth().catch((err) => {
        logger.error('系统健康巡检失败:', err.message);
      });
    });
    logger.info('定时任务已配置: 系统健康巡检 (每5分钟)');

    // 数据保留清理（每日 03:00）
    nodeCron.schedule('0 3 * * *', () => {
      const retentionService = require('./services/retentionService');
      retentionService.runRetention().catch((err) => {
        logger.error('数据保留清理失败:', err.message);
      });
    });
    logger.info('定时任务已配置: 数据保留清理 (每日03:00)');

    // 数据库备份（每日 02:00，可关 PERSIST_BACKUP=0）
    if (process.env.PERSIST_BACKUP !== '0') {
      nodeCron.schedule('0 2 * * *', () => {
        try {
          const { backup } = require('../scripts/backup');
          const r = backup();
          logger.info(`定时备份完成: ${r.dest}`);
        } catch (err) {
          logger.error('定时备份失败:', err.message);
        }
      });
      logger.info('定时任务已配置: 数据库备份 (每日02:00)');
    }

    // Copilot 主动巡检（默认每周一 05:00，PATROL_CRON 可调整）
    try {
      const patrolCron = process.env.PATROL_CRON || '0 5 * * 1';
      nodeCron.schedule(patrolCron, () => {
        const copilotService = require('./services/copilotService');
        copilotService.runProactivePatrol().catch((err) => {
          logger.error('Copilot 主动巡检失败:', err.message);
        });
      });
      logger.info(`定时任务已配置: Copilot 主动巡检 (${patrolCron})`);
    } catch (err) {
      logger.error('配置 Copilot 主动巡检失败:', err.message);
    }

    // 安全周报生成与推送（每周一 08:00，REPORT_CRON 可调整）
    // 生成任务入队执行，完成后由 queueHandlers 的 completed:report_generate 事件推送通知
    try {
      const reportCron = process.env.REPORT_CRON || '0 8 * * 1';
      nodeCron.schedule(reportCron, () => {
        try {
          const { getQueue } = require('./services/queue');
          getQueue().add('report_generate', { title: '安全态势周报', type: 'weekly', time_range: 'weekly', userId: 1, notify: true }, { attempts: 2, backoff: 5000 });
        } catch (err) {
          logger.error('定时周报生成失败:', err.message);
        }
      });
      logger.info(`定时任务已配置: 安全周报生成与推送 (${reportCron})`);
    } catch (err) {
      logger.error('配置安全周报推送失败:', err.message);
    }

    // 定时病毒扫描（默认每6小时，VIRUS_SCAN_ENABLED=0 可关闭）
    try {
      if (config.virusScan.enabled) {
        nodeCron.schedule(config.virusScan.cron, () => {
          const { runScanTask } = require('./services/virusScanScheduler');
          runScanTask().catch((err) => {
            logger.error('定时病毒扫描失败:', err.message);
          });
        });
        logger.info(`定时任务已配置: 病毒扫描 (${config.virusScan.cron})，扫描目录: ${config.virusScan.watchDirs.join(', ')}`);
      } else {
        logger.info('定时病毒扫描已禁用（VIRUS_SCAN_ENABLED=0）');
      }
    } catch (err) {
      logger.error('配置定时病毒扫描失败:', err.message);
    }

    // 业务指标采集（每 30 秒刷新 DB 行数 / WS 连接数 gauge）
    const businessMetricsTimer = setInterval(() => {
      try {
        const db = getDb();
        metrics.setGauge('db_row_count', { table: 'users' }, (db._rawTable('users') || []).length, '数据库表行数');
        metrics.setGauge('db_row_count', { table: 'alert_records' }, (db._rawTable('alert_records') || []).length, '数据库表行数');
        metrics.setGauge('db_row_count', { table: 'scan_tasks' }, (db._rawTable('scan_tasks') || []).length, '数据库表行数');
        metrics.setGauge('db_row_count', { table: 'threat_intel' }, (db._rawTable('threat_intel') || []).length, '数据库表行数');
        metrics.setGauge('ws_frontend_clients', {}, frontendClients.size, '前端 WebSocket 连接数');
        metrics.setGauge('ws_device_clients', {}, wss.clients.size, '设备 WebSocket 连接数');
      } catch (err) {
        logger.error('业务指标采集失败:', err.message);
      }
    }, 30000);

    try {
      const defenseService = require('./services/defenseService');
      defenseService.initEngines();
    } catch (err) {
      logger.error('防御策略引擎初始化失败:', err.message);
    }

    // 知识库完整性校验：每 6 小时自动校验一次
    try {
      nodeCron.schedule('0 */6 * * *', () => {
        const { verifyIntegrity } = require('./services/kbIntegrityService');
        try {
          const anomalies = verifyIntegrity();
          if (anomalies.length > 0) {
            logger.error(`[KB-Integrity] 定时校验发现 ${anomalies.length} 处异常（可能遭篡改）`);
          } else {
            logger.info('[KB-Integrity] 定时校验通过，所有文档完整性正常');
          }
        } catch (e) {
          logger.error('[KB-Integrity] 定时校验异常:', e.message);
        }
      });
      logger.info('定时任务已配置: 知识库完整性校验 (每6小时)');
    } catch (err) {
      logger.error('配置知识库完整性校验失败:', err.message);
    }

    // 威胁情报 LLM 融合：每 4 小时拉取最新安全更新，注入系统 Prompt
    try {
      nodeCron.schedule('0 */4 * * *', async () => {
        const { syncThreatIntelligence } = require('./services/threatLLMFusion');
        try {
          const result = await syncThreatIntelligence();
          if (result.updated) {
            logger.info(`[ThreatFusion] 威胁情报同步完成: ${result.update_count} 条更新`);
          }
        } catch (e) {
          logger.error('[ThreatFusion] 威胁情报同步异常:', e.message);
        }
      });
      logger.info('定时任务已配置: 威胁情报 LLM 融合 (每4小时)');
    } catch (err) {
      logger.error('配置威胁情报融合失败:', err.message);
    }

    // 差分隐私投毒检测：每 12 小时批量扫描知识库
    try {
      nodeCron.schedule('0 */12 * * *', () => {
        const { detectPoisoningDocs } = require('./services/diffPrivacyService');
        try {
          const result = detectPoisoningDocs();
          if (result.detected_count > 0) {
            logger.error(`[DiffPrivacy] 投毒检测发现 ${result.detected_count} 处异常`);
          } else {
            logger.info('[DiffPrivacy] 投毒检测通过，所有文档正常');
          }
        } catch (e) {
          logger.error('[DiffPrivacy] 投毒检测异常:', e.message);
        }
      });
      logger.info('定时任务已配置: 差分隐私投毒检测 (每12小时)');
    } catch (err) {
      logger.error('配置投毒检测失败:', err.message);
    }

    // 导入 SOAR 剧本模板（幂等）
    try {
      const playbookService = require('./services/playbookService');
      playbookService.seedTemplates();
    } catch (err) {
      logger.error('SOAR 剧本模板导入失败:', err.message);
    }

    // Phase 4: 初始化威胁情报 LLM 融合（启动时加载历史更新）
    try {
      const { loadAppliedUpdates } = require('./services/threatLLMFusion');
      loadAppliedUpdates();
      logger.info('[Phase4] 威胁情报 LLM 融合已初始化');
    } catch (err) {
      logger.error('[Phase4] 威胁情报融合初始化失败:', err.message);
    }

    // Phase 4: 初始化多模型仲裁器
    try {
      const { registerModel } = require('./services/modelArbitrator');
      // 注册第二个 LLM 后端（如 OpenAI、Claude 等）
      if (config.llm?.apiKey && config.llm.apiKey !== '') {
        registerModel('openai', {
          name: 'OpenAI-GPT',
          apiKey: config.llm.apiKey,
          apiBase: config.llm.apiBase,
          model: config.llm.model || 'gpt-4o-mini'
        });
      }
      logger.info('[Phase4] 多模型仲裁器已初始化');
    } catch (err) {
      logger.error('[Phase4] 多模型仲裁器初始化失败:', err.message);
    }

    const PORT = config.port;

    const startListening = () => {
      server.listen(PORT, () => {
        logger.info('========================================');
        logger.info('  玄鉴安全智能体 - 多引擎协同安全评估系统');
        logger.info('========================================');
        logger.info(`  服务地址: http://localhost:${PORT}`);
        logger.info(`  API地址:  http://localhost:${PORT}/api`);
        logger.info(`  指标端点: http://localhost:${PORT}/metrics`);
        logger.info(`  WebSocket(设备): ws://localhost:${PORT}/ws/device`);
        logger.info(`  WebSocket(前端): ws://localhost:${PORT}/ws/frontend`);
        logger.info(`  环境: ${config.nodeEnv}`);
        logger.info(`  AI服务: ${config.aiService.url}`);
        logger.info(`  任务队列: ${require('./services/queue').getQueue().stats().driver}`);
        logger.info('========================================');
        logger.info('  默认账号: admin / admin123');
        logger.info('========================================');

        try {
          const scanService = require('./services/scanService');
          scanService.setBroadcastFn(broadcastToFrontend);
        } catch (err) {
          logger.error('设置扫描服务广播函数失败:', err.message);
        }
        try {
          const defenseService = require('./services/defenseService');
          defenseService.setBroadcastFn(broadcastToFrontend);
        } catch (err) {
          logger.error('设置防御服务广播函数失败:', err.message);
        }
      });
    };

    if (listen) {
      startListening();
    }

    function gracefulShutdown(signal) {
      logger.info(`收到 ${signal} 信号，开始优雅退出...`);

      clearInterval(businessMetricsTimer);

      server.close(() => {
        logger.info('HTTP服务器已关闭');
      });

      wss.clients.forEach((ws) => {
        ws.close(1001, '服务器关闭');
      });
      wss.close(() => {
        logger.info('设备WebSocket服务器已关闭');
      });

      frontendClients.forEach((ws) => {
        try { ws.close(1001, '服务器关闭'); } catch (e) {}
      });
      frontendWss.close(() => {
        logger.info('前端WebSocket服务器已关闭');
      });

      try {
        closeDb();
      } catch (err) {
        logger.error('关闭数据库失败:', err.message);
      }

      logger.info('优雅退出完成');
      process.exit(0);
    }

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    process.on('uncaughtException', (err) => {
      logger.error('未捕获的异常:', err.stack || err.message);
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('未处理的Promise拒绝:', reason);
    });

    return app;
  } catch (err) {
    logger.error('服务器启动失败:', err.message);
    process.exit(1);
  }
}

// 仅当直接执行本文件时启动服务（被测试/其他模块 require 时不自动监听）
if (require.main === module) {
  startServer();
}

module.exports = { startServer };