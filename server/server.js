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

    const app = express();

    app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
          imgSrc: ["'self'", "data:", "blob:"],
          fontSrc: ["'self'", "data:", "https://unpkg.com"],
          connectSrc: ["'self'", "ws:", "wss:"],
          objectSrc: ["'none'"],
          frameAncestors: ["'self'"]
        }
      },
      crossOriginEmbedderPolicy: false
    }));

    // CORS 白名单（可通过环境变量 CORS_ORIGINS 扩展，逗号分隔）
    const allowedOrigins = (process.env.CORS_ORIGINS ||
      'http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173')
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

    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 1000,
      message: { code: 1, message: '请求过于频繁，请稍后再试', data: null }
    });
    app.use('/api/', limiter);

    // 上传目录不再对外公开托管，避免上传的敏感/恶意文件被匿名访问
    // 静态资源优先使用新前端构建产物（frontend-app/dist），缺失时回退旧版 frontend/
    const frontendDist = path.join(__dirname, '../frontend-app/dist');
    const legacyFrontend = path.join(__dirname, '../frontend');
    const staticDir = require('fs').existsSync(frontendDist) ? frontendDist : legacyFrontend;
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

    // Prometheus 指标端点（文本格式，供 Prometheus 抓取）
    app.get('/metrics', (req, res) => {
      res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
      res.send(metrics.render());
    });

    app.get('/api/djpp-data-check', (req, res) => {
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
      serverError(res, err.message || '服务器内部错误');
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
        ws.ping();
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
        const situationalService = require('./services/situationalService');
        situationalService.collectThreatIntel().catch(err => {
          logger.error('威胁情报采集失败:', err.message);
        });
      } catch (err) {
        logger.error('威胁情报采集失败:', err.message);
      }
    });
    logger.info(`定时任务已配置: 威胁情报采集 (每${threatIntelInterval}分钟)`);

    nodeCron.schedule('* * * * *', () => {
      try {
        const deviceService = require('./services/deviceService');
        deviceService.checkHeartbeats();
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
    try {
      const reportCron = process.env.REPORT_CRON || '0 8 * * 1';
      nodeCron.schedule(reportCron, async () => {
        try {
          const situationalService = require('./services/situationalService');
          const report = await situationalService.generateReport('安全态势周报', 'weekly', 'weekly', 1);
          const notifyService = require('./services/notifyService');
          await notifyService.send({
            channel: 'all',
            message: `安全态势周报已生成：${report.title}（报告ID ${report.id}）`,
            severity: 'medium'
          });
          logger.info(`定时周报已生成并推送: ${report.title}`);
        } catch (err) {
          logger.error('定时周报生成失败:', err.message);
        }
      });
      logger.info(`定时任务已配置: 安全周报生成与推送 (${reportCron})`);
    } catch (err) {
      logger.error('配置安全周报推送失败:', err.message);
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

    // 导入 SOAR 剧本模板（幂等）
    try {
      const playbookService = require('./services/playbookService');
      playbookService.seedTemplates();
    } catch (err) {
      logger.error('SOAR 剧本模板导入失败:', err.message);
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