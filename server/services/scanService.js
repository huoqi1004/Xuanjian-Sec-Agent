const net = require('net');
const { getDb } = require('../db/database');
const { generateId, parseCIDR, parsePortRange } = require('../utils/helpers');
const { config } = require('../config');
const logger = require('../utils/logger');
const { getQueue } = require('./queue');

// 常见端口服务指纹库
const SERVICE_FINGERPRINTS = {
  21: { service: 'ftp', version: '', banner_pattern: /FTP|ftp|FileZilla|vsftpd|ProFTPD/i },
  22: { service: 'ssh', version: '', banner_pattern: /SSH|OpenSSH|Dropbear/i },
  23: { service: 'telnet', version: '', banner_pattern: /Telnet|telnet/i },
  25: { service: 'smtp', version: '', banner_pattern: /SMTP|smtp|ESMTP|Postfix|Exim/i },
  53: { service: 'dns', version: '', banner_pattern: /DNS|BIND|dnsmasq/i },
  80: { service: 'http', version: '', banner_pattern: /HTTP|Apache|nginx|IIS|Server:/i },
  110: { service: 'pop3', version: '', banner_pattern: /POP3|pop3|Dovecot/i },
  143: { service: 'imap', version: '', banner_pattern: /IMAP|imap|Dovecot/i },
  443: { service: 'https', version: '', banner_pattern: /HTTP|Apache|nginx|TLS|SSL/i },
  445: { service: 'smb', version: '', banner_pattern: /SMB|smb/i },
  993: { service: 'imaps', version: '', banner_pattern: /IMAP|TLS/i },
  995: { service: 'pop3s', version: '', banner_pattern: /POP3|TLS/i },
  1433: { service: 'mssql', version: '', banner_pattern: /Microsoft SQL Server/i },
  1521: { service: 'oracle', version: '', banner_pattern: /Oracle|ORACLE/i },
  3306: { service: 'mysql', version: '', banner_pattern: /MySQL|MariaDB|mysql/i },
  3389: { service: 'rdp', version: '', banner_pattern: /RDP|Terminal/i },
  5432: { service: 'postgresql', version: '', banner_pattern: /PostgreSQL|postgres/i },
  5900: { service: 'vnc', version: '', banner_pattern: /RFB|VNC/i },
  6379: { service: 'redis', version: '', banner_pattern: /redis/i },
  8080: { service: 'http-proxy', version: '', banner_pattern: /HTTP|Apache|nginx|Tomcat/i },
  8443: { service: 'https-alt', version: '', banner_pattern: /HTTP|Apache|nginx|Tomcat|TLS/i },
  9200: { service: 'elasticsearch', version: '', banner_pattern: /Elasticsearch|elasticsearch/i },
  27017: { service: 'mongodb', version: '', banner_pattern: /MongoDB|mongodb/i }
};

// 活跃任务追踪
const activeTasks = new Map();

// WebSocket广播函数（由server.js设置）
let broadcastFn = null;
function setBroadcastFn(fn) { broadcastFn = fn; }

/**
 * TCP Connect端口扫描
 */
function scanPort(host, port, timeout) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = '';
    let resolved = false;

    const finish = (state, data) => {
      if (resolved) return;
      resolved = true;
      try { socket.destroy(); } catch (e) {}
      resolve({ state, banner: data || '' });
    };

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      // 端口开放，尝试抓取Banner
      finish('open', '');
    });

    socket.on('data', (data) => {
      banner = data.toString('utf-8').replace(/[\r\n]/g, ' ').trim().substring(0, 200);
      finish('open', banner);
    });

    socket.on('timeout', () => {
      finish('filtered', '');
    });

    socket.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') {
        finish('closed', '');
      } else if (err.code === 'EHOSTUNREACH') {
        finish('filtered', '');
      } else {
        finish('error', '');
      }
    });

    socket.connect(port, host);
  });
}

/**
 * 识别服务信息
 */
function identifyService(port, banner) {
  const fingerprint = SERVICE_FINGERPRINTS[port];
  if (!fingerprint) {
    // 尝试从banner中识别
    if (banner.match(/SSH/i)) return { service: 'ssh', version: '' };
    if (banner.match(/HTTP/i)) return { service: 'http', version: '' };
    if (banner.match(/FTP/i)) return { service: 'ftp', version: '' };
    if (banner.match(/SMTP/i)) return { service: 'smtp', version: '' };
    if (banner.match(/MySQL/i)) return { service: 'mysql', version: '' };
    return { service: 'unknown', version: '' };
  }

  const service = fingerprint.service;
  let version = '';

  // 尝试从banner中提取版本
  const versionPatterns = [
    /([0-9]+\.[0-9]+(?:\.[0-9]+)?)/,
    /SSH-([0-9.]+[^\s]*)/,
    /Apache\/([0-9.]+)/,
    /nginx\/([0-9.]+)/,
    /OpenSSH_([0-9.]+)/,
    /MySQL\s+([0-9.]+)/,
    /vsftpd\s+([0-9.]+)/,
    /PostgreSQL\s+([0-9.]+)/,
    /Redis\s+v?([0-9.]+)/
  ];

  for (const pattern of versionPatterns) {
    const match = banner.match(pattern);
    if (match) {
      version = match[1];
      break;
    }
  }

  return { service, version };
}

/**
 * 并发控制扫描
 */
async function scanHostConcurrent(host, ports, concurrency, timeout, taskId, db) {
  const results = [];
  const insertStmt = db.prepare(
    'INSERT INTO scan_results (task_id, ip, port, service, version, banner, state) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );

  for (let i = 0; i < ports.length; i += concurrency) {
    const batch = ports.slice(i, i + concurrency);
    const promises = batch.map(async (port) => {
      const result = await scanPort(host, port, timeout);
      if (result.state === 'open') {
        const { service, version } = identifyService(port, result.banner);
        const record = {
          task_id: taskId,
          ip: host,
          port,
          service,
          version,
          banner: result.banner,
          state: 'open'
        };
        try {
          insertStmt.run(taskId, host, port, service, version, result.banner, 'open');
        } catch (err) {
          logger.error('写入扫描结果失败:', err.message);
        }
        results.push(record);
      }
    });

    await Promise.all(promises);

    // 更新进度
    const progress = Math.min(100, Math.round(((i + batch.length) / ports.length) * 100));
    try {
      db.prepare('UPDATE scan_tasks SET progress = ? WHERE id = ?').run(progress, taskId);
    } catch (err) {
      logger.error('更新扫描进度失败:', err.message);
    }

    // 通过WebSocket推送扫描进度
    if (broadcastFn) {
      try {
        broadcastFn('scan_progress', { task_id: taskId, progress, status: 'running' });
      } catch (err) {
        logger.error('推送扫描进度失败:', err.message);
      }
    }
  }

  return results;
}

/**
 * 启动扫描任务
 */
async function startScan(params) {
  const { target_cidr, scan_mode, port_range, created_by } = params;
  const db = getDb();
  const taskId = generateId();

  // 解析目标和端口
  let hosts;
  try {
    if (target_cidr.includes('/')) {
      hosts = parseCIDR(target_cidr);
    } else {
      hosts = [target_cidr];
    }
  } catch (err) {
    throw new Error(`目标地址解析失败: ${err.message}`);
  }

  const ports = parsePortRange(port_range);

  if (hosts.length === 0) {
    throw new Error('没有有效的扫描目标');
  }

  if (ports.length === 0) {
    throw new Error('没有有效的扫描端口');
  }

  // N-04 扫描安全管控：目标必须位于 CIDR 白名单内（拒绝公网/未授权网段）
  const { checkHostsInCidrs } = require('../utils/helpers');
  const whitelistCheck = checkHostsInCidrs(hosts, config.scan.allowedCidrs);
  if (!whitelistCheck.ok) {
    const denied = new Error(
      `扫描目标 ${whitelistCheck.outside} 不在允许的网段内（白名单: ${config.scan.allowedCidrs.join(', ')}），已拒绝`
    );
    denied.code = 'SCAN_TARGET_DENIED';
    denied.outside = whitelistCheck.outside;
    logger.warn(`[扫描安全] 拒绝白名单外目标: ${whitelistCheck.outside} (发起人: ${created_by})`);
    throw denied;
  }

  // N-04 扫描安全管控：大型扫描（主机数超阈值）需人工审批后方可执行
  const needsApproval = hosts.length > config.scan.approvalHostThreshold;

  // 创建任务记录（全参数形式：内存 shim 按位置映射占位符）
  db.prepare(`
    INSERT INTO scan_tasks (id, target_cidr, scan_mode, port_range, status, created_by)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    taskId,
    target_cidr,
    scan_mode,
    port_range,
    needsApproval ? 'pending_approval' : 'running',
    created_by
  );

  // 任务上下文（供取消/进度追踪）
  const taskInfo = { hosts, ports, totalHosts: hosts.length, scannedHosts: 0 };
  activeTasks.set(taskId, taskInfo);

  // 需审批：挂起等待管理员审批，不进入执行队列
  if (needsApproval) {
    logger.warn(`[扫描安全] 任务 ${taskId} 主机数 ${hosts.length} 超过审批阈值 ${config.scan.approvalHostThreshold}，已挂起等待审批`);
    return {
      task_id: taskId,
      target_cidr,
      scan_mode,
      port_range,
      hosts_count: hosts.length,
      ports_count: ports.length,
      status: 'pending_approval',
      needs_approval: true,
      approval_threshold: config.scan.approvalHostThreshold
    };
  }

  // 通过统一任务队列异步执行（QUEUE_DRIVER=memory 时进程内并发执行；bullmq 时跨实例共享）
  getQueue().add('scan', { taskId, hosts, ports }, { attempts: 1, backoff: 2000 });

  return {
    task_id: taskId,
    target_cidr,
    scan_mode,
    port_range,
    hosts_count: hosts.length,
    ports_count: ports.length,
    status: 'running'
  };
}

/**
 * N-04 扫描安全管控：审批大型扫描任务（管理员）
 * @param {string} taskId
 * @param {'approve'|'reject'} decision
 * @param {number} reviewerId 审批人
 */
function reviewScanTask(taskId, decision, reviewerId) {
  const db = getDb();
  const task = db.prepare('SELECT * FROM scan_tasks WHERE id = ?').get(taskId);
  if (!task) return { error: '任务不存在' };
  if (task.status !== 'pending_approval') {
    return { error: `任务当前状态为 ${task.status}，无需审批` };
  }

  const taskInfo = activeTasks.get(taskId);
  if (decision === 'approve') {
    db.prepare("UPDATE scan_tasks SET status = 'running', approved_by = ?, approved_at = CURRENT_TIMESTAMP WHERE id = ?")
      .run(reviewerId, taskId);
    if (taskInfo) {
      getQueue().add('scan', { taskId, hosts: taskInfo.hosts, ports: taskInfo.ports }, { attempts: 1, backoff: 2000 });
    } else {
      return { error: '任务上下文已丢失，无法执行' };
    }
    logger.info(`[扫描安全] 任务 ${taskId} 已由用户 ${reviewerId} 审批通过，开始执行`);
    return { ok: true, status: 'running' };
  }

  db.prepare("UPDATE scan_tasks SET status = 'rejected', approved_by = ?, approved_at = CURRENT_TIMESTAMP WHERE id = ?")
    .run(reviewerId, taskId);
  activeTasks.delete(taskId);
  logger.warn(`[扫描安全] 任务 ${taskId} 已被用户 ${reviewerId} 拒绝`);
  return { ok: true, status: 'rejected' };
}

/**
 * 扫描任务处理器（由队列调度执行）
 */
async function executeScanJob(job) {
  const { taskId, hosts, ports } = job.data;
  const db = getDb();
  const taskInfo = activeTasks.get(taskId) || { hosts, ports, totalHosts: hosts.length, scannedHosts: 0 };

  try {
    const scanEngine = require('./scanEngine');
    const allResults = [];
    for (const host of hosts) {
      if (!activeTasks.has(taskId)) break; // 任务被取消

      const results = await scanEngine.scanHost(host, ports, {
        engine: config.scan.engine,
        timeout: config.scan.timeout,
        concurrency: config.scan.maxConcurrency,
        taskId,
        db
      });
      allResults.push(...results);
      taskInfo.scannedHosts++;
    }

    // 更新任务状态
    db.prepare(`
      UPDATE scan_tasks SET status = 'completed', completed_at = CURRENT_TIMESTAMP, progress = 100
      WHERE id = ?
    `).run(taskId);

    // 通过WebSocket推送扫描完成
    if (broadcastFn) {
      try {
        broadcastFn('scan_complete', { task_id: taskId, progress: 100, status: 'completed' });
      } catch (err) {
        logger.error('推送扫描完成通知失败:', err.message);
      }
    }

    activeTasks.delete(taskId);
    logger.info(`扫描任务 ${taskId} 完成，发现 ${allResults.length} 个开放端口`);
    return { open_ports: allResults.length };
  } catch (err) {
    db.prepare(`
      UPDATE scan_tasks SET status = 'failed', completed_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(taskId);

    // 通过WebSocket推送扫描失败
    if (broadcastFn) {
      try {
        broadcastFn('scan_failed', { task_id: taskId, status: 'failed' });
      } catch (e) {
        logger.error('推送扫描失败通知失败:', e.message);
      }
    }

    activeTasks.delete(taskId);
    logger.error(`扫描任务 ${taskId} 失败:`, err.message);
    throw err; // 交由队列记录失败/重试
  }
}

// 注册扫描任务处理器（幂等）
getQueue().process('scan', executeScanJob);

/**
 * 获取扫描任务列表（N-02：非管理员仅可见本组织任务）
 */
function getTasks(page, pageSize, status, tenant) {
  const db = getDb();
  const offset = (page - 1) * pageSize;

  // 内存 shim：全量 JOIN 后内存过滤（含组织隔离）
  const tasks = db.prepare(`
    SELECT t.*, u.username as created_by_name
    FROM scan_tasks t
    LEFT JOIN users u ON t.created_by = u.id
  `).all();

  const { inOrg } = require('../utils/tenantHelpers');
  let filtered = inOrg(tasks, tenant, 'created_by');
  if (status) filtered = filtered.filter((t) => t.status === status);
  filtered.sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));

  return { list: filtered.slice(offset, offset + pageSize), total: filtered.length, page, pageSize };
}

/**
 * 获取任务详情和结果（N-01：非管理员仅本人创建可访问）
 */
function getTaskDetail(taskId, tenant) {
  const db = getDb();

  const task = db.prepare(`
    SELECT t.*, u.username as created_by_name
    FROM scan_tasks t
    LEFT JOIN users u ON t.created_by = u.id
    WHERE t.id = ?
  `).get(taskId);

  if (!task) return null;
  if (!require('../utils/tenantHelpers').isOwner(tenant, task, 'created_by')) return null;

  const results = db.prepare('SELECT * FROM scan_results WHERE task_id = ? ORDER BY ip, port').all(taskId);

  // 统计信息
  const stats = {
    total_hosts: results.length > 0 ? new Set(results.map(r => r.ip)).size : 0,
    open_ports: results.length,
    services: {}
  };

  results.forEach(r => {
    if (r.service && r.service !== 'unknown') {
      stats.services[r.service] = (stats.services[r.service] || 0) + 1;
    }
  });

  return { ...task, results, stats };
}

/**
 * 删除任务（N-01：非管理员仅本人创建可删除）
 */
function deleteTask(taskId, tenant) {
  const db = getDb();
  const task = db.prepare('SELECT * FROM scan_tasks WHERE id = ?').get(taskId);
  if (!task) return { error: '任务不存在' };
  if (!require('../utils/tenantHelpers').isOwner(tenant, task, 'created_by')) {
    return { error: '无权删除他人创建的扫描任务' };
  }
  db.prepare('DELETE FROM scan_results WHERE task_id = ?').run(taskId);
  db.prepare('DELETE FROM scan_tasks WHERE id = ?').run(taskId);
  activeTasks.delete(taskId);
  return { ok: true };
}

module.exports = {
  startScan,
  reviewScanTask,
  getTasks,
  getTaskDetail,
  deleteTask,
  setBroadcastFn,
  scanHostConcurrent,
  executeScanJob,
  scanPort,
  identifyService
};
