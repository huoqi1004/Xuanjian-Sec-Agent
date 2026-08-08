const crypto = require('crypto');
const { getDb } = require('../db/database');
const { config } = require('../config');
const logger = require('../utils/logger');

// WebSocket连接管理
const wsConnections = new Map();

/**
 * 主机 Agent 支持的白名单指令
 * 与 agent/checks.js 的指令集保持一致；非白名单指令拒绝下发
 */
const ALLOWED_COMMANDS = new Set([
  'system_info',
  'baseline_check',
  'djpp_check',
  'port_scan',
  'file_hash',
  'list_checks'
]);

/**
 * 设备注册
 */
function registerDevice(device_id, device_type, ip) {
  const db = getDb();

  // 检查设备是否已注册
  const existing = db.prepare('SELECT * FROM edge_devices WHERE device_id = ?').get(device_id);

  const token = generateDeviceToken(device_id);

  if (existing) {
    // 更新token
    db.prepare(`
      UPDATE edge_devices SET token = ?, ip = ?, device_type = ?, online_status = 0
      WHERE device_id = ?
    `).run(token, ip || existing.ip, device_type || existing.device_type, device_id);

    return {
      device_id,
      token,
      ip: ip || existing.ip,
      device_type: device_type || existing.device_type,
      message: '设备已更新'
    };
  }

  // 新注册
  db.prepare(`
    INSERT INTO edge_devices (device_id, token, ip, device_type, online_status)
    VALUES (?, ?, ?, ?, 0)
  `).run(device_id, token, ip || '', device_type || 'gateway');

  return {
    device_id,
    token,
    ip: ip || '',
    device_type: device_type || 'gateway',
    message: '设备注册成功'
  };
}

/**
 * 生成设备Token
 */
function generateDeviceToken(device_id) {
  const secret = config.jwt.secret;
  return crypto.createHash('sha256')
    .update(`${device_id}-${Date.now()}-${secret}`)
    .digest('hex');
}

/**
 * 验证设备Token
 */
function verifyDeviceToken(device_id, token) {
  const db = getDb();
  const device = db.prepare('SELECT * FROM edge_devices WHERE device_id = ? AND token = ?').get(device_id, token);
  return !!device;
}

/**
 * 更新心跳
 */
function updateHeartbeat(device_id, metrics) {
  const db = getDb();

  db.prepare(`
    UPDATE edge_devices SET online_status = 1, last_heartbeat = CURRENT_TIMESTAMP, metrics = ?
    WHERE device_id = ?
  `).run(JSON.stringify(metrics || {}), device_id);
}

/**
 * 获取设备列表
 */
function getDevices(page, pageSize, online_status) {
  const db = getDb();
  const offset = (page - 1) * pageSize;

  let whereClause = '1=1';
  const params = [];

  if (online_status !== undefined && online_status !== '') {
    whereClause += ' AND online_status = ?';
    params.push(parseInt(online_status));
  }

  const total = db.prepare(`SELECT COUNT(*) as count FROM edge_devices WHERE ${whereClause}`).get(...params).count;
  const devices = db.prepare(`
    SELECT * FROM edge_devices
    WHERE ${whereClause}
    ORDER BY registered_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, pageSize, offset);

  return {
    list: devices.map(d => ({
      ...d,
      metrics: JSON.parse(d.metrics || '{}')
    })),
    total,
    page,
    pageSize
  };
}

/**
 * 获取设备状态
 */
function getDeviceStatus(device_id) {
  const db = getDb();
  const device = db.prepare('SELECT * FROM edge_devices WHERE device_id = ?').get(device_id);

  if (!device) return null;

  return {
    ...device,
    metrics: JSON.parse(device.metrics || '{}'),
    is_online: device.online_status === 1,
    heartbeat_age: device.last_heartbeat
      ? Math.round((Date.now() - new Date(device.last_heartbeat).getTime()) / 1000)
      : null
  };
}

/**
 * 下发指令
 */
function sendCommand(device_id, command, params) {
  const db = getDb();

  // 指令白名单校验（防止任意命令下发）
  if (!ALLOWED_COMMANDS.has(command)) {
    throw new Error(`指令不在白名单中: ${command}（允许: ${[...ALLOWED_COMMANDS].join(', ')}）`);
  }

  const device = db.prepare('SELECT * FROM edge_devices WHERE device_id = ?').get(device_id);
  if (!device) {
    throw new Error('设备不存在');
  }

  const commandId = db.prepare(`
    INSERT INTO device_commands (device_id, command, params, status)
    VALUES (?, ?, ?, 'pending')
  `).run(device_id, command, JSON.stringify(params || {}));

  // 如果设备在线，通过WebSocket发送指令
  const ws = wsConnections.get(device_id);
  if (ws && ws.readyState === 1) {
    ws.send(JSON.stringify({
      type: 'command',
      command_id: commandId.lastInsertRowid,
      command,
      params: params || {}
    }));
    logger.info(`指令已通过WebSocket下发到设备 ${device_id}: ${command}`);
  } else {
    logger.warn(`设备 ${device_id} 不在线，指令已入队等待`);
  }

  return {
    command_id: commandId.lastInsertRowid,
    device_id,
    command,
    status: 'pending'
  };
}

/**
 * 获取指令历史
 */
function getCommandHistory(device_id, page, pageSize) {
  const db = getDb();
  const offset = (page - 1) * pageSize;

  const total = db.prepare('SELECT COUNT(*) as count FROM device_commands WHERE device_id = ?').get(device_id).count;
  const commands = db.prepare(`
    SELECT * FROM device_commands
    WHERE device_id = ?
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).all(device_id, pageSize, offset);

  return { list: commands, total, page, pageSize };
}

/**
 * 处理设备WebSocket连接
 */
function handleDeviceConnection(ws, device_id, token) {
  if (!verifyDeviceToken(device_id, token)) {
    ws.close(4001, '认证失败');
    return;
  }

  // 标记设备在线
  updateHeartbeat(device_id, {});
  wsConnections.set(device_id, ws);
  logger.info(`设备 ${device_id} 已连接`);

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);

      switch (msg.type) {
        case 'heartbeat':
          updateHeartbeat(device_id, msg.metrics);
          ws.send(JSON.stringify({ type: 'heartbeat_ack', timestamp: Date.now() }));
          break;

        case 'command_result':
          handleCommandResult(device_id, msg);
          break;

        case 'metrics':
          updateHeartbeat(device_id, msg.metrics);
          break;

        case 'get_pending':
          flushPendingCommands(device_id, ws);
          break;

        default:
          logger.warn(`设备 ${device_id} 发送了未知消息类型: ${msg.type}`);
      }
    } catch (err) {
      logger.error(`处理设备 ${device_id} 消息失败:`, err.message);
    }
  });

  ws.on('close', () => {
    const db = getDb();
    db.prepare('UPDATE edge_devices SET online_status = 0 WHERE device_id = ?').run(device_id);
    wsConnections.delete(device_id);
    logger.info(`设备 ${device_id} 已断开连接`);
  });

  ws.on('error', (err) => {
    logger.error(`设备 ${device_id} WebSocket错误:`, err.message);
  });
}

/**
 * 处理指令执行结果
 */
function handleCommandResult(device_id, msg) {
  const db = getDb();

  db.prepare(`
    UPDATE device_commands SET status = ?, result = ?, executed_at = CURRENT_TIMESTAMP
    WHERE id = ? AND device_id = ?
  `).run(msg.status || 'executed', JSON.stringify(msg.result || {}), msg.command_id, device_id);

  logger.info(`设备 ${device_id} 指令 ${msg.command_id} 执行结果: ${msg.status}`);
}

/**
 * 将设备待执行（pending）指令下发到连接
 * 用于 Agent 断线重连后补发离线期间入队的指令
 */
function flushPendingCommands(device_id, ws) {
  const db = getDb();
  const pending = db.prepare(
    "SELECT * FROM device_commands WHERE device_id = ? AND status = 'pending' ORDER BY id ASC"
  ).all(device_id);

  if (pending.length > 0) {
    logger.info(`补发 ${device_id} 待执行指令 ${pending.length} 条`);
  }
  pending.forEach((cmd) => {
    if (ws && ws.readyState === 1) {
      ws.send(JSON.stringify({
        type: 'command',
        command_id: cmd.id,
        command: cmd.command,
        params: JSON.parse(cmd.params || '{}')
      }));
    }
  });
}

/**
 * 检查设备心跳超时
 */
function checkHeartbeats() {
  const db = getDb();
  const timeout = config.device.heartbeatTimeout;

  const offlineDevices = db.prepare(`
    UPDATE edge_devices SET online_status = 0
    WHERE online_status = 1 AND last_heartbeat < datetime('now', '-' || ? || ' seconds')
  `).run(timeout);

  if (offlineDevices.changes > 0) {
    logger.info(`${offlineDevices.changes} 个设备因心跳超时标记为离线`);
  }
}

/**
 * 获取WebSocket连接管理器
 */
function getWsConnections() {
  return wsConnections;
}

function unregisterDevice(deviceId) {
  const db = getDb();
  const device = db.prepare('SELECT * FROM edge_devices WHERE device_id = ?').get(deviceId);
  if (!device) return null;
  db.prepare('DELETE FROM edge_devices WHERE device_id = ?').run(deviceId);
  db.prepare('DELETE FROM device_commands WHERE device_id = ?').run(deviceId);
  return true;
}

module.exports = {
  registerDevice,
  verifyDeviceToken,
  updateHeartbeat,
  getDevices,
  getDeviceStatus,
  sendCommand,
  getCommandHistory,
  unregisterDevice,
  handleDeviceConnection,
  checkHeartbeats,
  getWsConnections
};
