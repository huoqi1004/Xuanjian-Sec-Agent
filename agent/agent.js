/*
玄鉴安全智能体 - 轻量主机 Agent（Node.js，跨平台）
功能:
  1. 连接平台 WebSocket 设备通道（/ws/device）并保持心跳
  2. 周期上报系统信息（CPU/内存/磁盘/进程/开放端口）
  3. 接收白名单指令: system_info / baseline_check / djpp_check / port_scan / file_hash
  4. 指令执行结果回传平台（command_result）
安全: 基线/等保检查仅允许执行 checks.js 内置白名单命令；断线自动重连。
*/

require('dotenv').config();
const WebSocket = require('ws');
const os = require('os');
const crypto = require('crypto');
const fs = require('fs');

const { collectSystemInfo, getOpenPorts } = require('./systemInfo');
const { executeCheck, listChecks } = require('./checks');

const SERVER_URL = process.env.SERVER_URL || 'ws://localhost:3000/ws/device';
const DEVICE_ID = process.env.DEVICE_ID || '';
const DEVICE_TOKEN = process.env.DEVICE_TOKEN || '';
const HEARTBEAT_INTERVAL = parseInt(process.env.HEARTBEAT_INTERVAL) || 30;
const SCAN_TIMEOUT = parseInt(process.env.SCAN_TIMEOUT) || 3000;
const RETRY_DELAY = 5000;

if (!DEVICE_ID || !DEVICE_TOKEN) {
  console.error('[agent] 缺少 DEVICE_ID 或 DEVICE_TOKEN，请检查 .env 配置');
  process.exit(1);
}

let ws = null;
let heartbeatTimer = null;
let reconnectTimer = null;
let shouldReconnect = true;

/** TCP Connect 端口扫描（纯 Node，跨平台） */
function tcpScan(target, ports) {
  const net = require('net');
  const list = [];
  const all = ports.map((port) => new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      if (open) list.push(port);
      socket.destroy();
      resolve();
    };
    socket.setTimeout(SCAN_TIMEOUT);
    socket.on('connect', () => finish(true));
    socket.on('timeout', () => finish(false));
    socket.on('error', () => finish(false));
    socket.connect(port, target);
  }));
  return Promise.all(all).then(() => list);
}

function parsePortRange(range) {
  const ports = [];
  for (const part of String(range || '1-1024').split(',')) {
    const m = part.trim().match(/^(\d+)(?:-(\d+))?$/);
    if (!m) continue;
    const start = parseInt(m[1]);
    const end = m[2] ? parseInt(m[2]) : start;
    for (let p = start; p <= Math.min(end, 65535); p++) ports.push(p);
  }
  return ports;
}

/** 处理服务端下发的指令（白名单） */
async function handleCommand(msg) {
  const { command_id, command, params = {} } = msg;
  const result = { status: 'executed', result: {}, command_id, command };

  try {
    switch (command) {
      case 'system_info': {
        result.result = await collectSystemInfo();
        break;
      }
      case 'baseline_check':
      case 'djpp_check': {
        const checkId = params.check_id;
        if (!checkId) throw new Error('缺少 check_id 参数');
        const checkResult = executeCheck(checkId);
        if (!checkResult) throw new Error(`检查项不在白名单: ${checkId}`);
        result.result = checkResult;
        break;
      }
      case 'port_scan': {
        const target = params.target;
        if (!target) throw new Error('缺少 target 参数');
        const ports = parsePortRange(params.ports || '1-1024');
        const open = await tcpScan(target, ports);
        result.result = { target, scanned: ports.length, open, open_count: open.length };
        break;
      }
      case 'file_hash': {
        const filePath = params.path;
        if (!filePath) throw new Error('缺少 path 参数');
        if (!fs.existsSync(filePath)) throw new Error(`文件不存在: ${filePath}`);
        const data = fs.readFileSync(filePath);
        result.result = {
          path: filePath,
          size: data.length,
          md5: crypto.createHash('md5').update(data).digest('hex'),
          sha256: crypto.createHash('sha256').update(data).digest('hex')
        };
        break;
      }
      case 'list_checks': {
        result.result = { checks: listChecks() };
        break;
      }
      default:
        throw new Error(`未知指令: ${command}`);
    }
  } catch (e) {
    result.status = 'error';
    result.result = { error: e.message };
  }

  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'command_result', ...result }));
  }
}

/** 连接后拉取待执行指令（离线期间入队的指令） */
function requestPendingCommands() {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'get_pending' }));
  }
}

function connect() {
  if (ws) {
    try { ws.terminate(); } catch (e) { /* ignore */ }
  }

  const url = `${SERVER_URL}${SERVER_URL.includes('?') ? '&' : '?'}device_id=${encodeURIComponent(DEVICE_ID)}&token=${encodeURIComponent(DEVICE_TOKEN)}`;
  console.log(`[agent] 连接平台: ${SERVER_URL} (${DEVICE_ID})`);
  ws = new WebSocket(url);

  ws.on('open', async () => {
    console.log('[agent] 已连接，开始上报系统信息');
    try {
      const info = await collectSystemInfo();
      ws.send(JSON.stringify({ type: 'metrics', metrics: info }));
      ws.send(JSON.stringify({ type: 'command_result', status: 'executed', command: 'system_info', result: info }));
    } catch (e) {
      console.error('[agent] 系统信息采集失败:', e.message);
    }
    requestPendingCommands();
    startHeartbeat();
  });

  ws.on('message', async (data) => {
    let msg;
    try {
      msg = JSON.parse(data);
    } catch (e) {
      return;
    }
    if (msg.type === 'command') {
      console.log(`[agent] 收到指令: ${msg.command} (id=${msg.command_id})`);
      await handleCommand(msg);
    } else if (msg.type === 'heartbeat_ack') {
      // 服务端心跳确认
    } else if (msg.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong' }));
    }
  });

  ws.on('close', () => {
    console.log('[agent] 连接断开');
    stopHeartbeat();
    scheduleReconnect();
  });

  ws.on('error', (err) => {
    console.error('[agent] WebSocket错误:', err.message);
  });
}

function startHeartbeat() {
  stopHeartbeat();
  heartbeatTimer = setInterval(async () => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try {
      const info = await collectSystemInfo();
      ws.send(JSON.stringify({ type: 'heartbeat', metrics: info, timestamp: Date.now() }));
    } catch (e) {
      console.error('[agent] 心跳上报失败:', e.message);
    }
  }, HEARTBEAT_INTERVAL * 1000);
}

function stopHeartbeat() {
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}

function scheduleReconnect() {
  if (!shouldReconnect || reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, RETRY_DELAY);
}

process.on('SIGINT', () => {
  shouldReconnect = false;
  console.log('[agent] 正在退出...');
  if (ws) ws.close();
  process.exit(0);
});

connect();
