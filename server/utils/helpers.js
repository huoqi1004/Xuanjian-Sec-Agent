const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

/**
 * 统一API响应格式
 */
function success(res, data = null, message = '操作成功') {
  return res.json({ code: 0, message, data });
}

function fail(res, message = '操作失败', code = 1, statusCode = 400) {
  return res.status(statusCode).json({ code, message, data: null });
}

function unauthorized(res, message = '未授权访问') {
  return res.status(401).json({ code: 1, message, data: null });
}

function forbidden(res, message = '权限不足') {
  return res.status(403).json({ code: 1, message, data: null });
}

function serverError(res, message = '服务器内部错误') {
  return res.status(500).json({ code: 1, message, data: null });
}

/**
 * 异步包装器
 */
function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * 计算文件MD5
 */
function calculateMD5(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('md5');
    const fs = require('fs');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

/**
 * 计算文件SHA256
 */
function calculateSHA256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const fs = require('fs');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

/**
 * 生成UUID
 */
function generateId() {
  return uuidv4();
}

/**
 * 解析CIDR地址段
 */
function parseCIDR(cidr) {
  const [ip, bits] = cidr.split('/');
  const mask = parseInt(bits) || 32;

  // /32（或单 IP 无掩码）直接返回该地址
  if (mask >= 32) return [ip];

  const ipParts = ip.split('.').map(Number);
  const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];

  const maskNum = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
  const networkNum = (ipNum & maskNum) >>> 0;
  const broadcastNum = (networkNum | (~maskNum >>> 0)) >>> 0;

  const hosts = [];
  const start = networkNum + 1;
  // 排除广播地址（仅当存在广播地址时）
  const end = broadcastNum > networkNum ? broadcastNum - 1 : broadcastNum;

  // 限制最大主机数量防止内存溢出
  const maxHosts = 65536;
  const actualEnd = Math.min(end, start + maxHosts - 1);

  for (let i = start; i <= actualEnd; i++) {
    hosts.push(
      `${(i >>> 24) & 255}.${(i >>> 16) & 255}.${(i >>> 8) & 255}.${i & 255}`
    );
  }

  return hosts;
}

/**
 * IPv4 字符串转 32 位整数
 */
function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
  return ((parts[0] & 255) << 24) | ((parts[1] & 255) << 16) | ((parts[2] & 255) << 8) | (parts[3] & 255);
}

/**
 * 判断 IP 是否属于某个 CIDR 网段（N-04 扫描白名单）
 */
function isIpInCidr(ip, cidr) {
  const [cidrIp, bits] = String(cidr).split('/');
  const mask = parseInt(bits);
  if (!mask || Number.isNaN(mask)) return String(ip) === String(cidrIp);
  const maskNum = (~0 << (32 - mask)) >>> 0;
  const ipNum = ipToInt(ip);
  const networkNum = ipToInt(cidrIp) & maskNum;
  return (ipNum & maskNum) === networkNum;
}

/**
 * 检查主机列表是否全部位于允许网段内（N-04 扫描安全管控）
 * @param {string[]} hosts 目标主机列表
 * @param {string[]} allowedCidrs 允许的 CIDR 列表
 * @returns {{ok: boolean, outside: string}} outside 返回首个白名单外地址
 */
function checkHostsInCidrs(hosts, allowedCidrs) {
  const cidrs = (allowedCidrs || []).filter(Boolean);
  for (const host of hosts) {
    const allowed = cidrs.some((cidr) => isIpInCidr(host, cidr));
    if (!allowed) return { ok: false, outside: host };
  }
  return { ok: true, outside: null };
}

/**
 * 解析端口范围
 */
function parsePortRange(range) {
  const ports = [];
  const parts = range.split(',');

  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.includes('-')) {
      const [start, end] = trimmed.split('-').map(Number);
      if (start && end && start <= end) {
        for (let p = start; p <= end; p++) {
          ports.push(p);
        }
      }
    } else {
      const port = parseInt(trimmed);
      if (port > 0 && port <= 65535) {
        ports.push(port);
      }
    }
  }

  return [...new Set(ports)].sort((a, b) => a - b);
}

/**
 * 格式化文件大小
 */
function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * 延迟函数
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * 获取客户端IP
 */
function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.ip ||
    'unknown';
}

module.exports = {
  success, fail, unauthorized, forbidden, serverError,
  asyncHandler,
  calculateMD5, calculateSHA256,
  generateId,
  parseCIDR, parsePortRange,
  ipToInt, isIpInCidr, checkHostsInCidrs,
  formatFileSize,
  sleep,
  getClientIp
};
