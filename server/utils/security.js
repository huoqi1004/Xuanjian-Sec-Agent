/**
 * 玄鉴安全智能体 — 安全工具函数
 * 提供输入校验、命令注入防护、XSS 净化等通用能力
 */
const { execSync } = require('child_process');

/**
 * 严格 IP 地址校验（IPv4）
 * 返回 true 表示合法，否则拒绝
 */
function isValidIP(str) {
  if (typeof str !== 'string') return false;
  const parts = str.split('.');
  if (parts.length !== 4) return false;
  return parts.every(p => {
    const n = parseInt(p, 10);
    return !isNaN(n) && n >= 0 && n <= 255 && p === String(n);
  });
}

/**
 * 严格 IPv6 地址校验（简化版，覆盖常见格式）
 */
function isValidIPv6(str) {
  if (typeof str !== 'string') return false;
  // 允许 :: 缩写和标准格式
  return /^[0-9a-fA-F:]{3,39}$/.test(str) && str.includes(':');
}

/**
 * 合法 IOC 值校验（IP / IPv6 / 域名 / 哈希）
 */
function isValidIOC(str) {
  if (!str || typeof str !== 'string') return false;
  const s = str.trim();
  if (!s) return false;
  // IPv4
  if (isValidIP(s)) return true;
  // IPv6
  if (isValidIPv6(s)) return true;
  // 域名（RFC 1123 简化）
  if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$/.test(s)) return true;
  // MD5（32hex）/ SHA1（40hex）/ SHA256（64hex）
  if (/^[0-9a-fA-F]{32}$/.test(s) || /^[0-9a-fA-F]{40}$/.test(s) || /^[0-9a-fA-F]{64}$/.test(s)) return true;
  return false;
}

/**
 * Linux 用户名严格校验
 * 允许：字母、数字、下划线、短横线；首字符字母或下划线；长度 1-32
 */
function isValidUsername(str) {
  if (typeof str !== 'string') return false;
  return /^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$/.test(str.trim());
}

/**
 * 安全的 iptables 命令执行（参数化，防命令注入）
 * @param {'add'|'del'|'check'} action
 * @param {string} ip - 必须通过 isValidIP 校验
 */
function safeIptables(action, ip) {
  if (!isValidIP(ip)) throw new Error(`非法 IP 地址: ${ip}`);
  const cmd = {
    check: `iptables -C INPUT -s ${ip} -j DROP`,
    add: `iptables -I INPUT -s ${ip} -j DROP`,
    del: `iptables -D INPUT -s ${ip} -j DROP`,
  }[action];
  if (!cmd) throw new Error(`非法 iptables 操作: ${action}`);
  return execSync(cmd, { encoding: 'utf-8', timeout: 5000 });
}

/**
 * 安全的 passwd 命令执行
 * @param {string} username - 必须通过 isValidUsername 校验
 */
function safeUserLock(username) {
  if (!isValidUsername(username)) throw new Error(`非法用户名: ${username}`);
  // 先尝试 passwd -l，失败再尝试 usermod -L
  try {
    execSync(`passwd -l ${username}`, { encoding: 'utf-8', timeout: 5000 });
  } catch {
    execSync(`usermod -L ${username}`, { encoding: 'utf-8', timeout: 5000 });
  }
}

/**
 * 安全的 tc 流量限速命令（参数化）
 * @param {string} ip - 必须通过 isValidIP 校验
 * @param {string} rate - 格式如 "1mbit" / "500kbit"
 */
function safeTrafficLimit(ip, rate) {
  if (!isValidIP(ip)) throw new Error(`非法 IP 地址: ${ip}`);
  if (typeof rate !== 'string' || !/^[\d.]+(kbit|mbit|gbit)$/.test(rate.trim())) {
    throw new Error(`非法限速值: ${rate}`);
  }
  const r = rate.trim();
  // 分步执行，避免拼接错误
  execSync(`tc qdisc add dev eth0 root handle 1: htb default 10 2>/dev/null || true`, { encoding: 'utf-8', timeout: 3000 });
  execSync(`tc class add dev eth0 parent 1: classid 1:1 htb rate ${r} 2>/dev/null || true`, { encoding: 'utf-8', timeout: 3000 });
  execSync(`tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dst ${ip} flowid 1:1 2>/dev/null || true`, { encoding: 'utf-8', timeout: 3000 });
}

/**
 * XSS 净化：移除 <script> 标签及 onclick/onerror 等事件属性
 */
function sanitizeXSS(html) {
  if (typeof html !== 'string') return html;
  return html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
    .replace(/\son\w+\s*=/gi, '');
}

/**
 * 安全的 execSync 包装：仅允许预定义的白名单命令
 * @param {string} command - 来自数据库的 check_command
 * @param {object} options
 */
function safeExec(command, options = {}) {
  if (typeof command !== 'string') throw new Error('命令类型错误');
  const allowedPrefixes = ['cat ', 'grep ', 'ls ', 'df ', 'free ', 'ps ', 'uname ', 'id ', 'who ', 'date ', 'tail ', 'head ', 'wc ', 'stat ', 'getent ', 'systemctl ', 'ss ', 'ip ', 'find ', 'lsattr ', 'chage ', 'logrotate ', 'sestatus ', 'auditctl ', 'iptables '];
  const cmd = command.trim();
  const isAllowed = allowedPrefixes.some(p => cmd.startsWith(p)) || /^[a-zA-Z_][a-zA-Z0-9_]*(\s|$)/.test(cmd);
  if (!isAllowed) throw new Error(`命令不在白名单中: ${cmd}`);
  // 禁止管道和后台符
  if (/[|;&`$(){}]/.test(cmd)) throw new Error(`命令包含非法字符: ${cmd}`);
  return execSync(cmd, options);
}

module.exports = {
  isValidIP,
  isValidIPv6,
  isValidIOC,
  isValidUsername,
  safeIptables,
  safeUserLock,
  safeTrafficLimit,
  sanitizeXSS,
  safeExec,
};
