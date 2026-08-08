/*
系统信息采集模块（跨平台 Windows / Linux / macOS）
使用 os 模块 + 系统命令（子进程，命令均为固定白名单，无用户输入拼接）
*/

const os = require('os');
const { execSync } = require('child_process');

const isWindows = process.platform === 'win32';
const isMac = process.platform === 'darwin';

/** 安全执行系统命令，失败返回 null */
function safeExec(cmd) {
  try {
    return execSync(cmd, { encoding: 'utf-8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch (e) {
    return null;
  }
}

/** CPU 使用率（0-100），Windows 用 wmic，Linux/macOS 用 /proc/stat 采样 */
function getCpuUsage() {
  try {
    if (isWindows) {
      const out = safeExec('wmic cpu get loadpercentage /value');
      const m = out && out.match(/LoadPercentage=(\d+)/);
      return m ? parseFloat(m[1]) : 0;
    }
    if (isMac) {
      return safeExec("ps -A -o %cpu | awk '{s+=$1} END {print s/NR}'") || 0;
    }
    // Linux: 读取 /proc/stat 两次采样
    const readStat = () => {
      const line = require('fs').readFileSync('/proc/stat', 'utf-8').split('\n')[0];
      const parts = line.split(/\s+/).slice(1).map(Number);
      const idle = parts[3] + (parts[4] || 0);
      const total = parts.reduce((a, b) => a + b, 0);
      return { idle, total };
    };
    const t1 = readStat();
    return new Promise((resolve) => {
      setTimeout(() => {
        const t2 = readStat();
        const idleDelta = t2.idle - t1.idle;
        const totalDelta = t2.total - t1.total;
        resolve(totalDelta > 0 ? Math.round(((totalDelta - idleDelta) / totalDelta) * 100) : 0);
      }, 300);
    });
  } catch (e) {
    return 0;
  }
}

/** 磁盘信息（总数/可用 GB） */
function getDiskInfo() {
  try {
    if (isWindows) {
      const out = safeExec('wmic logicaldisk get size,freespace /format:list') || '';
      let total = 0, free = 0;
      const sizeMatches = [...out.matchAll(/Size=(\d+)/g)];
      const freeMatches = [...out.matchAll(/FreeSpace=(\d+)/g)];
      sizeMatches.forEach((m) => (total += parseInt(m[1]) || 0));
      freeMatches.forEach((m) => (free += parseInt(m[1]) || 0));
      return { total_gb: +(total / 1024 ** 3).toFixed(1), free_gb: +(free / 1024 ** 3).toFixed(1) };
    }
    const out = safeExec('df -k -P /') || '';
    const line = out.split('\n')[1];
    if (line) {
      const parts = line.trim().split(/\s+/);
      return { total_gb: +(parseInt(parts[1]) / 1024 ** 2).toFixed(1), free_gb: +(parseInt(parts[3]) / 1024 ** 2).toFixed(1) };
    }
    return { total_gb: 0, free_gb: 0 };
  } catch (e) {
    return { total_gb: 0, free_gb: 0 };
  }
}

/** 进程数 */
function getProcessCount() {
  try {
    if (isWindows) {
      const out = safeExec('tasklist /FO CSV /NH');
      return out ? out.split('\n').filter(Boolean).length : 0;
    }
    const out = safeExec('ps -e --no-headers | wc -l');
    return out ? parseInt(out) || 0 : 0;
  } catch (e) {
    return 0;
  }
}

/** 开放 TCP 监听端口列表 */
function getOpenPorts() {
  try {
    if (isWindows) {
      const out = safeExec('netstat -an') || '';
      const ports = new Set();
      for (const line of out.split('\n')) {
        const m = line.match(/TCP\s+\d+\.\d+\.\d+\.\d+:(\d+)\s+.*LISTENING/i);
        if (m) ports.add(parseInt(m[1]));
      }
      return [...ports].sort((a, b) => a - b).slice(0, 100);
    }
    const out = safeExec('ss -tuln 2>/dev/null || netstat -tuln') || '';
    const ports = new Set();
    for (const line of out.split('\n')) {
      const m = line.match(/:(\d+)\s/);
      if (m && (line.includes('LISTEN') || line.includes('0.0.0.0') || line.includes('::'))) ports.add(parseInt(m[1]));
    }
    return [...ports].sort((a, b) => a - b).slice(0, 100);
  } catch (e) {
    return [];
  }
}

/**
 * 采集完整系统信息（同步部分立即返回，CPU 使用率异步）
 * @returns {Promise<Object>}
 */
async function collectSystemInfo() {
  const base = {
    hostname: os.hostname(),
    platform: process.platform,
    arch: os.arch(),
    os_release: os.release(),
    uptime_sec: Math.round(os.uptime()),
    cpu_model: os.cpus()[0]?.model || '',
    cpu_count: os.cpus().length,
    cpu_usage: await getCpuUsage(),
    memory_total_gb: +(os.totalmem() / 1024 ** 3).toFixed(1),
    memory_free_gb: +(os.freemem() / 1024 ** 3).toFixed(1),
    memory_usage_pct: Math.round((1 - os.freemem() / os.totalmem()) * 100),
    disk: getDiskInfo(),
    process_count: getProcessCount(),
    open_ports: getOpenPorts(),
    node_version: process.version,
    collected_at: new Date().toISOString()
  };
  return base;
}

module.exports = { collectSystemInfo, getOpenPorts };
