/**
 * 扫描引擎适配器
 * 支持引擎: nmap（快速批量）/ masscan（预留）/ node（内置 TCP Connect，兜底）
 * 策略: 按配置引擎优先，工具不可用时自动回退 Node 引擎（不中断现有功能）
 */

const { spawnSync } = require('child_process');
const logger = require('../utils/logger');

let toolCache = null;

/** 探测系统可用扫描工具（结果缓存） */
function detectTools() {
  if (toolCache) return toolCache;
  const tools = { nmap: null, masscan: null };

  try {
    const r = spawnSync('nmap', ['--version'], { encoding: 'utf-8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
    if (r.status === 0 && r.stdout) {
      tools.nmap = (r.stdout.match(/Nmap version (\S+)/i) || [])[1] || 'unknown';
      logger.info(`[扫描引擎] 检测到 nmap ${tools.nmap}`);
    }
  } catch (e) { /* 未安装 */ }

  try {
    const r = spawnSync('masscan', ['--version'], { encoding: 'utf-8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
    if (r.status === 0) {
      tools.masscan = (r.stdout.match(/Masscan version (\S+)/i) || [])[1] || 'unknown';
      logger.info(`[扫描引擎] 检测到 masscan ${tools.masscan}`);
    }
  } catch (e) { /* 未安装 */ }

  toolCache = tools;
  return tools;
}

/** 解析实际使用的引擎：auto -> 优先 nmap，否则 node */
function resolveEngine(preferred) {
  const tools = detectTools();
  if (preferred === 'nmap' && tools.nmap) return 'nmap';
  if (preferred === 'masscan' && tools.masscan) return 'masscan';
  if (tools.nmap) return 'nmap';
  return 'node';
}

/** 解析 nmap 文本输出中的开放端口与服务 */
function parseNmapOutput(stdout, host) {
  const results = [];
  const lines = stdout.split('\n');
  let inPortSection = false;

  for (const line of lines) {
    const sectionMatch = line.match(/^PORT\s+STATE\s+SERVICE/i);
    if (sectionMatch) {
      inPortSection = true;
      continue;
    }
    if (inPortSection) {
      const portMatch = line.match(/^(\d+)\/tcp\s+(\w+)\s+(\S+)/);
      if (portMatch) {
        const [, port, state, service] = portMatch;
        if (state === 'open') {
          results.push({
            task_id: null, ip: host, port: parseInt(port),
            service: service || 'unknown', version: '', banner: '', state: 'open'
          });
        }
      } else if (line.trim() === '') {
        inPortSection = false;
      }
    }
  }
  return results;
}

/** 使用 nmap 批量扫描主机 */
function nmapScan(host, ports, taskId, db) {
  const portList = ports.join(',');
  // -sS SYN半开扫描; -Pn 跳过主机发现; -n 不做DNS解析; --open 只显示开放端口
  const args = ['-sS', '-Pn', '-n', '--open', '-T4', '--host-timeout', '10m', '-p', portList, host];
  logger.info(`[扫描引擎] nmap 扫描 ${host} (${ports.length} 个端口)`);

  const result = spawnSync('nmap', args, {
    encoding: 'utf-8',
    timeout: 300000,
    maxBuffer: 50 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'ignore']
  });

  if (result.status !== 0 && !result.stdout) {
    throw new Error(`nmap 执行失败 (exit=${result.status})`);
  }

  const results = parseNmapOutput(result.stdout || '', host);
  const insertStmt = db.prepare(
    'INSERT INTO scan_results (task_id, ip, port, service, version, banner, state) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );
  for (const r of results) {
    try {
      insertStmt.run(taskId, r.ip, r.port, r.service, r.version, r.banner, r.state);
    } catch (err) {
      logger.error('写入扫描结果失败:', err.message);
    }
  }
  logger.info(`[扫描引擎] nmap 完成 ${host}: 发现 ${results.length} 个开放端口`);
  return results;
}

/**
 * 统一扫描入口
 * @param {string} host - 目标主机
 * @param {number[]} ports - 端口列表
 * @param {Object} opts - { engine, timeout, concurrency, taskId, db }
 * @returns {Array} 扫描结果（含 service/version/banner/state）
 */
async function scanHost(host, ports, opts = {}) {
  const engine = resolveEngine(opts.engine || 'auto');

  if (engine === 'nmap') {
    return nmapScan(host, ports, opts.taskId, opts.db);
  }
  if (engine === 'masscan') {
    logger.warn('[扫描引擎] masscan 适配器待接入，回退 Node 引擎');
  }

  // 回退: Node TCP Connect（延迟加载避免循环依赖）
  const scanService = require('./scanService');
  return scanService.scanHostConcurrent(
    host, ports, opts.concurrency, opts.timeout, opts.taskId, opts.db
  );
}

module.exports = { scanHost, detectTools, resolveEngine, parseNmapOutput };
