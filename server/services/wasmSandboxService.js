/**
 * Phase 4.4: WebAssembly 沙箱分析框架
 * 功能：
 * 1. 提供 WASM 沙箱分析接口（当前为 Python 降级方案）
 * 2. 预存 WASM 字节码加载器（待部署 WASM 文件后启用）
 * 3. 记录分析结果到 wasm_sandbox_logs 表
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const logger = require('../utils/logger');
const { getDb } = require('../db/database');
const metrics = require('../utils/metrics');

const WASM_MODULE_PATH = path.join(__dirname, '../assets', 'sandbox.wasm');
const SOFT_ANALYZER_PATH = path.join(__dirname, '../assets', 'wasm', 'analyzer.js');

let wasmInstance = null;
let softAnalyzer = null;
let analysisMode = 'none'; // 'native' | 'soft' | 'heuristic'

/**
 * 计算文件哈希
 */
function hashFile(filePath) {
  const t0 = performance.now();
  try {
    const data = fs.readFileSync(filePath);
    const tHash = performance.now();
    const md5 = crypto.createHash('md5').update(data).digest('hex');
    const sha1 = crypto.createHash('sha1').update(data).digest('hex');
    const sha256 = crypto.createHash('sha256').update(data).digest('hex');
    const elapsed = (performance.now() - t0).toFixed(2);
    logger.debug(`[WasmSandbox] hashFile: size=${data.length}B, elapsed=${elapsed}ms (read=${(tHash - t0).toFixed(2)}ms, hash=${(performance.now() - tHash).toFixed(2)}ms)`);
    return { md5, sha1, sha256 };
  } catch (e) {
    logger.warn(`[WasmSandbox] hashFile 失败: ${e.message}`);
    return null;
  }
}

/**
 * 初始化分析器（启动时调用，缓存 wasmInstance 和 softAnalyzer）
 */
async function initAnalysisMode() {
  // 1. 尝试加载原生 WASM
  if (fs.existsSync(WASM_MODULE_PATH)) {
    try {
      const wasmBuffer = fs.readFileSync(WASM_MODULE_PATH);
      wasmInstance = await WebAssembly.compile(wasmBuffer);
      analysisMode = 'native';
      logger.info(`[WasmSandbox] 原生 WASM 加载成功: size=${wasmBuffer.length}B`);
      metrics.inc('wasm_module_loaded', 1);
      return;
    } catch (e) {
      logger.warn(`[WasmSandbox] 原生 WASM 加载失败: ${e.message}，降级到软 WASM`);
    }
  }

  // 2. 尝试加载 JS 软 WASM
  if (fs.existsSync(SOFT_ANALYZER_PATH)) {
    try {
      softAnalyzer = require(SOFT_ANALYZER_PATH);
      analysisMode = 'soft';
      logger.info('[WasmSandbox] JS 软 WASM 加载成功（server/assets/wasm/analyzer.js）');
      metrics.inc('wasm_soft_loaded', 1);
      return;
    } catch (e) {
      logger.warn(`[WasmSandbox] 软 WASM 加载失败: ${e.message}，使用启发式分析`);
    }
  }

  // 3. 最终降级：启发式分析
  analysisMode = 'heuristic';
  logger.info('[WasmSandbox] 无可用分析器，使用纯启发式分析');
  metrics.inc('wasm_heuristic_fallback', 1);
}

// 启动时初始化
initAnalysisMode().catch(e => logger.error(`[WasmSandbox] 初始化失败: ${e.message}`));

/**
 * 尝试加载原生 WASM 模块（已废弃，由 initAnalysisMode 统一管理）
 * @deprecated 请使用 initAnalysisMode()
 */
async function loadWasmModule() {
  await initAnalysisMode();
  if (analysisMode === 'native') return wasmInstance;
  return null;
}

/**
 * 启发式本地分析（WASM 不可用时的降级方案）
 * 分析 PE 特征、可疑 API、熵值等
 * @param {string} filePath - 文件路径
 * @param {Object} hashes - 文件哈希（可选，避免重复计算）
 * @param {Buffer|null} fileData - 已读取的文件数据（由 scanFile 传入，避免重复读文件）
 */
function heuristicAnalysis(filePath, hashes, fileData = null) {
  const startTime = Date.now();
  const t0 = performance.now();
  try {
    const tRead = performance.now();
    const data = fileData || fs.readFileSync(filePath);
    const fileSize = data.length;
    const tReadDone = performance.now();
    logger.debug(`[WasmSandbox] heuristicAnalysis: 文件读取 ${fileSize}B, read_time=${(tReadDone - tRead).toFixed(2)}ms`);

    // 计算熵值（逐字节统计频次）
    const tEntropy = performance.now();
    const freq = new Map();
    for (const byte of data) freq.set(byte, (freq.get(byte) || 0) + 1);
    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / fileSize;
      entropy -= p * Math.log2(p);
    }
    logger.debug(`[WasmSandbox] 熵值计算: entropy=${entropy.toFixed(4)}, unique_bytes=${freq.size}, elapsed=${(performance.now() - tEntropy).toFixed(2)}ms`);

    let score = 0;
    const behaviors = [];

    // PE 可执行文件特征
    const tPE = performance.now();
    if (data.length >= 2 && data[0] === 0x4d && data[1] === 0x5a) {
      score += 0.2;
      behaviors.push('PE_MZ_header');
      logger.debug(`[WasmSandbox] 检测到 PE MZ header，score+=0.2`);

      // 提取文本段中的可疑 API（仅扫描前 64KB）
      const tAPI = performance.now();
      const text = data.toString('utf8', 0, Math.min(65536, fileSize));
      const suspiciousApis = [
        'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread',
        'NtUnmapViewOfSection', 'SetWindowsHookEx', 'GetAsyncKeyState',
        'URLDownloadToFile', 'InternetOpen', 'WinExec', 'system(',
        'powershell', '-enc', '-encodedcommand', 'cmd.exe', '/c'
      ];
      let apiMatchCount = 0;
      for (const api of suspiciousApis) {
        if (text.includes(api)) {
          score += 0.12;
          behaviors.push(`suspicious_api:${api}`);
          apiMatchCount++;
        }
      }
      logger.debug(`[WasmSandbox] PE API扫描: text_len=${text.length}B, matched=${apiMatchCount}/${suspiciousApis.length}, elapsed=${(performance.now() - tAPI).toFixed(2)}ms`);
    }
    logger.debug(`[WasmSandbox] PE特征检查 elapsed=${(performance.now() - tPE).toFixed(2)}ms`);

    // 熵值异常
    if (entropy > 7.8) {
      score += 0.3;
      behaviors.push(`high_entropy:${entropy.toFixed(2)}`);
      logger.debug(`[WasmSandbox] 高熵异常: entropy=${entropy.toFixed(2)} > 7.8, score+=0.3`);
    } else if (entropy > 7.0) {
      score += 0.15;
      behaviors.push(`elevated_entropy:${entropy.toFixed(2)}`);
      logger.debug(`[WasmSandbox] 熵值偏高: entropy=${entropy.toFixed(2)} > 7.0, score+=0.15`);
    }

    // 恶意字符串检测
    const tMalware = performance.now();
    const malwareStrings = ['eval(', 'exec(', 'base64', 'wscript', 'cscript', 'mshta', 'regsvr32', 'certutil'];
    let malwareMatchCount = 0;
    for (const s of malwareStrings) {
      if (data.includes(s)) {
        score += 0.15;
        behaviors.push(`malware_string:${s}`);
        malwareMatchCount++;
      }
    }
    logger.debug(`[WasmSandbox] 恶意字符串扫描: matched=${malwareMatchCount}/${malwareStrings.length}, elapsed=${(performance.now() - tMalware).toFixed(2)}ms`);

    // Shellcode 特征（连续 NOP sled 检测）
    const tNOP = performance.now();
    let nopCount = 0;
    let maxConsecutive = 0;
    for (const byte of data) {
      if (byte === 0x90) {
        nopCount++;
        maxConsecutive = Math.max(maxConsecutive, nopCount);
      } else {
        nopCount = 0;
      }
    }
    if (maxConsecutive >= 16) {
      score += 0.25;
      behaviors.push(`nop_sled:${maxConsecutive}`);
      logger.debug(`[WasmSandbox] 检测到 NOP sled: length=${maxConsecutive}, score+=0.25`);
    }
    logger.debug(`[WasmSandbox] NOP sled扫描: max_consecutive=${maxConsecutive}, elapsed=${(performance.now() - tNOP).toFixed(2)}ms`);

    const verdict = score >= 0.5 ? 'malicious' : (score >= 0.25 ? 'suspicious' : 'clean');
    const confidence = Math.min(score, 1.0);
    const analysisTime = Date.now() - startTime;

    logger.debug(
      `[WasmSandbox] heuristicAnalysis 完成: score=${score.toFixed(2)} → verdict=${verdict}, confidence=${confidence.toFixed(2)}, behaviors=[${behaviors.join(', ')}]`
    );
    logger.info(
      `[WasmSandbox] 启发式分析: verdict=${verdict} | confidence=${confidence.toFixed(2)} | entropy=${entropy.toFixed(2)} | behaviors=${behaviors.length} | total_time=${analysisTime}ms (file_read=${(tReadDone - t0).toFixed(2)}ms)`
    );
    return { verdict, confidence, behaviors: behaviors.join('; ') || 'no_suspicious_indicators', analysisTime };
  } catch (e) {
    const analysisTime = Date.now() - startTime;
    logger.error(`[WasmSandbox] heuristicAnalysis 异常: ${e.message} (elapsed=${analysisTime}ms)`);
    return { verdict: 'error', confidence: 0, behaviors: e.message, analysisTime };
  }
}

/**
 * WASM 沙箱分析入口
 * 优先尝试 WASM 分析，失败时降级为启发式分析
 */
async function analyzeWithWasmSandbox(filePath) {
  const startTime = Date.now();
  const t0 = performance.now();

  logger.info(`[WasmSandbox] 开始分析: filePath=${filePath}`);

  // 文件哈希计算
  const hashes = hashFile(filePath);
  if (!hashes) {
    logger.warn(`[WasmSandbox] 文件哈希计算失败，跳过分析`);
    return { error: '无法读取文件', verdict: 'unknown', confidence: 0 };
  }
  logger.debug(`[WasmSandbox] 文件哈希: sha256=${hashes.sha256.substring(0, 16)}..., file_size=${fs.statSync(filePath).size}B`);

  // 尝试加载 WASM 模块
  const wasmModule = await loadWasmModule();
  let result;
  const tAfterWasm = performance.now();

  if (wasmModule) {
    // WASM 原生分析功能暂未实现，继续使用启发式降级方案
    // TODO: 部署 WASM 字节码分析模块后启用原生路径
    logger.info('[WasmSandbox] WASM 模块已加载，原生分析功能待部署');
  } else {
    logger.debug(`[WasmSandbox] WASM 模块不可用，总加载耗时=${(tAfterWasm - t0).toFixed(2)}ms`);
  }

  // 启发式分析（降级方案）
  const tHeurStart = performance.now();
  result = heuristicAnalysis(filePath, hashes);
  const tHeurEnd = performance.now();
  result.engine = 'wasm_heuristic';
  result.fallback_reason = wasmModule ? 'wasm_unimplemented' : 'wasm_module_not_found';
  result.analysisTime = Date.now() - startTime;
  logger.info(`[WasmSandbox] 启发式分析耗时: ${(tHeurEnd - tHeurStart).toFixed(2)}ms`);

  // 持久化到数据库
  const tDB = performance.now();
  try {
    const db = getDb();
    const insertStart = performance.now();
    db.prepare(
      `INSERT INTO wasm_sandbox_logs (file_hash, file_name, file_size, verdict, confidence, behaviors, sandbox_engine, fallback_reason, analysis_time_ms, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
    ).run(
      hashes.sha256,
      path.basename(filePath),
      fs.statSync(filePath).size,
      result.verdict,
      result.confidence,
      result.behaviors,
      'wasm',
      result.fallback_reason,
      result.analysisTime
    );
    logger.debug(`[WasmSandbox] 分析结果入库: ${path.basename(filePath)}, elapsed=${(performance.now() - insertStart).toFixed(2)}ms`);
  } catch (e) {
    logger.warn(`[WasmSandbox] 分析结果入库失败: ${e.message}`);
  }

  const totalElapsed = performance.now() - t0;
  logger.info(
    `[WasmSandbox] 分析完成: verdict=${result.verdict} | confidence=${result.confidence.toFixed(2)} | engine=${result.engine} | total_time=${totalElapsed.toFixed(2)}ms`
  );
  metrics.inc('wasm_sandbox_analysis', 1);
  metrics.observe('wasm_analysis_latency_ms', totalElapsed);

  return {
    ...result,
    hashes
  };
}

/**
 * 获取沙箱分析历史记录
 */
function getAnalysisHistory(limit = 50) {
  const t0 = performance.now();
  const db = getDb();
  const rows = db.prepare(
    `SELECT * FROM wasm_sandbox_logs ORDER BY created_at DESC LIMIT ?`
  ).all(limit);
  logger.debug(`[WasmSandbox] getAnalysisHistory: ${rows.length} 条, elapsed=${(performance.now() - t0).toFixed(2)}ms`);
  return rows;
}

/**
 * 检查文件是否已被沙箱分析过
 */
function checkCachedResult(fileHash) {
  const t0 = performance.now();
  const db = getDb();
  const row = db.prepare(
    'SELECT verdict, confidence, behaviors, created_at FROM wasm_sandbox_logs WHERE file_hash = ? ORDER BY created_at DESC LIMIT 1'
  ).get(fileHash);
  logger.debug(`[WasmSandbox] checkCachedResult: hash=${fileHash.substring(0, 16)}..., hit=${!!row}, elapsed=${(performance.now() - t0).toFixed(2)}ms`);
  return row;
}

/**
 * 获取沙箱统计信息
 */
function getStats() {
  const t0 = performance.now();
  const db = getDb();
  const total = db.prepare('SELECT COUNT(*) as count FROM wasm_sandbox_logs').get();
  const malicious = db.prepare("SELECT COUNT(*) as count FROM wasm_sandbox_logs WHERE verdict = 'malicious'").get();
  const suspicious = db.prepare("SELECT COUNT(*) as count FROM wasm_sandbox_logs WHERE verdict = 'suspicious'").get();
  const clean = db.prepare("SELECT COUNT(*) as count FROM wasm_sandbox_logs WHERE verdict = 'clean'").get();
  const wasmNative = db.prepare("SELECT COUNT(*) as count FROM wasm_sandbox_logs WHERE sandbox_engine = 'wasm_soft' OR sandbox_engine = 'wasm' AND fallback_reason IS NULL").get();
  const wasmSoft = db.prepare("SELECT COUNT(*) as count FROM wasm_sandbox_logs WHERE sandbox_engine = 'wasm_soft'").get();
  const wasmHeuristic = db.prepare("SELECT COUNT(*) as count FROM wasm_sandbox_logs WHERE sandbox_engine = 'wasm_heuristic'").get();
  logger.debug(`[WasmSandbox] getStats: total=${total.count}, malicious=${malicious.count}, suspicious=${suspicious.count}, clean=${clean.count}, elapsed=${(performance.now() - t0).toFixed(2)}ms`);

  return {
    total_analyses: total.count,
    malicious: malicious.count,
    suspicious: suspicious.count,
    clean: clean.count,
    wasm_native: wasmNative.count,
    wasm_soft: wasmSoft.count,
    wasm_heuristic: wasmHeuristic.count,
    current_mode: analysisMode
  };
}

module.exports = {
  analyzeWithWasmSandbox,
  getAnalysisHistory,
  checkCachedResult,
  getStats,
  heuristicAnalysis,
  loadWasmModule,
  hashFile
};
