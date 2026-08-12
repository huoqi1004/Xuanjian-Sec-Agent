/**
 * WASM 软分析器（JS 实现）
 *
 * 当原生 sandbox.wasm 不可用时，提供与 WASM 相同接口的 JS 分析器。
 * 实现逻辑与启发式分析器一致：
 *   - PE MZ header 检测
 *   - 可疑 API 字符串匹配（VirtualAlloc, powershell 等）
 *   - Shannon 熵值计算
 *   - NOP sled 检测（连续 0x90 字节 >= 16）
 *   - 恶意字符串匹配（eval(, exec(, base64, wscript 等）
 *
 * 使用方式：
 *   const analyzer = require('./assets/wasm/analyzer.js');
 *   const result = analyzer.analyze(fileBuffer);
 */

/**
 * 软 WASM 分析器
 */
class WasmSoftAnalyzer {
  constructor() {
    this.resultBuf = null;
  }

  /**
   * 分析文件数据
   * @param {Buffer} data - 文件数据
   * @returns {Object} { verdict, confidence, score, entropy, behaviors, is_pe, size, engine }
   */
  analyze(data) {
    const startTime = performance.now();

    if (!(data instanceof Buffer)) {
      data = Buffer.from(data);
    }

    const size = data.length;
    let score = 0;
    const behaviors = [];

    // PE MZ header 检测（offset 0-1: 0x4D 0x5A）
    const isPE = size >= 2 && data[0] === 0x4d && data[1] === 0x5a;

    if (isPE) {
      score += 0.2;
      behaviors.push('PE_MZ_header');

      // 可疑 API 扫描（前 64KB）
      const scanLen = Math.min(65536, size);
      const textSlice = data.subarray(0, scanLen);
      const suspiciousApis = [
        'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread',
        'NtUnmapViewOfSection', 'SetWindowsHookEx', 'GetAsyncKeyState',
        'URLDownloadToFile', 'InternetOpen', 'WinExec', 'system(',
        'powershell', '-enc', '-encodedcommand', 'cmd.exe', '/c'
      ];
      for (const api of suspiciousApis) {
        if (textSlice.includes(api)) {
          score += 0.12;
          behaviors.push(`suspicious_api:${api}`);
        }
      }
    }

    // 熵值计算
    const freq = new Uint16Array(256);
    for (let i = 0; i < size; i++) freq[data[i]]++;
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / size;
        entropy -= p * Math.log2(p);
      }
    }

    if (entropy > 7.8) {
      score += 0.3;
      behaviors.push(`high_entropy:${entropy.toFixed(2)}`);
    } else if (entropy > 7.0) {
      score += 0.15;
      behaviors.push(`elevated_entropy:${entropy.toFixed(2)}`);
    }

    // 恶意字符串检测
    const malwareStrings = ['eval(', 'exec(', 'base64', 'wscript', 'cscript', 'mshta', 'regsvr32', 'certutil'];
    for (const s of malwareStrings) {
      if (data.includes(s)) {
        score += 0.15;
        behaviors.push(`malware_string:${s}`);
      }
    }

    // NOP sled 检测
    let nopCount = 0;
    let maxConsecutive = 0;
    for (let i = 0; i < size; i++) {
      if (data[i] === 0x90) {
        nopCount++;
        maxConsecutive = Math.max(maxConsecutive, nopCount);
      } else {
        nopCount = 0;
      }
    }
    if (maxConsecutive >= 16) {
      score += 0.25;
      behaviors.push(`nop_sled:${maxConsecutive}`);
    }

    const verdict = score >= 0.5 ? 'malicious' : (score >= 0.25 ? 'suspicious' : 'clean');
    const confidence = Math.min(score, 1.0);
    const analysisTimeUs = Math.round((performance.now() - startTime) * 1000);

    this.resultBuf = Buffer.from(JSON.stringify({
      verdict, confidence, score: Math.round(score * 1000) / 1000,
      entropy: Math.round(entropy * 100) / 100,
      behaviors: behaviors.join('; '),
      is_pe: isPE, size, analysis_time_us: analysisTimeUs
    }), 'utf8');

    return {
      verdict,
      confidence,
      score,
      entropy,
      behaviors: behaviors.join('; ') || 'no_suspicious_indicators',
      is_pe: isPE,
      size,
      analysis_time_us: analysisTimeUs,
      engine: 'wasm_soft'
    };
  }

  /**
   * 获取上次分析结果（JSON 字符串）
   */
  readResult() {
    return this.resultBuf ? this.resultBuf.toString('utf8') : null;
  }

  /**
   * 释放结果缓冲区
   */
  freeResult() {
    this.resultBuf = null;
  }
}

module.exports = new WasmSoftAnalyzer();
