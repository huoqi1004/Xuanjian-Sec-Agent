/**
 * WASM 二进制构建脚本（需 clang/emcc 或 rustup+wasm-pack）
 *
 * 用法：
 *   ./scripts/wasm/build.sh           # Linux/macOS
 *   node scripts/wasm/build.js        # Node.js 备用路径（生成 JS 软 WASM）
 *
 * 产物：server/assets/sandbox.wasm
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const PROJECT_ROOT = path.resolve(__dirname, '../../');
const WASM_DIR = path.join(PROJECT_ROOT, 'server', 'assets', 'wasm');
const C_SRC = path.join(WASM_DIR, 'analyzer.c');
const OUT_WASM = path.join(PROJECT_ROOT, 'server', 'assets', 'sandbox.wasm');

/**
 * 写入 C 源码（PE 特征分析器）
 */
function writeCSource() {
  const src = `
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define MAX_INPUT 4096
#define MAX_BEHAVIORS 64
#define BEHAVIOR_LEN 64

typedef struct {
  int32_t verdict;      // 0=clean, 1=suspicious, 2=malicious
  float confidence;
  float entropy;
  int32_t is_pe;
  int32_t size;
  int32_t behavior_count;
  char behaviors[MAX_BEHAVIORS][BEHAVIOR_LEN];
} AnalysisResult;

static AnalysisResult result;
static uint8_t input_buf[MAX_INPUT];

// 可疑 API 列表
static const char* SUSPICIOUS_APIS[] = {
  "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
  "NtUnmapViewOfSection", "SetWindowsHookEx", "GetAsyncKeyState",
  "URLDownloadToFile", "InternetOpen", "WinExec", "system(",
  "powershell", "-enc", "-encodedcommand", "cmd.exe", "/c"
};
static const int NUM_SUSPICIOUS_APIS = 15;

// 恶意字符串列表
static const char* MALWARE_STRINGS[] = {
  "eval(", "exec(", "base64", "wscript", "cscript", "mshta", "regsvr32", "certutil"
};
static const int NUM_MALWARE_STRINGS = 8;

// 文本匹配（不区分大小写）
static int strcasestr_custom(const uint8_t* buf, int buf_len, const char* pattern) {
  int plen = strlen(pattern);
  if (plen == 0 || plen > buf_len) return 0;
  for (int i = 0; i <= buf_len - plen; i++) {
    int match = 1;
    for (int j = 0; j < plen; j++) {
      char a = buf[i + j] >= 'A' && buf[i + j] <= 'Z'
               ? buf[i + j] + 32 : buf[i + j];
      if (a != pattern[j]) { match = 0; break; }
    }
    if (match) return 1;
  }
  return 0;
}

// 计算 Shannon 熵
static float calc_entropy(const uint8_t* buf, int len) {
  uint32_t freq[256] = {0};
  for (int i = 0; i < len; i++) freq[buf[i]]++;
  float entropy = 0.0f;
  for (int i = 0; i < 256; i++) {
    if (freq[i] == 0) continue;
    float p = (float)freq[i] / (float)len;
    entropy -= p * (float)(log(p) / log(2.0f));
  }
  return entropy;
}

void analyze(const uint8_t* data, int32_t len) {
  // 复制输入数据
  int copy_len = len < MAX_INPUT ? len : MAX_INPUT;
  memcpy(input_buf, data, copy_len);

  // 重置结果
  memset(&result, 0, sizeof(result));
  result.entropy = calc_entropy(input_buf, copy_len);

  float score = 0.0f;

  // PE MZ header 检测
  int is_pe = (copy_len >= 2 && input_buf[0] == 0x4d && input_buf[1] == 0x5a);
  if (is_pe) {
    score += 0.2f;
    result.is_pe = 1;
    if (result.behavior_count < MAX_BEHAVIORS)
      snprintf(result.behaviors[result.behavior_count++], BEHAVIOR_LEN, "PE_MZ_header");
  }

  // 可疑 API 扫描
  int scan_len = copy_len < 65536 ? copy_len : 65536;
  for (int i = 0; i < NUM_SUSPICIOUS_APIS; i++) {
    if (strcasestr_custom(input_buf, scan_len, SUSPICIOUS_APIS[i])) {
      score += 0.12f;
      if (result.behavior_count < MAX_BEHAVIORS) {
        snprintf(result.behaviors[result.behavior_count++], BEHAVIOR_LEN,
                 "suspicious_api:%s", SUSPICIOUS_APIS[i]);
      }
    }
  }

  // 高熵检测
  if (result.entropy > 7.8f) {
    score += 0.3f;
    if (result.behavior_count < MAX_BEHAVIORS)
      snprintf(result.behaviors[result.behavior_count++], BEHAVIOR_LEN,
               "high_entropy:%.2f", result.entropy);
  } else if (result.entropy > 7.0f) {
    score += 0.15f;
    if (result.behavior_count < MAX_BEHAVIORS)
      snprintf(result.behaviors[result.behavior_count++], BEHAVIOR_LEN,
               "elevated_entropy:%.2f", result.entropy);
  }

  // 恶意字符串
  for (int i = 0; i < NUM_MALWARE_STRINGS; i++) {
    if (strcasestr_custom(input_buf, copy_len, MALWARE_STRINGS[i])) {
      score += 0.15f;
      if (result.behavior_count < MAX_BEHAVIORS)
        snprintf(result.behaviors[result.behavior_count++], BEHAVIOR_LEN,
                 "malware_string:%s", MALWARE_STRINGS[i]);
    }
  }

  // NOP sled 检测
  int nop_count = 0, max_nop = 0;
  for (int i = 0; i < copy_len; i++) {
    if (input_buf[i] == 0x90) {
      nop_count++;
      if (nop_count > max_nop) max_nop = nop_count;
    } else {
      nop_count = 0;
    }
  }
  if (max_nop >= 16) {
    score += 0.25f;
    if (result.behavior_count < MAX_BEHAVIORS)
      snprintf(result.behaviors[result.behavior_count++], BEHAVIOR_LEN,
               "nop_sled:%d", max_nop);
  }

  // 判定
  if (score >= 0.5f) result.verdict = 2;
  else if (score >= 0.25f) result.verdict = 1;
  else result.verdict = 0;
  result.confidence = score < 1.0f ? score : 1.0f;
  result.size = len;
}

// JSON 结果序列化（导出为 C 字符串）
const char* get_result_json() {
  // 使用静态缓冲区（线程不安全，但沙箱分析为单线程）
  static char json_buf[4096];
  snprintf(json_buf, sizeof(json_buf),
    "{\"verdict\":%s,\"confidence\":%.4f,\"entropy\":%.2f,\"is_pe\":%d,\"size\":%d,\"behaviors\":\"",
    result.verdict == 2 ? "\"malicious\"" : (result.verdict == 1 ? "\"suspicious\"" : "\"clean\""),
    result.confidence, result.entropy, result.is_pe, result.size);

  for (int i = 0; i < result.behavior_count; i++) {
    strncat(json_buf, result.behaviors[i], sizeof(json_buf) - strlen(json_buf) - 1);
    if (i < result.behavior_count - 1) strncat(json_buf, ";", sizeof(json_buf) - strlen(json_buf) - 1);
  }
  strncat(json_buf, "\"}", sizeof(json_buf) - strlen(json_buf) - 1);
  return json_buf;
}
`;
  fs.writeFileSync(C_SRC, src, 'utf8');
}

/**
 * 尝试使用 emcc 编译 WASM
 */
function compileWasm() {
  // 检查 emcc 是否可用
  try {
    execSync('emcc --version', { stdio: 'ignore' });
  } catch {
    console.log('[wasm-build] emcc 不可用，跳过原生 WASM 编译');
    console.log('[wasm-build] 将使用 JS 软 WASM 实现（性能相当）');
    return false;
  }

  try {
    const cmd = `emcc "${C_SRC}" -o "${OUT_WASM}" -Os -s EXPORTED_FUNCTIONS='["_analyze","_get_result_json"]' -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","UTF8ToString"]' -s ALLOW_MEMORY_GROWTH=1 -s ENVIRONMENT='node'`;
    execSync(cmd, { stdio: 'inherit' });
    console.log(`[wasm-build] ✓ 编译成功: ${OUT_WASM}`);
    return true;
  } catch (e) {
    console.error('[wasm-build] 编译失败:', e.message);
    return false;
  }
}

/**
 * 主入口
 */
function main() {
  console.log('[wasm-build] 开始构建 WASM 分析模块...');

  // 确保目录存在
  fs.mkdirSync(WASM_DIR, { recursive: true });

  // 写入 C 源码
  writeCSource();
  console.log(`[wasm-build] ✓ C 源码已写入: ${C_SRC}`);

  // 尝试编译
  const compiled = compileWasm();

  if (!compiled) {
    console.log('[wasm-build] ℹ 使用 JS 软 WASM 实现（server/assets/wasm/analyzer.js）');
    console.log('[wasm-build] ℹ 要启用原生 WASM，请安装 Emscripten: https://emscripten.org/docs/getting_started/downloads.html');
  } else {
    const stat = fs.statSync(OUT_WASM);
    console.log(`[wasm-build] ✓ WASM 产物大小: ${(stat.size / 1024).toFixed(1)} KB`);
  }
}

main();
