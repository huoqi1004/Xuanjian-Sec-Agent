# 性能与内存审计 Report

> 生成时间：2026-08-11  
> 审计范围：Phase 1-3 GAN 模块 + 核心服务  
> 工具：代码扫描 + 运行验证

---

## 一、已修复问题（4 个高优先级）

| # | 文件 | 问题 | 修复 |
|---|------|------|------|
| H1 | `multiEngineScanService.js:438` | **ReferenceError** — `info` 变量在使用前未定义 | 调整赋值顺序，先定义再使用 |
| H2 | `trainer.py:12` | **NameError** — `np.percentile` 未导入 numpy | 补充 `import numpy as np` |
| H3 | `aiService.js:28` | **内存泄漏** — `conversationHistory` Map 无限增长 | 添加 LRU 淘汰机制，上限 500 会话 |
| H4 | `prompt_adversarial.py:265` | **内存泄漏** — `results` 列表无限累积 | 添加 `max_results=500` 限制，超出淘汰旧记录 |

## 二、性能瓶颈分析（5 个中优先级）

### P1: 单文件重复同步读取 3 次

**位置：** `multiEngineScanService.js`

```
scanFile() 入口 → _calculateHashes()   → fs.readFileSync  (第1次)
                              ↓
                    _scanFileEntropy()   → fs.readFileSync  (第2次)
                              ↓
                    _heuristicSandboxAnalysis() → fs.readFileSync (第3次)
```

**影响：** 23KB 文件每次扫描读 3 次（69KB 内存峰值），10MB 文件则 30MB  
**建议：** 在 `scanFile()` 入口读取一次，将 `fileData` 作为参数传递给各引擎复用

### P2: 360 Ti 与 360 VirusDB 重复调用同一 API

**位置：** `multiEngineScanService.js` 第 226 行、第 398 行

```javascript
// _scan360Ti:  https://api.ti.360.net/safe/api/v2/file?md5=...
// _scan360VirusDB: https://api.ti.360.net/safe/api/v2/file?md5=...  ← 完全相同
```

**影响：** 每次扫描多发 1 次 360 API 请求，浪费配额  
**建议：** 合并为单一引擎 `_scan360Ti`，结果同时用于 360_ti 和 360_virus_db 两个逻辑判断

### P3: 哈希计算三次独立遍历

**位置：** `multiEngineScanService.js` 第 188-195 行

```javascript
md5: crypto.createHash('md5').update(data).digest('hex'),
sha1: crypto.createHash('sha1').update(data).digest('hex'),
sha256: crypto.createHash('sha256').update(data).digest('hex')
```

**影响：** 每次对数据执行 3 次完整遍历（10MB 文件 = 30MB CPU 时间）  
**建议：** 使用 `crypto.createHash` 链式或 `stream.pipeline` 一次遍历多哈希

### P4: aiService 全量 Buffer 拼接

**位置：** `aiService.js` 第 900-908 行

```javascript
const fileBuffer = fs.readFileSync(filePath);  // 全量读入
const body = Buffer.concat([
    Buffer.from(multipart_head),
    fileBuffer,   // 双倍内存：原始 + 拼接
    Buffer.from(multipart_tail)
]);
```

**影响：** 10MB 文件 = 20MB+ 内存峰值（原始 buffer + multipart body）  
**建议：** 使用 `fs.createReadStream` + `axios` 流式上传

### P5: GAN batch 检测串行

**位置：** `gan/detector.py` 第 114-116 行

```python
def detect_batch(self, file_paths):
    return [self.detect(p) for p in file_paths]  # 串行
```

**影响：** N 个文件 = N 次独立预处理 + N 次独立推理  
**建议：** 批量预处理后一次性送入模型推理

## 三、代码质量优化（5 个低优先级）

| # | 文件 | 建议 |
|---|------|------|
| L1 | `multiEngineScanService.js` 464/919/948 | 3 个熵值计算函数重复，统一到 `utils/calcEntropy` |
| L2 | `multiEngineScanService.js` 967 | `getScanHistory` 全表加载 + 内存分页，改为 SQL LIMIT/OFFSET |
| L3 | `server.js` 235 | WebSocket `frontendClients` 缺少 finish 事件清理 |
| L4 | `anomaly_gan.py` 108-125 | `anomaly_score` 与 `reconstruct_error` 重复 forward，提取共享结果 |
| L5 | `aiService.js` 1270 | `estimateTokensForMessages` 每次全量遍历，可缓存 |

## 四、验证结果

```
✅ multiEngineScanService.js  — import 正常（info 变量修复）
✅ aiService.js               — import 正常（LRU 淘汰机制正常）
✅ trainer.py                 — GANTrainer 导入正常（numpy 修复）
✅ prompt_adversarial.py      — 16/16 测试通过（max_results 限制生效）
✅ gan_integration.test.js    — 6/6 测试通过（投票逻辑正常）
✅ test_gan.py                — 22/22 测试通过
```

## 五、当前内存占用估算

| 组件 | 预估内存 |
|------|---------|
| Node.js 主服务 | ~120MB |
| PyTorch AnomalyGAN | ~60MB |
| PyTorch AdversarialGAN | ~30MB |
| conversationHistory (500会话上限) | ~50MB |
| 单次文件扫描（峰值） | ~20MB（3次同步读取） |
| **合计（正常负载）** | **~280MB** |
| **合计（10MB 文件扫描峰值）** | **~300MB** |
