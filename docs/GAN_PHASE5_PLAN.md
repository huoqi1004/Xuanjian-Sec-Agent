# Phase 5 — 性能优化与生产就绪

> 日期：2026-08-11  
> 状态：执行中  
> 基于：PERFORMANCE_AUDIT.md 中优先级 5 项 + 低优先级 5 项

---

## 中优先级（P1–P5）

### P1: 单文件重复同步读取 3 次
- **文件**: `server/services/multiEngineScanService.js`
- **现状**: `scanFile()` → `_calculateHashes()` (第1次), `_scanFileEntropy()` (第2次), `_heuristicSandboxAnalysis()` (第3次)
- **修复**: 在 `scanFile()` 入口读一次 `fileData`，传入各引擎复用
- **预期收益**: 内存峰值降低 66%，大文件扫描速度提升 2x

### P2: 360 Ti 与 360 VirusDB 重复调用同一 API
- **文件**: `server/services/multiEngineScanService.js`
- **现状**: 两个引擎分别调用 `https://api.ti.360.net/safe/api/v2/file`，完全相同
- **修复**: 合并为单一 `_scan360ThreatIntel()`，结果同时填充 `360_ti` 和 `360_virus_db`
- **预期收益**: 每次扫描减少 1 次 HTTP 请求，节省 360 API 配额

### P3: 哈希计算三次独立遍历
- **文件**: `server/services/multiEngineScanService.js:192`
- **现状**: `crypto.createHash('md5').update(data)` + `sha1` + `sha256`，三次完整遍历
- **修复**: 使用 `crypto.createHash('md5')` + `.update(data)` + 独立创建 sha1/sha256（Node.js crypto 内部已优化）
- **预期收益**: CPU 时间降低 ~30%（一次读取，但 Node.js crypto 的 hash 链式调用仍独立遍历；真正优化是使用 `stream.pipeline` 一次读取多输出）

### P4: aiService 全量 Buffer 拼接
- **文件**: `server/services/aiService.js:922`
- **现状**: `fs.readFileSync(filePath)` + `Buffer.concat([head, fileBuffer, tail])`，内存峰值 2x
- **修复**: 使用 `fs.createReadStream(filePath)` + axios `data: stream` 流式上传
- **预期收益**: 10MB 文件内存峰值从 ~20MB 降至 ~2MB

### P5: GAN batch 检测串行
- **文件**: `ai-service/gan/detector.py:114`
- **现状**: `[self.detect(p) for p in file_paths]`，N 个文件 = N 次预处理 + N 次推理
- **修复**: 批量预处理后一次性送入模型推理
- **预期收益**: N=100 时推理时间降低 ~80%（减少预处理开销）

## 低优先级（L1–L5）

### L1: 统一熵值计算函数
- **文件**: `server/services/multiEngineScanService.js:468, 969`
- **现状**: 两处独立的 `calcEntropy` 实现（逻辑相同）
- **修复**: 提取为 `_calcEntropy(data)` 方法，两处复用
- **预期收益**: 代码可维护性提升

### L2: getScanHistory 全表加载 + 内存分页
- **文件**: `server/services/multiEngineScanService.js:1016`
- **现状**: `SELECT * FROM virus_scan_records` 全表加载，内存过滤+切片
- **修复**: 改为 SQL LIMIT/OFFSET +  WHERE tenant 过滤
- **预期收益**: 大数据量下响应时间从 O(N) 降至 O(pageSize)

### L3: WebSocket frontendClients 缺少 finish 事件清理
- **文件**: `server/server.js:270-282`
- **现状**: 只监听 `close` 和 `error`，`finish` 事件（HTTP upgrade 后）未清理
- **修复**: 添加 `ws.on('finish', ...)` 清理
- **预期收益**: 防止 finish 状态连接泄漏

### L4: anomaly_gan.py 重复 forward
- **文件**: `ai-service/gan/anomaly_gan.py:105, 119`
- **现状**: `reconstruct_error()` 和 `anomaly_score()` 各自调用 `self.forward(x)`，对同一 x 执行两次前向传播
- **修复**: `anomaly_score()` 复用 `reconstruct_error()` 的结果，或提取共享 `forward()` 调用
- **预期收益**: 推理时减少 50% 模型前向传播开销

### L5: estimateTokensForMessages 全量遍历
- **文件**: `server/services/aiService.js:1294`
- **现状**: 每次调用遍历完整 messages 数组
- **修复**: 添加简单的 LRU 缓存（基于 messages 引用 ID）
- **预期收益**: 高频调用场景下减少 token 计算开销

---

## 修复执行顺序

```
第 1 轮（快速收益）：
  P2  合并 360 重复 API 调用          ← 50 行（删冗余函数）
  P3  哈希计算优化                   ← 5 行
  L1  统一熵值计算函数               ← 10 行
  L4  anomaly_gan.py 重复 forward    ← 10 行

第 2 轮（中等收益）：
  P1  单文件读一次复用               ← 30 行
  P5  GAN batch 批量推理             ← 20 行
  L2  getScanHistory SQL 分页        ← 10 行

第 3 轮（小收益）：
  P4  aiService 流式上传             ← 20 行（需测试验证）
  L3  WebSocket finish 事件          ← 5 行
  L5  token 估算缓存                 ← 10 行
```
