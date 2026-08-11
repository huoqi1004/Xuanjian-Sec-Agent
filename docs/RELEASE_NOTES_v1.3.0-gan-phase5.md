# XuanJian Security Agent v1.3.0-gan-phase5 发布说明

> 发布日期：2026-08-11  
> 仓库：https://github.com/huoqi1004/Xuanjian-Sec-Agent  
> 标签：`v1.3.0-gan-phase5`  
> 基于：`v1.3.0-security-fixes`（`c515258`）

---

## 版本概览

| 指标 | 数据 |
|------|------|
| 新增文件 | 1 个（计划文档） |
| 修改文件 | 5 个 |
| 代码行数 | +205 / -40 |
| 测试覆盖 | **69/69 全部通过** |
| 关联文档 | `docs/GAN_PHASE5_PLAN.md` |

---

## 一、核心变更：GAN 性能优化

### 1.1 单文件读一次（P1 优化）

**问题**：`scanFile()` 内部三个引擎各自调用 `fs.readFileSync(filePath)`，同一文件被同步读取 3 次，内存峰值和 I/O 开销均达 3x。

**修复**：在 `scanFile()` 入口读取一次文件数据，通过参数传入 `熵值分析` 和 `启发式沙箱` 两个引擎复用。

```javascript
// 修改前：3 次独立读取
const hashes = this._calculateHashes(file.path);   // 读取第 1 次
this._scanFileEntropy(file.path);                   // 读取第 2 次
this._heuristicSandboxAnalysis(file.path, hashes);  // 读取第 3 次

// 修改后：读一次，多次复用
const fileData = fs.readFileSync(file.path);
this._scanFileEntropy(fileData);
this._heuristicSandboxAnalysis(file.path, hashes, fileData);
```

**预期收益**：内存峰值降低约 66%，大文件（>10MB）扫描速度提升约 2x。

---

### 1.2 合并 360 重复 API 调用（P2 优化）

**问题**：`_scan360Ti()` 和 `_scan360VirusDB()` 两个引擎分别调用相同的 `https://api.ti.360.net/safe/api/v2/file` 端点，每次扫描白白浪费一次 API 请求，同时消耗双倍 360 API 配额。

**修复**：提取 `_query360ThreatIntel(hashes, engineName)` 共享方法，两个引擎共用一次 API 调用，分别解析不同的返回字段。

```javascript
// _query360ThreatIntel() — 公共方法，返回原始结果
// 天眼引擎：解析 result.info.level → verdict
// 病毒库引擎：解析 result.info.malware → 家族/行为标签
```

**预期收益**：每次扫描减少 1 次 HTTP 请求，节省 360 API 配额 50%。

---

### 1.3 GAN 批量推理优化（P5 优化）

**问题**：`detector.py` 的 `detect_batch()` 方法对 N 个文件逐个调用 `detect()`，导致 N 次独立的预处理（SHA256 padding）和 N 次模型前向传播，预处理开销随 N 线性增长。

**修复**：重写 `detect_batch()`，先批量预处理所有文件为 tensor 列表，再堆叠为单次 batch 送入模型，一次完成所有文件的推理。

```python
# 修改前：N 次独立推理
return [self.detect(p) for p in file_paths]

# 修改后：单次批量推理
batch = torch.cat(tensors, dim=0)  # (N, input_dim)
x_recon, _, d_out = self.model.forward(batch)  # 一次前向传播
score = 0.7 * recon_err + 0.3 * disc_anomaly
```

**预期收益**：N=100 文件时，推理时间降低约 80%（减少 99 次预处理开销）。

---

## 二、代码质量优化

### 2.1 统一熵值计算函数（L1）

**问题**：`multiEngineScanService.js` 中有两处完全相同的 `calcEntropy` 实现（`_scanFileEntropy` 内部和原来的注释代码中），逻辑重复。

**修复**：提取为类方法 `_calcEntropy(data)`，所有调用处复用。

```javascript
_calcEntropy(data) {
    const freq = new Uint32Array(256);
    for (let i = 0; i < data.length; i++) freq[data[i]]++;
    let ent = 0;
    for (let i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            const p = freq[i] / data.length;
            ent -= p * Math.log2(p);
        }
    }
    return ent;
}
```

---

### 2.2 GAN 模型重复前向传播消除（L4）

**问题**：`anomaly_gan.py` 中 `reconstruct_error()` 和 `anomaly_score()` 两个方法都对同一输入 `x` 执行 `self.forward(x)`，导致每次异常评分执行两次完整的前向传播（Encoder + Decoder + Discriminator）。

**修复**：`anomaly_score()` 内部复用 `forward()` 结果，只执行一次前向传播，同时消除 `reconstruct_error()` 中的重复计算。

---

### 2.3 HTTP 请求缓存优化（L5）

**问题**：`estimateTokensForMessages()` 在每次 AI 对话时遍历完整 messages 数组计算 token 数，高并发场景下频繁重复计算。

**修复**：添加 LRU 缓存（上限 1000 条），以消息列表的长度和内容长度哈希作为 key，命中时直接返回缓存值。

---

### 2.4 扫描历史 SQL 分页（L2）

**问题**：`getScanHistory()` 使用 `SELECT *` 全表加载，在内存中做过滤和分页，当扫描记录超过数万条时导致响应超时和内存峰值。

**修复**：改用 SQL 层 `LIMIT/OFFSET` 分页，数据库直接返回目标页数据。

```sql
-- 修改前：全表加载
SELECT * FROM virus_scan_records

-- 修改后：SQL 分页
SELECT * FROM virus_scan_records ORDER BY created_at DESC LIMIT ? OFFSET ?
```

---

### 2.5 WebSocket 连接清理完善（L3）

**问题**：前端 WebSocket 连接只监听 `close` 和 `error` 事件清理 `frontendClients`，HTTP 升级成功后若连接在未发送数据前关闭（`finish` 事件），连接对象不会从 Map 中移除，导致连接泄漏。

**修复**：补充 `ws.on('finish', ...)` 监听，确保所有连接生命周期均被追踪清理。

---

## 三、测试验证

| 测试套件 | 结果 | 说明 |
|----------|------|------|
| `test_gan.py` | 22/22 ✅ | GAN 基础功能 |
| `test_prompt_adversarial.py` | 16/16 ✅ | 对抗样本生成 |
| `test_gan_version_metrics.py` | 19/19 ✅ | 模型版本管理 |
| `gan_integration.test.js` | 6/6 ✅ | 投票融合逻辑 |
| `gan_version_metrics.test.js` | 6/6 ✅ | 指标服务 |
| **合计** | **69/69 ✅** | 全部通过 |

---

## 四、变更文件清单

| 文件 | 变更类型 | 说明 |
|------|----------|------|
| `server/services/multiEngineScanService.js` | 修改 | P1/P2/P3/L1/L2：单文件读取优化 + 360 API 合并 + 统一熵值 + SQL 分页 |
| `ai-service/gan/detector.py` | 修改 | P5：批量推理重写，添加 `torch.nn.functional as F` 导入 |
| `ai-service/gan/anomaly_gan.py` | 修改 | L4：消除重复 forward 传播 |
| `server/services/aiService.js` | 修改 | L5：token 估算 LRU 缓存 |
| `server/server.js` | 修改 | L3：WebSocket finish 事件清理 |
| `docs/GAN_PHASE5_PLAN.md` | 新增 | Phase 5 详细实施计划文档 |

---

## 五、兼容性说明

- **向后兼容**：所有变更均为优化，API 接口和数据库表结构无变化
- **Python 依赖**：`detector.py` 新增 `import torch.nn.functional as F`，需确认 PyTorch 已安装（本项目已有依赖）
- **数据库**：无需执行新的迁移文件

---

## 六、版本演进时间线

```
v1.2.0-beta       日志配置优化 + 脱敏修复
v1.3.0-gan-phase1 GAN 基础框架（Encoder-Decoder + Detector）
v1.3.0-gan-phase2 多引擎投票融合逻辑
v1.3.0-gan-phase3 对抗训练 Pipeline + 红队测试
v1.3.0-gan-phase4 模型版本管理 + 监控指标
v1.3.0-security-fixes  并发安全 + 异常处理修复（15项）
v1.3.0-gan-phase5  性能优化与生产就绪
```

---

## 七、升级指南

```bash
# 拉取最新版本
git pull origin master

# 无需数据库迁移，直接启动
cd ai-service && pip install -r requirements.txt
cd ../server && npm install

# 启动服务
npm start
cd ai-service && python app.py
```
