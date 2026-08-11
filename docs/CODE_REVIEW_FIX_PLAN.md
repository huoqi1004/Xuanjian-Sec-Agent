# 代码审查修复计划

> 生成日期：2026-08-11  
> 完成日期：2026-08-11  
> 审查范围：Phase 1–4 新增代码 + 核心服务模块  
> 问题总数：15 项（高 4 / 中 5 / 低 6）  
> 状态：✅ **全部修复完成** — commit `c515258`

---

## 高优先级（P0）— 建议本轮立即修复

---

### P0-1：`version_manager.py` 内存字典无锁保护

**文件**: `ai-service/gan/version_manager.py`（第 359–386 行）

**问题描述**：  
`metrics_collector.py` 使用 `threading.Lock()` 保护所有写操作，但 `version_manager.py` 的 `_save_to_memory()`、`_deploy_memory()`、`_deprecate_model()` 均无锁。Flask `threaded=True` 下，`register_model()` / `deploy_model()` 对 `in_memory_models` 字典的读写存在竞态，可能导致数据丢失或状态不一致。

**影响范围**：  
- 模型注册/部署操作的原子性
- 高并发场景下 `in_memory_models` 字典状态错乱

**修复方案**：  
1. 在 `GANVersionManager.__init__()` 中添加 `self._lock = threading.Lock()`
2. 所有修改 `in_memory_models` 的方法（`_save_to_memory`、`_deploy_memory`、`_deprecate_model`）用 `with self._lock:` 包裹
3. `get_active_model()` 的内存回退路径也需加锁读取（读多写少场景下，RLock 可简化为普通 Lock）

**涉及改动行数**：约 10 行

---

### P0-2：`sqlite.js` 事务并发崩溃

**文件**: `server/db/drivers/sqlite.js`（第 68–80 行）

**问题描述**：  
SQLite 是单连接数据库（`better-sqlite3` 和 `node:sqlite` 均为同步 API，但通过 `async` 包装后仍共享同一连接）。两个并发请求同时调用 `transaction()` 时：
1. 请求 A 执行 `BEGIN`
2. 请求 B 尝试执行 `BEGIN` → **SQLite 报错 "database is locked"**
3. 请求 A 执行 `COMMIT`
4. 请求 B 的 `catch` 执行 `ROLLBACK` → 可能报 "no transaction is active"

**影响范围**：  
- 所有通过 `db.transaction()` 包装的操作（数据保留清理、备份、健康检查等）
- 多请求并发时偶发 500 错误

**修复方案**：  
方案 A（推荐）：添加事务队列  
- 在 `SQLiteDriver` 中维护一个 `Promise` 队列
- `transaction(fn)` 改为 await 队列中前置事务完成后才执行

方案 B：移除 async 包装，改为同步事务  
- `transaction(fn)` 直接同步执行（SQLite 同步 API 本身支持）
- 需要评估对现有调用方的影响

**涉及改动行数**：约 15 行（方案 A）或 10 行（方案 B）

---

### P0-3：`server.js` 设备心跳检测 Promise 未处理

**文件**: `server/server.js`（第 326–333 行）

**问题描述**：  
```javascript
nodeCron.schedule('* * * * *', () => {
  try {
    deviceService.checkHeartbeats();  // 返回 Promise，未 .catch()
  } catch (err) {
    logger.error('设备心跳检测失败:', err.message);  // 仅捕获同步异常
  }
});
```
`checkHeartbeats()` 是异步函数，其 Promise rejection 无法被 `try/catch` 捕获，会触发 unhandled promise rejection，在 Node.js 15+ 中会导致进程崩溃。

**对比**：同文件第 339 行 `alertingService.checkSystemHealth().catch(...)` 是正确的写法。

**修复方案**：  
将 `deviceService.checkHeartbeats()` 改为 `deviceService.checkHeartbeats().catch(err => logger.error(...))`，与 `checkSystemHealth` 保持一致。

**涉及改动行数**：约 5 行

---

### P0-4：WASM 沙箱功能未实现（TODO 桩代码）

**文件**: `server/services/wasmSandboxService.js`（第 218 行）

**问题描述**：  
```javascript
if (wasmModule) {
    // TODO: 实现 WASM 字节码执行分析
    logger.info('[WasmSandbox] WASM 模块存在但未实现，降级为启发式分析');
}
```
当 `WASM_MODULE_PATH` 文件存在时，代码只打印日志就跳过，功能完全不可用。虽然当前已降级为启发式分析（功能可用），但这是一个明显的 TODO 缺口。

**影响范围**：  
- WASM 原生分析路径永远不执行
- 监控指标 `wasm_native` 始终为 0，误导运维判断

**修复方案**：  
方案 A（短期）：移除 `if (wasmModule)` 分支中的 TODO 注释，明确标记"WASM 分析待部署"，避免误导。在 `getStats()` 中修正 `wasm_pending_reason` 描述。

方案 B（中期）：实现 WASM 字节码执行分析（需要部署 `.wasm` 文件）。

**涉及改动行数**：约 5 行（方案 A）/ 约 200 行（方案 B）

---

## 中优先级（P1）— 建议下迭代修复

---

### P1-1：`app.py` 25 处宽泛异常捕获

**文件**: `ai-service/app.py`

**问题描述**：  
大量路由处理使用 `except Exception as e:`，掩盖了真实的错误类型，调试困难。部分位置已有 `# noqa: BLE001` 注释表明开发者已知此问题但选择了忽略。

**修复方案**：  
按功能分类为具体异常：
| 场景 | 应捕获的异常类型 |
|------|----------------|
| 模型加载失败 | `RuntimeError`, `FileNotFoundError`, `_pickle.PicklingError` |
| AI 服务调用 | `requests.exceptions.RequestException`, `TimeoutError` |
| 文件处理 | `ValueError`, `IOError`, `OSError` |
| 数据库操作 | `sqlite3.Error`, `OperationalError` |
| 参数校验 | `ValueError` |

**涉及改动行数**：约 50 行（分类重写 except 块）

---

### P1-2：`_recordGANMetrics` 不记录引擎失败状态

**文件**: `server/services/multiEngineScanService.js`（第 691 行）

**问题描述**：  
```javascript
if (!ganResult || ganResult.status === 'skipped' || ganResult.status === 'error') {
    return;  // 直接跳过，不写入任何记录
}
```
当 GAN 引擎报错时，`gan_scan_metrics` 表中没有对应记录，导致：
1. 监控看板中 GAN 故障不可见
2. 无法区分"GAN 未启用"和"GAN 故障"
3. `_recordGANMetrics` 是同步方法，但其内部的 DB 操作若失败也不通知调用方

**修复方案**：  
1. 将条件改为：仅 `status === 'skipped'` 时跳过，`error` 状态也要记录（`skipped=1, skip_reason='gan_engine_error'`）
2. 将方法改为 `async`，并正确 propagate 错误（或至少记录 ERROR 日志）

**涉及改动行数**：约 8 行

---

### P1-3：`defenseService.js` 冷却锁检查-更新非原子

**文件**: `server/services/defenseService.js`（第 8–13 行）

**问题描述**：  
```javascript
const cooldowns = new Map();
// 检查 + 设置 不是原子操作
if (!cooldowns.get(ip)) {
    cooldowns.set(ip, Date.now() + cooldownMs);
    // 执行封禁...
}
```
在高并发防御动作执行时（如同时多个 IP 被封禁），两个请求可能同时通过检查，导致同一 IP 被重复封禁或冷却时间被覆盖。

**修复方案**：  
使用 `Set` + 原子检查，或添加简单的内存锁（`mutex`）：
```javascript
// 方案：使用 WeakMap + 锁
const cooldownLocks = new Map();
async function withCooldown(key, fn) {
    if (!cooldownLocks.has(key)) cooldownLocks.set(key, Promise.resolve());
    const prev = cooldownLocks.get(key);
    return prev.then(() => {
        const next = fn().finally(() => cooldownLocks.set(key, Promise.resolve()));
        cooldownLocks.set(key, next);
        return next;
    });
}
```

**涉及改动行数**：约 20 行

---

### P1-4：`metrics_collector.py` 数据库连接未用上下文管理器

**文件**: `ai-service/gan/metrics_collector.py`（第 171、206、316、364 行）

**问题描述**：  
```python
conn = sqlite3.connect(self.db_path)
# ... SQL 操作 ...
conn.close()  # 若中间抛异常，连接泄漏
```
若 SQL 执行失败，`conn.close()` 不会被调用，连接泄漏累积后可能导致 SQLite 文件锁死。

**修复方案**：  
所有 `sqlite3.connect()` 改为 `with sqlite3.connect(...) as conn:` 上下文管理器，或统一使用 `try/finally`。

**涉及改动行数**：约 12 行（4 处 × 3 行）

---

### P1-5：`mysql.js` 连接池无超时配置

**文件**: `server/db/drivers/mysql.js`（第 26 行）

**问题描述**：  
```javascript
connectionLimit: 10,
waitForConnections: true,  // 无超时，请求无限等待
```
高负载时 10 个连接全被占用，后续请求无限阻塞，最终导致线程饥饿和请求堆积。

**修复方案**：  
```javascript
connectionLimit: 10,
waitForConnections: true,
connectionTimeout: 5000,  // 5 秒超时
acquireTimeout: 5000,
```

**涉及改动行数**：约 2 行

---

## 低优先级（P2）— 可后续优化

---

### P2-1：`app.py` 多次调用 `logging.basicConfig()`

**文件**: `ai-service/app.py`（第 42 行）、`train_adversarial.py`（第 27 行）、`train_anomaly_gan.py`（第 28 行）、`scripts/adv_training_pipeline.py`（第 41 行）

**问题描述**：  
多个脚本独立调用 `logging.basicConfig()`，第二次调用会覆盖第一次的配置（handler 重复添加），导致日志双份输出或配置不一致。

**修复方案**：  
统一由 `app.py` 入口配置日志，其他脚本使用 `logging.getLogger(__name__)` 但不重复调用 `basicConfig`。

**涉及改动行数**：约 8 行

---

### P2-2：`server.js` 心跳间隔无错误处理

**文件**: `server/server.js`（第 299–307 行）

**问题描述**：  
```javascript
const heartbeatInterval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();  // 若 ping 失败，错误无处理
  });
}, 30000);
```
WebSocket `ping()` 失败时错误未捕获，可能导致 `ws.terminate()` 在无效连接上抛出。

**修复方案**：  
```javascript
ws.ping().catch(() => ws.terminate());
```

**涉及改动行数**：约 3 行

---

### P2-3：`queue.js` `_drain()` 递归风险

**文件**: `server/services/queue.js`（第 81–88 行）

**问题描述**：  
`_run()` 是 async 函数，若在 `_run()` 内部触发 `_drain()`（如任务完成时），可能导致递归调用。虽然 V8 事件循环机制下 `while` 循环不会被中断，但 `await` 会让出控制权，其他任务可能在此期间触发 `_drain()`。

**修复方案**：  
添加防重入标志：
```javascript
_draining = false;
async _drain() {
    if (this._draining) return;
    this._draining = true;
    try {
        while (this.waiting.length > 0 && this.active.size < this.concurrency) { ... }
    } finally {
        this._draining = false;
    }
}
```

**涉及改动行数**：约 8 行

---

### P2-4：`alertingService.js` 全局 `lastCheck` 对象无保护

**文件**: `server/services/alertingService.js`（第 18–24 行）

**问题描述**：  
```javascript
const lastCheck = { ts: null, aiOk: false, aiLatencyMs: 0, ... };
```
`lastCheck` 是模块级共享对象。健康检查（每 5 分钟）和定时巡检并发写入时，对象的属性更新不是原子的。Node.js 单线程下实际风险较低，但在多进程部署时会有问题。

**修复方案**：  
将 `lastCheck` 改为写入时深拷贝，或使用 `Object.freeze()` 后替换整个对象。

**涉及改动行数**：约 5 行

---

### P2-5：`scanService.js` `activeTasks` 无并发保护

**文件**: `server/services/scanService.js`（第 36 行）

**问题描述**：  
```javascript
const activeTasks = new Map();
// 检查-添加 非原子
if (!activeTasks.has(scanId)) {
    activeTasks.set(scanId, task);
}
```
两个请求同时创建相同 `scanId` 时，后写入的会覆盖前者。

**修复方案**：  
使用 `Map.prototype.setIfAbsent`（Node.js 22+）或手动检查：
```javascript
if (activeTasks.has(scanId)) return activeTasks.get(scanId);
const task = new ScanTask(scanId, ...);
activeTasks.set(scanId, task);
return task;
```

**涉及改动行数**：约 5 行

---

### P2-6：`version_manager.py` 大文件哈希计算无锁保护

**文件**: `ai-service/gan/version_manager.py`（第 128–130 行）

**问题描述**：  
```python
with open(file_path, 'rb') as f:
    sha256 = hashlib.sha256(f.read()).hexdigest()
```
大文件哈希计算期间，`in_memory_models` 的更新无锁保护（见 P0-1）。修复 P0-1 后此问题自动解决，无需单独处理。

**涉及改动行数**：0 行（依赖 P0-1 修复）

---

## 修复执行顺序建议

```
第 1 轮（本次）：
  P0-3  server.js 心跳 Promise 未处理          ← 5 行，风险最低
  P0-2  sqlite.js 事务并发崩溃                ← 15 行，核心稳定性
  P1-5  mysql.js 连接池超时配置               ← 2 行，防御性修复
  P1-4  metrics_collector.py 连接上下文管理   ← 12 行，防止连接泄漏

第 2 轮（下迭代）：
  P0-1  version_manager.py 加锁               ← 10 行，与 P0-2 配套
  P1-2  _recordGANMetrics 记录错误状态        ← 8 行，可观测性提升
  P1-3  defenseService.js 冷却锁原子性        ← 20 行
  P2-2  server.js 心跳 ping 错误处理          ← 3 行
  P2-3  queue.js _drain() 防重入              ← 8 行

第 3 轮（后续）：
  P0-4  WASM TODO 清理                        ← 5 行
  P1-1  app.py 异常分类                       ← 50 行
  P2-1  logging 配置统一                      ← 8 行
  P2-4  alertingService.js lastCheck 保护     ← 5 行
  P2-5  scanService.js activeTasks 保护       ← 5 行
  P2-6  （依赖 P0-1，自动解决）
```

---

## 验证标准

每轮修复后需执行：
1. `pytest ai-service/test/test_gan_version_metrics.py -v` → 19/19 通过
2. `npx jest server/test/gan_version_metrics.test.js` → 6/6 通过
3. `npx jest server/test/gan_integration.test.js` → 6/6 通过
4. `pytest ai-service/test/test_gan.py -v` → 22/22 通过
5. `pytest ai-service/test/test_prompt_adversarial.py -v` → 16/16 通过
6. 手动启动服务，确认无 unhandled promise rejection 日志

---

## 风险评估矩阵

| 问题 | 触发条件 | 影响 | 紧急度 | 修复工作量 |
|------|---------|------|--------|-----------|
| P0-1 版本管理无锁 | 并发注册/部署模型 | 数据丢失 | 🔴 高 | 10 行 |
| P0-2 SQLite 事务并发 | 多请求并发事务操作 | 500 错误 | 🔴 高 | 15 行 |
| P0-3 未处理 Promise | 设备心跳检测 | 进程崩溃 | 🔴 高 | 5 行 |
| P0-4 WASM TODO | WASM 模块存在时 | 功能缺失 | 🟡 中 | 5–200 行 |
| P1-1 宽泛异常 | 任何路由错误 | 调试困难 | 🟡 中 | 50 行 |
| P1-2 GAN 错误不记录 | GAN 引擎故障 | 不可观测 | 🟡 中 | 8 行 |
| P1-3 冷却锁非原子 | 高并发封禁 | 重复封禁 | 🟡 中 | 20 行 |
| P1-4 连接泄漏 | SQL 异常 | 文件锁死 | 🟡 中 | 12 行 |
| P1-5 连接池无超时 | 高负载 | 请求堆积 | 🟡 中 | 2 行 |
| P2-1 日志重复配置 | 多脚本导入 | 日志双份 | 🟢 低 | 8 行 |
| P2-2 心跳 ping 无处理 | WebSocket 断连 | 连接泄漏 | 🟢 低 | 3 行 |
| P2-3 drain 递归 | 任务完成触发 | 状态错乱 | 🟢 低 | 8 行 |
| P2-4 lastCheck 无保护 | 多进程部署 | 状态不一致 | 🟢 低 | 5 行 |
| P2-5 activeTasks 无保护 | 并发相同 scanId | 任务覆盖 | 🟢 低 | 5 行 |
| P2-6 哈希无锁 | （依赖 P0-1） | — | 🟢 低 | 0 行 |
