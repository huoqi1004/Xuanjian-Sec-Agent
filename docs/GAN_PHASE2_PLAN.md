# Phase 2 详细实施计划 — GAN 集成推理与投票融合

> 版本：v1.0.0  
> 日期：2026-08-11  
> 前置条件：Phase 1 ✅（AnomalyGAN + AdversarialGAN 训练完成）  
> 预估工期：1.5 周

---

## 一、架构概览

```
┌──────────────────────────────────────────────────────────────────────┐
│                        多引擎扫描流程                                  │
│                                                                      │
│  file.upload()                                                       │
│       │                                                              │
│       ▼                                                              │
│  calculateHashes()              ← 计算 MD5 + SHA256                  │
│       │                                                              │
│       ▼                                                              │
│  Promise.allSettled([                                            │
│    _scanLocalHash(),          // 引擎1: 本地哈希库 (weight=1.0)      │
│    _scan360Ti(),              // 引擎2: 360天眼 (weight=0.9)        │
│    _scanKaspersky(),          // 引擎3: 卡巴斯基 (weight=0.95)       │
│    _scanAIMalware(),          // 引擎4: AI GBDT (weight=0.7)        │
│    _scanAIPoisoning(),        // 引擎5: AI投毒检测 (weight=0.6)      │
│    _scan360VirusDB(),         // 引擎6: 360特征库 (weight=0.95)      │
│    _scanFileEntropy(),        // 引擎7: 熵值分析 (weight=0.3)        │
│    _scanGANCHomaly()          // 引擎8: GAN异常检测 (weight=0.3) ⭐  │
│  ])                                                                │
│       │                                                              │
│       ▼                                                              │
│  _aiArbitrate(engineResults)   ← 加权投票仲裁                        │
│       │                                                              │
│       ▼                                                              │
│  GAN 专项投票逻辑（新增）                                            │
│       │                                                              │
│       ▼                                                              │
│  输出：verdict + confidence + recommendation                         │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 二、GAN 投票逻辑设计

### 2.1 权重体系

| 引擎 | 权重 | 判定阈值 | 说明 |
|------|------|---------|------|
| local_hash | 1.0 | — | 命中已知威胁即 malicious |
| 360_ti | 0.9 | level≥70 → malicious | 外部威胁情报 |
| kaspersky | 0.95 | Red → malicious | 外部威胁情报 |
| ai_malware | 0.7 | score≥0.7 → malicious | GBDT 模型 |
| ai_poisoning | 0.6 | prob≥0.7 → poisoned | 投毒检测 |
| 360_virus_db | 0.95 | 命中特征 → malicious | 外部特征库 |
| entropy | 0.3 | >7.8 → suspicious | 启发式 |
| **gan_anomaly** | **0.3** | **error>threshold → anomaly** | **新增 ⭐** |

### 2.2 GAN 投票融合规则

```
规则 1：GAN 异常触发 secondary review
  IF gan_anomaly.is_anomaly == TRUE
     AND 现有 maliciousScore < 0.3
  THEN 提升 verdict 为 "suspicious"（二次确认）
       增加 recommendation："GAN 异常检测命中，建议人工复核"

规则 2：GAN + 规则引擎双重命中 → 强制提升
  IF gan_anomaly.is_anomaly == TRUE
     AND 任意规则引擎 verdict == "malicious"
  THEN 强制提升 confidence = max(gan_confidence, rule_confidence) * 1.1
       增加 recommendation："GAN 与规则引擎双重命中，建议立即隔离"

规则 3：GAN clean + 规则 malicious → 降级确认
  IF gan_anomaly.is_anomaly == FALSE
     AND maliciousScore >= 0.6
     AND 规则引擎数量 >= 3
  THEN 维持 malicious 但降低置信度 10%（提示可能为误报）
       增加 recommendation："GAN 判定安全但规则引擎多数命中，建议人工复核"

规则 4：GAN 不可用时降级
  IF gan_anomaly.status in ['error', 'skipped', 'missing']
  THEN 不参与投票，记录日志 "GAN 引擎不可用，降级为纯规则引擎"
```

### 2.3 投票算法伪代码

```python
def gan_vote_merge(gan_result, engine_results, malicious_score, suspicious_score, total_weight):
    """
    在现有仲裁逻辑基础上，叠加 GAN 投票逻辑
    """
    gan_weight = 0.3
    gan_threshold = config.gan.anomaly_threshold or 0.02

    # ── 情况1：GAN 不可用，返回现有结果 ──
    if gan_result.status in ('error', 'skipped', 'missing'):
        logger.info("[GAN投票] GAN引擎不可用，使用纯规则仲裁")
        return current_decision

    # ── 情况2：GAN 异常 + 规则未命中 → suspicious ──
    if gan_result.is_anomaly and malicious_score < 0.3:
        # 提升为 suspicious
        suspicious_score += gan_weight * gan_result.confidence
        total_weight += gan_weight
        recommendation = "GAN 异常检测命中，建议人工复核"
        logger.info(f"[GAN投票] GAN异常触发可疑升级: gan_score={gan_result.confidence:.4f}")

    # ── 情况3：GAN 异常 + 规则恶意 → 强制提升 ──
    elif gan_result.is_anomaly and malicious_score >= 0.3:
        boosted = min(0.99, malicious_score + gan_weight * gan_result.confidence * 0.2)
        recommendation = "GAN与规则引擎双重命中，建议立即隔离"
        logger.info(f"[GAN投票] GAN+规则双重命中: maliciousScore={malicious_score:.3f}→{boosted:.3f}")

    # ── 情况4：GAN clean + 规则恶意 → 降级确认 ──
    elif not gan_result.is_anomaly and malicious_score >= 0.6:
        rule_count = count_malicious_engines(engine_results)
        if rule_count >= 3:
            reduced = malicious_score * 0.9
            recommendation = "GAN判定安全但多数规则引擎命中，建议人工复核"
            logger.info(f"[GAN投票] GAN与规则冲突: maliciousScore={malicious_score:.3f}→{reduced:.3f}")

    return updated_decision
```

---

## 三、文件变更清单

### 3.1 修改文件（2 个）

#### 文件1：`server/services/multiEngineScanService.js`

**变更点 1 — 新增第 8 个引擎调用（第 38-46 行）**

```javascript
// 原代码（7个引擎）
const engineResults = await Promise.allSettled([
    this._scanLocalHash(hashes),
    this._scan360Ti(hashes),
    this._scanKaspersky(file.path, file.originalname),
    this._scanAIMalware(file.path),
    this._scanAIPoisoning(file.path, hashes),
    this._scan360VirusDB(hashes),
    this._scanFileEntropy(file.path)
]);

// 修改后（8个引擎）
const engineResults = await Promise.allSettled([
    this._scanLocalHash(hashes),
    this._scan360Ti(hashes),
    this._scanKaspersky(file.path, file.originalname),
    this._scanAIMalware(file.path),
    this._scanAIPoisoning(file.path, hashes),
    this._scan360VirusDB(hashes),
    this._scanFileEntropy(file.path),
    this._scanGANCHomaly(file.path)   // ⭐ 新增
]);
```

**变更点 2 — 新增引擎元数据（第 49-57 行）**

```javascript
const engines = [
    { name: '本地哈希库', key: 'local_hash', icon: 'database' },
    { name: '360天眼', key: '360_ti', icon: 'shield' },
    { name: '卡巴斯基OpenTIP', key: 'kaspersky', icon: 'security' },
    { name: 'AI恶意代码检测', key: 'ai_malware', icon: 'cpu' },
    { name: 'AI投毒检测', key: 'ai_poisoning', icon: 'warning' },
    { name: '360病毒特征库', key: '360_virus_db', icon: 'virus' },
    { name: '文件熵值分析', key: 'entropy', icon: 'chart' },
    { name: 'GAN异常检测', key: 'gan_anomaly', icon: 'brain' }  // ⭐ 新增
];
```

**变更点 3 — 新增 `_scanGANCHomaly` 方法**

```javascript
/**
 * 引擎8: GAN 异常检测
 * 调用 ai-service Python 微服务的 /api/gan/anomaly 接口
 * 返回 reconstruction_error, is_anomaly, confidence
 */
async _scanGANCHomaly(filePath) {
    const start = Date.now();
    try {
        const result = await aiService.callAiServiceFileDetection('/api/gan/anomaly', filePath);

        // 解析 GAN 返回结果
        const reconError = parseFloat(result.reconstruction_error || 0);
        const isAnomaly = result.is_anomaly === true;
        const ganConfidence = parseFloat(result.confidence || 0);

        // GAN 异常分数 → 置信度映射
        // recon_error 越高 → 越异常 → 置信度越高
        let verdict, confidence, detail;
        if (isAnomaly) {
            verdict = 'suspicious';
            confidence = Math.min(0.95, ganConfidence * 0.8 + 0.2);  // 最低 0.2，最高 0.95
            detail = `GAN异常检测: 重构误差=${reconError.toFixed(6)}, 判定为异常 (阈值=${config.gan?.anomalyThreshold || 0.02})`;
        } else {
            verdict = 'clean';
            confidence = Math.max(0.05, 1.0 - reconError);
            detail = `GAN异常检测: 重构误差=${reconError.toFixed(6)}, 判定为安全`;
        }

        logger.info(`[GAN异常检测] filePath=${filePath} | recon_error=${reconError.toFixed(6)} | verdict=${verdict} | confidence=${confidence.toFixed(4)} | elapsed=${Date.now() - start}ms`);

        return {
            engine: 'GAN异常检测',
            status: 'completed',
            verdict,
            confidence,
            detail,
            reconstructionError: reconError,
            ganModelVersion: result.model_version || 'unknown',
            responseTime: Date.now() - start
        };
    } catch (error) {
        logger.warn(`[GAN异常检测] 调用失败: ${error.message}`);
        return {
            engine: 'GAN异常检测',
            status: 'error',
            verdict: 'unknown',
            confidence: 0,
            detail: `GAN检测失败: ${error.message}`,
            responseTime: Date.now() - start
        };
    }
}
```

**变更点 4 — 更新 `_aiArbitrate` 中的权重表**

```javascript
const engineWeights = {
    'local_hash': 1.0,
    '360_ti': 0.9,
    'kaspersky': 0.95,
    'ai_malware': 0.7,
    'ai_poisoning': 0.6,
    '360_virus_db': 0.95,
    'entropy': 0.3,
    'gan_anomaly': 0.3   // ⭐ 新增
};
```

**变更点 5 — 新增 GAN 专项投票逻辑函数**

```javascript
/**
 * GAN 专项投票融合
 * 在 _aiArbitrate 之后调用，调整 verdict 和 recommendation
 */
_ganVoteMerge(engineResultsMap, decision) {
    const ganResult = engineResultsMap['gan_anomaly'];
    if (!ganResult || ganResult.status === 'skipped' || ganResult.status === 'error') {
        logger.info('[GAN投票] GAN引擎不可用，跳过GAN投票逻辑');
        return decision;
    }

    const ganAnomaly = ganResult.verdict === 'suspicious';
    const ganConfidence = ganResult.confidence || 0;
    const malformedScore = decision.maliciousScore || 0;
    const suspiciousScore = decision.suspiciousScore || 0;

    // 规则1: GAN异常 + 规则未命中 → 升级为 suspicious
    if (ganAnomaly && malformedScore < 0.3) {
        decision.verdict = 'suspicious';
        decision.confidence = Math.max(decision.confidence, ganConfidence * 0.5);
        decision.ganBoosted = true;
        decision.ganDetail = `GAN重构误差异常(${ganResult.reconstructionError?.toFixed(6) || 'N/A'})触发升级`;
        logger.info(`[GAN投票] 规则1触发: GAN异常 + 低恶意分数 → 升级为suspicious`);
    }

    // 规则2: GAN异常 + 规则恶意 → 强制提升
    else if (ganAnomaly && malformedScore >= 0.3) {
        const boostedConf = Math.min(0.99, decision.confidence + ganConfidence * 0.15);
        decision.confidence = boostedConf;
        decision.ganBoosted = true;
        decision.ganDetail = `GAN与规则引擎双重命中，置信度提升至${(boostedConf * 100).toFixed(1)}%`;
        logger.info(`[GAN投票] 规则2触发: GAN+规则双重命中, confidence ${decision.confidence.toFixed(3)} → ${boostedConf.toFixed(3)}`);
    }

    // 规则3: GAN clean + 规则恶意 → 降级确认
    else if (!ganAnomaly && malformedScore >= 0.6) {
        const maliciousEngineCount = Object.values(engineResultsMap).filter(
            e => e.verdict === 'malicious' || e.verdict === 'poisoned'
        ).length;
        if (maliciousEngineCount >= 3) {
            const reducedConf = decision.confidence * 0.9;
            decision.confidence = reducedConf;
            decision.ganConflicted = true;
            decision.ganDetail = `GAN判定安全但${maliciousEngineCount}个规则引擎命中，建议人工复核`;
            logger.info(`[GAN投票] 规则3触发: GAN与规则冲突, confidence ${(decision.confidence * 0.9).toFixed(3)}`);
        }
    }

    return decision;
}
```

**变更点 6 — 在 `scanFile` 中调用 GAN 投票**

```javascript
// 现有代码（第 89 行附近）
const decision = this._aiArbitrate(engineResultsMap, hashes, file);

// 新增：GAN 专项投票融合
const decisionWithGAN = this._ganVoteMerge(engineResultsMap, decision);
logger.info(`[GAN投票] 最终仲裁: verdict=${decisionWithGAN.verdict} | confidence=${(decisionWithGAN.confidence * 100).toFixed(1)}% | ganBoosted=${!!decisionWithGAN.ganBoosted} | ganConflicted=${!!decisionWithGAN.ganConflicted}`);

// 替换原 decision
const decision = decisionWithGAN;
```

---

#### 文件2：`server/routes/virus.js`

**变更点 1 — 新增 GAN 单独分析端点**

```javascript
/**
 * POST /api/virus/gan-analyze - 单独调用 GAN 异常检测
 */
router.post('/gan-analyze', checkPermission('POST'), asyncHandler(async (req, res) => {
    const { filePath } = req.body;
    if (!filePath) return fail(res, 'filePath 不能为空');

    try {
        const result = await aiService.callAiServiceFileDetection('/api/gan/anomaly', filePath);
        return success(res, {
            filePath,
            is_anomaly: result.is_anomaly,
            reconstruction_error: result.reconstruction_error,
            anomaly_score: result.anomaly_score,
            confidence: result.confidence,
            model_version: result.model_version,
            gpt_simplified: result.gpt_simplified || null,
        }, 'GAN 异常检测完成');
    } catch (error) {
        return fail(res, `GAN 检测失败: ${error.message}`);
    }
}));

/**
 * GET /api/virus/gan/model-status - 查询 GAN 模型状态
 */
router.get('/gan/model-status', checkPermission('GET'), asyncHandler(async (req, res) => {
    try {
        const status = await aiService.callAiServiceJson('/api/gan/model-status');
        return success(res, status);
    } catch (error) {
        return fail(res, `查询 GAN 模型状态失败: ${error.message}`);
    }
}));
```

---

### 3.2 配置变更

#### `server/config/index.js` — 新增 gan 配置节点

```javascript
gan: {
    enabled: process.env.GAN_SCAN_ENABLED === 'true',
    anomalyThreshold: parseFloat(process.env.GAN_ANOMALY_THRESHOLD) || 0.02,
    weight: parseFloat(process.env.GAN_ENGINE_WEIGHT) || 0.3,
    timeoutMs: parseInt(process.env.GAN_SCAN_TIMEOUT_MS) || 20000,
    fallbackToRule: process.env.GAN_FALLBACK_TO_RULE !== 'false',
},
```

---

## 四、AI Service 调用封装

### 4.1 `aiService.js` 新增方法

```javascript
/**
 * 调用 AI 微服务的 GAN 分析接口
 * 复用 callAiServiceFileDetection，路径为 /api/gan/anomaly
 */
async callGANAnalysis(filePath) {
    const start = Date.now();
    try {
        const result = await callAiServiceFileDetection('/api/gan/anomaly', filePath);
        const elapsed = Date.now() - start;
        logger.info(`[aiService.GAN] GAN分析完成: ${filePath} | ${elapsed}ms`);
        return result;
    } catch (error) {
        logger.warn(`[aiService.GAN] GAN分析失败: ${error.message}`);
        return {
            is_anomaly: false,
            reconstruction_error: 0,
            anomaly_score: 0,
            confidence: 0,
            model_version: 'error',
            error: error.message
        };
    }
}
```

---

## 五、测试方案

### 5.1 单元测试

**文件：** `server/test/gan_integration.test.js`

```javascript
describe('GAN 投票融合测试', () => {
    const scanService = require('../services/multiEngineScanService');

    it('规则1: GAN异常 + 低恶意分数 → suspicious', async () => {
        const result = await scanService._ganVoteMerge(
            { gan_anomaly: { verdict: 'suspicious', confidence: 0.7, reconstructionError: 0.05 } },
            { verdict: 'clean', maliciousScore: 0.1, confidence: 0.3 }
        );
        expect(result.verdict).toBe('suspicious');
        expect(result.ganBoosted).toBe(true);
    });

    it('规则2: GAN异常 + 规则恶意 → 提升置信度', async () => {
        const result = await scanService._ganVoteMerge(
            { gan_anomaly: { verdict: 'suspicious', confidence: 0.8 } },
            { verdict: 'malicious', maliciousScore: 0.6, confidence: 0.75 }
        );
        expect(result.confidence).toBeGreaterThan(0.75);
        expect(result.ganBoosted).toBe(true);
    });

    it('规则3: GAN clean + 规则恶意 ≥3 → 降级', async () => {
        const result = await scanService._ganVoteMerge(
            { gan_anomaly: { verdict: 'clean', confidence: 0.9 } },
            { verdict: 'malicious', maliciousScore: 0.7, confidence: 0.8 }
        );
        expect(result.confidence).toBeLessThan(0.8);
        expect(result.ganConflicted).toBe(true);
    });

    it('规则4: GAN 不可用 → 跳过投票', async () => {
        const result = await scanService._ganVoteMerge(
            { gan_anomaly: { status: 'error', verdict: 'unknown' } },
            { verdict: 'malicious', maliciousScore: 0.7, confidence: 0.8 }
        );
        expect(result.ganBoosted).toBeUndefined();
    });
});
```

### 5.2 集成测试

```bash
# 1. 上传测试文件，验证 GAN 引擎出现在引擎结果中
curl -X POST http://localhost:3000/api/virus/upload \
  -F "file=@test_malware.exe" \
  -H "Authorization: Bearer $TOKEN"

# 验证响应中包含:
# engines.gan_anomaly.verdict
# decision.ganBoosted / decision.ganConflicted
# decision.ganDetail

# 2. 单独调用 GAN 检测
curl -X POST http://localhost:3000/api/virus/gan-analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filePath": "./uploads/virus/test.exe"}'

# 3. 查询模型状态
curl -X GET http://localhost:3000/api/virus/gan/model-status \
  -H "Authorization: Bearer $TOKEN"
```

---

## 六、性能影响分析

| 指标 | 当前（7引擎） | 预期（8引擎） | 影响 |
|------|-------------|-------------|------|
| 单次扫描耗时 | ~800ms | ~1000ms（+200ms） | GAN 推理 < 200ms |
| 并发上限 | 50 req/s | 45 req/s（-5%） | GAN 推理为 CPU 密集 |
| 内存占用 | ~120MB | ~180MB（+60MB） | PyTorch 模型加载 |
| Python 服务负载 | 中 | 中高 | 需监控 ai-service 负载 |

**缓解措施：**
- GAN 推理超时 20s 自动降级（`config.gan.timeoutMs`）
- GAN 引擎可通过 `GAN_SCAN_ENABLED=false` 关闭
- 大文件（>5MB）自动跳过 GAN 分析，仅用规则引擎

---

## 七、验收标准

| 标准 | 目标值 |
|------|--------|
| 单元测试通过率 | 100%（4/4） |
| GAN 引擎集成测试 | 通过 |
| 单次扫描耗时增加 | < 300ms |
| GAN 降级成功率 | 100%（服务不可用时不影响主流程） |
| 规则1触发率 | 可配置（默认开启） |
| 规则2触发率 | 可配置（默认开启） |
| 规则3触发率 | 可配置（默认开启） |

---

## 八、回滚方案

```bash
# 方式1：环境变量关闭
export GAN_SCAN_ENABLED=false

# 方式2：从 engineResults 中移除 gan_anomaly
# 修改 multiEngineScanService.js，注释掉第 8 个引擎调用

# 方式3：数据库禁用
UPDATE sys_config SET value = 'false' WHERE key = 'gan_scan_enabled';
```
