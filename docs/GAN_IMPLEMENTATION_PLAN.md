# 玄鉴安全智能体 — GAN 对抗生成网络应用实施计划

> 版本：v1.0.0  
> 日期：2026-08-11  
> 状态：**规划中**  
> 前置条件：Phase 1–4 全部完成 ✅

---

## 一、项目背景与目标

### 1.1 现状分析

```
当前检测能力                           瓶颈
──────────────────────────────────────────────────────────────────
malware_detector.py                  纯规则引擎，无 ML 模型
poisoning_detector.py                纯统计规则，无法检测未知模式
hallucinationDetector.js             依赖引用溯源，无法检测"真实但编造"的幻觉
promptGuard.js                       23 正则覆盖已知模式，对抗样本易绕过
multiEngineScanService.js            启发式降级方案，无法检测混淆/加密恶意代码
diffPrivacyService.js                字符级噪声扰动，无法检测语义级投毒
```

### 1.2 GAN 应用目标

| 目标 | 说明 | 预期收益 |
|------|------|---------|
| **未知恶意文件检测** | 用 AnomalyGAN 学习正常文件分布，重构误差异常即标记 | 发现 0-day 混淆样本，弥补规则引擎盲区 |
| **对抗样本加固** | 用 GAN 生成对抗样本训练检测器，提升鲁棒性 | 使 malware_detector 对变形/混淆恶意代码检出率提升 30%+ |
| **投毒样本生成** | 用 GAN 生成带噪声的对抗性训练数据，模拟投毒攻击 | 增强投毒检测器对未知攻击模式的泛化能力 |
| **红队自动化** | 用 GAN 自动生成对抗性 prompt 注入样本，持续测试 PromptGuard | 自动发现正则覆盖盲区，驱动策略迭代 |

### 1.3 技术选型

| 组件 | 选型 | 理由 |
|------|------|------|
| 框架 | PyTorch 2.x | 已有依赖（requirements.txt），学术生态成熟 |
| 编码器 | ResNet-1D / CNN-Bitcoin | 序列特征提取能力强，适合二进制文件 |
| 解码器 | 对称 CNN 上采样 | 轻量级，推理延迟低（< 50ms/文件） |
| 判别器 | PatchGAN 结构 | 局部判别，对文件级异常更敏感 |
| 训练设备 | CPU 优先，GPU 可选 | 检测服务无 GPU 依赖，CPU 可满足推理需求 |
| 模型格式 | TorchScript (.pt) | 与现有 joblib 模型并存，互不干扰 |

---

## 二、整体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                     XuanJian Security Agent                         │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  ai-service  │  │   server.js  │  │   frontend-react         │  │
│  │   (Python)   │  │   (Node.js)  │  │   (React + TS)           │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────────────────────┘  │
│         │                 │                                         │
│  ┌──────▼───────┐  ┌──────▼──────────────────────────────────┐     │
│  │  Malware     │  │  multiEngineScanService                 │     │
│  │  Detector    │  │  (并行调用各引擎结果)                     │     │
│  │  + Anomaly   │  │                                         │     │
│  │  GAN         │  │  ┌──────────────────────────────────┐   │     │
│  │              │  │  │  引擎结果汇总 + GAN 投票           │   │     │
│  │  ┌─────────┐ │  │  └──────────────────────────────────┘   │     │
│  │  │Generator│ │  │                                         │     │
│  │  │Discrim. │ │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐ │     │
│  │  └─────────┘ │  │  │规则引擎 │  │ GBDT模型│  │GAN异常  │ │     │
│  │              │  │  └─────────┘  └─────────┘  └────┬────┘ │     │
│  └──────────────┘  └─────────────────────────────────┼───────┘     │
│                                                        │            │
│  ┌────────────────────────────────────────────────────▼──────────┐  │
│  │  GAN Anomaly GAN — 文件级异常检测                              │  │
│  │  - AnomalyGAN（编码器-解码器，重建误差 → 异常分数）            │  │
│  │  - AdversarialGAN（生成对抗样本用于红队测试）                   │  │
│  │  - GANAdaptiveClassifier（GAN 辅助分类器，提升鲁棒性）         │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  GAN PromptGuard Enhancer — 对抗性 Prompt 测试                 │  │
│  │  - PromptAdversarialGAN（生成变体注入样本）                    │  │
│  │  - 自动化测试 → 触发正则更新 → 闭环迭代                        │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 三、实施路线图

### Phase 1 — 基础 GAN 框架（2 周）

#### 1.1 GAN 核心模块

**文件：** `ai-service/gan/anomaly_gan.py`

```python
class AnomalyGAN(nn.Module):
    """
    基于重构误差的异常检测 GAN
    编码器(784→64) → 解码器(64→784)
    正常文件重建误差低，异常文件重建误差高
    """
    def __init__(self, input_dim=784, latent_dim=64):
        super().__init__()
        # 编码器
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 512), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(512, 256), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(256, latent_dim), nn.Tanh()
        )
        # 解码器
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 256), nn.ReLU(),
            nn.Linear(256, 512), nn.ReLU(),
            nn.Linear(512, input_dim), nn.Sigmoid()
        )
        # 判别器（PatchGAN 简化版）
        self.discriminator = nn.Sequential(
            nn.Linear(input_dim, 256), nn.LeakyReLU(0.2),
            nn.Linear(256, 128), nn.LeakyReLU(0.2),
            nn.Linear(128, 1), nn.Sigmoid()
        )

    def forward(self, x):
        z = self.encoder(x)
        x_recon = self.decoder(z)
        d_out = self.discriminator(x_recon)
        return x_recon, z, d_out
```

**文件：** `ai-service/gan/adversarial_gan.py`

```python
class AdversarialMalwareGAN(nn.Module):
    """
    对抗样本生成器 — 在正常文件特征空间生成恶意变体
    用于增强 malware_detector 的对抗鲁棒性
    """
    def __init__(self, input_dim=14, latent_dim=32):
        super().__init__()
        self.generator = nn.Sequential(
            nn.Linear(latent_dim + input_dim, 128), nn.ReLU(),
            nn.Linear(128, 128), nn.ReLU(),
            nn.Linear(128, input_dim), nn.Tanh()
        )
        self.discriminator = nn.Sequential(
            nn.Linear(input_dim, 64), nn.LeakyReLU(0.2),
            nn.Linear(64, 1), nn.Sigmoid()
        )

    def generate_adversarial(self, x_clean, label, eps=0.1):
        """在 clean 特征附近生成对抗变体"""
        z = torch.randn(x_clean.shape[0], 32).to(x_clean.device)
        x_adv = self.generator(torch.cat([x_clean, z], dim=-1))
        return torch.clamp(x_adv, x_clean - eps, x_clean + eps)
```

#### 1.2 特征预处理

**文件：** `ai-service/gan/preprocessor.py`

```python
class FileFeaturePreprocessor:
    """
    将二进制文件转为 GAN 输入特征向量
    - 定长：截取/填充至 784 字节（28×28）
    - 归一化：[0, 255] → [0.0, 1.0]
    - 备选：14 维统计特征（兼容现有 FEATURE_NAMES）
    """
    def __init__(self, mode='image', size=784):
        self.mode = mode
        self.size = size

    def transform(self, file_path: str) -> torch.Tensor:
        # 读取文件前 size 字节
        # mode='image': 视为 28×28 图像灰度
        # mode='stats': 转为 14 维统计特征向量
        ...
```

#### 1.3 训练脚本

**文件：** `ai-service/train_anomaly_gan.py`

```python
"""
AnomalyGAN 训练脚本
用法:
    python train_anomaly_gan.py \\
        --train-dir ./data/training_samples \\
        --output models/anomaly_gan.pt \\
        --epochs 50 --batch-size 64
"""
# 训练流程:
# 1. 加载良性样本（系统自带 exe、官方安装包等）
# 2. 初始化 AnomalyGAN
# 3. 训练循环: encoder 重建 + discriminator 真假判断
# 4. 保存模型 + 评估指标（AUC-ROC）
```

#### 1.4 训练数据准备

**文件：** `ai-service/scripts/gather_training_data.py`

```python
"""
从系统目录自动收集良性样本用于 AnomalyGAN 训练
- Windows: C:\\Windows\\System32\\*.exe, *.dll
- 排除：已知恶意软件目录
"""
```

---

### Phase 2 — 集成与推理（1.5 周）

#### 2.1 GAN 检测器集成

**文件：** `ai-service/gan/detector.py`

```python
class GANAnomalyDetector:
    """
    AnomalyGAN 推理服务
    输入: 文件路径
    输出: {'is_anomaly': bool, 'reconstruction_error': float, 'confidence': float}
    """
    def __init__(self, model_path, device='cpu'):
        self.model = AnomalyGAN().to(device)
        self.model.load_state_dict(torch.load(model_path, map_location=device))
        self.model.eval()
        self.preprocessor = FileFeaturePreprocessor()

    def detect(self, file_path: str) -> dict:
        x = self.preprocessor.transform(file_path)
        x_recon, z, d_out = self.model(x)
        recon_error = F.mse_loss(x, x_recon).item()
        # 重构误差 > 阈值 → 异常
        return {
            'reconstruction_error': round(recon_error, 6),
            'is_anomaly': recon_error > self.anomaly_threshold,
            'confidence': round(1.0 - recon_error, 4),
        }
```

#### 2.2 多引擎集成

修改 `server/services/multiEngineScanService.js`：

```javascript
// 新增第 8 个引擎
{
    name: 'GAN异常检测',
    key: 'gan_anomaly',
    icon: 'brain',
    engine: () => this._scanGANAnomaly(file.path)
}

async _scanGANAnomaly(filePath) {
    // 调用 Python GAN 服务 /api/gan/anomaly
    // 返回 { verdict, confidence, reconstruction_error }
}
```

修改 `server/routes/virus.js`，新增 GAN 分析路由：
- `POST /api/virus/gan-analyze` — 文件 GAN 异常分析
- `GET /api/virus/gan/model-status` — 模型状态查询

#### 2.3 GAN 投票融合

在 `multiEngineScanService.js` 中引入 GAN 投票逻辑：

```javascript
function voteResult(engineResults) {
    const ganResult = engineResults.gan_anomaly;
    // GAN 异常分数权重 0.3（辅助权重，不替代规则引擎）
    // 规则引擎 malicious + GAN anomaly → 强制提升为 malicious
    // GAN anomaly + 规则 clean → 提升为 suspicious（二次确认）
}
```

---

### Phase 3 — 对抗鲁棒性增强（1.5 周）

#### 3.1 对抗训练循环

**文件：** `ai-service/train_adversarial.py`

```python
"""
对抗训练脚本 — 用 GAN 生成的对抗样本增强 malware_detector
训练流程:
  1. 加载 GBDT 模型（由 train_malware_model.py 产出）
  2. 用 AdversarialGAN 生成对抗样本（epsilon=0.1）
  3. 将对抗样本加入训练集，重新训练 GBDT
  4. 评估对抗鲁棒性（accuracy on adversarial test set）
"""
```

#### 3.2 Prompt 对抗测试

**文件：** `ai-service/gan/prompt_adversarial.py`

```python
"""
对抗性 Prompt 生成器
用于红队测试 PromptGuard 的覆盖盲区
生成策略:
  - 字符级扰动：同音字替换、Unicode 规范化变体
  - 语义级扰动： paraphrase + 注入指令混合
  - 编码级扰动：Base64/rot13 多层嵌套
"""
class PromptAdversarialGenerator:
    def generate(self, base_prompt: str, n_variants: int = 10) -> list:
        """生成 n 个对抗变体"""
        ...

    def test_promptguard(self, variants: list) -> dict:
        """批量测试 PromptGuard 检测率"""
        ...
```

#### 3.3 自动化对抗训练 pipeline

**文件：** `ai-service/scripts/adv_training_pipeline.py`

```bash
# 一键运行完整对抗训练流程
python scripts/adv_training_pipeline.py \
    --gan-model models/anomaly_gan.pt \
    --malware-model models/malware_detector.pkl \
    --output models/malware_detector_v2.pkl
```

---

### Phase 4 — 生产化与监控（1 周）

#### 4.1 模型版本管理

**文件：** `server/db/migrations/015_create_gan_models.js`

```sql
CREATE TABLE IF NOT EXISTS gan_models (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    model_path TEXT NOT NULL,
    trained_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    metrics JSON,
    status TEXT DEFAULT 'active'
);
```

#### 4.2 监控指标

| 指标 | 说明 | 告警阈值 |
|------|------|---------|
| GAN 重构误差均值 | 整体文件分布漂移 | > 1.5× 基线 |
| GAN 异常检出率 | 每小时异常文件数 | > 10%/小时 |
| GAN 误报率 | 良性文件被判异常 | > 5% |
| 对抗样本生成量 | 每小时测试变体数 | — |
| PromptGuard 逃逸率 | GAN 生成的 prompt 逃逸比例 | > 20% |

#### 4.3 API 端点

| 端点 | 方法 | 功能 |
|------|------|------|
| `/api/gan/anomaly` | POST | 单文件 GAN 异常检测 |
| `/api/gan/anomaly/batch` | POST | 批量文件 GAN 检测 |
| `/api/gan/adv-generate` | POST | 生成对抗样本（红队测试） |
| `/api/gan/model-status` | GET | 查询 GAN 模型状态 |

### Phase 2 交付清单

```
server/services/multiEngineScanService.js  新增 _scanGANCHomaly + _ganVoteMerge（+160行）
server/services/aiService.js               新增 callGANAnalysis + callAiServiceJson
server/config/index.js                     新增 gan 配置节点
server/routes/virus.js                     新增 2 个 GAN API 端点
server/test/gan_integration.test.js        6 项集成测试（规则1-4全覆盖）✅
```

### Phase 2 投票融合 4 条规则

| 规则 | 触发条件 | 行为 |
|------|---------|------|
| 规则1 | GAN异常 + maliciousScore < 0.3 | 升级为 suspicious，设 ganBoosted=true |
| 规则2 | GAN异常 + maliciousScore ≥ 0.3 | confidence 提升 15%，设 ganBoosted=true |
| 规则3 | GAN clean + 恶意引擎 ≥ 3 | confidence 降级 10%，设 ganConflicted=true |
| 规则4 | GAN 不可用（skipped/error/missing） | 跳过，维持原决策 |

### Phase 2 新增 API 端点

| 端点 | 方法 | 功能 |
|------|------|------|
| `/api/virus/gan-analyze` | POST | 单独调用 GAN 异常检测 |
| `/api/virus/gan/model-status` | GET | 查询 GAN 模型状态 |
| `/api/gan/metrics` | GET | 查询 GAN 监控指标 |
| `/api/gan/prompt-test` | POST | 运行 Prompt 对抗测试 |

---

## 四、文件清单

### 新增文件（15 个）

| 文件 | 说明 | 类型 |
|------|------|------|
| `ai-service/gan/__init__.py` | GAN 模块入口 | Python 包 |
| `ai-service/gan/anomaly_gan.py` | AnomalyGAN 模型定义 | PyTorch |
| `ai-service/gan/adversarial_gan.py` | AdversarialMalwareGAN | PyTorch |
| `ai-service/gan/prompt_adversarial.py` | Prompt 对抗生成器 | Python |
| `ai-service/gan/preprocessor.py` | 文件特征预处理 | Python |
| `ai-service/gan/detector.py` | GAN 推理服务 | Python |
| `ai-service/gan/trainer.py` | GAN 训练循环 | Python |
| `ai-service/gan/metrics.py` | 评估指标计算 | Python |
| `ai-service/train_anomaly_gan.py` | AnomalyGAN 训练入口 | Python |
| `ai-service/train_adversarial.py` | 对抗训练入口 | Python |
| `ai-service/scripts/gather_training_data.py` | 训练数据收集 | Python |
| `ai-service/scripts/adv_training_pipeline.py` | 对抗训练 Pipeline | Python |
| `ai-service/test_gan.py` | GAN 单元测试 | pytest |
| `server/db/migrations/015_create_gan_models.js` | GAN 模型元数据表 | SQL |
| `ai-service/routes/gan.py` | Flask GAN 路由 | Python |

### 修改文件（4 个）

| 文件 | 修改内容 |
|------|---------|
| `ai-service/app.py` | 注册 GAN 路由 |
| `ai-service/requirements.txt` | 新增 torch、torchaudio（如有需要） |
| `server/routes/virus.js` | 新增 GAN 分析 API |
| `server/services/multiEngineScanService.js` | 新增 GAN 引擎 + 投票融合 |

---

## 五、依赖与兼容性

### Python 依赖变更

```txt
# requirements.txt 新增
torch>=2.0.0          # 已存在，无需变更
torchaudio>=2.0.0     # 可选，仅用于音频异常检测
```

### Node.js 依赖

无新增依赖，仅修改 `aiService.js` 调用 Python GAN 服务。

### 向后兼容

- GAN 引擎作为 **辅助权重**（confidence 权重 0.3），不影响现有规则引擎结果
- GAN 模型不可用时自动降级为纯规则引擎（与现有 `model_loaded` 机制一致）
- 数据库迁移 015 为增量新增，不修改任何现有表结构

---

## 八、实施状态

| Phase | 状态 | 完成日期 | 提交 |
|-------|------|---------|------|
| Phase 1 — 基础框架 | ✅ 完成 | 2026-08-11 | `f713f14` / 标签 `v1.3.0-gan-phase1` |
| Phase 2 — 集成推理 | ✅ 完成 | 2026-08-11 | `a8e2c5f` / 标签 `v1.3.0-gan-phase2` |
| Phase 3 — 对抗增强 | ⏳ 规划中 | — | — |
| Phase 4 — 生产化 | ⏳ 规划中 | — | — |

### Phase 1 交付清单

```
ai-service/gan/
  anomaly_gan.py        AnomalyGAN 模型（Encoder-Decoder + Discriminator）
  adversarial_gan.py    AdversarialGAN（对抗样本生成器）
  preprocessor.py       文件特征预处理（image/stats 双模式）
  metrics.py            评估指标（AUC/F1/precision/recall）
  trainer.py            训练循环
  detector.py           GAN 推理服务

ai-service/models/
  anomaly_gan.pt        训练好的异常检测模型（5.1MB）
  adversarial_gan.pt    训练好的对抗生成模型（118KB）

ai-service/train_anomaly_gan.py   AnomalyGAN 训练入口
ai-service/train_adversarial.py   AdversarialGAN 训练入口
ai-service/test_gan.py            22 项单元测试全部通过 ✅
ai-service/scripts/generate_training_samples.py  合成数据生成器
```

### 训练结果

```
AnomalyGAN:  50 良性样本, 20 epochs, batch=16
  final_recon_loss: 0.0518
  训练耗时: 1.1s (CPU)

AdversarialGAN: 50 样本, 20 epochs, batch=16
  best_D_acc: 0.6429
  final_G_loss: 0.6832
  训练耗时: 0.3s (CPU)
```

### 新增 API 端点

| 端点 | 方法 | 功能 |
|------|------|------|
| `/api/gan/anomaly` | POST | 单文件 GAN 异常检测 |
| `/api/gan/anomaly/batch` | POST | 批量检测 |
| `/api/gan/adv-generate` | POST | 生成对抗样本（红队测试） |
| `/api/gan/model-status` | GET | 查询 GAN 模型状态 |
| `/api/gan/metrics` | GET | 查询监控指标 |

---

## 六、风险评估

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|---------|
| 训练数据不足（无恶意样本） | 高 | 中 | 使用开源样本集（MalwareBazaar API）或合成数据 |
| GAN 训练不稳定（模式崩溃） | 中 | 中 | 使用 WGAN-GP 替代标准 GAN，添加梯度惩罚 |
| CPU 推理延迟过高 | 低 | 中 | 模型量化（INT8），批处理推理 |
| 对抗样本逃逸现有检测器 | 中 | 高 | 对抗训练闭环，持续迭代 PromptGuard 正则 |
| 误报率过高影响用户体验 | 中 | 中 | GAN 异常结果仅标记为 suspicious，需人工确认 |

---

## 七、验收标准

### 单元测试（pytest）

```
ai-service/test_gan.py
  test_anomaly_gan_forward ✓
  test_anomaly_gan_reconstruction_error ✓
  test_adversarial_gan_generate ✓
  test_prompt_adversarial_generator ✓
  test_file_preprocessor_image_mode ✓
  test_file_preprocessor_stats_mode ✓
```

### 集成测试

```
POST /api/gan/anomaly → { is_anomaly: bool, score: float }
POST /api/gan/adv-generate → { variants: [...], n: int }
POST /api/virus/upload → 包含 gan_anomaly 引擎结果
```

### 性能指标

| 指标 | 目标值 |
|------|--------|
| GAN 单文件推理延迟 | < 200ms（CPU） |
| GAN 异常检测 AUC-ROC | ≥ 0.85 |
| 对抗样本生成数量/分钟 | ≥ 100 variants |
| PromptGuard 逃逸率（测试后） | < 5% |

---

## 八、时间规划

| Phase | 工期 | 主要交付物 |
|-------|------|-----------|
| Phase 1 — 基础框架 | 2 周 | AnomalyGAN + AdversarialGAN + 训练脚本 |
| Phase 2 — 集成推理 | 1.5 周 | GAN 检测器 + 多引擎集成 + API |
| Phase 3 — 对抗增强 | 1.5 周 | 对抗训练 Pipeline + Prompt 红队测试 |
| Phase 4 — 生产化 | 1 周 | 模型版本管理 + 监控指标 + 文档 |
| **总计** | **6 周** | GAN 对抗安全能力完整闭环 |

---

## 九、技术栈总结

```
ai-service/
  gan/                         ← 新增 GAN 模块
    anomaly_gan.py            ← AnomalyGAN（重构误差异常检测）
    adversarial_gan.py        ← AdversarialGAN（对抗样本生成）
    prompt_adversarial.py     ← Prompt 对抗生成器
    preprocessor.py           ← 文件特征预处理
    detector.py               ← GAN 推理服务
    trainer.py                ← 训练循环
    metrics.py                ← 评估指标
  train_anomaly_gan.py        ← AnomalyGAN 训练入口
  train_adversarial.py        ← 对抗训练入口
  scripts/
    gather_training_data.py   ← 训练数据收集
    adv_training_pipeline.py  ← 对抗训练 Pipeline
  routes/gan.py               ← Flask GAN 路由
  test_gan.py                 ← 单元测试

server/
  db/migrations/015_gan_models.js  ← 模型元数据表
  routes/virus.js               ← 新增 GAN 分析端点
  services/multiEngineScanService.js ← 新增 GAN 引擎
```
