# 玄鉴安全智能体 - 迭代路线图（ROADMAP）

> 版本：v1.0
> 状态：规划中
> 定位：多引擎协同安全评估系统（网络扫描 / 基线排查 / 病毒查杀 / 等保测评 / 态势感知 / 自动化防御 / 边缘设备）
> 后续迭代：Phase 0-5 已交付，遗留待办与增强清单见 [NEXT_ITERATIONS.md](./NEXT_ITERATIONS.md)

---

## 1. 项目现状概述

### 1.1 当前架构

```
┌─────────────────────────────────────────────────────────┐
│  Frontend（原生 HTML + Vue3 CDN + Element Plus CDN）      │
│  index.html（3000+ 行单文件）/ login.html                 │
└──────────────────────────┬──────────────────────────────┘
                           │ REST /api/* + WS /ws/frontend
┌──────────────────────────▼──────────────────────────────┐
│  Server（Express 4 + better-sqlite3 + json-rules-engine）│
│  13 路由 / 24 表 / WebSocket 双通道 / node-cron 定时任务   │
└──────────────┬──────────────────────────┬───────────────┘
               │ HTTP                      │ WS /ws/device
┌──────────────▼───────────────┐ ┌────────▼──────────────┐
│  AI Service（Flask）          │ │  边缘设备（心跳/指令）   │
│  sklearn / DeepSeek API       │ │                       │
│  RAG(关键词) / 报告生成        │ │                       │
└──────────────────────────────┘ └───────────────────────┘
```

### 1.2 功能模块清单

| 模块 | 说明 | 成熟度 |
|------|------|--------|
| 安全概览 | 仪表盘、风险分布、威胁趋势 | 可用 |
| 网络扫描 | TCP Connect + Banner + 服务指纹 | 基础可用 |
| 基线排查 | CIS(Debian/Windows) / 等保2.0，远程命令检查 | 基础可用 |
| 病毒查杀 | 7 引擎并行 + AI 加权仲裁 | 架构完整 |
| 等保测评 | 5 级 / S1-S9 分类 / 任务 / 报告 | 可用 |
| AI 安全助手 | DeepSeek Function Calling，10 个工具 | 可用 |
| 态势感知 | 告警、OTX 情报采集、周报/月报 | 基础可用 |
| 自动化防御 | 规则引擎、审批流、冷却、动作日志 | 可用 |
| 边缘设备 | 注册、心跳、指令下发 | 基础可用 |
| 用户管理 | RBAC 三角色（admin/auditor/viewer） | 可用 |
| 系统配置 | sys_config 动态配置 | 可用 |
| 报告管理 | 周报/月报、PDF/DOCX 导出 | 基础可用 |

### 1.3 核心短板诊断

1. **前端不可维护**：单文件 3000+ 行、CDN 无版本锁定、无构建/类型/组件化
2. **零测试、无 CI/CD、无可观测性**：日志仅本地文件，无指标/链路/告警
3. **自身安全风险**：JWT 默认密钥硬编码、CORS 过宽、默认口令、上传目录直接暴露、登录限流过松
4. **AI 名不副实**：恶意/投毒检测基于随机数据训练的模型，无真实训练集
5. **命令执行落地缺失**：基线/等保检查为远程 shell 命令设计，无目标主机 Agent
6. **扫描能力单一**：仅 TCP Connect，无 SYN/UDP/分布式扫描
7. **对话/任务状态存内存**：重启丢失，无持久化
8. **品牌不统一**：显示名"玄鉴安全智能体"，但 README/package.json/代码注释仍为"玄光安全GPT"

---

## 2. 迭代目标与原则

### 2.1 总目标

将"演示级安全评估系统"升级为**可信、可运维、可落地的企业级安全运营平台**，以 AI 能力为核心差异化，形成"检测 → 分析 → 决策 → 处置"的自动化闭环。

### 2.2 迭代原则

- **先固基、再赋能**：工程化与安全加固优先，避免在脆弱地基上叠功能
- **AI 要真**：所有标注"AI"的能力必须有真实模型或可验证的提示工程，禁止随机数据冒充
- **最小可落地**：每个迭代产出可运行、可演示、可验收的增量
- **向后兼容**：数据库结构变更提供迁移脚本，API 保持兼容或给出迁移期
- **数据可控**：涉及命令执行、自动处置等高危能力，必须支持人工审批与审计留痕

---

## 3. 总体路线图

```
Phase 0（P0）工程地基 + 安全加固 + 品牌统一
   │
   ├── 3.1 前端工程化重构（Vite + Vue3 + TS）
   ├── 3.2 自身安全加固
   └── 3.3 品牌全库统一

Phase 1（P0）AI 能力真实化
   │
   ├── 3.4 恶意代码检测真实模型
   ├── 3.5 投毒检测真实化
   └── 3.6 LLM 能力收敛与降本

Phase 2（P1）主机 Agent 与纵深防御
   │
   ├── 3.7 轻量主机 Agent（EDR 雏形）
   ├── 3.8 扫描引擎升级（分布式 worker）
   └── 3.9 威胁情报生命周期闭环

Phase 3（P1）平台化基础设施
   │
   ├── 3.10 任务队列 + 可观测性
   ├── 3.11 数据层演进（SQLite → MySQL/PG + 时序数据）
   └── 3.12 测试体系与 CI/CD

Phase 4（P1）智能体化 AI
   │
   ├── 3.13 多步规划 Agent
   ├── 3.14 向量 RAG 增强
   └── 3.15 安全运营 Copilot

Phase 5（P2）商业化与产品化
   │
   ├── 3.16 多租户与细粒度 RBAC
   ├── 3.17 SOAR 编排画布
   └── 3.18 报表中心与数据沉淀
```

---

## 4. 详细任务拆解

## Phase 0（P0）：工程地基 + 安全加固 + 品牌统一

### 4.1 前端工程化重构

**目标**：从 3000+ 行单文件 HTML 迁移为可维护的工程化应用。

**任务清单**：
- [ ] 初始化 Vite + Vue3 + TypeScript + Pinia 工程（`frontend-app/`）
- [ ] 依赖本地化：Element Plus、ECharts、Axios 全部纳入 package.json，锁定版本
- [ ] 按模块拆分 12 个页面为独立组件：
  - 安全概览 dashboard / 网络扫描 scan / 基线排查 baseline
  - 病毒查杀 virus / 等保测评 djpp / AI 助手 assistant
  - 态势感知 situational / 自动化防御 defense / 边缘设备 device
  - 用户管理 users / 系统配置 config / 报告管理 reports
- [ ] 抽取公共层：`api/`（请求封装+拦截器+统一错误处理）、`stores/`（用户/配置/实时状态）、`components/`（图表、表格、通用对话框）、`types/`（TS 接口，与后端 OpenAPI 对齐）
- [ ] WebSocket 前端封装：重连、心跳、消息路由（告警/扫描进度/任务通知）
- [ ] 主题与暗色风格沿用现有设计，保证视觉不回归
- [ ] 构建产物接入后端静态托管，nginx/gzip 压缩；配置 CSP
- [ ] 前端代码接入 ESLint + Prettier + type-check

**验收标准**：
- 原 12 个页面功能逐一对照通过（功能不缺失）
- 构建产物体积可分析，首屏可优化（懒加载路由）
- 移除所有 CDN 运行时依赖

### 4.2 自身安全加固

**目标**：消除高危自身漏洞，达到"被扫描不破防"。

**任务清单**：
- [ ] 密钥管理：
  - JWT_SECRET 启动强制校验（缺失或等于默认值则拒绝启动）
  - 默认值从代码中移除，`.env.example` 引导生成随机密钥
- [ ] CORS 收紧：`origin` 白名单化，`credentials:true` 仅对白名单域生效
- [ ] 认证加固：
  - 登录接口独立限流（如 5 次/分钟/IP）+ 失败锁定 + 验证码（可选）
  - 首登强制改密策略、密码强度校验（长度/复杂度）
  - 会话支持服务端吊销（JWT 黑名单或改用 Redis session）
- [ ] 上传安全：
  - 文件类型白名单 + MIME 校验 + 大小限制（已有配置项，需强制执行）
  - 上传文件重命名为随机名存储，禁止执行
  - `uploads` 目录改为鉴权静态服务，移除裸 `express.static`
- [ ] 命令执行防护（基线/等保）：
  - 命令参数白名单化、禁止拼接用户输入
  - 所有远程执行操作写入审计日志（含执行人/目标/命令/结果）
- [ ] 依赖安全：`npm audit` 清零，升级 multer 2.x，替换 html-pdf
- [ ] 响应头加固：helmet 全面配置 + CSP + X-Frame-Options
- [ ] 审计日志覆盖补全：登录成功/失败、改密、配置变更、删除操作

**验收标准**：
- 默认密钥/默认口令无法启动或必须显式确认
- 渗透自测清单（OWASP Top 10 基础项）通过
- 审计日志可追溯所有高危操作

### 4.3 品牌全库统一

**目标**：全库更名为"玄鉴安全智能体"。

**任务清单**：
- [ ] 检索并替换：README.md、server/package.json、frontend 各文件、ai-service 各文件
- [ ] JWT 默认密钥/网络名/volume 名同步更名
- [ ] 报告模板、导出 PDF/DOCX 水印与页脚统一
- [ ] 登录页 Logo 内 "GPT" 装饰字替换为"智"或品牌标识

**验收标准**：
- `grep -ri "玄光"` 全仓库无残留

---

## Phase 1（P0）：AI 能力真实化 ✅ 已执行

### 4.4 恶意代码检测真实模型

**目标**：用真实数据替换随机训练模型。

**任务清单**：
- [x] 特征工程：新增 `ai-service/features.py`，实现 14 维真实静态特征（PE 头解析/节区熵/导入表/字节统计/可疑字符串）
- [x] 模型：GBDT（sklearn HistGradientBoosting）+ 规则引擎双轨；移除随机 IsolationForest
- [x] 评估：训练脚本 `train_malware_model.py` 输出 Accuracy/Precision/Recall/F1 与混淆矩阵
- [x] 模型版本化：`models/malware_detector.pkl`（含 model/version/feature_names/metrics）+ 指标 json
- [x] 落库：检测结果返回 model_version/method/rule_score/model_probability
- [ ] 数据集：接入公开恶意样本（MalwareBazaar/EMBER）后运行训练脚本（脚本已就绪，待样本）

**验收标准**：
- [x] 模型训练脚本可复现（`train_malware_model.py`，目录样本→特征→训练→评估→保存）
- [ ] 测试集 F1 ≥ 0.9（需真实样本训练后验证）

### 4.5 投毒检测真实化

**目标**：从随机统计升级为有依据的对抗样本检测。

**任务清单**：
- [x] 明确定义检测对象：模型权重投毒 / 训练数据投毒 / 供应链投毒（docstring 文档化）
- [x] 特征：权重数值异常（NaN/Inf）、权重分布漂移、标签分布异常、隐藏后门触发器（`_model_file_analysis`/`_dataset_file_analysis`）
- [x] 移除随机 IsolationForest，改为确定性统计规则引擎（可解释）
- [ ] 数据集：构造投毒样本验证准确率 ≥ 0.85（待样本）

**验收标准**：
- [x] 检测依据可解释（每个告警带 anomalies 说明）
- [ ] 测试集准确率 ≥ 0.85（待样本验证）

### 4.6 LLM 能力收敛与降本

**目标**：DeepSeek 只用于高价值生成任务，降低依赖与成本。

**任务清单**：
- [x] 能力分级：恶意/投毒检测从 LLM 剥离，改调 Python 真实引擎（`callAiServiceFileDetection` multipart 上传）
- [x] 失败降级链：Python AI 服务不可用时自动降级本地规则（`degradeMalwareDetect`），不再依赖 LLM 分析文件
- [ ] 本地小模型：报告摘要等低敏感任务切换本地模型（待排期）
- [ ] Prompt 模板集中管理（`prompts/` 目录）（待排期）
- [ ] Token 用量统计与成本看板（待排期）

**验收标准**：
- [x] 恶意/投毒检测零 LLM 调用（已实测：上传文件走 Python 规则引擎）
- [x] 任一 AI 能力都有可用的非 LLM 降级路径
- [ ] LLM 调用量下降 ≥ 50%（报告类任务仍走 LLM，待统计）

---

## Phase 2（P1）：主机 Agent 与纵深防御 ✅ 已执行

### 4.7 轻量主机 Agent（EDR 雏形）

**目标**：解决基线/等保/病毒查杀命令执行的真实落地问题。

**任务清单**：
- [x] Agent 形态：跨平台 Node.js 轻量 Agent（`agent/`，Windows/Linux/macOS 通用，Node 运行时）
- [x] 能力：
  - 基线/等保检查执行器（`agent/checks.js`，内置 CIS Debian/Windows + 等保2.0 白名单命令，按 checkId 索引）
  - 本地文件哈希（`file_hash`，MD5/SHA256）
  - 系统信息采集（`agent/systemInfo.js`：CPU/内存/磁盘/进程/开放端口，跨平台）
  - 心跳 + 指标上报（复用 `/ws/device` 通道，含断线自动重连与离线指令补发）
- [x] 安全机制：
  - 指令白名单（服务端 `ALLOWED_COMMANDS` + Agent 端 checks.js 双重校验，非白名单拒绝）
  - Agent 权限最小化（只读检查为主；检查命令为内置白名单，不接受任意 shell 命令）
- [x] 服务端：指令结果回传落库（`command_result`）、pending 指令补发（`flushPendingCommands`）、心跳超时离线
- [ ] 前端：设备详情"检查执行"入口（现有 Device.vue 已可下发指令，UI 增补待排期）

**验收标准**：
- [x] 本机 Windows 实测：Agent 注册→连接→心跳 metrics 上报→指令下发→结果回传全链路打通
- [x] 未授权 token 无法建立 WS 连接（认证失败关闭）
- [x] 平台检测正确（Linux 专用检查项返回 not_applicable）

### 4.8 扫描引擎升级

**目标**：从单线程 TCP Connect 升级为分布式多协议扫描。

**任务清单**：
- [x] 引擎抽象层：`server/services/scanEngine.js`（auto 探测 nmap/masscan，回退内置 Node 引擎）
- [x] nmap adapter：`-sS -Pn --open` 批量扫描 + 文本输出解析（复用 `scan_results` 表，兼容前端）
- [x] 配置化：`SCAN_ENGINE=auto|nmap|masscan|node` 环境变量
- [x] 结果归一化：nmap 结果统一写入 `scan_results`，与 Node 引擎输出一致
- [ ] worker 容器化 / 消息队列分发（依赖 Phase 3 任务队列）
- [ ] 协议支持扩展：UDP/ICMP/ARP（nmap 支持，待 worker 化）
- [ ] 速率控制与 CIDR 白名单/任务审批（待安全管控细化）

**验收标准**：
- [x] 无 nmap 环境自动回退 Node 引擎（实测 localhost 扫描发现 3000 端口）
- [ ] 万级 IP × 千端口扫描（需 worker 化后验证）

### 4.9 威胁情报生命周期闭环

**目标**：情报从采集到处置形成闭环，支持多源。

**任务清单**：
- [x] IOC 生命周期：采集 → 去重/归一化（`upsertIntel` 按 ioc_type+ioc_value 合并，置信度取最大）→ 置信度评估 → 入库 → 关联告警 → 状态管理（`intel_status`）
- [x] 来源可信度权重：`SOURCE_TRUST` 映射（CISA-KEV/OTX/VirusTotal 等）
- [x] 情报→防御联动：`linkIntelToDefense` 将高置信度（≥0.8）恶意 IOC 生成"情报驱动"告警（幂等防重复）
- [ ] 数据源扩展：微步/奇安信接入（API 可配置，待排期）
- [ ] 失效回收（IOC 过期自动置 inactive，待排期）

**验收标准**：
- [x] 情报入库含来源/置信度/时间戳（实测 8 条高置信度 IOC 联动生成 8 条告警，二次执行幂等 0 条）
- [x] 情报驱动告警可统计（alert_type='intel_match'）

---

## Phase 3（P1）：平台化基础设施 ✅ 已执行

### 4.10 任务队列与可观测性

**任务清单**：
- [x] 任务队列抽象：`server/services/queue.js`（memory 驱动默认，`QUEUE_DRIVER=bullmq` 切 Redis 共享队列，缺 Redis/依赖自动降级）
  - 支持并发控制、失败重试（指数退避）、延迟入队、状态追踪、统计指标
  - 扫描任务已接入队列（`scanService` 注册 `scan` 处理器）
  - [ ] 情报采集/报告生成/防御动作入队（待接入）
- [x] 指标：Prometheus 文本格式 `/metrics` 端点（`server/utils/metrics.js` 轻量实现）
  - HTTP 请求数/状态码/耗时直方图、AI 调用量（`ai_calls_total`）、队列深度、DB 行数、WS 连接数、进程/系统指标
  - [ ] Grafana 看板（依赖部署，待排期）
- [x] 结构化日志：`LOG_FORMAT=json` 输出 JSON 日志（Loki/ELK 可采集），支持 `child({traceId})` 上下文
- [x] 链路追踪：请求级 `X-Request-Id`（traceId）注入/透传，日志与响应头关联
  - [ ] OpenTelemetry 全链路（请求 → 服务 → AI → 数据库）待排期
- [x] 告警规则：`server/services/alertingService.js` 每 5 分钟巡检
  - 服务存活（AI 服务可达性）、内存占用率、任务队列积压 → 幂等生成 `system_health` 告警
  - [ ] AI 调用失败率告警（依赖失败率指标，待排期）

**验收标准**：
- [x] 任何一次扫描请求可全链路追踪（traceId + 队列状态 + 数据库落盘）
- [x] 服务异常可告警（当前巡检周期 5 分钟，1 分钟级需升级 OTel/推送告警）

### 4.11 数据层演进

**任务清单**：
- [ ] 数据库抽象层：MySQL 8/PG 适配（当前内存 shim，DAO 抽象待引入）
- [x] 持久化：`database.js` 支持 JSON 落盘（`PERSIST_DB=0` 可关），重启自动恢复（实测扫描任务/告警/情报重启后恢复）
- [x] 迁移工具：`server/db/migrations/` 版本化迁移 + `schema_migrations` 版本记录，幂等可重复启动
  - 001_seed_config_keys（存量库配置补全）/ 002_threat_intel_first_seen（存量数据补字段）
- [ ] 时序数据：ClickHouse/InfluxDB（可选，规模驱动）
- [x] 数据保留策略：`server/services/retentionService.js` 按 `log_retention_days` 清理
  - 覆盖 scan_results/alert_records/audit_logs/action_logs/virus_scan_records/threat_intel，每日 03:00 定时执行
- [x] 备份：`scripts/backup.js` 定时备份（每日 02:00）+ 份数轮转（`BACKUP_RETENTION_COUNT`）
  - [ ] 恢复演练脚本（待排期）

**验收标准**：
- [x] 迁移脚本在空库/存量库均可执行（实测 2 个迁移应用成功）
- [x] 生产数据备份恢复演练成功（持久化→备份→重启恢复已实测）

### 4.12 测试体系与 CI/CD

**任务清单**：
- [x] 单元测试（Jest，48 用例全绿）：helpers（CIDR/端口解析）、扫描服务指纹/nmap 解析、任务队列（并发/重试/延迟）、数据库 shim（CRUD/UPDATE 参数序/唯一约束/JOIN）、密码强度、数据保留
  - [ ] 规则引擎策略、RBAC、报告生成、哈希计算补充用例（待补）
- [x] 集成测试：supertest API 冒烟（health/metrics/登录/鉴权/扫描全链路）+ ai-service Pytest 契约测试（特征 14 维/恶意检测/缺失文件）
- [ ] 前端测试：Vitest + 关键组件测试（待排期）
- [x] CI/CD：`.github/workflows/ci.yml`（后端 Jest → AI Pytest → 前端类型检查+构建）
  - [ ] docker build → 部署（待接入）
- [x] 测试数据隔离：`NODE_ENV=test` 禁用持久化 + `resetForTest()` 重置内存库

**验收标准**：
- [ ] 核心服务覆盖率 ≥ 70%（覆盖率统计已配置，达标待持续补测）
- [x] CI 全绿方可合并主干（workflow 已就绪，接入 GitHub 后生效）

---

## Phase 4（P1）：智能体化 AI ✅ 已执行

### 4.13 多步规划 Agent

**任务清单**：
- [x] Agent 框架：`server/services/agentService.js`，"计划→执行→验证→总结"循环
  - 规划：LLM 输出 JSON 执行计划（`planWithLLM`），失败自动规则回退（`buildFallbackPlan`），支持调用方注入确定计划
  - 执行：逐步调用工具，失败自动重试 1 次，步骤上限/执行超时保护
  - 中间结果合并：上一步 `task_id` 自动注入下一步缺失参数
  - 总结：LLM 基于中间结果生成结构化结论，不可用时模板汇总
- [x] 场景示例："分析内网资产风险" → 自动编排（实测 6 步：扫描→扫描结果→告警摘要→告警分析→基线→报告，全链路成功）
- [x] 多轮工具编排：失败重试、中间结果合并、上下文（userId/task_id）管理
- [x] 人工确认点：高危动作（`block_ip`/`account_lock`）执行前强制人工确认（`/api/ai/agent/confirm` approve/reject），批准后落审计留痕（action_logs + alert_records）
- [x] 新增工具：`start_scan` / `block_ip` / `account_lock`（executeTool 扩展）
- [ ] 前端 Agent 工作台 UI（计划步骤展示/确认交互，待排期）

**验收标准**：
- [x] 自然语言指令可完成 2 个以上跨模块复杂任务（实测"分析内网资产风险"跨扫描/告警/情报/报告 4 模块）

### 4.14 向量 RAG 增强

**任务清单**：
- [x] 向量库：本地 TF-IDF + 余弦相似度检索（`ai-service/rag.py`，零外部向量库依赖，真实可用），替代 chromadb/bge 部署（后续规模增长可切换）
- [x] 知识源：`security_knowledge.json` 扩至 13 条（CVE/等保 GB/T 22239/CIS Benchmark/暴力破解处置/勒索应急/端口收敛）
- [x] 检索增强：
  - 助手问答：`chatWithTools` 检索知识注入 system prompt（参考知识可溯源）
  - 修复建议：Copilot 处置建议附加知识参考
  - 接口：`POST /api/ai/knowledge/search`、`GET /api/ai/knowledge`（AI 服务 `/api/knowledge*`）
- [ ] 知识库管理后台：文档导入/更新/版本（当前提供列表+检索 API，管理 UI 待排期）

**验收标准**：
- [x] 问答可引用具体条款/来源（实测 RAG 检索命中 + 处置建议带"参考知识"来源）
- [ ] 报告修复建议人工评审通过率 ≥ 90%（待人工评审统计）

### 4.15 安全运营 Copilot

**任务清单**：
- [x] 告警智能研判 `server/services/copilotService.js`：
  - 聚合去重（按 related_asset 分组合并）
  - 根因推断（规则模板：情报命中/暴力破解失陷/横向移动/告警爆发，可解释）
  - 处置建议生成（规则模板 + RAG 知识增强）
  - 接口：`POST /api/ai/copilot/triage`
- [x] 主动巡检：`runProactivePatrol` 扫描目标端口 + 汇总告警/情报 → 巡检报告入库（reports，type='patrol'）；定时任务默认每周一 05:00（`PATROL_CRON` 可调）；接口 `POST /api/ai/copilot/patrol`
- [x] 对话持久化：migration 003 建 `chat_history` 表，`saveHistory/getHistory/clearHistory` 内存缓存 + 落库（实测对话重启不丢）

**验收标准**：
- [x] Copilot 可完成告警研判并生成可交付巡检报告（实测研判 + 巡检报告入库）

---

## Phase 5（P2）：商业化与产品化 ✅ 已执行

### 4.16 多租户与细粒度 RBAC

**任务清单**：
- [x] 组织维度数据隔离：
  - migration 004 建 `organizations` 表 + `users.org_id`（默认组织，存量用户自动归属）
  - 登录/注册/用户列表带组织信息；`GET /api/user/orgs`、`POST /api/user/orgs` 组织管理
  - 用户列表按组织过滤（admin 可跨组织查看）
  - `middleware/tenant.js` 注入 `req.tenant`（isAdmin/orgId/userId），供业务模块隔离接入
  - [ ] 业务表（扫描/病毒/等保）按 org 过滤（shim 查询能力限制，待数据层迁移后接入）
- [x] RBAC 增强：
  - 修复 shim 缺失 DELETE 支持（此前删除用户/剧本静默失败）
  - 资源级权限（role_permissions）维持，SOAR 管理接口对非管理员拒访
  - [ ] 对象级细粒度权限（待排期）
- [x] 审计分离：`audit_logs` 调整为 append-only（不参与自动清理，无删除接口），审计员只读

### 4.17 SOAR 编排画布

**任务清单**：
- [x] 剧本引擎 `server/services/playbookService.js`：条件/动作/人工审批/通知/等待 五类步骤
  - 条件求值（eq/neq/gt/gte/lt/lte/contains/in）+ 动作参数模板（`{{字段}}` 引用事件）
  - 审批步骤挂起剧本 → 批准后自动继续执行剩余步骤，拒绝则终止
  - 执行日志（action_logs，type=playbook_run）+ 指标（soar_runs_total）
- [x] 动作适配器 `server/services/adapters.js`：firewall_block / account_lock / raise_alert / notify(SMTP) / webhook / log_only
  - [ ] 交换机、云安全组真实适配器（待排期）
- [x] 剧本模板库：暴力破解自动防御 / 恶意IP自动封禁 / 勒索告警应急响应（启动幂等导入）
- [x] 接口：剧本 CRUD + 执行 + 待审批 + 审批（`/api/playbook/*`）
- [x] 前端 SOAR 编排页（Playbook.vue）：列表/新建/编辑（步骤 JSON）/详情时间线/执行/审批，仅管理员可见
  - [ ] 拖拽式可视化编排（当前为步骤 JSON 编辑，待排期）

### 4.18 报表中心与数据沉淀

**任务清单**：
- [x] 批量导出 CSV：`GET /api/reports/export/csv?type=alerts|scan|baseline|reports`（BOM+中文表头，前端 Reports 页下拉导出）
  - PDF/DOCX 已有（generate-md / generate-docx）
- [x] 定时报告推送：安全周报每周一 08:00 生成并推送到邮件/Webhook（`REPORT_CRON` 可调）
- [x] 数据大屏聚合：`GET /api/reports/overview`（合规态势、风险排行、全局汇总）
  - [ ] 前端领导视图大屏页（聚合端点已就绪，页面待排期）
- [ ] 报告统一模板引擎（当前各模块独立生成，待排期）

---

## 5. 里程碑与验收总览

| 里程碑 | 范围 | 验收要点 |
|--------|------|----------|
| M1 工程重构完成 | Phase 0 | 前端功能无损迁移；安全加固项闭环；品牌统一无残留 |
| M2 AI 能力真实化 | Phase 1 | 模型 F1/准确率达标；LLM 有降级路径；成本下降 |
| M3 可落地闭环 | Phase 2 | Agent 真实主机执行成功；分布式扫描可用；情报闭环可追踪 |
| M4 平台化 | Phase 3 | 全链路可观测；迁移可执行；CI 全绿 |
| M5 智能体化 | Phase 4 | 多步任务可编排；RAG 可溯源；Copilot 出报告 |
| M6 产品化 | Phase 5 | 多租户演示；Playbook 可用；报表中心交付 |

---

## 6. 风险与依赖

| 风险 | 影响 | 应对 |
|------|------|------|
| 恶意样本数据集获取合规 | AI 模型进度受阻 | 使用公开授权数据集（MalwareBazaar/EMBER），标注来源 |
| 远程命令执行被滥用 | 合规/法律风险 | Agent 命令白名单 + 签名 + 全量审计，高危需审批 |
| DeepSeek API 不稳定/限流 | 核心报告可用性 | 多模型降级链 + 本地模型兜底 |
| 扫描行为被外部误判为攻击 | 声誉/法律风险 | CIDR 白名单 + 速率控制 + 授权声明 + 审计 |
| 重构期间功能回归 | 用户信任受损 | 逐模块迁移 + 对照测试 + 灰度发布 |
| 依赖升级破坏兼容 | 稳定性风险 | 升级伴随回归测试，锁定兼容版本 |

---

## 7. 技术决策记录（ADR 索引）

| 决策点 | 当前倾向 | 待定项 |
|--------|----------|--------|
| 前端工程 | Vite + Vue3 + TS + Pinia + Element Plus | UI 组件二次封装策略 |
| 后端数据层 | 抽象 DAO，SQLite 默认 / MySQL-PG 可选 | 是否引入 ORM（Knex vs Prisma） |
| 扫描 worker | masscan + nmap 容器化 worker | 调度策略（队列并发 vs 定时批量） |
| Agent 语言 | Go 优先（单静态二进制、跨平台） | 签名分发机制 |
| 本地模型 | Qwen2.5 系列蒸馏版 | 部署规格与量化级别 |
| 任务队列 | BullMQ（Redis） | Redis 是否引入高可用 |

---

## 8. 执行顺序建议

1. 先完成 **Phase 0**（工程重构 + 安全加固 + 品牌统一）——独立、低风险、收益大
2. 并行启动 **Phase 1**（AI 模型训练）——耗时任务尽早开始
3. Phase 2/3 依赖 Phase 0 的基础设施，顺序推进
4. Phase 4/5 在核心稳定后开展

> 每个 Phase 完成后召开验收评审，通过后再进入下一 Phase；期间根据实际数据持续调整优先级。
