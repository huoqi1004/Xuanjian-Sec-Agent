# 玄鉴安全智能体 - 后续迭代清单

> 版本：v1.0 ｜ 生成日期：2026-08-08
> 说明：ROADMAP Phase 0-5 已全部交付后，梳理的**遗留待办与后续增强**清单，按优先级分类，供下一轮迭代排期。
> 关联文档：[ROADMAP.md](./ROADMAP.md)

---

## 一、总览

| 编号 | 项目 | 优先级 | 来源阶段 | 状态 |
|------|------|--------|----------|------|
| N-01 | 对象级细粒度 RBAC | P0 | Phase 5 | ✅ 已完成 |
| N-02 | 业务数据按组织（租户）隔离 | P0 | Phase 5 | ✅ 已完成 |
| N-03 | 依赖安全加固（npm audit / multer / html-pdf） | P0 | Phase 0 | ✅ 已完成 |
| N-04 | 扫描安全管控（CIDR 白名单 / 速率控制 / 审批） | P0 | Phase 2 | ✅ 已完成 |
| N-05 | 前端工程化质量门禁（ESLint + Prettier） | P0 | Phase 0 | ✅ 已完成 |
| N-06 | 数据库抽象层（MySQL 8/PG + DAO + 迁移） | P1 | Phase 3 | 待排期 |
| N-07 | 任务队列全面接入（BullMQ / Redis） | P1 | Phase 3 | 待排期 |
| N-08 | 可观测性增强（Grafana + OpenTelemetry + 失败率告警） | P1 | Phase 3 | 待排期 |
| N-09 | 扫描 worker 容器化 + 协议扩展（UDP/ICMP/ARP） | P1 | Phase 2 | 待排期 |
| N-10 | 时序数据接入与归档 | P1 | Phase 3 | 待排期 |
| N-11 | 备份恢复演练脚本 | P1 | Phase 3 | 待排期 |
| N-12 | CI/CD 部署流水线（docker build → 部署） | P1 | Phase 3 | 待排期 |
| N-13 | 恶意代码检测真实样本训练（F1 ≥ 0.9） | P1 | Phase 1 | 待排期 |
| N-14 | 投毒检测样本集验证（准确率 ≥ 0.85） | P1 | Phase 1 | 待排期 |
| N-15 | LLM 成本优化（本地小模型 / prompts 集中 / Token 看板） | P1 | Phase 1 | 待排期 |
| N-16 | 知识库管理后台（导入 / 更新 / 版本） | P1 | Phase 4 | 待排期 |
| N-17 | Agent 工作台 UI（计划步骤展示 / 确认交互） | P1 | Phase 4 | 待排期 |
| N-18 | 威胁情报源扩展 + IOC 失效回收 | P1 | Phase 2 | 待排期 |
| N-19 | 拖拽式 SOAR 可视化编排 | P2 | Phase 5 | 待排期 |
| N-20 | 领导视图数据大屏页 | P2 | Phase 5 | 待排期 |
| N-21 | 报告统一模板引擎 | P2 | Phase 5 | 待排期 |
| N-22 | 设备详情"检查执行"入口 UI | P2 | Phase 2 | 待排期 |
| N-23 | 真实动作适配器（交换机 / 云安全组） | P2 | Phase 5 | 待排期 |
| N-24 | 测试覆盖补全（Vitest / 覆盖率 ≥ 70%） | P1 | Phase 3 | 待排期 |

---

## 二、P0 安全与合规（下一轮优先）

### N-01 对象级细粒度 RBAC
- **现状**：RBAC 为 URL 前缀 + HTTP 方法级（`role_permissions`），管理员/审计员/普通用户三角色。
- **目标**：资源实例级权限，如"仅可查看本人创建的扫描任务/剧本"，数据越权访问被拒。
- **涉及**：`middleware/rbac.js`、`routes/*`、`frontend-app/src/layouts`。
- **依赖**：N-02（对象归属需先有组织/创建人维度）。
- **验收**：普通用户访问他人资源返回 403；权限变更即时生效并可审计。

### N-02 业务数据按组织（租户）隔离
- **现状**：仅用户管理按 `org_id` 过滤；扫描/病毒/等保/报告等业务表未隔离。
- **目标**：非管理员仅可见本组织业务数据（扫描任务、查杀记录、等保任务、剧本）。
- **涉及**：`services/scanService.js`、`virusService.js`、`djppService.js` 等列表查询；`middleware/tenant.js` 已就绪。
- **依赖**：shim 查询能力有限，建议随 N-06 数据层迁移一并接入；短期可在 service 层内存过滤。
- **验收**：A 组织用户查询不到 B 组织数据（接口级实测）。

### N-03 依赖安全加固
- **现状**：`npm audit` 报告 13 个漏洞；`multer@1.4.5-lts.1` 偏旧；`html-pdf` 依赖已弃用的 PhantomJS。
- **目标**：`npm audit` 清零或仅剩无可利用项；升级 multer 2.x；以 pdfkit 方案替换 html-pdf。
- **涉及**：`server/package.json`、`virus.js`（上传）、`pdfService.js`。
- **验收**：`npm audit` 通过；上传与 PDF 导出回归测试全绿。

### N-04 扫描安全管控
- **现状**：扫描目标与端口范围无 CIDR 白名单/速率限制/审批。
- **目标**：非法目标拒绝；并发/速率受限；大型扫描任务需人工审批；扫描行为全量审计。
- **涉及**：`services/scanService.js`、`scanEngine.js`、`routes/scan.js`。
- **验收**：白名单外目标创建任务被拒；审计日志可追溯扫描发起人/目标/参数。

### N-05 前端工程化质量门禁
- **现状**：有 `vue-tsc` 类型检查，无 ESLint/Prettier。
- **目标**：接入 ESLint + Prettier + husky/lint-staged，代码风格统一、CI 拦截低质变更。
- **涉及**：`frontend-app/`、`.github/workflows/ci.yml`。
- **验收**：CI 增加 lint 步骤；全库代码风格一致。
- **实现**（2026-08-08）：`eslint.config.js`（flat config：JS 推荐 + TS 推荐 + vue flat/recommended + prettier）+ `.prettierrc.json`；`lint/lint:fix/format/format:check` 脚本；全库 Prettier 格式化 + ESLint 修复至 **0 errors / 0 warnings**；修复 `Assistant.vue` v-html XSS（formatContent 先转义再渲染）；CI `frontend-build` 增加 ESLint + Prettier 检查步骤；验收通过。

---

## 二·补充 本轮实现记录（2026-08-08）

### N-01/N-02 租户与对象级权限（一体推进）
- `server/utils/tenantHelpers.js`（新建）：`orgUserIds` / `inOrg`（组织过滤）/ `isOwner`（对象级）。
- 接入服务：`scanService.js`（列表/详情/删除）、`virusService.js`、`multiEngineScanService.js`（扫描历史/报告含 `scannedBy`）、`djppService.js`（任务/报告）、`playbookService.js`（列表/详情/执行）、`routes/reports.js`（列表/详情/删除/生成）。
- 路由接入 `tenantScope`：`scan.js`、`virus.js`、`djpp.js`、`playbook.js`、`reports.js`。
- 修复 `middleware/rbac.js` 路径匹配 bug（`req.route.path` 子路径 ↔ 权限表全路径不匹配导致非管理员全 403），改为 `baseUrl + route.path`。
- 修复 `middleware/auth.js`：从 DB 实时加载 `org_id/role_id`（JWT 不含 org_id，导致隔离失效；同时满足"权限变更即时生效"）。
- 修复 `scanService.startScan` INSERT 混合字面量导致 `created_by` 为空（内存 shim 参数按位置映射）。
- `init.js` 为角色 2/3 增加 `/api/playbook` 权限；迁移 `007_playbook_permissions.js` 为存量库补齐。
- 验收：`server/test/tenant.test.js` 7 用例（跨组织列表隔离/详情越权/删除越权/剧本执行隔离/报告隔离/管理员放行）全绿。

### N-03 依赖安全加固
- 升级：`multer ^1.4.5-lts.1 → ^2.0.0`、`axios ^1.6.0 → ^1.18.0`、`nodemailer ^6.10.1 → ^9.0.0`、`uuid ^9 → ^11.0.0`、`node-cron ^3.0.3 → ^4.0.0`。
- 移除 `html-pdf`（依赖已弃用 PhantomJS + request，无代码引用，PDF 走 pdfkit）。
- 结果：`npm audit` 13 个漏洞 → **0 vulnerabilities**。

### N-04 扫描安全管控
- 目标 CIDR 白名单：`config.scan.allowedCidrs`（默认内网段，`SCAN_ALLOWED_CIDRS` 可配），`helpers.js` 新增 `ipToInt/isIpInCidr/checkHostsInCidrs`；白名单外目标创建任务直接拒绝（`SCAN_TARGET_DENIED`）。
- 大型任务审批：主机数 > `SCAN_APPROVAL_HOST_THRESHOLD`（默认 256）时任务进入 `pending_approval` 挂起；`POST /api/scan/tasks/:id/review`（approve/reject，仅管理员）审批后入队执行或终止；`scan_tasks` 补 `approved_by/approved_at`（迁移 `006_scan_approval.js`）。
- 验收：`server/test/scanControl.test.js` 5 用例全绿；`npm audit` 归零。

---

## 三、P1 平台与数据

### N-06 数据库抽象层（MySQL 8 / PostgreSQL + DAO）
- **现状**：自研内存 shim（`database.js`），支持 SQL 子集，生产不可规模化。
- **目标**：引入 DAO 抽象层，SQLite 保持开发默认，`DB_DRIVER=mysql|pg` 切换真实数据库；Schema 迁移（migrations）对齐。
- **涉及**：`db/`、全部 `services/*`（查询改造）、`docker-compose.yml`。
- **依赖**：N-02、N-24 依赖此改造后的回归保障。
- **验收**：空库/存量库迁移可执行；同一套业务代码在 SQLite 与 MySQL 双跑测试通过。
- **详细实施步骤与风险评估**：见 [N-06-数据层迁移实施与风险评估.md](./N-06-数据层迁移实施与风险评估.md)（v1.0，2026-08-09）
- **现状基线**：41 个文件直接调用 `getDb()`、282 处 `db.prepare()`、28 张表；shim 仅支持 `SELECT *`/单条件 WHERE/单 JOIN/COUNT，**无事务、无索引、无多条件/子查询/GROUP BY**；最大改造面是 N-02 遗留的"全量 SELECT + 内存过滤"需下推为 SQL 条件。
- **实施步骤**（5 阶段，每批可回滚）：
  1. **A 驱动抽象层**：`sqlite/mysql2/pg` 驱动 + DAO 兼容层（保持 `prepare().get/all/run` 签名），`config` 增 `DB_DRIVER/DB_HOST/...`；
  2. **B Schema DDL + 迁移升级**：28 表 DDL + 列表过滤列索引（`scan_tasks(created_by)`、`virus_scan_records(uploaded_by)`、`reports(generated_by,type)` 等）+ seed 幂等化，迁移执行器按 `DB_DRIVER` 分支（JS 迁移 ↔ SQL 迁移）；
  3. **C 查询下推**（核心，按 C1-C8 分批）：配置/字典 → 扫描 → 查杀 → 等保 → 剧本 → 报告 → 运维审计 → 收尾清除 `_rawTable`（约 15 处）与内存过滤兜底；每批全量测试 + 双跑断言；
  4. **D MySQL/PG 双跑**：docker-compose 加 `mysql:8`，新增 `db-adapters.test.js` 同断言双驱动执行，CI 增 mysql job；PG 补占位符 `?→$n` 转换单测；
  5. **E 部署切换**：备份脚本升级为真实库 dump（联动 N-11），docker-compose 生产 profile。
- **关键风险 Top 3**：R1/R2 查询语义漂移与组织隔离失效（高，靠每批双跑 + 租户断言防回归）；R9 切换窗口数据丢失（高，只读比对 → 短停全量迁移 → 校验行数 → 切换）；R4 事务缺失致脏数据（中，DAO 提供 `transaction()` 包装）。完整 12 项风险矩阵见报告第五节。
- **回滚**：每批独立提交可 `git revert`；保留 `DB_DRIVER=shim/sqlite` 回切窗口；切换前 JSON 快照 + 迁移 `down()` 支持。
- **里程碑**：M1 抽象层+schema+迁移器 → M2 C1-C4 → M3 C5-C8 → M4 MySQL 容器化+双跑+备份升级。
- **执行脚本（M1 已落地，2026-08-09）**：
  - `scripts/n06/generate-schema.js`：从 init.js/迁移自动提取 28 表 → 生成 SQLite/MySQL/PG 三方言 DDL（`server/db/schema/schema.*.sql`）；
  - `scripts/n06/run-migrations.js`：真实库建表 + SQL 增量迁移 + 幂等记录（`node scripts/n06/run-migrations.js`，`DB_DRIVER=mysql` 时走 MySQL）；
  - `server/db/dao.js` + `server/db/drivers/{base,sqlite,mysql,pg}.js`：驱动抽象层，`DB_DRIVER=sqlite|mysql|pg|shim` 切换，`transaction()` 事务包装（R4 缓解）；SQLite 双后端（better-sqlite3 → Node 内置 node:sqlite 回退，R10 缓解）；
  - `scripts/n06/start-mysql.ps1`：本地 MySQL 容器一键起库 + 迁移 + 双跑测试；
  - `scripts/n06/README.commands.md`：全阶段执行命令手册；
  - `server/test/db-adapters.test.js`：SQLite/MySQL 双驱动 CRUD + 事务断言（本机 SQLite 7 例通过）；CI 新增 `db-adapter-test` job（mysql 服务双跑）；
  - `docker-compose.yml` 增 `mysql` profile；`.env.example`/`server/config` 增 `DB_DRIVER/DB_HOST/...`。
  - **待办（M2-M4）**：C1-C8 服务层查询下推（当前 87 Jest 用例仍走 shim 路径，服务层尚未接入 `getDao()`）；seed 数据 SQL 迁移（`migrations/sql/`）。

### N-07 任务队列全面接入（BullMQ / Redis）
- **现状**：`queue.js` 已抽象，扫描任务入队；情报采集/报告生成/防御动作仍为同步执行。
- **目标**：全部异步任务接入队列；`QUEUE_DRIVER=bullmq` 生产可用（Redis 高可用可选）。
- **涉及**：`situationalService.js`、`reportService.js`、`defenseService.js`、`queue.js`。
- **验收**：情报采集/周报生成/剧本执行均走队列并可观测积压/重试。

### N-08 可观测性增强
- **现状**：`/metrics`（Prometheus 文本）、结构化日志、traceId、健康告警已就绪。
- **目标**：Grafana 看板（系统健康/业务/AI 成本）；OpenTelemetry 全链路（请求→服务→AI→DB）；AI 调用失败率告警。
- **涉及**：部署侧（docker-compose 加 Grafana/Prometheus/Loki）、`utils/metrics.js`、`aiService.js`。
- **验收**：扫描/查杀请求在 Jaeger/OTel 中可全链路追踪；服务异常 1 分钟内告警。

### N-09 扫描 worker 容器化 + 协议扩展
- **现状**：nmap/masscan 适配已在 `scanEngine.js`，单进程回退 Node 引擎。
- **目标**：扫描 worker 容器化（nmap/masscan 随镜像分发），UDP/ICMP/ARP 协议支持，万级 IP × 千端口验证。
- **涉及**：`Dockerfile.scan-worker`、`scanEngine.js`、docker-compose。
- **依赖**：N-07 消息队列分发。
- **验收**：分布式扫描任务正确聚合结果；无 nmap 环境仍回退内置引擎。

### N-10 时序数据与归档
- **现状**：态势/告警历史存普通表，保留策略（retentionService）已清理过期数据。
- **目标**：高吞吐告警/指标入 ClickHouse/InfluxDB（可选，规模驱动）；归档策略联动。
- **涉及**：`situationalService.js`、部署侧。
- **验收**：告警历史查询在大数据量下保持可用；归档可恢复。

### N-11 备份恢复演练
- **现状**：每日备份脚本 + 轮转已就绪（`scripts/backup.js`）。
- **目标**：恢复演练脚本（备份→清库→恢复→校验行数/数据一致性），并纳入 CI 或定时演练。
- **涉及**：`scripts/`、`tests/`。
- **验收**：演练脚本可在空环境完整恢复并校验通过。

### N-12 CI/CD 部署流水线
- **现状**：GitHub Actions 已覆盖 lint→unit→integration→build。
- **目标**：docker build（server/ai/frontend）→ 推镜像 → 部署（SSH/docker-compose up）→ 健康检查。
- **涉及**：`.github/workflows/ci.yml`、`Dockerfile.server`、`Dockerfile.ai`、`docker-compose.yml`。
- **验收**：主干合并自动构建并部署到测试环境，健康检查通过。

---

## 四、P1 AI 能力深化

### N-13 恶意代码检测真实样本训练（F1 ≥ 0.9）
- **现状**：`train_malware_model.py` 就绪，14 维特征 + GBDT，缺真实样本。
- **目标**：接入 MalwareBazaar/EMBER 公开样本，产出 `malware_detector.pkl` v2，测试集 F1 ≥ 0.9。
- **涉及**：`ai-service/`、`models/`。
- **注意**：样本获取合规（标注来源），不提交二进制样本入库。
- **验收**：训练可复现，指标 json 达标，检测接口返回 model_version=v2。

### N-14 投毒检测样本集验证（准确率 ≥ 0.85）
- **现状**：确定性统计规则引擎已就绪（模型/数据集/供应链三类），缺样本验证。
- **目标**：构造投毒/正常样本集，验证准确率 ≥ 0.85 并固化为回归测试。
- **涉及**：`ai-service/poisoning_detector.py`、`test_contract.py`。
- **验收**：样本集回归测试全绿，检测依据（anomalies）可解释。

### N-15 LLM 成本优化
- **现状**：恶意/投毒检测已零 LLM；报告类仍调 DeepSeek。
- **目标**：低敏感任务切换本地小模型；Prompt 模板集中到 `prompts/`；Token 用量统计与成本看板（指标）。
- **涉及**：`ai-service/llm_report.py`、`server/services/aiService.js`、`utils/metrics.js`。
- **验收**：LLM 调用量下降 ≥ 50%；成本看板可视化。

### N-16 知识库管理后台
- **现状**：RAG 检索/列表 API 已就绪，知识条目为静态 JSON。
- **目标**：管理后台（文档导入/编辑/版本/启停），写入知识源供检索实时生效。
- **涉及**：`ai-service/rag.py`（写入接口）、`frontend-app`（管理页）、`routes/ai.js`。
- **验收**：新增/停用知识条目后检索结果实时反映。

### N-17 Agent 工作台 UI
- **现状**：多步 Agent 接口完备（规划/执行/确认），无前端界面。
- **目标**：Agent 工作台：任务输入、计划步骤展示、逐步结果、高危确认弹窗。
- **涉及**：`frontend-app/src/views/Assistant.vue` 或新页面、`routes/ai.js`。
- **验收**："分析内网资产风险"在工作台可视化完成并展示中间结果。

### N-18 威胁情报源扩展 + IOC 回收
- **现状**：OTX/CISA 采集 + SOURCE_TRUST + 联动告警已闭环。
- **目标**：接入微步、奇安信（API 可配置）；IOC 过期自动置 `intel_status=inactive`（调度任务）。
- **涉及**：`situationalService.js`、`threatIntelligence.js`、`.env.example`。
- **验收**：多源情报入库去重正确；过期 IOC 定时回收并可查历史。

---

## 五、P2 产品体验

### N-19 拖拽式 SOAR 可视化编排
- **现状**：Playbook 引擎完备，前端为步骤 JSON 编辑。
- **目标**：拖拽画布（条件/动作/审批/通知/等待节点连线），保存为剧本 JSON 落地。
- **涉及**：`frontend-app`（新编排画布组件，可基于 vue-flow/x6）。
- **依赖**：N-05 质量门禁先行。
- **验收**：非技术用户可拖拽生成可执行剧本。

### N-20 领导视图数据大屏页
- **现状**：`/api/reports/overview` 聚合端点已就绪。
- **目标**：大屏页（风险排行/合规态势/告警趋势/资产概览），暗色主题，适合投屏。
- **涉及**：`frontend-app/src/views`（新页面）、Dashboard 复用 ECharts。
- **验收**：大屏在 1080p 投屏分辨率下无溢出，数据自动刷新。

### N-21 报告统一模板引擎
- **现状**：等保/基线/查杀/周月报各自生成，格式不统一。
- **目标**：统一 Markdown/PDF/DOCX 模板引擎（章节/水印/页脚一致）。
- **涉及**：`reportService.js`、`pdfService.js`、`llm_report.py`。
- **验收**：五类报告同风格输出，批量导出一次到位。

### N-22 设备详情"检查执行"入口 UI
- **现状**：Device.vue 可下发指令，无针对单设备的检查项执行视图。
- **目标**：设备详情页：发起基线/等保检查、查看命令结果、最近心跳指标。
- **涉及**：`frontend-app/src/views/Device.vue`、`deviceService.js`。
- **验收**：对 Agent 主机一键发起检查并展示结果。

### N-23 真实动作适配器（交换机 / 云安全组）
- **现状**：SOAR 适配器为本地落库模拟（firewall_block 写日志+告警）。
- **目标**：对接真实设备：交换机 ACL、云安全组（阿里云/腾讯云 API）、SIEM Webhook。
- **涉及**：`services/adapters.js`、配置化凭据管理。
- **注意**：高危动作保留人工审批，凭据加密存储。
- **验收**：在测试环境完成一次真实封禁动作并留痕。

---

## 六、质量与测试

### N-24 测试覆盖补全（Vitest / 覆盖率 ≥ 70%）
- **现状**：Jest 69 用例 + Pytest 11 用例全绿，覆盖率统计已配置。
- **目标**：补规则引擎策略、RBAC、报告生成、哈希计算用例；前端 Vitest 关键组件测试；核心服务覆盖率 ≥ 70%。
- **涉及**：`server/test/`、`frontend-app`（vitest 配置）、`.github/workflows/ci.yml`。
- **验收**：CI 输出覆盖率报告且 ≥ 70%；前端关键组件用例进入 CI。

---

## 七、排期建议

1. **下一轮（P0 安全合规）**：✅ 已完成（2026-08-08）——N-01 + N-02（租户与对象级权限一体推进）→ N-04（扫描管控）→ N-03（依赖安全）→ N-05（前端门禁）。
2. **并行（数据与平台）**：N-06（数据层迁移）是 N-02/N-10 的前置，尽早启动；N-07/N-08 可随 N-06 一并改造。
3. **AI 深化**：N-13/N-14（样本训练）耗时最长，尽早启动；N-15 降本紧随。
4. **体验增强**：N-19/N-20/N-21 在平台稳定后开展。
5. 每项完成后沿用既有验收标准（勾选清单 + 实测 + 测试全绿）。
