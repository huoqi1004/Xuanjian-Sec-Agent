# ============================================================
# N-06 数据层迁移 · 执行命令手册
# 关联报告: N-06-数据层迁移实施与风险评估.md（五、实施步骤）
# 日期: 2026-08-09
# ============================================================

# ------------------------------------------------------------
# 阶段 A：驱动抽象层（已完成代码，本机已验证）
# ------------------------------------------------------------
# 1) 安装驱动依赖（server/ 下执行）
cd server
npm install better-sqlite3 mysql2 pg

# 2) 验证 DAO 工厂可按 DB_DRIVER 切换
node -e "const {getDao}=require('./db/dao'); console.log(getDao().driverName())"
#   预期: shim（默认，未设 DB_DRIVER 时）

# ------------------------------------------------------------
# 阶段 B：Schema 生成 + 迁移（本机已验证）
# ------------------------------------------------------------
# 1) 重新生成三方言 Schema（修改 init.js/迁移后必须重跑）
node scripts/n06/generate-schema.js
#   产物: server/db/schema/schema.{sqlite,mysql,pg}.sql（28 表 + 10 索引）

# 2) 空库迁移（SQLite，开发默认）
DB_DRIVER=sqlite DB_PATH=./data/dev.db node scripts/n06/run-migrations.js
#   预期日志: SQLite 驱动已连接 -> 应用 schema -> 表数量: 28

# 3) 新增增量 SQL 迁移（放 server/db/migrations/sql/）
#    命名: NNN_name.sql，执行器按文件名升序、写 schema_migrations 记录、幂等。

# 4) 存量库迁移（有数据时仅补增量，schema 文件自动跳过重复 CREATE IF NOT EXISTS）

# ------------------------------------------------------------
# 阶段 C：服务层查询下推（按 C1-C8 分批，每批全量测试）
# ------------------------------------------------------------
# 每批完成后的回归命令：
cd server
npx jest --silent --forceExit          # 全量测试
node ../scripts/n06/generate-schema.js # 若新增/调整了表
node scripts/n06/run-migrations.js      # 空库冒烟

# ------------------------------------------------------------
# 阶段 D：MySQL / PG 双跑
# ------------------------------------------------------------
# 1) 本地 MySQL 容器一键起库 + 迁移 + 双跑测试（Windows）
.\scripts\n06\start-mysql.ps1
#   或 bash: bash scripts/n06/start-mysql.sh

# 2) 手动方式（容器已在跑时）
docker run -d --name xuanjian-mysql -e MYSQL_ROOT_PASSWORD=root123456 `
  -e MYSQL_DATABASE=xuanjian -e MYSQL_USER=xuanjian -e MYSQL_PASSWORD=xuanjian123 `
  -p 3306:3306 mysql:8.0
cd server
$env:DB_DRIVER='mysql'; $env:DB_HOST='127.0.0.1'; $env:DB_PORT='3306'
$env:DB_USER='root'; $env:DB_PASSWORD='root123456'; $env:DB_NAME='xuanjian'
node ../scripts/n06/run-migrations.js
npx jest test/db-adapters.test.js --forceExit

# 3) PG 双跑（占位符 ?->$n 已转换，需本机/容器 PG）
#    DB_DRIVER=pg DB_HOST=... npx jest test/db-adapters.test.js --forceExit

# ------------------------------------------------------------
# 阶段 E：部署切换
# ------------------------------------------------------------
# 1) 一键拉起生产栈（默认 SQLite，不带 mysql profile）
docker compose up -d

# 2) 启用 MySQL profile（生产真实库）
docker compose --profile mysql up -d

# 3) 备份脚本升级后（联动 N-11）:
#    mysqldump -h $DB_HOST -u $DB_USER -p$DB_PASSWORD $DB_NAME > backup.sql

# ------------------------------------------------------------
# 回滚
# ------------------------------------------------------------
# 代码级: git revert 对应批次提交
# 数据级: 删除测试库重跑迁移 或 恢复备份快照
# 运行时: 环境变量 DB_DRIVER=shim 回切旧内存模拟器
