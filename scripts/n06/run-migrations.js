/**
 * N-06 run-migrations.js — 真实数据库迁移执行器
 *
 * 职责（对应报告 Phase B）：
 *   1. 按 DB_DRIVER 选择驱动（sqlite/mysql/pg）
 *   2. 若目标库为空 → 应用 schema.{driver}.sql（28 表 + 索引）
 *   3. 应用 server/db/migrations/sql/*.sql（增量 SQL 迁移，可选）
 *   4. 应用 JS 数据迁移（seed：admin/角色/基线/等保/情报），沿用 schema_migrations 记录
 *
 * 用法：
 *   node scripts/n06/run-migrations.js                # DB_DRIVER=sqlite 默认
 *   DB_DRIVER=mysql DB_HOST=... node scripts/n06/run-migrations.js
 *
 * 说明：本脚本为 N-06 Phase B 的可执行入口；Phase C 服务层查询下推完成后，
 * 服务启动路径将改用 getDao() + 本执行器完成库初始化。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');

// 可选加载根目录 .env（脚本无 node_modules，不依赖 dotenv 包）
const envFile = path.join(ROOT, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) {
      process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  }
}

const { getDao, resetDao } = require(path.join(ROOT, 'server', 'db', 'dao'));
const logger = require(path.join(ROOT, 'server', 'utils', 'logger'));

async function main() {
  const driver = process.env.DB_DRIVER || 'sqlite';
  const db = getDao();

  // 1. 空库建表
  const schemaFile = path.join(ROOT, 'server', 'db', 'schema', `schema.${driver}.sql`);
  if (!fs.existsSync(schemaFile)) {
    throw new Error(`未找到 schema 文件: ${schemaFile}，请先运行 node scripts/n06/generate-schema.js`);
  }
  logger.info(`[N-06] 应用 schema: ${path.relative(ROOT, schemaFile)}`);
  await db.exec(fs.readFileSync(schemaFile, 'utf8'));

  // 2. 增量 SQL 迁移
  const sqlDir = path.join(ROOT, 'server', 'db', 'migrations', 'sql');
  if (fs.existsSync(sqlDir)) {
    const files = fs.readdirSync(sqlDir).filter((f) => /^\d+_.*\.sql$/.test(f)).sort();
    for (const f of files) {
      const name = f.replace(/\.sql$/, '');
      const applied = db.prepare('SELECT name FROM schema_migrations WHERE name = ?').get(name);
      if (applied) continue;
      logger.info(`[N-06] 应用 SQL 迁移: ${f}`);
      await db.exec(fs.readFileSync(path.join(sqlDir, f), 'utf8'));
      db.prepare('INSERT INTO schema_migrations (name) VALUES (?)').run(name);
    }
  }

  // 3. Seed 数据迁移（admin/角色/基线/等保/情报）
  //    注意：JS 侧 insertDefaultData() 操作的是内存 shim，与真实库无关；
  //    真实库的 seed 需以 SQL 迁移形式落在 migrations/sql/ 下（对应报告 C 阶段批次），
  //    届时在 001_seed.js / 002_seed.js 中实现 INSERT ... ON DUPLICATE KEY 幂等逻辑。
  logger.warn('[N-06] 提醒：真实库 seed 数据迁移（migrations/sql/）尚未生成，admin 账号需手工创建或后续 SQL 迁移补齐。');

  logger.info('[N-06] 迁移完成。校验:');
  const tables = driver === 'sqlite'
    ? (await db.prepare("SELECT COUNT(*) as c FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").get()).c
    : 'n/a（真实库表数请用数据库客户端确认）';
  logger.info(`  - 表数量: ${JSON.stringify(tables)}`);

  resetDao();
  process.exit(0);
}

main().catch((err) => {
  logger.error('[N-06] 迁移失败:', err.message);
  process.exit(1);
});
