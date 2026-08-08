/**
 * 玄鉴安全智能体 - 数据库迁移执行器
 *
 * 迁移文件约定：server/db/migrations/NNN_name.js
 *   module.exports = { name: 'NNN_name', up: async (db) => { ... } }
 * 按文件名升序执行，已执行的迁移记录在 schema_migrations 表，幂等可重复启动。
 *
 * 说明：当前内存 shim 无 ALTER TABLE 能力，迁移以 JS 数据变更实现
 * （补默认值/补数据/索引重建）；切换真实数据库（MySQL/PG）时迁移脚本改为 SQL 文件。
 */

const fs = require('fs');
const path = require('path');
const { getDb } = require('../database');
const logger = require('../../utils/logger');

function ensureMigrationsTable(db) {
  db.exec(
    'CREATE TABLE IF NOT EXISTS schema_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)'
  );
}

async function runMigrations() {
  const db = getDb();
  ensureMigrationsTable(db);

  const appliedRows = db.prepare('SELECT * FROM schema_migrations').all();
  const appliedNames = new Set(appliedRows.map((r) => r.name));

  const migrationsDir = __dirname;
  const files = fs
    .readdirSync(migrationsDir)
    .filter((f) => /^\d+_.*\.js$/.test(f))
    .sort();

  let executed = 0;
  for (const file of files) {
    const mod = require(path.join(migrationsDir, file));
    const name = mod.name || file.replace(/\.js$/, '');
    if (appliedNames.has(name)) {
      logger.debug(`[迁移] ${name} 已应用，跳过`);
      continue;
    }
    logger.info(`[迁移] 执行 ${name} ...`);
    try {
      await mod.up(db);
      db.prepare('INSERT INTO schema_migrations (name) VALUES (?)').run(name);
      executed++;
      logger.info(`[迁移] ${name} 完成`);
    } catch (err) {
      logger.error(`[迁移] ${name} 执行失败: ${err.stack || err.message}`);
      throw err;
    }
  }

  logger.info(executed > 0 ? `[迁移] 本次应用 ${executed} 个迁移` : '[迁移] 无待执行迁移');
  return executed;
}

module.exports = { runMigrations };
