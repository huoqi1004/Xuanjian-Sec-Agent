/**
 * N-06 generate-schema.js — 数据库 Schema 自动生成器
 *
 * 从 server/db/init.js 与 server/db/migrations/*.js 中自动提取 CREATE TABLE 定义，
 * 生成三种方言的建表脚本：
 *   - server/db/schema/schema.sqlite.sql
 *   - server/db/schema/schema.mysql.sql
 *   - server/db/schema/schema.pg.sql
 *
 * 用法：
 *   node scripts/n06/generate-schema.js
 *   （可配环境变量 SKIP_PG=1 跳过 PG 方言输出）
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const SERVER_DB = path.join(ROOT, 'server', 'db');
const OUT_DIR = path.join(SERVER_DB, 'schema');

/* ---------------- 1. 从源码提取 CREATE TABLE 语句 ---------------- */

/** 提取文件中的所有 CREATE TABLE IF NOT EXISTS ... ; 语句块 */
function extractCreateTables(source) {
  const tables = [];
  // 匹配 db.exec(`CREATE TABLE IF NOT EXISTS xxx ( ... \n );`);
  // 用"换行 + 收尾 );"锚定结束，避免 FOREIGN KEY 内部括号导致提前截断
  const re = /CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+(\w+)\s*\(([\s\S]*?)\n\s*\)\s*;/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    tables.push({ name: m[1], body: m[2] });
  }
  return tables;
}

/** 提取 init.js 中的 CREATE INDEX 数组 */
function extractIndexes(source) {
  const idx = [];
  const re = /CREATE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+(\w+)\s+ON\s+(\w+)\(([^)]+)\)/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    idx.push({ name: m[1], table: m[2], columns: m[3] });
  }
  return idx;
}

/* ---------------- 2. 列定义解析 ---------------- */

/**
 * 解析一行列定义
 * 支持形如：id INTEGER PRIMARY KEY AUTOINCREMENT / username TEXT UNIQUE NOT NULL
 *          / created_at DATETIME DEFAULT CURRENT_TIMESTAMP / FOREIGN KEY (x) REFERENCES y(z)
 */
function parseColumn(line, dialect) {
  const raw = line.trim().replace(/,\s*$/, '');
  if (!raw) return null;
  // 表级约束（FOREIGN KEY / PRIMARY KEY(id,col) 等）原样透传
  if (/^(FOREIGN\s+KEY|PRIMARY\s+KEY|UNIQUE\s*\(|CHECK\s*\()/i.test(raw)) {
    return { constraint: raw, raw };
  }

  const parts = raw.split(/\s+/);
  const name = parts[0];
  const rest = parts.slice(1).join(' ');

  // 类型映射（含 PRIMARY KEY AUTOINCREMENT 特殊处理）
  let type = 'TEXT';
  let constraints = rest;
  const autoIncr = /PRIMARY\s+KEY\s+AUTOINCREMENT/i.test(rest);
  if (autoIncr) {
    constraints = rest.replace(/PRIMARY\s+KEY\s+AUTOINCREMENT/i, '').trim();
  }

  if (/^INTEGER\b/i.test(rest)) type = 'INTEGER';
  else if (/^REAL\b/i.test(rest)) type = 'REAL';
  else if (/^BOOLEAN\b/i.test(rest)) type = 'BOOLEAN';
  else if (/^DATETIME\b/i.test(rest)) type = 'DATETIME';
  else if (/^TEXT\b/i.test(rest)) type = 'TEXT';

  let ddlType;
  let extra = '';

  switch (dialect) {
    case 'mysql': {
      const map = { INTEGER: 'BIGINT', REAL: 'DOUBLE', BOOLEAN: 'TINYINT(1)', DATETIME: 'DATETIME', TEXT: 'TEXT' };
      ddlType = map[type];
      if (autoIncr) extra = 'AUTO_INCREMENT PRIMARY KEY';
      // MySQL DATETIME 无 CURRENT_TIMESTAMP 默认需特殊处理（已在约束中保留）
      break;
    }
    case 'pg': {
      const map = { INTEGER: 'BIGINT', REAL: 'DOUBLE PRECISION', BOOLEAN: 'BOOLEAN', DATETIME: 'TIMESTAMP', TEXT: 'TEXT' };
      // BIGSERIAL 已隐含 BIGINT，autoIncr 时不再叠加基础类型
      if (autoIncr) {
        ddlType = '';
        extra = 'BIGSERIAL PRIMARY KEY';
      } else {
        ddlType = map[type];
      }
      break;
    }
    case 'sqlite':
    default: {
      ddlType = type;
      if (autoIncr) extra = 'PRIMARY KEY AUTOINCREMENT';
      break;
    }
  }

  // 归一化约束：去除类型关键字残留、把 true/false 转 1/0、PG BOOLEAN 默认 true/false 保留
  let c = constraints
    .replace(/^(INTEGER|REAL|BOOLEAN|DATETIME|TEXT)\b/i, '')
    .trim()
    .replace(/\s+/g, ' ');

  if (dialect === 'mysql') {
    c = c.replace(/\btrue\b/g, '1').replace(/\bfalse\b/g, '0');
  }
  if (dialect === 'pg') {
    c = c.replace(/DEFAULT\s+CURRENT_TIMESTAMP/i, 'DEFAULT CURRENT_TIMESTAMP');
  }

  const tokens = [name, ddlType];
  if (extra) tokens.push(extra);
  if (c) tokens.push(c);

  return { name, line: tokens.filter(Boolean).join(' '), raw };
}

/* ---------------- 3. 方言渲染 ---------------- */

function renderTable(table, dialect) {
  const rows = table.body
    .split('\n')
    .map((l) => parseColumn(l, dialect))
    .filter(Boolean);

  // 除最后一行外统一加逗号分隔（避免尾随逗号导致 MySQL/PG 语法错误）
  const lines = rows.map((r, i) => {
    const body = r.constraint ? r.raw : r.line;
    const comma = i < rows.length - 1 ? ',' : '';
    return `  ${body}${comma}`;
  });

  return `CREATE TABLE IF NOT EXISTS ${table.name} (\n${lines.join('\n')}\n);`;
}

function renderIndexes(indexes, dialect) {
  return indexes
    .map((i) => {
      // PG/MySQL 语法一致；SQLite 也支持
      const drop = dialect === 'pg' ? `DROP INDEX IF EXISTS ${i.name};` : '';
      return `${drop}CREATE INDEX IF NOT EXISTS ${i.name} ON ${i.table} (${i.columns});`;
    })
    .join('\n');
}

/* ---------------- 4. 主流程 ---------------- */

function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const initSource = fs.readFileSync(path.join(SERVER_DB, 'init.js'), 'utf8');
  let tables = extractCreateTables(initSource);

  // 迁移中的额外表（organizations / playbooks / chat_history 等）
  const migrationsDir = path.join(SERVER_DB, 'migrations');
  const seen = new Set(tables.map((t) => t.name));
  fs.readdirSync(migrationsDir)
    .filter((f) => /^\d+_.*\.js$/.test(f))
    .forEach((f) => {
      const src = fs.readFileSync(path.join(migrationsDir, f), 'utf8');
      for (const t of extractCreateTables(src)) {
        if (!seen.has(t.name)) {
          tables.push(t);
          seen.add(t.name);
        }
      }
    });

  // schema_migrations 表（迁移执行器自身）
  tables.push({
    name: 'schema_migrations',
    body: 'id INTEGER PRIMARY KEY AUTOINCREMENT,\nname TEXT UNIQUE NOT NULL,\napplied_at DATETIME DEFAULT CURRENT_TIMESTAMP'
  });

  const indexes = extractIndexes(initSource);

  // 按表名排序保证确定性
  tables.sort((a, b) => a.name.localeCompare(b.name));

  const dialects = ['sqlite', 'mysql', 'pg'].filter((d) => d !== 'pg' || process.env.SKIP_PG !== '1');
  const outputs = {};

  for (const dialect of dialects) {
    const header = `-- ${dialect.toUpperCase()} Schema（由 scripts/n06/generate-schema.js 自动生成，请勿手改）\n` +
      `-- 生成时间: ${new Date().toISOString()}\n` +
      `-- 共 ${tables.length} 张表\n\n`;
    const body = tables.map((t) => renderTable(t, dialect)).join('\n\n');
    const idx = '\n\n-- 索引\n\n' + renderIndexes(indexes, dialect);
    const file = path.join(OUT_DIR, `schema.${dialect}.sql`);
    fs.writeFileSync(file, header + body + idx + '\n');
    outputs[dialect] = { file, tables: tables.length, indexes: indexes.length };
    console.log(`[生成] ${path.relative(ROOT, file)} (${tables.length} 表 / ${indexes.length} 索引)`);
  }

  console.log('\n✅ Schema 生成完成。可执行迁移：');
  console.log('  - SQLite: node scripts/n06/run-migrations.js');
  console.log('  - MySQL : DB_DRIVER=mysql node scripts/n06/run-migrations.js');
}

main();
