/**
 * 玄鉴安全智能体 - 数据库备份脚本
 *
 * 将持久化数据库文件复制到 backups/ 目录，并按 BACKUP_RETENTION_COUNT 轮转保留。
 *
 * 手动执行：node scripts/backup.js
 * 定时执行（可选）：node-cron 或系统 crontab 调用本脚本
 */

const fs = require('fs');
const path = require('path');

// 手动加载项目根 .env（脚本独立于 server 的 node_modules，避免依赖 dotenv 包）
try {
  const envPath = path.resolve(__dirname, '../.env');
  const envContent = fs.readFileSync(envPath, 'utf8');
  for (const line of envContent.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && !(m[1] in process.env)) {
      process.env[m[1]] = m[2].trim();
    }
  }
} catch (e) {
  // .env 缺失时使用默认配置
}

const { getDb } = require('../server/db/database');

const DATA_DIR = path.resolve(__dirname, '../data');
// 与 server/db/database.js 保持一致：优先 env DB_PATH，否则 data/security.db.json
const DB_PATH = path.resolve(process.env.DB_PATH || path.join(DATA_DIR, 'security.db.json'));
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(path.dirname(DB_PATH), 'backups');
const KEEP = parseInt(process.env.BACKUP_RETENTION_COUNT, 10) || 7;

function backup() {
  // 触发内存表初始化并落盘，确保备份的是最新数据
  const db = getDb();
  db.saveDb();

  if (!fs.existsSync(DB_PATH)) {
    throw new Error(`数据库文件不存在: ${DB_PATH}`);
  }

  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const dest = path.join(BACKUP_DIR, `security.db.${ts}.json`);
  fs.copyFileSync(DB_PATH, dest);

  // 轮转：仅保留最近 KEEP 份
  const files = fs
    .readdirSync(BACKUP_DIR)
    .filter((f) => f.startsWith('security.db.'))
    .sort();
  let removed = 0;
  while (files.length > KEEP) {
    const old = files.shift();
    fs.unlinkSync(path.join(BACKUP_DIR, old));
    removed++;
  }

  return { dest, kept: files.length, removed, dbPath: DB_PATH };
}

if (require.main === module) {
  try {
    const r = backup();
    console.log(`[备份] 完成: ${r.dest}（保留 ${r.kept} 份${r.removed ? `，清理 ${r.removed} 份` : ''}）`);
  } catch (err) {
    console.error(`[备份] 失败: ${err.message}`);
    process.exit(1);
  }
}

module.exports = { backup };
