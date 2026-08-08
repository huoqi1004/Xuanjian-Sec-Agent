/**
 * N-06 SQLite 驱动（开发默认）
 *
 * 双后端实现（对应报告 R10 缓解）：
 *   1. 优先 better-sqlite3（Linux/CI 预编译可用，Node ≥ 18）
 *   2. 若原生 binding 编译失败/缺失，回退 Node 内置 node:sqlite（DatabaseSync，Node ≥ 22.5）
 *
 * 同步 API，调用面与现有内存 shim 完全兼容：
 *   db.prepare('SELECT * FROM t WHERE id = ?').get(id)
 *   db.prepare('SELECT * FROM t').all()
 *   db.prepare('INSERT INTO t (a) VALUES (?)').run(a)
 *
 * 配置：
 *   DB_DRIVER=sqlite（默认）
 *   DB_PATH=/path/to/security.db（缺省 data/security.db）
 */
const { DriverBase } = require('./base');
const logger = require('../../utils/logger');

class SQLiteDriver extends DriverBase {
  constructor(dbPath) {
    super();
    this._backend = null;

    // 优先 better-sqlite3
    try {
      const Database = require('better-sqlite3');
      this._db = new Database(dbPath);
      this._db.pragma('foreign_keys = ON');
      this._backend = 'better-sqlite3';
    } catch (e) {
      // 回退 Node 内置 node:sqlite（Node ≥ 22.5，无原生编译依赖）
      const { DatabaseSync } = require('node:sqlite');
      this._db = new DatabaseSync(dbPath);
      this._db.exec('PRAGMA foreign_keys = ON');
      this._backend = 'node:sqlite';
      logger.warn(`[N-06] better-sqlite3 不可用（${e.message}），已回退 Node 内置 node:sqlite`);
    }

    // 行内 JSON 字段直存字符串，关闭自动转换以保持与原 shim 行为一致
    logger.info(`[N-06] SQLite 驱动已连接(${this._backend}): ${dbPath}`);
  }

  driverName() {
    return 'sqlite';
  }

  exec(sql) {
    return this._db.exec(sql);
  }

  prepare(sql) {
    const stmt = this._db.prepare(sql);
    return {
      get: (...params) => stmt.get(...params),
      all: (...params) => stmt.all(...params),
      run: (...params) => {
        const info = stmt.run(...params);
        return {
          lastInsertRowid: Number(info.lastInsertRowid),
          changes: Number(info.changes)
        };
      }
    };
  }

  /** 事务包装（对应 N-06 风险 R4 缓解）：返回可调用函数，支持 async fn，与 mysql/pg 语义一致 */
  transaction(fn) {
    return async (...args) => {
      this._db.exec('BEGIN');
      try {
        const r = await fn(...args);
        this._db.exec('COMMIT');
        return r;
      } catch (e) {
        this._db.exec('ROLLBACK');
        throw e;
      }
    };
  }

  close() {
    this._db.close();
  }
}

module.exports = { SQLiteDriver };
