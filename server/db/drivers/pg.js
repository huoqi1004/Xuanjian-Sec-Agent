/**
 * N-06 PostgreSQL 驱动（生产可选）
 *
 * 基于 pg Pool，异步 API。与 MySQL 差异点：占位符为 $1/$2（由本驱动在 prepare 时转换）。
 * 现有 service 层为同步调用面，切换 PG 时需按 N-06 报告 C 阶段改造。
 *
 * 配置：
 *   DB_DRIVER=pg
 *   DB_HOST / DB_PORT / DB_USER / DB_PASSWORD / DB_NAME
 */
const { DriverBase } = require('./base');
const logger = require('../../utils/logger');

class PostgresDriver extends DriverBase {
  constructor(opts) {
    super();
    const { Pool } = require('pg');
    this._pool = new Pool({
      host: opts.host || '127.0.0.1',
      port: Number(opts.port) || 5432,
      user: opts.user || 'postgres',
      password: opts.password || '',
      database: opts.database || 'xuanjian'
    });
    logger.info(`[N-06] PG 驱动已连接: ${opts.host}:${opts.port}/${opts.database}`);
  }

  driverName() {
    return 'pg';
  }

  /** ? 占位符 -> $n（跳过字符串字面量中的 ?） */
  _convertPlaceholders(sql) {
    let out = '';
    let n = 0;
    let inStr = false;
    for (let i = 0; i < sql.length; i++) {
      const ch = sql[i];
      if ((ch === "'" || ch === '"') && (i === 0 || sql[i - 1] !== '\\')) {
        inStr = !inStr;
        out += ch;
      } else if (ch === '?' && !inStr) {
        out += `$${++n}`;
      } else {
        out += ch;
      }
    }
    return { sql: out, count: n };
  }

  async exec(sql) {
    // 不支持多语句（pg 的 simple query 可，但为一致性拆分按单条处理）
    await this._pool.query(sql);
  }

  prepare(sql) {
    const { sql: converted, count } = this._convertPlaceholders(sql);
    return {
      get: async (...params) => {
        const flat = params.flat();
        const res = await this._pool.query(converted, flat.length ? flat : undefined);
        return res.rows[0];
      },
      all: async (...params) => {
        const flat = params.flat();
        const res = await this._pool.query(converted, flat.length ? flat : undefined);
        return res.rows;
      },
      run: async (...params) => {
        const flat = params.flat();
        const res = await this._pool.query(converted, flat.length ? flat : undefined);
        // PG 无 insertId；返回行数（lastInsertRowid 由调用方按需处理）
        return { lastInsertRowid: null, changes: res.rowCount, rows: res.rows };
      }
    };
  }

  async transaction(fn) {
    const client = await this._pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async close() {
    await this._pool.end();
  }
}

module.exports = { PostgresDriver };
