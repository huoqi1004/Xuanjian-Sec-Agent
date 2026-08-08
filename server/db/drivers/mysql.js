/**
 * N-06 MySQL 驱动（生产可选）
 *
 * 基于 mysql2/promise，异步 API（返回 Promise）。
 * 现有 service 层为同步调用面，切换 MySQL 时需按 N-06 报告 C 阶段
 * 将列表过滤下推为 SQL 并将相关函数改为 async（DAO 层已封装 Promise 化差异）。
 *
 * 配置：
 *   DB_DRIVER=mysql
 *   DB_HOST / DB_PORT / DB_USER / DB_PASSWORD / DB_NAME
 */
const { DriverBase } = require('./base');
const logger = require('../../utils/logger');

class MySQLDriver extends DriverBase {
  constructor(opts) {
    super();
    const mysql = require('mysql2/promise');
    this._pool = mysql.createPool({
      host: opts.host || '127.0.0.1',
      port: Number(opts.port) || 3306,
      user: opts.user || 'root',
      password: opts.password || '',
      database: opts.database || 'xuanjian',
      waitForConnections: true,
      connectionLimit: 10,
      namedPlaceholders: false,
      charset: 'utf8mb4'
    });
    logger.info(`[N-06] MySQL 驱动已连接: ${opts.host}:${opts.port}/${opts.database}`);
  }

  driverName() {
    return 'mysql';
  }

  async exec(sql) {
    const conn = await this._pool.getConnection();
    try {
      await conn.query(sql);
    } finally {
      conn.release();
    }
  }

  prepare(sql) {
    return {
      get: async (...params) => {
        const [rows] = await this._pool.query(sql, params.flat());
        return rows[0];
      },
      all: async (...params) => {
        const [rows] = await this._pool.query(sql, params.flat());
        return rows;
      },
      run: async (...params) => {
        const [res] = await this._pool.query(sql, params.flat());
        return { lastInsertRowid: res.insertId, changes: res.affectedRows };
      }
    };
  }

  /** 事务包装：conn.beginTransaction → fn(conn) → commit/rollback */
  async transaction(fn) {
    const conn = await this._pool.getConnection();
    try {
      await conn.beginTransaction();
      const result = await fn(conn);
      await conn.commit();
      return result;
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  }

  async close() {
    await this._pool.end();
  }
}

module.exports = { MySQLDriver };
