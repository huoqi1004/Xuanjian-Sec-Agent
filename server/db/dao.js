/**
 * N-06 DAO 工厂 —— 数据库访问层统一入口
 *
 * 通过环境变量 DB_DRIVER 选择驱动：
 *   - shim（默认，缺省）  ：现有内存 shim（database.js），迁移过渡期行为不变
 *   - sqlite             ：better-sqlite3（同步，兼容现有调用面）
 *   - mysql              ：mysql2/promise（异步）
 *   - pg                 ：pg Pool（异步）
 *
 * 接入方式（服务层）：
 *   const { getDao } = require('../db/dao');
 *   const db = getDao();            // 与 getDb() 同签名：db.prepare(sql).get/all/run
 *   await db.transaction(fn);       // 事务包装（仅真实驱动支持；shim 为直通）
 *
 * 配置（config/index.js 已支持）：
 *   DB_DRIVER / DB_PATH / DB_HOST / DB_PORT / DB_USER / DB_PASSWORD / DB_NAME
 */
const path = require('path');
const logger = require('../utils/logger');

let daoInstance = null;

function createDriver() {
  const driver = process.env.DB_DRIVER || 'shim';
  switch (driver) {
    case 'sqlite': {
      const { SQLiteDriver } = require('./drivers/sqlite');
      const dbPath = process.env.DB_PATH || path.resolve(__dirname, '../../data/security.db');
      return new SQLiteDriver(dbPath);
    }
    case 'mysql': {
      const { MySQLDriver } = require('./drivers/mysql');
      return new MySQLDriver({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME
      });
    }
    case 'pg': {
      const { PostgresDriver } = require('./drivers/pg');
      return new PostgresDriver({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME
      });
    }
    case 'shim':
    default: {
      // 过渡期默认：返回现有内存 shim（无事务能力，transaction 直通）
      const { getDb } = require('./database');
      const db = getDb();
      db.driverName = () => 'shim';
      db.transaction = async (fn) => fn(db);
      return db;
    }
  }
}

/**
 * 获取 DAO 单例（惰性初始化）
 */
function getDao() {
  if (!daoInstance) {
    daoInstance = createDriver();
    logger.info(`[N-06] 数据访问层就绪，驱动: ${daoInstance.driverName()}`);
  }
  return daoInstance;
}

/** 测试用：重置单例 */
function resetDao() {
  if (daoInstance && daoInstance.close && daoInstance.driverName() !== 'shim') {
    try { daoInstance.close(); } catch (e) { /* ignore */ }
  }
  daoInstance = null;
}

module.exports = { getDao, resetDao };
