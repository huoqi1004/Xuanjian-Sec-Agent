/**
 * N-06 数据库驱动统一接口契约
 *
 * 所有驱动实现必须提供：
 * - exec(sql)：执行一条或多条 DDL/DML（无返回值）
 * - prepare(sql)：返回语句对象 { get(...), all(...), run(...) }
 * - close()：关闭连接
 * - driverName()：返回 'sqlite' | 'mysql' | 'pg'
 *
 * 同步性说明：
 * - sqlite 驱动为同步 API（better-sqlite3），可直接兼容现有 service 层同步调用面
 * - mysql/pg 驱动为异步 API（返回 Promise），对应 service 层改造见 N-06 报告 C 阶段
 */
class DriverBase {
  constructor() {
    if (this.constructor === DriverBase) {
      throw new Error('DriverBase 为抽象基类，请使用具体驱动 sqlite/mysql/pg');
    }
  }

  driverName() {
    throw new Error('driverName() 未实现');
  }

  exec() {
    throw new Error('exec() 未实现');
  }

  prepare() {
    throw new Error('prepare() 未实现');
  }

  close() {
    throw new Error('close() 未实现');
  }
}

module.exports = { DriverBase };
