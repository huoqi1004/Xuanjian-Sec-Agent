const jwt = require('jsonwebtoken');
const { config } = require('../config');
const { unauthorized, fail } = require('../utils/helpers');
const logger = require('../utils/logger');

/**
 * JWT认证中间件
 */
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return unauthorized(res, '缺少认证令牌');
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    // 从数据库加载最新用户信息（含 org_id），保证组织隔离与权限变更即时生效
    const { getDb } = require('../db/database');
    const user = getDb().prepare(
      'SELECT * FROM users WHERE id = ?'
    ).get(decoded.id);
    if (!user) {
      return unauthorized(res, '用户不存在或已被删除');
    }
    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return unauthorized(res, '令牌已过期，请重新登录');
    }
    if (err.name === 'JsonWebTokenError') {
      return unauthorized(res, '无效的认证令牌');
    }
    logger.error('JWT验证失败:', err.message);
    return unauthorized(res, '认证失败');
  }
}

/**
 * 生成JWT Token
 */
function generateToken(user) {
  const payload = {
    id: user.id,
    username: user.username,
    role_id: user.role_id
  };
  return jwt.sign(payload, config.jwt.secret, { expiresIn: config.jwt.expiresIn });
}

module.exports = { authMiddleware, generateToken };
