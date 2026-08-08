const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { getDb } = require('../db/database');
const { authMiddleware, generateToken } = require('../middleware/auth');
const { adminOnly } = require('../middleware/rbac');
const { auditLog, recordAudit } = require('../middleware/audit');
const { success, fail, asyncHandler, getClientIp } = require('../utils/helpers');
const { config } = require('../config');
const logger = require('../utils/logger');

const router = express.Router();

// 登录接口独立限流：防止暴力破解（5次/分钟/IP）
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  message: { code: 1, message: '登录尝试过于频繁，请稍后再试', data: null }
});

// 密码强度校验：至少8位，且同时包含字母和数字
function validatePasswordStrength(password) {
  if (!password || password.length < 8) {
    return '密码长度不能少于8位';
  }
  if (!/[a-zA-Z]/.test(password) || !/\d/.test(password)) {
    return '密码必须同时包含字母和数字';
  }
  return null;
}

/**
 * POST /api/auth/login - 用户登录
 */
router.post('/login', loginLimiter, asyncHandler(async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return fail(res, '用户名和密码不能为空');
  }

  const db = getDb();
  const user = db.prepare('SELECT u.*, r.name as role_name FROM users u JOIN roles r ON u.role_id = r.id WHERE u.username = ?').get(username);

  if (!user) {
    recordAudit(null, username || 'anonymous', 'login_failed', 'system', '用户登录失败：用户名不存在', 'fail', getClientIp(req));
    return fail(res, '用户名或密码错误');
  }

  if (user.status !== 1) {
    recordAudit(user.id, user.username, 'login_failed', 'system', '用户登录失败：账号被禁用', 'fail', getClientIp(req));
    return fail(res, '账号已被禁用，请联系管理员');
  }

  const isMatch = bcrypt.compareSync(password, user.password_hash);
  if (!isMatch) {
    recordAudit(user.id, user.username, 'login_failed', 'system', '用户登录失败：密码错误', 'fail', getClientIp(req));
    return fail(res, '用户名或密码错误');
  }

  const token = generateToken(user);

  // 记录登录审计
  try {
    db.prepare(`
      INSERT INTO audit_logs (user_id, username, operation_type, operation_target, operation_detail, result, client_ip)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(user.id, user.username, 'login', 'system', '用户登录', 'success', getClientIp(req));
  } catch (err) {
    logger.error('记录登录审计失败:', err.message);
  }

  return success(res, {
    token,
    user: {
      id: user.id,
      username: user.username,
      role_id: user.role_id,
      role_name: user.role_name,
      department: user.department,
      org_id: user.org_id
    }
  }, '登录成功');
}));

/**
 * POST /api/auth/register - 用户注册（仅管理员）
 */
router.post('/register', authMiddleware, adminOnly, auditLog('user_register'), asyncHandler(async (req, res) => {
  const { username, password, role_id, department, org_id } = req.body;

  if (!username || !password) {
    return fail(res, '用户名和密码不能为空');
  }

  const strengthError = validatePasswordStrength(password);
  if (strengthError) {
    return fail(res, strengthError);
  }

  const db = getDb();

  // 检查用户名是否已存在
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return fail(res, '用户名已存在');
  }

  // 检查角色是否存在
  const role = db.prepare('SELECT id FROM roles WHERE id = ?').get(role_id || 3);
  if (!role) {
    return fail(res, '角色不存在');
  }

  const passwordHash = bcrypt.hashSync(password, config.bcrypt.rounds);

  const result = db.prepare(
    'INSERT INTO users (username, password_hash, role_id, department, org_id) VALUES (?, ?, ?, ?, ?)'
  ).run(username, passwordHash, role_id || 3, department || '', org_id || 1);

  return success(res, { id: result.lastInsertRowid }, '用户创建成功');
}));

/**
 * GET /api/auth/profile - 获取当前用户信息
 */
router.get('/profile', authMiddleware, asyncHandler(async (req, res) => {
  const db = getDb();
  const user = db.prepare(`
    SELECT u.id, u.username, u.role_id, u.department, u.status, u.created_at, r.name as role_name, r.permissions
    FROM users u
    JOIN roles r ON u.role_id = r.id
    WHERE u.id = ?
  `).get(req.user.id);

  if (!user) {
    return fail(res, '用户不存在');
  }

  return success(res, user);
}));

/**
 * PUT /api/auth/password - 修改密码
 */
router.put('/password', authMiddleware, auditLog('password_change'), asyncHandler(async (req, res) => {
  const { old_password, new_password } = req.body;

  if (!old_password || !new_password) {
    return fail(res, '旧密码和新密码不能为空');
  }

  const strengthError = validatePasswordStrength(new_password);
  if (strengthError) {
    return fail(res, strengthError);
  }

  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

  if (!user) {
    return fail(res, '用户不存在');
  }

  const isMatch = bcrypt.compareSync(old_password, user.password_hash);
  if (!isMatch) {
    return fail(res, '旧密码错误');
  }

  const newPasswordHash = bcrypt.hashSync(new_password, config.bcrypt.rounds);
  db.prepare('UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(newPasswordHash, req.user.id);

  return success(res, null, '密码修改成功');
}));

module.exports = router;
module.exports.validatePasswordStrength = validatePasswordStrength;
