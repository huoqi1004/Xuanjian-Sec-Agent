const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const { adminOnly } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { success, fail, asyncHandler } = require('../utils/helpers');
const { getDb } = require('../db/database');

const router = express.Router();

router.use(authMiddleware);

/**
 * GET /api/user/list - 获取用户列表（管理员）
 */
router.get('/list', adminOnly, asyncHandler(async (req, res) => {
  const { page = 1, pageSize = 10, keyword } = req.query;
  const db = getDb();
  const offset = (parseInt(page) - 1) * parseInt(pageSize);
  const limit = parseInt(pageSize);

  // 组织过滤（默认展示当前登录用户所在组织；管理员可通过 org_id 参数查看）
  const orgFilter = parseInt(req.query.org_id) || req.user.org_id || 1;

  // 内存 shim 的 JOIN WHERE 多条件解析能力有限，采用全量 JOIN + 内存过滤
  const allUsers = db.prepare(`
    SELECT u.id, u.username, u.role_id, u.department, u.org_id, u.status, u.created_at, u.updated_at, r.name as role_name
    FROM users u
    JOIN roles r ON u.role_id = r.id
  `).all();

  let filtered = allUsers.filter((u) => Number(u.org_id) === orgFilter);
  if (keyword) {
    filtered = filtered.filter(
      (u) => (u.username || '').includes(keyword) || (u.department || '').includes(keyword)
    );
  }
  filtered.sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));

  return success(res, {
    list: filtered.slice(offset, offset + limit),
    total: filtered.length,
    page: parseInt(page),
    pageSize: limit,
    org_id: orgFilter
  });
}));

/**
 * GET /api/user/orgs - 组织列表（管理员）
 */
router.get('/orgs', adminOnly, asyncHandler(async (req, res) => {
  const db = getDb();
  const orgs = db.prepare('SELECT * FROM organizations ORDER BY id ASC').all();
  return success(res, orgs);
}));

/**
 * POST /api/user/orgs - 创建组织（管理员）
 */
router.post('/orgs', adminOnly, auditLog('org_create'), asyncHandler(async (req, res) => {
  const { name, description } = req.body;
  if (!name) {
    return fail(res, '组织名称不能为空');
  }
  const db = getDb();
  const result = db.prepare('INSERT INTO organizations (name, description) VALUES (?, ?)').run(name, description || '');
  if (result.changes === 0) {
    return fail(res, '组织创建失败（可能名称重复）');
  }
  return success(res, { id: result.lastInsertRowid, name }, '组织创建成功');
}));

/**
 * PUT /api/user/:id - 更新用户信息
 */
router.put('/:id', adminOnly, auditLog('user_update'), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { role_id, department, status } = req.body;
  const db = getDb();

  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(id);
  if (!user) {
    return fail(res, '用户不存在');
  }

  const updates = [];
  const values = [];

  if (role_id !== undefined) {
    updates.push('role_id = ?');
    values.push(role_id);
  }
  if (department !== undefined) {
    updates.push('department = ?');
    values.push(department);
  }
  if (status !== undefined) {
    updates.push('status = ?');
    values.push(status);
  }

  if (updates.length === 0) {
    return fail(res, '没有需要更新的字段');
  }

  updates.push('updated_at = CURRENT_TIMESTAMP');
  values.push(id);

  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values);

  return success(res, null, '用户信息已更新');
}));

/**
 * DELETE /api/user/:id - 删除用户
 */
router.delete('/:id', adminOnly, auditLog('user_delete'), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const db = getDb();

  if (parseInt(id) === req.user.id) {
    return fail(res, '不能删除当前登录的用户');
  }

  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(id);
  if (!user) {
    return fail(res, '用户不存在');
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(id);

  return success(res, null, '用户已删除');
}));

/**
 * GET /api/user/audit-logs - 获取审计日志
 */
router.get('/audit-logs', adminOnly, asyncHandler(async (req, res) => {
  const { page = 1, pageSize = 20, username, operation_type, start_date, end_date } = req.query;
  const db = getDb();
  const offset = (parseInt(page) - 1) * parseInt(pageSize);
  const limit = parseInt(pageSize);

  let whereClause = '1=1';
  const params = [];

  if (username) {
    whereClause += ' AND username LIKE ?';
    params.push(`%${username}%`);
  }
  if (operation_type) {
    whereClause += ' AND operation_type = ?';
    params.push(operation_type);
  }
  if (start_date) {
    whereClause += ' AND created_at >= ?';
    params.push(start_date);
  }
  if (end_date) {
    whereClause += ' AND created_at <= ?';
    params.push(end_date);
  }

  const total = db.prepare(`SELECT COUNT(*) as count FROM audit_logs WHERE ${whereClause}`).get(...params).count;
  const logs = db.prepare(`
    SELECT * FROM audit_logs
    WHERE ${whereClause}
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset);

  return success(res, logs);
}));

module.exports = router;
