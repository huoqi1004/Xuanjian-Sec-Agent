const { getDb } = require('../db/database');
const { forbidden } = require('../utils/helpers');
const logger = require('../utils/logger');

/**
 * RBAC权限检查中间件
 * @param {string[]} allowedActions - 允许的HTTP方法，如 ['GET', 'POST']
 */
function checkPermission(...allowedActions) {
  return (req, res, next) => {
    try {
      if (!req.user) {
        return forbidden(res, '用户信息缺失');
      }

      const db = getDb();
      const roleId = req.user.role_id;
      const method = req.method;
      // 完整请求路径：挂载前缀 + 路由子路径（权限表按 /api/xxx 前缀匹配）
      const path = req.route
        ? `${req.baseUrl || ''}${req.route.path}`
        : (req.originalUrl || req.path);

      // 管理员角色(role_id=1)拥有全部权限
      if (roleId === 1) {
        return next();
      }

      // 查询角色权限
      const permissions = db.prepare(
        'SELECT resource, actions FROM role_permissions WHERE role_id = ?'
      ).all(roleId);

      // 检查是否有匹配的资源权限
      let hasPermission = false;
      for (const perm of permissions) {
        // 匹配资源路径（支持前缀匹配）
        if (path.startsWith(perm.resource) || perm.resource.startsWith(path)) {
          const actions = JSON.parse(perm.actions || '[]');
          if (actions.includes('*') || actions.includes(method)) {
            hasPermission = true;
            break;
          }
        }
      }

      // 如果指定了allowedActions，进一步检查
      if (allowedActions.length > 0 && !allowedActions.includes(method)) {
        hasPermission = false;
      }

      if (hasPermission) {
        next();
      } else {
        logger.warn(`权限拒绝: 用户=${req.user.username}, 角色ID=${roleId}, 方法=${method}, 路径=${path}`);
        return forbidden(res, '您没有执行此操作的权限');
      }
    } catch (err) {
      logger.error('权限检查失败:', err.message);
      return forbidden(res, '权限检查失败');
    }
  };
}

/**
 * 管理员权限检查
 */
function adminOnly(req, res, next) {
  if (!req.user || req.user.role_id !== 1) {
    return forbidden(res, '仅管理员可执行此操作');
  }
  next();
}

module.exports = { checkPermission, adminOnly };
