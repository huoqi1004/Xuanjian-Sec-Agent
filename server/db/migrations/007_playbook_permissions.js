/**
 * 迁移 007：SOAR 剧本查看/执行权限（对应 NEXT_ITERATIONS N-02）
 * 存量库中 role_permissions 已存在（init.js 不会重插），为审计员/普通用户补 /api/playbook 权限
 */
const logger = require('../../utils/logger');

module.exports = {
  name: '007_playbook_permissions',
  up(db) {
    const hasPerm = (roleId) =>
      (db._rawTable('role_permissions') || []).some(
        (r) => Number(r.role_id) === roleId && String(r.resource) === '/api/playbook'
      );
    let added = 0;
    // 审计员(2)：查看 + 执行剧本
    if (!hasPerm(2)) {
      db.prepare('INSERT INTO role_permissions (role_id, resource, actions) VALUES (?, ?, ?)').run(2, '/api/playbook', '["GET","POST"]');
      added++;
    }
    // 普通用户(3)：查看剧本
    if (!hasPerm(3)) {
      db.prepare('INSERT INTO role_permissions (role_id, resource, actions) VALUES (?, ?, ?)').run(3, '/api/playbook', '["GET"]');
      added++;
    }
    if (added > 0) {
      logger.info(`[迁移:007] 为角色 2/3 补充剧本权限（新增 ${added} 条）`);
    }
  }
};
