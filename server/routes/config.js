const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const { adminOnly } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { success, fail, asyncHandler } = require('../utils/helpers');
const { getDb } = require('../db/database');
const { loadDbConfig } = require('../config');
const logger = require('../utils/logger');

const router = express.Router();

router.use(authMiddleware);

/**
 * GET /api/config/list - 获取系统配置
 */
router.get('/list', asyncHandler(async (req, res) => {
  const db = getDb();
  const configs = db.prepare('SELECT * FROM sys_config ORDER BY key').all();
  return success(res, configs);
}));

/**
 * PUT /api/config/:key - 更新配置
 */
router.put('/:key', adminOnly, auditLog('config_update'), asyncHandler(async (req, res) => {
  const { key } = req.params;
  const { value } = req.body;
  const db = getDb();

  const config = db.prepare('SELECT * FROM sys_config WHERE key = ?').get(key);
  if (!config) {
    return fail(res, '配置项不存在');
  }

  db.prepare(`
    UPDATE sys_config SET value = ?, version = version + 1, updated_by = ?, updated_at = CURRENT_TIMESTAMP
    WHERE key = ?
  `).run(value, req.user.id, key);

  // 重新加载配置
  loadDbConfig();

  return success(res, null, '配置已更新');
}));

/**
 * POST /api/config/backup - 备份配置
 */
router.post('/backup', adminOnly, auditLog('config_backup'), asyncHandler(async (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const db = getDb();

  // 创建备份目录
  const backupDir = path.join(process.cwd(), '..', 'data', 'backups');
  if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

  // 读取所有配置
  const configs = db.prepare('SELECT key, value, description FROM sys_config').all();

  // 读取所有策略
  const policies = db.prepare('SELECT * FROM auto_policies').all();

  // 读取所有角色权限
  const roles = db.prepare('SELECT * FROM roles').all();
  const permissions = db.prepare('SELECT * FROM role_permissions').all();

  const backup = {
    version: '1.0',
    timestamp: new Date().toISOString(),
    type: 'full',
    configs,
    policies,
    roles,
    permissions,
    backed_up_by: req.user.username
  };

  const filename = `backup_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  const filepath = path.join(backupDir, filename);
  fs.writeFileSync(filepath, JSON.stringify(backup, null, 2), 'utf-8');

  // 保留最近10个备份
  const backups = fs.readdirSync(backupDir).filter(f => f.startsWith('backup_')).sort();
  while (backups.length > 10) {
    fs.unlinkSync(path.join(backupDir, backups.shift()));
  }

  return success(res, { filename, path: filepath, size: fs.statSync(filepath).size }, '配置备份成功');
}));

/**
 * POST /api/config/restore - 恢复配置
 */
router.post('/restore', adminOnly, auditLog('config_restore'), asyncHandler(async (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const db = getDb();

  const { filename } = req.body;
  if (!filename) return fail(res, '请指定备份文件名');

  const backupDir = path.join(process.cwd(), '..', 'data', 'backups');
  const filepath = path.join(backupDir, filename);

  if (!fs.existsSync(filepath)) return fail(res, '备份文件不存在');

  try {
    const backup = JSON.parse(fs.readFileSync(filepath, 'utf-8'));

    // 恢复配置
    if (backup.configs) {
      const upsert = db.prepare('INSERT OR REPLACE INTO sys_config (key, value, description) VALUES (?, ?, ?)');
      const updateStmt = db.prepare('UPDATE sys_config SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?');
      backup.configs.forEach(c => {
        const existing = db.prepare('SELECT id FROM sys_config WHERE key = ?').get(c.key);
        if (existing) updateStmt.run(c.value, c.key);
        else upsert.run(c.key, c.value, c.description);
      });
    }

    // 重新加载配置
    loadDbConfig();

    return success(res, { restored_at: new Date().toISOString() }, '配置恢复成功');
  } catch(e) {
    return fail(res, '备份文件格式错误: ' + e.message);
  }
}));

/**
 * GET /api/config/backups - 获取备份文件列表
 */
router.get('/backups', adminOnly, asyncHandler(async (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const backupDir = path.join(process.cwd(), '..', 'data', 'backups');

  if (!fs.existsSync(backupDir)) return success(res, []);

  const files = fs.readdirSync(backupDir)
    .filter(f => f.startsWith('backup_') && f.endsWith('.json'))
    .sort()
    .reverse()
    .map(f => {
      const stat = fs.statSync(path.join(backupDir, f));
      return {
        filename: f,
        size: stat.size,
        created_at: stat.mtime.toISOString()
      };
    });

  return success(res, files);
}));

/**
 * GET /api/config/backup/list - 获取备份文件列表（别名）
 */
router.get('/backup/list', adminOnly, asyncHandler(async (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const backupDir = path.join(process.cwd(), '..', 'data', 'backups');

  if (!fs.existsSync(backupDir)) return success(res, []);

  const files = fs.readdirSync(backupDir)
    .filter(f => f.startsWith('backup_') && f.endsWith('.json'))
    .sort()
    .reverse()
    .map(f => {
      const stat = fs.statSync(path.join(backupDir, f));
      return {
        filename: f,
        size: stat.size,
        created_at: stat.mtime.toISOString()
      };
    });

  return success(res, files);
}));

module.exports = router;
