/**
 * 玄鉴安全智能体 - SOAR 适配器管理路由（N-23 Task E）
 *
 * 提供：
 * - GET    /api/adapters/credentials  凭据列表（敏感字段脱敏为 ***）
 * - PUT    /api/adapters/credentials  新增/覆盖凭据（服务端 AES-256-GCM 加密存储）
 * - DELETE /api/adapters/credentials  删除凭据
 * - GET    /api/adapters/list         适配器目录（硬编码元数据）
 */

const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const { adminOnly } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { success, fail, asyncHandler } = require('../utils/helpers');
const credentialStore = require('../utils/credentialStore');

const router = express.Router();

router.use(authMiddleware);

/** 凭据命名空间（credentialStore 支持的 provider） */
const ALLOWED_PROVIDERS = ['switch', 'aliyun', 'tencent'];

/** 适配器目录（硬编码元数据，供前端展示可编排的动作类型） */
const ADAPTER_CATALOG = [
  { type: 'switch_acl_block', name: '交换机 ACL 封禁', provider: 'switch', risk: 'high' },
  { type: 'switch_acl_unblock', name: '交换机 ACL 解封', provider: 'switch', risk: 'high' },
  { type: 'cloud_sg_block', name: '云安全组封禁', provider: 'aliyun', risk: 'high' },
  { type: 'cloud_sg_unblock', name: '云安全组解封', provider: 'aliyun', risk: 'high' },
  { type: 'siem_webhook', name: 'SIEM 事件推送', provider: '', risk: 'medium' },
  { type: 'firewall_block', name: '防火墙 IP 封禁', provider: '', risk: 'high' },
  { type: 'account_lock', name: '账号锁定', provider: '', risk: 'high' },
  { type: 'webhook', name: '自定义 Webhook 触发', provider: '', risk: 'medium' },
  { type: 'notify', name: '消息通知', provider: '', risk: 'low' },
  { type: 'raise_alert', name: '生成安全告警', provider: '', risk: 'low' },
  { type: 'log_only', name: '仅记录日志', provider: '', risk: 'low' }
];

/**
 * GET /api/adapters/credentials - 凭据列表（敏感字段脱敏）
 */
router.get('/credentials', adminOnly, asyncHandler(async (req, res) => {
  return success(res, credentialStore.listCredentials());
}));

/**
 * PUT /api/adapters/credentials - 保存凭据（服务端加密存储）
 */
router.put('/credentials', adminOnly, auditLog('adapter_cred_save'), asyncHandler(async (req, res) => {
  const { provider, name, fields, meta } = req.body || {};
  if (!ALLOWED_PROVIDERS.includes(provider)) {
    return fail(res, 'provider 仅支持 switch/aliyun/tencent');
  }
  if (typeof name !== 'string' || !name.trim()) {
    return fail(res, '凭据名称不能为空');
  }
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
    return fail(res, 'fields 必须为对象');
  }
  const result = credentialStore.setCredential(provider, name.trim(), fields, meta || {});
  return success(res, result, '凭据已保存');
}));

/**
 * DELETE /api/adapters/credentials - 删除凭据
 */
router.delete('/credentials', adminOnly, auditLog('adapter_cred_delete'), asyncHandler(async (req, res) => {
  const { provider, name } = req.body || {};
  if (!ALLOWED_PROVIDERS.includes(provider)) {
    return fail(res, 'provider 仅支持 switch/aliyun/tencent');
  }
  if (typeof name !== 'string' || !name.trim()) {
    return fail(res, '凭据名称不能为空');
  }
  credentialStore.deleteCredential(provider, name.trim());
  return success(res, { ok: true }, '凭据已删除');
}));

/**
 * GET /api/adapters/list - 适配器目录
 */
router.get('/list', asyncHandler(async (req, res) => {
  return success(res, ADAPTER_CATALOG);
}));

module.exports = router;
