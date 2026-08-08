/**
 * 玄鉴安全智能体 - 租户/对象级权限辅助（N-01/N-02）
 *
 * 两层数据权限：
 * - 组织级（N-02）：非管理员仅可见本组织数据（列表按 org 过滤）
 * - 对象级（N-01）：非管理员仅可访问本人创建的资源（详情/删除校验）
 * 说明：内存 shim 查询能力有限，业务表列表在内存中过滤；切换真实数据库后
 * 由 DAO 在 SQL 层完成（tenant_id / created_by 条件）。
 */

const { getDb } = require('../db/database');

/**
 * 获取某组织下全部用户 ID（用于业务表 created_by/uploaded_by 归属过滤）
 */
function orgUserIds(orgId) {
  const db = getDb();
  return (db._rawTable('users') || [])
    .filter((u) => Number(u.org_id) === Number(orgId))
    .map((u) => u.id);
}

/**
 * 列表按组织过滤（ownerCol：created_by / uploaded_by / generated_by）
 * 管理员放行全部。
 */
function inOrg(list, tenant, ownerCol) {
  if (!tenant || tenant.isAdmin) return list || [];
  const ids = new Set(orgUserIds(tenant.orgId));
  return (list || []).filter((r) => ids.has(Number(r[ownerCol])));
}

/**
 * 对象级归属校验：管理员放行；非管理员仅本人创建
 */
function isOwner(tenant, row, ownerCol) {
  if (!tenant || tenant.isAdmin) return true;
  if (!row) return false;
  return Number(row[ownerCol]) === Number(tenant.userId);
}

module.exports = { orgUserIds, inOrg, isOwner };
