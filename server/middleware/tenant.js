/**
 * 玄鉴安全智能体 - 多租户数据隔离中间件（对应 ROADMAP 4.16）
 *
 * 将请求上下文注入 req.tenant：
 * - isAdmin：管理员（role_id=1）可跨组织访问
 * - orgId：非管理员仅可访问本组织数据
 * 各 service 在列表/详情查询时依据 req.tenant 追加过滤条件。
 */

function tenantScope(req, res, next) {
  const isAdmin = req.user && Number(req.user.role_id) === 1;
  req.tenant = {
    isAdmin,
    userId: req.user ? req.user.id : null,
    username: req.user ? req.user.username : null,
    orgId: (req.user && req.user.org_id) ? Number(req.user.org_id) : 1
  };
  next();
}

module.exports = { tenantScope };
