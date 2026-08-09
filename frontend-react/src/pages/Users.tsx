import { useCallback, useEffect, useMemo, useState } from 'react';
import { userApi } from '@/api';
import type { AuditLog, Org, UserRecord } from '@/api';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import Dialog from '@/components/ui/dialog';
import { Table } from '@/components/ui/table';
import { useToast } from '@/components/ui/use-toast';
import { useUserStore } from '@/stores/user';

const PAGE_SIZE = 10;

const fieldCls =
  'rounded-md border border-cyan-500/20 bg-[#1a2340] px-3 py-2 text-sm text-gray-300 outline-none transition-colors placeholder:text-gray-500 focus:border-cyan-500/60';

type TabKey = 'users' | 'audit';

/** 角色选项（与后端 roles 表保持一致：1=admin 2=auditor 3=viewer） */
const ROLE_OPTIONS = [
  { value: 1, label: '管理员' },
  { value: 2, label: '审计员' },
  { value: 3, label: '普通用户' }
];

const OPERATION_TYPES = [
  { value: 'login', label: '登录' },
  { value: 'scan', label: '扫描' },
  { value: 'baseline_check', label: '基线检查' },
  { value: 'virus_scan', label: '病毒检测' },
  { value: 'policy', label: '策略操作' },
  { value: 'config', label: '配置变更' },
  { value: 'password_change', label: '密码修改' }
];

function formatTime(t?: string): string {
  return t ? new Date(t).toLocaleString('zh-CN') : '-';
}

/** 角色展示（优先 role_name，回退 role_id） */
function roleTag(roleName?: string, roleId?: number) {
  if (roleName === 'admin' || roleId === 1) return { label: '管理员', variant: 'danger' as const };
  if (roleName === 'auditor' || roleId === 2) return { label: '审计员', variant: 'warning' as const };
  if (roleName === 'viewer' || roleId === 3) return { label: '普通用户', variant: 'default' as const };
  return { label: roleName || (roleId !== undefined ? `角色${roleId}` : '-'), variant: 'default' as const };
}

function resultTag(result?: string) {
  return result === 'success'
    ? { label: '成功', variant: 'success' as const }
    : { label: '失败', variant: 'danger' as const };
}

function Pagination({
  page,
  total,
  pageSize,
  onChange
}: {
  page: number;
  total: number;
  pageSize: number;
  onChange: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (pages <= 1) return null;
  return (
    <div className="mt-4 flex items-center justify-end gap-2 text-xs text-gray-400">
      <span>共 {total} 条</span>
      <button
        type="button"
        disabled={page <= 1}
        onClick={() => onChange(page - 1)}
        className="rounded border border-white/10 px-2 py-1 transition-colors hover:border-cyan-500/40 disabled:opacity-40"
      >
        上一页
      </button>
      <span className="px-1">
        {page} / {pages}
      </span>
      <button
        type="button"
        disabled={page >= pages}
        onClick={() => onChange(page + 1)}
        className="rounded border border-white/10 px-2 py-1 transition-colors hover:border-cyan-500/40 disabled:opacity-40"
      >
        下一页
      </button>
    </div>
  );
}

interface UserForm {
  username: string;
  password: string;
  role_id: number;
  department: string;
  org_id: number;
}

const EMPTY_USER_FORM: UserForm = { username: '', password: '', role_id: 3, department: '', org_id: 1 };

interface EditForm {
  id: number;
  username: string;
  role_id: number;
  department: string;
  org_id: number;
  status: number;
}

export default function Users() {
  const { toast } = useToast();
  const currentUser = useUserStore((s) => s.user);
  const [activeTab, setActiveTab] = useState<TabKey>('users');
  const [loading, setLoading] = useState(true);

  // 用户列表
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [page, setPage] = useState(1);

  // 新建
  const [addOpen, setAddOpen] = useState(false);
  const [addForm, setAddForm] = useState<UserForm>(EMPTY_USER_FORM);
  const [addSaving, setAddSaving] = useState(false);

  // 编辑
  const [editOpen, setEditOpen] = useState(false);
  const [editForm, setEditForm] = useState<EditForm | null>(null);
  const [editSaving, setEditSaving] = useState(false);

  // 删除确认
  const [deleteTarget, setDeleteTarget] = useState<UserRecord | null>(null);
  const [deleting, setDeleting] = useState(false);

  // 审计日志
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [auditPage, setAuditPage] = useState(1);
  const [auditFilter, setAuditFilter] = useState({ username: '', operation_type: '', start_date: '', end_date: '' });

  const orgName = useCallback(
    (orgId?: number) => {
      if (orgId === undefined || orgId === null) return '-';
      return orgs.find((o) => o.id === orgId)?.name || `组织#${orgId}`;
    },
    [orgs]
  );

  const loadUsers = useCallback(async () => {
    setLoading(true);
    try {
      const [uData, oData] = await Promise.all([userApi.list({ page: 1, pageSize: 100 }), userApi.orgs()]);
      setUsers(uData?.list || []);
      setOrgs(oData || []);
    } catch {
      setUsers([]);
      setOrgs([]);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const paginatedUsers = useMemo(() => {
    const s = (page - 1) * PAGE_SIZE;
    return users.slice(s, s + PAGE_SIZE);
  }, [users, page]);

  async function loadAudit() {
    setLoading(true);
    try {
      const logs = await userApi.auditLogs({
        page: 1,
        pageSize: 100,
        username: auditFilter.username.trim() || undefined,
        operation_type: auditFilter.operation_type || undefined,
        start_date: auditFilter.start_date || undefined,
        end_date: auditFilter.end_date || undefined
      });
      setAuditLogs(logs || []);
      setAuditPage(1);
    } catch {
      setAuditLogs([]);
    }
    setLoading(false);
  }

  function switchTab(tab: TabKey) {
    setActiveTab(tab);
    if (tab === 'audit') loadAudit();
  }

  function resetAuditFilter() {
    setAuditFilter({ username: '', operation_type: '', start_date: '', end_date: '' });
    loadAudit();
  }

  function openAdd() {
    setAddForm({ ...EMPTY_USER_FORM, org_id: orgs[0]?.id || 1 });
    setAddOpen(true);
  }

  async function submitAdd() {
    if (!addForm.username.trim()) {
      toast({ title: '请输入用户名', variant: 'warning' });
      return;
    }
    if (!addForm.password) {
      toast({ title: '请输入密码', variant: 'warning' });
      return;
    }
    if (addForm.password.length < 8) {
      toast({ title: '密码长度不能少于8位', variant: 'warning' });
      return;
    }
    setAddSaving(true);
    try {
      await userApi.create({
        username: addForm.username.trim(),
        password: addForm.password,
        role_id: addForm.role_id,
        department: addForm.department.trim(),
        org_id: addForm.org_id
      });
      toast({ title: '用户创建成功', variant: 'success' });
      setAddOpen(false);
      loadUsers();
    } catch {
      // http 拦截器已提示
    }
    setAddSaving(false);
  }

  function openEdit(u: UserRecord) {
    setEditForm({
      id: u.id,
      username: u.username,
      role_id: u.role_id,
      department: u.department || '',
      org_id: u.org_id || 1,
      status: u.status || 1
    });
    setEditOpen(true);
  }

  async function submitEdit() {
    if (!editForm) return;
    setEditSaving(true);
    try {
      await userApi.update(editForm.id, {
        role_id: editForm.role_id,
        department: editForm.department.trim(),
        status: editForm.status
      });
      toast({ title: '用户信息已更新', variant: 'success' });
      setEditOpen(false);
      loadUsers();
    } catch {
      // http 拦截器已提示
    }
    setEditSaving(false);
  }

  async function toggleUserStatus(u: UserRecord) {
    const next = u.status ? 0 : 1;
    try {
      await userApi.update(u.id, { status: next });
      toast({ title: `用户已${next ? '启用' : '禁用'}`, variant: 'success' });
      loadUsers();
    } catch {
      // http 拦截器已提示
    }
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await userApi.remove(deleteTarget.id);
      toast({ title: '用户已删除', variant: 'success' });
      setDeleteTarget(null);
      loadUsers();
    } catch {
      // http 拦截器已提示
    }
    setDeleting(false);
  }

  function exportAuditLogs() {
    if (auditLogs.length === 0) {
      toast({ title: '暂无可导出的审计日志', variant: 'warning' });
      return;
    }
    const headers = '用户,操作类型,操作目标,IP,结果,时间\n';
    const rows = auditLogs
      .map(
        (l) =>
          `${l.username || '-'},${l.operation_type || '-'},${l.operation_target || '-'},${l.client_ip || '-'},${
            l.result || 'success'
          },${formatTime(l.created_at)}`
      )
      .join('\n');
    const blob = new Blob(['\uFEFF' + headers + rows], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'audit_logs.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({ title: '审计日志已导出', variant: 'success' });
  }

  const tabs: Array<[TabKey, string]> = [
    ['users', '用户列表'],
    ['audit', '审计日志']
  ];

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">用户管理</h2>
          <p className="mt-1 text-sm text-gray-400">系统用户管理与操作审计</p>
        </div>
        {activeTab === 'users' && (
          <Button size="sm" onClick={openAdd}>
            添加用户
          </Button>
        )}
      </div>

      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        {/* Tabs */}
        <div className="mb-4 flex gap-6 border-b border-white/10">
          {tabs.map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => switchTab(key)}
              className={`border-b-2 pb-2 text-sm transition-colors ${
                activeTab === key
                  ? 'border-cyan-400 text-cyan-300'
                  : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* 用户列表 */}
        {activeTab === 'users' && (
          <>
            <Table>
              <thead>
                <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                  <th className="px-2 py-2 font-medium">ID</th>
                  <th className="px-2 py-2 font-medium">用户名</th>
                  <th className="px-2 py-2 font-medium">角色</th>
                  <th className="px-2 py-2 font-medium">部门</th>
                  <th className="px-2 py-2 font-medium">组织</th>
                  <th className="px-2 py-2 font-medium">状态</th>
                  <th className="px-2 py-2 font-medium">创建时间</th>
                  <th className="px-2 py-2 font-medium">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {paginatedUsers.map((u) => {
                  const role = roleTag(u.role_name, u.role_id);
                  const active = !!u.status;
                  return (
                    <tr key={u.id} className="hover:bg-white/5">
                      <td className="px-2 py-2 font-mono text-xs text-gray-400">{u.id}</td>
                      <td className="px-2 py-2 text-gray-300">{u.username}</td>
                      <td className="px-2 py-2">
                        <Badge variant={role.variant}>{role.label}</Badge>
                      </td>
                      <td className="px-2 py-2 text-gray-400">{u.department || '-'}</td>
                      <td className="px-2 py-2 text-gray-400">{orgName(u.org_id)}</td>
                      <td className="px-2 py-2">
                        <Badge variant={active ? 'success' : 'default'}>{active ? '正常' : '禁用'}</Badge>
                      </td>
                      <td className="px-2 py-2 text-gray-400">{formatTime(u.created_at)}</td>
                      <td className="px-2 py-2">
                        <div className="flex gap-3">
                          <button
                            type="button"
                            onClick={() => openEdit(u)}
                            className="text-xs text-cyan-400 transition-colors hover:text-cyan-300"
                          >
                            编辑
                          </button>
                          <button
                            type="button"
                            onClick={() => toggleUserStatus(u)}
                            className="text-xs text-amber-400 transition-colors hover:text-amber-300"
                          >
                            {active ? '禁用' : '启用'}
                          </button>
                          {currentUser?.id !== u.id && (
                            <button
                              type="button"
                              onClick={() => setDeleteTarget(u)}
                              className="text-xs text-red-400 transition-colors hover:text-red-300"
                            >
                              删除
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {paginatedUsers.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-2 py-6 text-center text-gray-500">
                      {loading ? '加载中…' : '暂无用户'}
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
            <Pagination page={page} total={users.length} pageSize={PAGE_SIZE} onChange={setPage} />
          </>
        )}

        {/* 审计日志 */}
        {activeTab === 'audit' && (
          <>
            <div className="mb-4 flex flex-wrap items-end gap-3">
              <div>
                <label className="mb-1 block text-xs text-gray-500">用户名</label>
                <input
                  className={`${fieldCls} w-[150px]`}
                  value={auditFilter.username}
                  placeholder="用户名"
                  onChange={(e) => setAuditFilter({ ...auditFilter, username: e.target.value })}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-500">操作类型</label>
                <select
                  className={`${fieldCls} w-[150px]`}
                  value={auditFilter.operation_type}
                  onChange={(e) => setAuditFilter({ ...auditFilter, operation_type: e.target.value })}
                >
                  <option value="">全部</option>
                  {OPERATION_TYPES.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-500">开始日期</label>
                <input
                  type="date"
                  className={`${fieldCls} w-[150px]`}
                  value={auditFilter.start_date}
                  onChange={(e) => setAuditFilter({ ...auditFilter, start_date: e.target.value })}
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-500">结束日期</label>
                <input
                  type="date"
                  className={`${fieldCls} w-[150px]`}
                  value={auditFilter.end_date}
                  onChange={(e) => setAuditFilter({ ...auditFilter, end_date: e.target.value })}
                />
              </div>
              <div className="flex gap-2">
                <Button size="sm" onClick={loadAudit}>
                  查询
                </Button>
                <Button size="sm" variant="outline" onClick={resetAuditFilter}>
                  重置
                </Button>
                <Button size="sm" variant="outline" onClick={exportAuditLogs}>
                  导出CSV
                </Button>
              </div>
            </div>
            <Table>
              <thead>
                <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                  <th className="px-2 py-2 font-medium">日志ID</th>
                  <th className="px-2 py-2 font-medium">操作用户</th>
                  <th className="px-2 py-2 font-medium">操作类型</th>
                  <th className="px-2 py-2 font-medium">操作对象</th>
                  <th className="px-2 py-2 font-medium">来源IP</th>
                  <th className="px-2 py-2 font-medium">结果</th>
                  <th className="px-2 py-2 font-medium">时间</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {auditLogs.slice((auditPage - 1) * PAGE_SIZE, auditPage * PAGE_SIZE).map((l) => (
                  <tr key={l.id} className="hover:bg-white/5">
                    <td className="px-2 py-2 font-mono text-xs text-gray-400">AUD-{l.id}</td>
                    <td className="px-2 py-2 text-gray-300">{l.username || '-'}</td>
                    <td className="px-2 py-2 text-gray-400">{l.operation_type || '-'}</td>
                    <td className="max-w-[200px] truncate px-2 py-2 text-gray-400" title={l.operation_target || ''}>
                      {l.operation_target || '-'}
                    </td>
                    <td className="px-2 py-2 text-gray-400">{l.client_ip || '-'}</td>
                    <td className="px-2 py-2">
                      <Badge variant={resultTag(l.result).variant}>{resultTag(l.result).label}</Badge>
                    </td>
                    <td className="px-2 py-2 text-gray-400">{formatTime(l.created_at)}</td>
                  </tr>
                ))}
                {auditLogs.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-2 py-6 text-center text-gray-500">
                      {loading ? '加载中…' : '暂无审计日志'}
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
            <Pagination page={auditPage} total={auditLogs.length} pageSize={PAGE_SIZE} onChange={setAuditPage} />
          </>
        )}
      </div>

      {/* 新建用户 */}
      <Dialog
        open={addOpen}
        onOpenChange={(open) => !open && setAddOpen(false)}
        title="添加用户"
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setAddOpen(false)}>
              取消
            </Button>
            <Button size="sm" disabled={addSaving} onClick={submitAdd}>
              {addSaving ? '添加中…' : '添加'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <div>
            <label className="mb-1 block text-xs text-gray-400">用户名（必填）</label>
            <input
              className={`${fieldCls} w-full`}
              value={addForm.username}
              placeholder="请输入用户名"
              onChange={(e) => setAddForm({ ...addForm, username: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">密码（必填，≥8位且含字母和数字）</label>
            <input
              className={`${fieldCls} w-full`}
              type="password"
              value={addForm.password}
              placeholder="请输入密码"
              onChange={(e) => setAddForm({ ...addForm, password: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">角色</label>
            <select
              className={`${fieldCls} w-full`}
              value={addForm.role_id}
              onChange={(e) => setAddForm({ ...addForm, role_id: Number(e.target.value) })}
            >
              {ROLE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">部门</label>
            <input
              className={`${fieldCls} w-full`}
              value={addForm.department}
              placeholder="请输入部门"
              onChange={(e) => setAddForm({ ...addForm, department: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">组织</label>
            <select
              className={`${fieldCls} w-full`}
              value={addForm.org_id}
              onChange={(e) => setAddForm({ ...addForm, org_id: Number(e.target.value) })}
            >
              {orgs.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
              {orgs.length === 0 && <option value={1}>组织#1</option>}
            </select>
          </div>
        </div>
      </Dialog>

      {/* 编辑用户 */}
      <Dialog
        open={editOpen}
        onOpenChange={(open) => !open && setEditOpen(false)}
        title="编辑用户"
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setEditOpen(false)}>
              取消
            </Button>
            <Button size="sm" disabled={editSaving} onClick={submitEdit}>
              {editSaving ? '保存中…' : '保存'}
            </Button>
          </>
        }
      >
        {editForm && (
          <div className="space-y-4">
            <div>
              <label className="mb-1 block text-xs text-gray-400">用户名</label>
              <input className={`${fieldCls} w-full`} value={editForm.username} disabled />
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-400">角色</label>
              <select
                className={`${fieldCls} w-full`}
                value={editForm.role_id}
                onChange={(e) => setEditForm({ ...editForm, role_id: Number(e.target.value) })}
              >
                {ROLE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-400">部门</label>
              <input
                className={`${fieldCls} w-full`}
                value={editForm.department}
                placeholder="请输入部门"
                onChange={(e) => setEditForm({ ...editForm, department: e.target.value })}
              />
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-400">组织</label>
              <select
                className={`${fieldCls} w-full`}
                value={editForm.org_id}
                onChange={(e) => setEditForm({ ...editForm, org_id: Number(e.target.value) })}
              >
                {orgs.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
                {orgs.length === 0 && <option value={1}>组织#1</option>}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-400">状态</label>
              <select
                className={`${fieldCls} w-full`}
                value={editForm.status}
                onChange={(e) => setEditForm({ ...editForm, status: Number(e.target.value) })}
              >
                <option value={1}>正常</option>
                <option value={0}>禁用</option>
              </select>
            </div>
          </div>
        )}
      </Dialog>

      {/* 删除确认 */}
      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        title="删除用户"
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setDeleteTarget(null)}>
              取消
            </Button>
            <Button size="sm" variant="destructive" disabled={deleting} onClick={confirmDelete}>
              {deleting ? '删除中…' : '确认删除'}
            </Button>
          </>
        }
      >
        <p className="text-sm text-gray-700">
          确定要删除用户 <span className="font-semibold text-gray-900">{deleteTarget?.username}</span> 吗？此操作不可恢复。
        </p>
      </Dialog>
    </div>
  );
}
