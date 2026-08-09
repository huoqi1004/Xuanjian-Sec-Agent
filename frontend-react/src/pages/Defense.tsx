import { useEffect, useMemo, useState } from 'react';
import { defenseApi } from '@/api';
import type { ActionLog, AutoPolicy, PolicyApproval } from '@/api';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import Dialog from '@/components/ui/dialog';
import { Table } from '@/components/ui/table';
import { useToast } from '@/components/ui/use-toast';

const PAGE_SIZE = 10;

const fieldCls =
  'rounded-md border border-cyan-500/20 bg-[#1a2340] px-3 py-2 text-sm text-gray-300 outline-none transition-colors placeholder:text-gray-500 focus:border-cyan-500/60';

type TabKey = 'policies' | 'approvals' | 'logs';

interface TagInfo {
  label: string;
  variant: 'default' | 'success' | 'warning' | 'danger';
}

interface PolicyForm {
  name: string;
  description: string;
  conditionsJson: string;
  actionsJson: string;
  cooldown: number;
  unattended: boolean;
  enabled: boolean;
}

const EMPTY_FORM: PolicyForm = {
  name: '',
  description: '',
  conditionsJson: '[]',
  actionsJson: '[]',
  cooldown: 300,
  unattended: false,
  enabled: true
};

function isEnabled(v: number | boolean | undefined): boolean {
  return v !== 0 && v !== false && v !== undefined;
}

function enabledTag(enabled: boolean): TagInfo {
  return enabled ? { label: '已启用', variant: 'success' } : { label: '已禁用', variant: 'default' };
}

function approvalTag(status?: string): TagInfo {
  if (status === 'pending') return { label: '待审批', variant: 'warning' };
  if (status === 'approved') return { label: '已审批', variant: 'success' };
  if (status === 'rejected') return { label: '已驳回', variant: 'danger' };
  return { label: status || '-', variant: 'default' };
}

function resultTag(result?: string): TagInfo {
  return result === 'success' ? { label: '成功', variant: 'success' } : { label: '失败', variant: 'danger' };
}

/** 兼容后端返回的数组或 JSON 字符串，统一转为数组 */
function normalizeList<T>(v: unknown): T[] {
  if (Array.isArray(v)) return v as T[];
  if (typeof v === 'string') {
    try {
      const parsed = JSON.parse(v);
      if (Array.isArray(parsed)) return parsed as T[];
    } catch {
      // 非 JSON 字符串，返回空数组
    }
  }
  return [];
}

function conditionsText(v: unknown, fallback?: string): string {
  const list = normalizeList<{ field?: string; fact?: string }>(v);
  if (list.length > 0) {
    return list.map((c) => c.field || c.fact || JSON.stringify(c)).join('; ');
  }
  return fallback || '-';
}

function actionsText(v: unknown): string {
  const list = normalizeList<{ type?: string }>(v);
  if (list.length > 0) {
    return list.map((a) => a.type || JSON.stringify(a)).join(', ');
  }
  return '-';
}

function formatTime(t?: string): string {
  return t ? new Date(t).toLocaleString('zh-CN') : '-';
}

function ToggleSwitch({
  checked,
  disabled,
  onChange
}: {
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
        checked ? 'bg-green-500' : 'bg-gray-600'
      }`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
          checked ? 'translate-x-[18px]' : 'translate-x-0.5'
        }`}
      />
    </button>
  );
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

export default function Defense() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState<TabKey>('policies');
  const [loading, setLoading] = useState(false);

  const [policies, setPolicies] = useState<AutoPolicy[]>([]);
  const [approvals, setApprovals] = useState<PolicyApproval[]>([]);
  const [logs, setLogs] = useState<ActionLog[]>([]);

  const [policyPage, setPolicyPage] = useState(1);
  const [logPage, setLogPage] = useState(1);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form, setForm] = useState<PolicyForm>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  const [deleteTarget, setDeleteTarget] = useState<AutoPolicy | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function loadData() {
    setLoading(true);
    try {
      const [pol, app, logRes] = await Promise.all([
        defenseApi.policies(),
        defenseApi.pendingApprovals(),
        defenseApi.actionLogs({ page: 1, pageSize: 100 })
      ]);
      setPolicies(pol || []);
      setApprovals(app || []);
      setLogs(logRes?.list || []);
    } catch {
      setPolicies([]);
      setApprovals([]);
      setLogs([]);
    }
    setLoading(false);
  }

  useEffect(() => {
    loadData();
  }, []);

  const paginatedPolicies = useMemo(() => {
    const s = (policyPage - 1) * PAGE_SIZE;
    return policies.slice(s, s + PAGE_SIZE);
  }, [policies, policyPage]);

  const paginatedLogs = useMemo(() => {
    const s = (logPage - 1) * PAGE_SIZE;
    return logs.slice(s, s + PAGE_SIZE);
  }, [logs, logPage]);

  function openCreate() {
    setEditingId(null);
    setForm({ ...EMPTY_FORM });
    setDialogOpen(true);
  }

  function openEdit(p: AutoPolicy) {
    setEditingId(p.id);
    setForm({
      name: p.name,
      description: p.description || '',
      conditionsJson: JSON.stringify(normalizeList(p.conditions), null, 2),
      actionsJson: JSON.stringify(normalizeList(p.actions), null, 2),
      cooldown: p.cooldown || 300,
      unattended: !!p.unattended,
      enabled: isEnabled(p.enabled)
    });
    setDialogOpen(true);
  }

  async function savePolicy() {
    if (!form.name.trim()) {
      toast({ title: '请输入策略名称', variant: 'warning' });
      return;
    }
    let conditions: Array<Record<string, unknown>>;
    let actions: Array<Record<string, unknown>>;
    try {
      conditions = JSON.parse(form.conditionsJson || '[]');
    } catch {
      toast({ title: '触发条件 JSON 格式不正确', variant: 'error' });
      return;
    }
    try {
      actions = JSON.parse(form.actionsJson || '[]');
    } catch {
      toast({ title: '执行动作 JSON 格式不正确', variant: 'error' });
      return;
    }
    if (!Array.isArray(conditions) || !Array.isArray(actions)) {
      toast({ title: '条件与动作需为 JSON 数组', variant: 'error' });
      return;
    }
    const payload = {
      name: form.name.trim(),
      description: form.description.trim() || undefined,
      conditions,
      actions,
      cooldown: form.cooldown || 300,
      unattended: form.unattended,
      enabled: form.enabled
    };
    setSaving(true);
    try {
      if (editingId !== null) {
        await defenseApi.update(editingId, payload);
        toast({ title: '策略更新成功', variant: 'success' });
      } else {
        await defenseApi.create(payload);
        toast({ title: '策略创建成功', variant: 'success' });
      }
      setDialogOpen(false);
      loadData();
    } catch {
      // http 拦截器已提示
    }
    setSaving(false);
  }

  async function togglePolicy(p: AutoPolicy) {
    const enabled = !isEnabled(p.enabled);
    try {
      await defenseApi.toggle(p.id, enabled);
      toast({ title: `策略已${enabled ? '启用' : '禁用'}`, variant: 'success' });
      loadData();
    } catch {
      // http 拦截器已提示
    }
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await defenseApi.remove(deleteTarget.id);
      toast({ title: '策略已删除', variant: 'success' });
      setDeleteTarget(null);
      loadData();
    } catch {
      // http 拦截器已提示
    }
    setDeleting(false);
  }

  async function reviewApproval(a: PolicyApproval, approved: boolean) {
    if (a.approval_id === undefined) return;
    try {
      await defenseApi.approve(a.approval_id, approved ? 'approved' : 'rejected', approved ? '审批通过' : '审批驳回');
      toast({ title: approved ? '已审批通过' : '已驳回', variant: 'success' });
      loadData();
    } catch {
      // http 拦截器已提示
    }
  }

  const tabs: Array<[TabKey, string]> = [
    ['policies', '策略列表'],
    ['approvals', '待审批'],
    ['logs', '动作日志']
  ];

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">自动化防御</h2>
          <p className="mt-1 text-sm text-gray-400">安全策略管理与自动化响应</p>
        </div>
        <Button size="sm" onClick={openCreate}>
          创建策略
        </Button>
      </div>

      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        {/* Tabs */}
        <div className="mb-4 flex gap-6 border-b border-white/10">
          {tabs.map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => setActiveTab(key)}
              className={`flex items-center gap-2 border-b-2 pb-2 text-sm transition-colors ${
                activeTab === key
                  ? 'border-cyan-400 text-cyan-300'
                  : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}
            >
              {label}
              {key === 'approvals' && approvals.length > 0 && (
                <span className="rounded-full bg-amber-500/20 px-1.5 py-0.5 text-xs text-amber-400">
                  {approvals.length}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* 策略列表 */}
        {activeTab === 'policies' && (
          <>
            <Table>
              <thead>
                <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                  <th className="px-2 py-2 font-medium">ID</th>
                  <th className="px-2 py-2 font-medium">策略名称</th>
                  <th className="px-2 py-2 font-medium">描述</th>
                  <th className="px-2 py-2 font-medium">触发条件</th>
                  <th className="px-2 py-2 font-medium">执行动作</th>
                  <th className="px-2 py-2 font-medium">冷却时间</th>
                  <th className="px-2 py-2 font-medium">无人值守</th>
                  <th className="px-2 py-2 font-medium">启用</th>
                  <th className="px-2 py-2 font-medium">审批状态</th>
                  <th className="px-2 py-2 font-medium">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {paginatedPolicies.map((p) => {
                  const enabled = isEnabled(p.enabled);
                  const pending = p.approval_status === 'pending';
                  return (
                    <tr key={p.id} className="hover:bg-white/5">
                      <td className="px-2 py-2 font-mono text-xs text-gray-400">{p.id}</td>
                      <td className="px-2 py-2 text-gray-300">{p.name}</td>
                      <td className="max-w-[200px] truncate px-2 py-2 text-gray-400" title={p.description || ''}>
                        {p.description || '-'}
                      </td>
                      <td
                        className="max-w-[220px] truncate px-2 py-2 text-gray-400"
                        title={conditionsText(p.conditions)}
                      >
                        {conditionsText(p.conditions)}
                      </td>
                      <td className="max-w-[160px] truncate px-2 py-2 text-gray-400" title={actionsText(p.actions)}>
                        {actionsText(p.actions)}
                      </td>
                      <td className="px-2 py-2 text-gray-400">{p.cooldown}s</td>
                      <td className="px-2 py-2">
                        <Badge variant={p.unattended ? 'success' : 'default'}>{p.unattended ? '是' : '否'}</Badge>
                      </td>
                      <td className="px-2 py-2">
                        <div className="flex items-center gap-2">
                          <ToggleSwitch checked={enabled} disabled={pending} onChange={() => togglePolicy(p)} />
                          <Badge variant={enabledTag(enabled).variant}>{enabledTag(enabled).label}</Badge>
                        </div>
                      </td>
                      <td className="px-2 py-2">
                        <Badge variant={approvalTag(p.approval_status).variant}>
                          {approvalTag(p.approval_status).label}
                        </Badge>
                      </td>
                      <td className="px-2 py-2">
                        <div className="flex gap-3">
                          <button
                            type="button"
                            onClick={() => openEdit(p)}
                            className="text-xs text-cyan-400 transition-colors hover:text-cyan-300"
                          >
                            编辑
                          </button>
                          <button
                            type="button"
                            onClick={() => setDeleteTarget(p)}
                            className="text-xs text-red-400 transition-colors hover:text-red-300"
                          >
                            删除
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {paginatedPolicies.length === 0 && (
                  <tr>
                    <td colSpan={10} className="px-2 py-6 text-center text-gray-500">
                      {loading ? '加载中…' : '暂无防御策略'}
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
            <Pagination page={policyPage} total={policies.length} pageSize={PAGE_SIZE} onChange={setPolicyPage} />
          </>
        )}

        {/* 待审批 */}
        {activeTab === 'approvals' && (
          <>
            {approvals.length === 0 ? (
              <div className="py-10 text-center text-sm text-gray-500">{loading ? '加载中…' : '暂无待审批策略'}</div>
            ) : (
              <Table>
                <thead>
                  <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                    <th className="px-2 py-2 font-medium">策略ID</th>
                    <th className="px-2 py-2 font-medium">策略名称</th>
                    <th className="px-2 py-2 font-medium">触发条件</th>
                    <th className="px-2 py-2 font-medium">执行动作</th>
                    <th className="px-2 py-2 font-medium">申请人</th>
                    <th className="px-2 py-2 font-medium">申请时间</th>
                    <th className="px-2 py-2 font-medium">风险评估</th>
                    <th className="px-2 py-2 font-medium">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {approvals.map((a) => (
                    <tr key={a.approval_id ?? a.id} className="hover:bg-white/5">
                      <td className="px-2 py-2 font-mono text-xs text-gray-400">{a.id ?? '-'}</td>
                      <td className="px-2 py-2 text-gray-300">{a.name || '-'}</td>
                      <td
                        className="max-w-[220px] truncate px-2 py-2 text-gray-400"
                        title={conditionsText(a.conditions, a.description)}
                      >
                        {conditionsText(a.conditions, a.description)}
                      </td>
                      <td className="max-w-[160px] truncate px-2 py-2 text-gray-400" title={actionsText(a.actions)}>
                        {actionsText(a.actions)}
                      </td>
                      <td className="px-2 py-2 text-gray-400">{a.requester_name || '未知'}</td>
                      <td className="px-2 py-2 text-gray-400">{formatTime(a.request_date || a.created_at)}</td>
                      <td className="max-w-[200px] truncate px-2 py-2 text-gray-400" title={a.risk_assessment || ''}>
                        {a.risk_assessment || '-'}
                      </td>
                      <td className="px-2 py-2">
                        <div className="flex gap-2">
                          <Button size="sm" onClick={() => reviewApproval(a, true)}>
                            通过
                          </Button>
                          <Button size="sm" variant="destructive" onClick={() => reviewApproval(a, false)}>
                            驳回
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </>
        )}

        {/* 动作日志 */}
        {activeTab === 'logs' && (
          <>
            <Table>
              <thead>
                <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                  <th className="px-2 py-2 font-medium">日志ID</th>
                  <th className="px-2 py-2 font-medium">策略名称</th>
                  <th className="px-2 py-2 font-medium">动作类型</th>
                  <th className="px-2 py-2 font-medium">动作详情</th>
                  <th className="px-2 py-2 font-medium">结果</th>
                  <th className="px-2 py-2 font-medium">执行时间</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {paginatedLogs.map((l) => (
                  <tr key={l.id} className="hover:bg-white/5">
                    <td className="px-2 py-2 font-mono text-xs text-gray-400">{l.id}</td>
                    <td className="px-2 py-2 text-gray-300">
                      {l.policy_name || (l.policy_id !== undefined ? `策略#${l.policy_id}` : '-')}
                    </td>
                    <td className="px-2 py-2 text-gray-400">{l.action_type || '-'}</td>
                    <td className="max-w-[300px] truncate px-2 py-2 text-gray-400" title={l.action_detail || ''}>
                      {l.action_detail || '-'}
                    </td>
                    <td className="px-2 py-2">
                      <Badge variant={resultTag(l.result).variant}>{resultTag(l.result).label}</Badge>
                    </td>
                    <td className="px-2 py-2 text-gray-400">{formatTime(l.executed_at)}</td>
                  </tr>
                ))}
                {paginatedLogs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-2 py-6 text-center text-gray-500">
                      {loading ? '加载中…' : '暂无动作日志'}
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
            <Pagination page={logPage} total={logs.length} pageSize={PAGE_SIZE} onChange={setLogPage} />
          </>
        )}
      </div>

      {/* 新建/编辑策略弹窗 */}
      <Dialog
        open={dialogOpen}
        onOpenChange={(open) => !open && setDialogOpen(false)}
        title={editingId !== null ? '编辑防御策略' : '创建防御策略'}
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setDialogOpen(false)}>
              取消
            </Button>
            <Button size="sm" disabled={saving} onClick={savePolicy}>
              {saving ? '保存中…' : '保存'}
            </Button>
          </>
        }
      >
        <div className="max-h-[60vh] space-y-4 overflow-y-auto pr-1">
          <div>
            <label className="mb-1 block text-xs text-gray-400">策略名称</label>
            <input
              className={`${fieldCls} w-full`}
              value={form.name}
              placeholder="请输入策略名称"
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">描述</label>
            <input
              className={`${fieldCls} w-full`}
              value={form.description}
              placeholder="策略描述（可选）"
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">
              触发条件（JSON 数组，例：[{'{'} "field": "login_failures", "operator": "greaterThan", "value": 10 {'}'}{' '}
              ]）
            </label>
            <textarea
              className={`${fieldCls} w-full resize-none font-mono text-xs`}
              rows={3}
              value={form.conditionsJson}
              onChange={(e) => setForm({ ...form, conditionsJson: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">
              执行动作（JSON 数组，例：[{'{'} "type": "block_ip", "params": {'{'} "duration": 3600 {'}'} {'}'} ]）
            </label>
            <textarea
              className={`${fieldCls} w-full resize-none font-mono text-xs`}
              rows={3}
              value={form.actionsJson}
              onChange={(e) => setForm({ ...form, actionsJson: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">冷却时间（秒）</label>
            <input
              type="number"
              min={60}
              max={86400}
              step={60}
              className={`${fieldCls} w-full`}
              value={form.cooldown}
              onChange={(e) => setForm({ ...form, cooldown: Number(e.target.value) })}
            />
          </div>
          <div className="space-y-3 pt-1">
            <label className="flex cursor-pointer items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={form.unattended}
                onChange={(e) => setForm({ ...form, unattended: e.target.checked })}
                className="h-4 w-4 accent-cyan-500"
              />
              无人值守（开启后策略将自动执行无需审批）
            </label>
            <label className="flex cursor-pointer items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                className="h-4 w-4 accent-cyan-500"
              />
              立即启用
            </label>
          </div>
        </div>
      </Dialog>

      {/* 删除确认 */}
      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)} title="删除确认">
        <p className="text-sm text-gray-600">确定要删除策略「{deleteTarget?.name}」吗？删除后无法恢复。</p>
        <div className="mt-4 flex justify-end gap-2">
          <Button size="sm" variant="outline" onClick={() => setDeleteTarget(null)}>
            取消
          </Button>
          <Button size="sm" variant="destructive" disabled={deleting} onClick={confirmDelete}>
            {deleting ? '删除中…' : '删除'}
          </Button>
        </div>
      </Dialog>
    </div>
  );
}
