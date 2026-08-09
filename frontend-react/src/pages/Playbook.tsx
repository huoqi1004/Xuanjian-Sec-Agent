import { useEffect, useMemo, useState } from 'react';
import { playbookApi } from '@/api';
import type { Playbook, PlaybookApproval, PlaybookRunResult, PlaybookStep, PlaybookStepResult } from '@/api';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import Dialog from '@/components/ui/dialog';
import { Table } from '@/components/ui/table';
import { useToast } from '@/components/ui/use-toast';
import { useUserStore } from '@/stores/user';

const PAGE_SIZE = 10;

const fieldCls =
  'rounded-md border border-cyan-500/20 bg-[#1a2340] px-3 py-2 text-sm text-gray-300 outline-none transition-colors placeholder:text-gray-500 focus:border-cyan-500/60';

const TRIGGERS: Array<{ value: string; label: string }> = [
  { value: 'manual', label: '手动触发' },
  { value: 'brute_force', label: '暴力破解' },
  { value: 'intel_match', label: '情报命中' },
  { value: 'ransomware', label: '勒索告警' }
];

const STEP_PLACEHOLDER =
  '[{"type":"condition","fact":"fail_count","operator":"gt","value":5}, {"type":"action","action":"firewall_block","params":{"ip":"{{ip}}","duration":1800}}]';

const STEP_TIP =
  '步骤类型：condition 条件 / action 动作(firewall_block,account_lock,raise_alert,notify,webhook,log_only) / approval 人工审批 / notification 通知 / wait 等待。动作参数支持 {{字段}} 引用执行事件字段。';

function isEnabled(v: number | boolean | undefined): boolean {
  return v !== 0 && v !== false && v !== undefined;
}

function triggerVariant(trigger?: string): 'default' | 'success' | 'warning' | 'danger' {
  if (trigger === 'brute_force' || trigger === 'ransomware') return 'danger';
  if (trigger === 'intel_match') return 'warning';
  return 'default';
}

function triggerLabel(trigger?: string): string {
  return TRIGGERS.find((t) => t.value === trigger)?.label || trigger || '-';
}

function formatTime(t?: string): string {
  return t ? new Date(t).toLocaleString('zh-CN') : '-';
}

function stepTypeLabel(type?: string): string {
  const labels: Record<string, string> = {
    condition: '条件',
    action: '动作',
    approval: '审批',
    notification: '通知',
    wait: '等待'
  };
  return (type && labels[type]) || type || '-';
}

function resultCell(r: PlaybookStepResult): string {
  if (r.type === 'condition') return r.ok ? '✅ 满足' : '⛔ 不满足';
  if (r.success === false) return r.error || '失败';
  if (r.status === 'pending') return `等待人工审批（${r.approval_id}）`;
  return r.detail || r.message || '成功';
}

function resultStatusVariant(status?: string): 'success' | 'warning' | 'error' {
  if (status === 'completed') return 'success';
  if (status === 'awaiting_approval') return 'warning';
  return 'error';
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

interface PlaybookForm {
  name: string;
  description: string;
  trigger: string;
  enabled: boolean;
  stepsJson: string;
}

const DEFAULT_STEPS: PlaybookStep[] = [
  { type: 'condition', name: '条件示例', fact: 'severity', operator: 'eq', value: 'high' },
  { type: 'action', name: '封禁IP', action: 'firewall_block', params: { ip: '{{ip}}', duration: 3600 } }
];

const EMPTY_FORM: PlaybookForm = {
  name: '',
  description: '',
  trigger: 'manual',
  enabled: true,
  stepsJson: JSON.stringify(DEFAULT_STEPS, null, 2)
};

export default function Playbook() {
  const { toast } = useToast();
  const user = useUserStore((s) => s.user);
  const isAdmin = user?.role_id === 1;

  const [list, setList] = useState<Playbook[]>([]);
  const [loading, setLoading] = useState(false);
  const [pendingApprovals, setPendingApprovals] = useState<PlaybookApproval[]>([]);
  const [page, setPage] = useState(1);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form, setForm] = useState<PlaybookForm>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  const [execVisible, setExecVisible] = useState(false);
  const [execTarget, setExecTarget] = useState<Playbook | null>(null);
  const [eventJson, setEventJson] = useState('{}');
  const [executing, setExecuting] = useState(false);

  const [resultVisible, setResultVisible] = useState(false);
  const [runResult, setRunResult] = useState<PlaybookRunResult | null>(null);

  const [deleteTarget, setDeleteTarget] = useState<Playbook | null>(null);
  const [deleting, setDeleting] = useState(false);

  const [approvalVisible, setApprovalVisible] = useState(false);

  async function loadList() {
    setLoading(true);
    try {
      const data = await playbookApi.list({ page: 1, pageSize: 200 });
      setList(data?.list ?? []);
    } catch {
      setList([]);
    }
    setLoading(false);
  }

  async function loadApprovals() {
    try {
      setPendingApprovals(await playbookApi.pendingApprovals());
    } catch {
      setPendingApprovals([]);
    }
  }

  useEffect(() => {
    loadList();
    loadApprovals();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const paginated = useMemo(() => {
    const s = (page - 1) * PAGE_SIZE;
    return list.slice(s, s + PAGE_SIZE);
  }, [list, page]);

  function openCreate() {
    setEditingId(null);
    setForm({ ...EMPTY_FORM });
    setDialogOpen(true);
  }

  function openEdit(p: Playbook) {
    setEditingId(p.id);
    setForm({
      name: p.name,
      description: p.description || '',
      trigger: p.trigger || 'manual',
      enabled: isEnabled(p.enabled),
      stepsJson: JSON.stringify(Array.isArray(p.steps) ? p.steps : [], null, 2)
    });
    setDialogOpen(true);
  }

  async function save() {
    if (!form.name.trim()) {
      toast({ title: '请输入剧本名称', variant: 'warning' });
      return;
    }
    let steps: PlaybookStep[];
    try {
      const parsed: unknown = JSON.parse(form.stepsJson || '[]');
      if (!Array.isArray(parsed)) throw new Error('steps must be array');
      steps = parsed as PlaybookStep[];
    } catch {
      toast({ title: '步骤 JSON 格式错误，请检查', variant: 'error' });
      return;
    }
    const payload = {
      name: form.name.trim(),
      description: form.description.trim() || undefined,
      trigger: form.trigger,
      enabled: form.enabled,
      steps
    };
    setSaving(true);
    try {
      if (editingId !== null) {
        await playbookApi.update(editingId, payload);
        toast({ title: '剧本已更新', variant: 'success' });
      } else {
        await playbookApi.create(payload);
        toast({ title: '剧本创建成功', variant: 'success' });
      }
      setDialogOpen(false);
      loadList();
    } catch {
      // http 拦截器已提示
    }
    setSaving(false);
  }

  async function toggleEnabled(p: Playbook) {
    const enabled = !isEnabled(p.enabled);
    try {
      await playbookApi.update(p.id, { enabled });
      toast({ title: `剧本已${enabled ? '启用' : '停用'}`, variant: 'success' });
      loadList();
    } catch {
      // http 拦截器已提示
    }
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await playbookApi.remove(deleteTarget.id);
      toast({ title: '剧本已删除', variant: 'success' });
      setDeleteTarget(null);
      loadList();
    } catch {
      // http 拦截器已提示
    }
    setDeleting(false);
  }

  async function seedTemplates() {
    try {
      const r = await playbookApi.seedTemplates();
      toast({ title: `模板导入完成（新增 ${r.seeded} 个）`, variant: 'success' });
      loadList();
    } catch {
      // http 拦截器已提示
    }
  }

  function openExecute(p: Playbook) {
    setExecTarget(p);
    setEventJson(
      JSON.stringify({ ip: '185.220.101.34', severity: 'high', confidence: 0.9, fail_count: 8 }, null, 2)
    );
    setExecVisible(true);
  }

  async function doExecute() {
    if (!execTarget) return;
    let event: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(eventJson || '{}');
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('bad event');
      event = parsed as Record<string, unknown>;
    } catch {
      toast({ title: '事件 JSON 格式错误', variant: 'error' });
      return;
    }
    setExecuting(true);
    try {
      const r = await playbookApi.execute(execTarget.id, event);
      setRunResult(r);
      setExecVisible(false);
      setResultVisible(true);
      loadApprovals();
      loadList();
    } catch {
      // http 拦截器已提示
    }
    setExecuting(false);
  }

  function openApprovals() {
    setApprovalVisible(true);
    loadApprovals();
  }

  async function handleApproval(a: PlaybookApproval, decision: 'approve' | 'reject') {
    try {
      await playbookApi.confirmApproval(a.id, decision);
      toast({ title: decision === 'approve' ? '已批准' : '已拒绝', variant: 'success' });
      loadApprovals();
    } catch {
      // http 拦截器已提示
    }
  }

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">SOAR 编排</h2>
          <p className="mt-1 text-sm text-gray-400">安全剧本自动化编排与人工审批</p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={loadList}>
            刷新
          </Button>
          {isAdmin && (
            <Button size="sm" variant="outline" onClick={seedTemplates}>
              导入模板
            </Button>
          )}
          {isAdmin && (
            <Button size="sm" onClick={openCreate}>
              新建剧本
            </Button>
          )}
          {pendingApprovals.length > 0 && (
            <Button size="sm" variant="outline" onClick={openApprovals} className="relative">
              待审批
              <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-medium text-white">
                {pendingApprovals.length}
              </span>
            </Button>
          )}
        </div>
      </div>

      {/* 剧本列表 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <Table>
          <thead>
            <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
              <th className="px-2 py-2 font-medium">ID</th>
              <th className="px-2 py-2 font-medium">名称</th>
              <th className="px-2 py-2 font-medium">触发</th>
              <th className="px-2 py-2 font-medium">描述</th>
              <th className="px-2 py-2 font-medium">步骤数</th>
              <th className="px-2 py-2 font-medium">启用</th>
              <th className="px-2 py-2 font-medium">创建人</th>
              <th className="px-2 py-2 font-medium">更新时间</th>
              <th className="px-2 py-2 font-medium">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {paginated.map((p) => {
              const enabled = isEnabled(p.enabled);
              return (
                <tr key={p.id} className="hover:bg-white/5">
                  <td className="px-2 py-2 font-mono text-xs text-gray-400">{p.id}</td>
                  <td className="px-2 py-2 text-gray-300">{p.name}</td>
                  <td className="px-2 py-2">
                    <Badge variant={triggerVariant(p.trigger)}>{triggerLabel(p.trigger)}</Badge>
                  </td>
                  <td className="max-w-[220px] truncate px-2 py-2 text-gray-400" title={p.description || ''}>
                    {p.description || '-'}
                  </td>
                  <td className="px-2 py-2 text-gray-400">{Array.isArray(p.steps) ? p.steps.length : 0}</td>
                  <td className="px-2 py-2">
                    <div className="flex items-center gap-2">
                      <ToggleSwitch checked={enabled} disabled={!isAdmin} onChange={() => toggleEnabled(p)} />
                      <Badge variant={enabled ? 'success' : 'default'}>{enabled ? '启用' : '停用'}</Badge>
                    </div>
                  </td>
                  <td className="px-2 py-2 text-gray-400">{p.created_by ?? '-'}</td>
                  <td className="px-2 py-2 text-gray-400">{formatTime(p.updated_at)}</td>
                  <td className="px-2 py-2">
                    <div className="flex gap-3">
                      <button
                        type="button"
                        onClick={() => openExecute(p)}
                        className="text-xs text-green-400 transition-colors hover:text-green-300"
                      >
                        执行
                      </button>
                      {isAdmin && (
                        <>
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
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
            {paginated.length === 0 && (
              <tr>
                <td colSpan={9} className="px-2 py-6 text-center text-gray-500">
                  {loading ? '加载中…' : '暂无剧本'}
                </td>
              </tr>
            )}
          </tbody>
        </Table>
        <Pagination page={page} total={list.length} pageSize={PAGE_SIZE} onChange={setPage} />
      </div>

      {/* 新建/编辑弹窗 */}
      <Dialog
        open={dialogOpen}
        onOpenChange={(open) => !open && setDialogOpen(false)}
        title={editingId !== null ? '编辑剧本' : '新建剧本'}
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setDialogOpen(false)}>
              取消
            </Button>
            <Button size="sm" disabled={saving} onClick={save}>
              {saving ? '保存中…' : '保存'}
            </Button>
          </>
        }
      >
        <div className="max-h-[60vh] space-y-4 overflow-y-auto pr-1">
          <div>
            <label className="mb-1 block text-xs text-gray-400">名称</label>
            <input
              className={`${fieldCls} w-full`}
              value={form.name}
              placeholder="剧本名称"
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">描述</label>
            <textarea
              className={`${fieldCls} w-full resize-none`}
              rows={2}
              value={form.description}
              placeholder="剧本用途说明"
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">触发方式</label>
            <select
              className={`${fieldCls} w-full`}
              value={form.trigger}
              onChange={(e) => setForm({ ...form, trigger: e.target.value })}
            >
              {TRIGGERS.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">步骤 JSON（数组，五项步骤类型）</label>
            <textarea
              className={`${fieldCls} w-full resize-none font-mono text-xs`}
              rows={10}
              value={form.stepsJson}
              placeholder={STEP_PLACEHOLDER}
              onChange={(e) => setForm({ ...form, stepsJson: e.target.value })}
            />
            <div className="mt-1 text-xs leading-5 text-gray-500">{STEP_TIP}</div>
          </div>
          <label className="flex cursor-pointer items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
              className="h-4 w-4 accent-cyan-500"
            />
            创建后立即启用
          </label>
        </div>
      </Dialog>

      {/* 执行弹窗 */}
      <Dialog
        open={execVisible}
        onOpenChange={(open) => !open && setExecVisible(false)}
        title={`执行剧本：${execTarget?.name || ''}`}
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setExecVisible(false)}>
              取消
            </Button>
            <Button size="sm" disabled={executing} onClick={doExecute}>
              {executing ? '执行中…' : '执行'}
            </Button>
          </>
        }
      >
        <div className="space-y-2">
          <label className="block text-xs text-gray-400">事件 JSON（可选）</label>
          <textarea
            className={`${fieldCls} w-full resize-none font-mono text-xs`}
            rows={8}
            value={eventJson}
            placeholder='{"ip":"185.220.101.34","severity":"high","confidence":0.9,"fail_count":8}'
            onChange={(e) => setEventJson(e.target.value)}
          />
          <div className="text-xs leading-5 text-gray-500">
            事件字段供 condition 判断与动作参数「{'{{字段}}'}」引用。
          </div>
        </div>
      </Dialog>

      {/* 执行结果弹窗 */}
      <Dialog
        open={resultVisible}
        onOpenChange={(open) => !open && setResultVisible(false)}
        title="执行结果"
      >
        <div className="space-y-3">
          <div
            className={`rounded-md border px-3 py-2 text-sm ${
              resultStatusVariant(runResult?.status) === 'success'
                ? 'border-green-500/30 bg-green-500/10 text-green-300'
                : resultStatusVariant(runResult?.status) === 'warning'
                  ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
                  : 'border-red-500/30 bg-red-500/10 text-red-300'
            }`}
          >
            <div className="font-medium">状态：{runResult?.status || 'unknown'}</div>
            <div className="mt-0.5 text-xs opacity-80">
              {runResult?.success ? `运行ID: ${runResult.run_id}` : runResult?.error || '运行失败'}
            </div>
          </div>
          {Array.isArray(runResult?.results) && runResult!.results!.length > 0 && (
            <Table>
              <thead>
                <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                  <th className="px-2 py-2 font-medium">步骤</th>
                  <th className="px-2 py-2 font-medium">类型</th>
                  <th className="px-2 py-2 font-medium">结果</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {runResult!.results!.map((r, i) => (
                  <tr key={i} className="hover:bg-white/5">
                    <td className="px-2 py-2 text-gray-300">{r.name || stepTypeLabel(r.type)}</td>
                    <td className="px-2 py-2">
                      <Badge variant={r.type === 'action' ? 'default' : r.type === 'approval' ? 'warning' : 'default'}>
                        {stepTypeLabel(r.type)}
                      </Badge>
                    </td>
                    <td className="px-2 py-2 text-gray-400">{resultCell(r)}</td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </div>
      </Dialog>

      {/* 删除确认 */}
      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)} title="删除确认">
        <p className="text-sm text-gray-600">确定要删除剧本「{deleteTarget?.name}」吗？删除后无法恢复。</p>
        <div className="mt-4 flex justify-end gap-2">
          <Button size="sm" variant="outline" onClick={() => setDeleteTarget(null)}>
            取消
          </Button>
          <Button size="sm" variant="destructive" disabled={deleting} onClick={confirmDelete}>
            {deleting ? '删除中…' : '删除'}
          </Button>
        </div>
      </Dialog>

      {/* 待审批 */}
      <Dialog
        open={approvalVisible}
        onOpenChange={(open) => !open && setApprovalVisible(false)}
        title="待人工审批"
      >
        {pendingApprovals.length === 0 ? (
          <div className="py-8 text-center text-sm text-gray-500">暂无待审批事项</div>
        ) : (
          <Table>
            <thead>
              <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                <th className="px-2 py-2 font-medium">审批ID</th>
                <th className="px-2 py-2 font-medium">事项</th>
                <th className="px-2 py-2 font-medium">剧本ID</th>
                <th className="px-2 py-2 font-medium">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {pendingApprovals.map((a) => (
                <tr key={a.id} className="hover:bg-white/5">
                  <td className="px-2 py-2 font-mono text-xs text-gray-400">{a.id}</td>
                  <td className="px-2 py-2 text-gray-300">{a.title}</td>
                  <td className="px-2 py-2 text-gray-400">{a.playbookId}</td>
                  <td className="px-2 py-2">
                    <div className="flex gap-2">
                      <Button size="sm" onClick={() => handleApproval(a, 'approve')}>
                        批准
                      </Button>
                      <Button size="sm" variant="destructive" onClick={() => handleApproval(a, 'reject')}>
                        拒绝
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Dialog>
    </div>
  );
}
