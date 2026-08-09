import { useEffect, useState } from 'react';
import { adapterApi, configApi } from '@/api';
import type { AdapterInfo, ConfigBackupItem, ConfigItem, CredentialItem } from '@/api';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import Dialog from '@/components/ui/dialog';
import { Table } from '@/components/ui/table';
import { useToast } from '@/components/ui/use-toast';

const fieldCls =
  'rounded-md border border-cyan-500/20 bg-[#1a2340] px-3 py-2 text-sm text-gray-300 outline-none transition-colors placeholder:text-gray-500 focus:border-cyan-500/60';

function formatTime(t?: string): string {
  return t ? new Date(t).toLocaleString('zh-CN') : '-';
}

function formatSize(bytes?: number): string {
  if (bytes === undefined || bytes === null) return '-';
  return (bytes / 1024).toFixed(1) + ' KB';
}

// ============ SOAR 适配器 ============
const PROVIDER_OPTIONS = [
  { value: 'switch', label: '交换机 (switch)' },
  { value: 'aliyun', label: '阿里云 (aliyun)' },
  { value: 'tencent', label: '腾讯云 (tencent)' }
];

interface FieldSpec {
  key: string;
  label: string;
  secret?: boolean;
}

const FIELD_TEMPLATES: Record<string, FieldSpec[]> = {
  switch: [
    { key: 'username', label: '用户名' },
    { key: 'password', label: '密码', secret: true },
    { key: 'host', label: '交换机地址' }
  ],
  aliyun: [
    { key: 'accessKeyId', label: 'AccessKey ID' },
    { key: 'accessKeySecret', label: 'AccessKey Secret', secret: true }
  ],
  tencent: [
    { key: 'secretId', label: 'SecretId' },
    { key: 'secretKey', label: 'SecretKey', secret: true }
  ]
};

const META_DEFAULTS: Record<string, string> = {
  switch: JSON.stringify({ port: 22, vendor: 'huawei' }, null, 2),
  aliyun: JSON.stringify({ region: 'cn-hangzhou', endpoint: 'ecs.aliyuncs.com', securityGroupId: '' }, null, 2),
  tencent: JSON.stringify({ region: 'ap-guangzhou', securityGroupId: '' }, null, 2)
};

const META_HINTS: Record<string, string> = {
  switch: '可选：port（端口）、vendor（huawei/h3c/cisco）',
  aliyun: '可选：region（地域）、endpoint、securityGroupId（安全组 ID）',
  tencent: '可选：region（地域）、securityGroupId（安全组 ID）'
};

function riskVariant(risk: string): 'default' | 'success' | 'warning' | 'danger' {
  if (risk === 'high') return 'danger';
  if (risk === 'medium') return 'warning';
  if (risk === 'low') return 'success';
  return 'default';
}

function formatMeta(meta?: Record<string, unknown>): string {
  if (!meta || Object.keys(meta).length === 0) return '-';
  return Object.entries(meta)
    .map(([k, v]) => `${k}=${v ?? ''}`)
    .join(' ');
}

function formatFields(fields?: Record<string, string>): string {
  if (!fields || Object.keys(fields).length === 0) return '-';
  return Object.keys(fields).map((k) => `${k}:***`).join(' ');
}

export default function Config() {
  const { toast } = useToast();

  const [items, setItems] = useState<ConfigItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [backups, setBackups] = useState<ConfigBackupItem[]>([]);
  const [busy, setBusy] = useState(false);

  const [editTarget, setEditTarget] = useState<ConfigItem | null>(null);
  const [editValue, setEditValue] = useState('');
  const [saving, setSaving] = useState(false);

  const [restoreTarget, setRestoreTarget] = useState<ConfigBackupItem | null>(null);
  const [restoring, setRestoring] = useState(false);

  const [adapters, setAdapters] = useState<AdapterInfo[]>([]);
  const [creds, setCreds] = useState<CredentialItem[]>([]);
  const [credLoading, setCredLoading] = useState(false);

  const [credOpen, setCredOpen] = useState(false);
  const [credProvider, setCredProvider] = useState('switch');
  const [credName, setCredName] = useState('');
  const [credFields, setCredFields] = useState<Record<string, string>>({});
  const [credMeta, setCredMeta] = useState(META_DEFAULTS.switch);
  const [credSaving, setCredSaving] = useState(false);

  const [deleteTarget, setDeleteTarget] = useState<CredentialItem | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function loadConfigs() {
    setLoading(true);
    try {
      setItems((await configApi.list()) || []);
    } catch {
      setItems([]);
    }
    setLoading(false);
  }

  async function loadBackups() {
    try {
      setBackups((await configApi.backups()) || []);
    } catch {
      setBackups([]);
    }
  }

  useEffect(() => {
    loadConfigs();
    loadBackups();
    loadAdapters();
    loadCreds();
  }, []);

  function openEdit(item: ConfigItem) {
    setEditTarget(item);
    setEditValue(item.value ?? '');
  }

  async function saveConfig() {
    if (!editTarget) return;
    setSaving(true);
    try {
      await configApi.update(editTarget.key, editValue);
      toast({ title: '配置已更新', variant: 'success' });
      setEditTarget(null);
      loadConfigs();
    } catch {
      // http 拦截器已提示
    }
    setSaving(false);
  }

  async function doBackup() {
    setBusy(true);
    try {
      await configApi.backup();
      toast({ title: '配置备份成功', variant: 'success' });
      loadBackups();
    } catch {
      // http 拦截器已提示
    }
    setBusy(false);
  }

  async function confirmRestore() {
    if (!restoreTarget) return;
    setRestoring(true);
    try {
      await configApi.restore(restoreTarget.filename);
      toast({ title: '配置恢复成功，部分设置将在刷新后生效', variant: 'success' });
      setRestoreTarget(null);
      loadConfigs();
    } catch {
      // http 拦截器已提示
    }
    setRestoring(false);
  }

  async function loadAdapters() {
    try {
      setAdapters((await adapterApi.list()) || []);
    } catch {
      setAdapters([]);
    }
  }

  async function loadCreds() {
    setCredLoading(true);
    try {
      setCreds((await adapterApi.credentials()) || []);
    } catch {
      setCreds([]);
    }
    setCredLoading(false);
  }

  function openCreateCred() {
    setCredProvider('switch');
    setCredName('');
    setCredFields({});
    setCredMeta(META_DEFAULTS.switch);
    setCredOpen(true);
  }

  function changeProvider(provider: string) {
    setCredProvider(provider);
    setCredFields({});
    setCredMeta(META_DEFAULTS[provider] || '{}');
  }

  async function saveCred() {
    if (!credName.trim()) {
      toast({ title: '请输入凭据名称', variant: 'warning' });
      return;
    }
    let meta: Record<string, unknown> | undefined;
    if (credMeta.trim()) {
      try {
        meta = JSON.parse(credMeta) as Record<string, unknown>;
      } catch {
        toast({ title: 'meta 需为合法 JSON', variant: 'error' });
        return;
      }
    }
    setCredSaving(true);
    try {
      await adapterApi.saveCredential({ provider: credProvider, name: credName.trim(), fields: credFields, meta });
      toast({ title: '凭据已保存', variant: 'success' });
      setCredOpen(false);
      loadCreds();
    } catch {
      // http 拦截器已提示
    }
    setCredSaving(false);
  }

  async function confirmDeleteCred() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await adapterApi.deleteCredential(deleteTarget.provider, deleteTarget.name);
      toast({ title: '凭据已删除', variant: 'success' });
      setDeleteTarget(null);
      loadCreds();
    } catch {
      // http 拦截器已提示
    }
    setDeleting(false);
  }

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">系统配置</h2>
          <p className="mt-1 text-sm text-gray-400">系统参数配置与备份恢复</p>
        </div>
      </div>

      {/* 配置键值表 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <Table>
          <thead>
            <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
              <th className="px-2 py-2 font-medium">配置键</th>
              <th className="px-2 py-2 font-medium">值</th>
              <th className="px-2 py-2 font-medium">描述</th>
              <th className="px-2 py-2 font-medium">版本</th>
              <th className="px-2 py-2 font-medium">更新时间</th>
              <th className="px-2 py-2 font-medium">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {items.map((c) => (
              <tr key={c.id} className="hover:bg-white/5">
                <td className="px-2 py-2 font-mono text-xs text-cyan-300">{c.key}</td>
                <td className="max-w-[260px] truncate px-2 py-2 text-gray-300" title={c.value || ''}>
                  {c.value || '-'}
                </td>
                <td className="max-w-[220px] truncate px-2 py-2 text-gray-400" title={c.description || ''}>
                  {c.description || '-'}
                </td>
                <td className="px-2 py-2 text-gray-400">{c.version ?? '-'}</td>
                <td className="px-2 py-2 text-gray-400">{formatTime(c.updated_at)}</td>
                <td className="px-2 py-2">
                  <button
                    type="button"
                    onClick={() => openEdit(c)}
                    className="text-xs text-cyan-400 transition-colors hover:text-cyan-300"
                  >
                    编辑
                  </button>
                </td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={6} className="px-2 py-6 text-center text-gray-500">
                  {loading ? '加载中…' : '暂无配置项'}
                </td>
              </tr>
            )}
          </tbody>
        </Table>
      </div>

      {/* 备份管理 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-cyan-300">备份管理</h3>
            <p className="mt-0.5 text-xs text-gray-500">配置全量备份与恢复（保留最近 10 份）</p>
          </div>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" disabled={busy} onClick={loadBackups}>
              刷新备份列表
            </Button>
            <Button size="sm" disabled={busy} onClick={doBackup}>
              {busy ? '处理中…' : '立即备份'}
            </Button>
          </div>
        </div>
        <Table>
          <thead>
            <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
              <th className="px-2 py-2 font-medium">备份文件</th>
              <th className="px-2 py-2 font-medium">大小</th>
              <th className="px-2 py-2 font-medium">创建时间</th>
              <th className="px-2 py-2 font-medium">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {backups.map((b) => (
              <tr key={b.filename} className="hover:bg-white/5">
                <td className="px-2 py-2 font-mono text-xs text-gray-300">{b.filename}</td>
                <td className="px-2 py-2 text-gray-400">{formatSize(b.size)}</td>
                <td className="px-2 py-2 text-gray-400">{formatTime(b.created_at)}</td>
                <td className="px-2 py-2">
                  <button
                    type="button"
                    onClick={() => setRestoreTarget(b)}
                    className="text-xs text-amber-400 transition-colors hover:text-amber-300"
                  >
                    恢复
                  </button>
                </td>
              </tr>
            ))}
            {backups.length === 0 && (
              <tr>
                <td colSpan={4} className="px-2 py-6 text-center text-gray-500">
                  暂无备份文件
                </td>
              </tr>
            )}
          </tbody>
        </Table>
      </div>

      {/* SOAR 适配器 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-cyan-300">SOAR 适配器</h3>
            <p className="mt-0.5 text-xs text-gray-500">
              凭据经 AES-256-GCM 加密存储于服务端，前端仅回显 ***
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                loadAdapters();
                loadCreds();
              }}
            >
              刷新
            </Button>
            <Button size="sm" onClick={openCreateCred}>
              新建凭据
            </Button>
          </div>
        </div>

        {/* 适配器目录 */}
        <h4 className="mb-2 text-xs font-semibold text-cyan-200/70">适配器目录</h4>
        <Table>
          <thead>
            <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
              <th className="px-2 py-2 font-medium">类型</th>
              <th className="px-2 py-2 font-medium">名称</th>
              <th className="px-2 py-2 font-medium">凭据 Provider</th>
              <th className="px-2 py-2 font-medium">风险</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {adapters.map((a) => (
              <tr key={a.type} className="hover:bg-white/5">
                <td className="px-2 py-2 font-mono text-xs text-cyan-300">{a.type}</td>
                <td className="px-2 py-2 text-gray-300">{a.name}</td>
                <td className="px-2 py-2 text-gray-400">{a.provider || '-'}</td>
                <td className="px-2 py-2">
                  <Badge variant={riskVariant(a.risk)}>{a.risk}</Badge>
                </td>
              </tr>
            ))}
            {adapters.length === 0 && (
              <tr>
                <td colSpan={4} className="px-2 py-6 text-center text-gray-500">
                  加载中…
                </td>
              </tr>
            )}
          </tbody>
        </Table>

        {/* 凭据管理 */}
        <h4 className="mb-2 mt-5 text-xs font-semibold text-cyan-200/70">凭据管理</h4>
        <Table>
          <thead>
            <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
              <th className="px-2 py-2 font-medium">Provider</th>
              <th className="px-2 py-2 font-medium">名称</th>
              <th className="px-2 py-2 font-medium">Meta</th>
              <th className="px-2 py-2 font-medium">字段（脱敏）</th>
              <th className="px-2 py-2 font-medium">更新时间</th>
              <th className="px-2 py-2 font-medium">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {creds.map((c) => (
              <tr key={`${c.provider}:${c.name}`} className="hover:bg-white/5">
                <td className="px-2 py-2 text-xs text-cyan-300">{c.provider}</td>
                <td className="px-2 py-2 text-gray-300">{c.name}</td>
                <td
                  className="max-w-[220px] truncate px-2 py-2 font-mono text-xs text-gray-400"
                  title={formatMeta(c.meta)}
                >
                  {formatMeta(c.meta)}
                </td>
                <td
                  className="max-w-[200px] truncate px-2 py-2 font-mono text-xs text-gray-400"
                  title={formatFields(c.fields)}
                >
                  {formatFields(c.fields)}
                </td>
                <td className="px-2 py-2 text-gray-400">{formatTime(c.updatedAt)}</td>
                <td className="px-2 py-2">
                  <button
                    type="button"
                    onClick={() => setDeleteTarget(c)}
                    className="text-xs text-red-400 transition-colors hover:text-red-300"
                  >
                    删除
                  </button>
                </td>
              </tr>
            ))}
            {creds.length === 0 && (
              <tr>
                <td colSpan={6} className="px-2 py-6 text-center text-gray-500">
                  {credLoading ? '加载中…' : '暂无凭据'}
                </td>
              </tr>
            )}
          </tbody>
        </Table>
      </div>

      {/* 编辑配置弹窗 */}
      <Dialog
        open={!!editTarget}
        onOpenChange={(open) => !open && setEditTarget(null)}
        title={`编辑配置：${editTarget?.key || ''}`}
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setEditTarget(null)}>
              取消
            </Button>
            <Button size="sm" disabled={saving} onClick={saveConfig}>
              {saving ? '保存中…' : '保存'}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <div>
            <label className="mb-1 block text-xs text-gray-400">配置键</label>
            <input className={`${fieldCls} w-full font-mono`} value={editTarget?.key || ''} disabled />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">配置值</label>
            <textarea
              className={`${fieldCls} w-full resize-none font-mono text-xs`}
              rows={3}
              value={editValue}
              onChange={(e) => setEditValue(e.target.value)}
            />
          </div>
          <p className="text-xs leading-5 text-gray-500">{editTarget?.description || ''}</p>
        </div>
      </Dialog>

      {/* 新建凭据弹窗 */}
      <Dialog
        open={credOpen}
        onOpenChange={(open) => !open && setCredOpen(false)}
        title="新建适配器凭据"
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setCredOpen(false)}>
              取消
            </Button>
            <Button size="sm" disabled={credSaving} onClick={saveCred}>
              {credSaving ? '保存中…' : '保存'}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <div>
            <label className="mb-1 block text-xs text-gray-400">Provider</label>
            <select
              className={`${fieldCls} w-full`}
              value={credProvider}
              onChange={(e) => changeProvider(e.target.value)}
            >
              {PROVIDER_OPTIONS.map((p) => (
                <option key={p.value} value={p.value} className="bg-[#16213e]">
                  {p.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">名称</label>
            <input
              className={`${fieldCls} w-full`}
              value={credName}
              onChange={(e) => setCredName(e.target.value)}
              placeholder="如：核心交换机、华东生产环境"
            />
          </div>
          {(FIELD_TEMPLATES[credProvider] || []).map((f) => (
            <div key={f.key}>
              <label className="mb-1 block text-xs text-gray-400">{f.label}</label>
              <input
                className={`${fieldCls} w-full font-mono`}
                type={f.secret ? 'password' : 'text'}
                value={credFields[f.key] || ''}
                onChange={(e) => setCredFields((prev) => ({ ...prev, [f.key]: e.target.value }))}
                placeholder={f.secret ? '••••••••' : ''}
                autoComplete="off"
              />
            </div>
          ))}
          <div>
            <label className="mb-1 block text-xs text-gray-400">Meta（JSON，可选）</label>
            <textarea
              className={`${fieldCls} w-full resize-none font-mono text-xs`}
              rows={4}
              value={credMeta}
              onChange={(e) => setCredMeta(e.target.value)}
            />
            <p className="mt-1 text-xs text-gray-500">{META_HINTS[credProvider]}</p>
          </div>
          <p className="text-xs leading-5 text-gray-500">
            明文密钥仅在保存时传输，服务端以 AES-256-GCM 加密存储；列表中一律回显 ***。
          </p>
        </div>
      </Dialog>

      {/* 删除凭据确认 */}
      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)} title="确认删除凭据">
        <p className="text-sm text-gray-600">
          确定要删除凭据 {deleteTarget?.provider}/{deleteTarget?.name} 吗？删除后相关适配器将无法使用该凭据。
        </p>
        <div className="mt-4 flex justify-end gap-2">
          <Button size="sm" variant="outline" onClick={() => setDeleteTarget(null)}>
            取消
          </Button>
          <Button size="sm" variant="destructive" disabled={deleting} onClick={confirmDeleteCred}>
            {deleting ? '删除中…' : '删除'}
          </Button>
        </div>
      </Dialog>

      {/* 恢复确认 */}
      <Dialog open={!!restoreTarget} onOpenChange={(open) => !open && setRestoreTarget(null)} title="确认恢复">
        <p className="text-sm text-gray-600">确定要恢复此备份（{restoreTarget?.filename}）吗？当前配置将被覆盖。</p>
        <div className="mt-4 flex justify-end gap-2">
          <Button size="sm" variant="outline" onClick={() => setRestoreTarget(null)}>
            取消
          </Button>
          <Button size="sm" variant="destructive" disabled={restoring} onClick={confirmRestore}>
            {restoring ? '恢复中…' : '恢复'}
          </Button>
        </div>
      </Dialog>
    </div>
  );
}
