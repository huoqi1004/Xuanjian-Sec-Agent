import { useEffect, useState } from 'react';
import { configApi } from '@/api';
import type { ConfigBackupItem, ConfigItem } from '@/api';
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
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

      {/* 恢复确认 */}
      <Dialog open={!!restoreTarget} onOpenChange={(open) => !open && setRestoreTarget(null)} title="确认恢复">
        <p className="text-sm text-gray-600">
          确定要恢复此备份（{restoreTarget?.filename}）吗？当前配置将被覆盖。
        </p>
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
