import { useCallback, useEffect, useMemo, useState } from 'react';
import { deviceApi } from '@/api';
import type { DeviceCommand, EdgeDevice } from '@/api';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import Dialog from '@/components/ui/dialog';
import { Table } from '@/components/ui/table';
import { useToast } from '@/components/ui/use-toast';
import { useWsStore } from '@/stores/ws';

const PAGE_SIZE = 10;

const fieldCls =
  'rounded-md border border-cyan-500/20 bg-[#1a2340] px-3 py-2 text-sm text-gray-300 outline-none transition-colors placeholder:text-gray-500 focus:border-cyan-500/60';

/** 后端指令白名单（与 server/services/deviceService.js ALLOWED_COMMANDS 保持一致） */
const COMMAND_OPTIONS = [
  { value: 'system_info', label: 'system_info（系统信息采集）' },
  { value: 'baseline_check', label: 'baseline_check（基线检查）' },
  { value: 'djpp_check', label: 'djpp_check（等保检查）' },
  { value: 'port_scan', label: 'port_scan（端口扫描）' },
  { value: 'file_hash', label: 'file_hash（文件哈希）' },
  { value: 'list_checks', label: 'list_checks（检查项列表）' }
];

function formatTime(t?: string): string {
  return t ? new Date(t).toLocaleString('zh-CN') : '-';
}

/** 兼容后端返回数组或 { list, total } 分页结构 */
function extractList<T>(v: unknown): T[] {
  if (Array.isArray(v)) return v as T[];
  if (v && typeof v === 'object' && Array.isArray((v as { list?: unknown }).list)) {
    return (v as { list: T[] }).list;
  }
  return [];
}

/** params/result 可能为 JSON 字符串或对象，统一输出可读文本 */
function jsonText(v: unknown): string {
  if (v === null || v === undefined || v === '') return '-';
  if (typeof v === 'string') {
    try {
      return JSON.stringify(JSON.parse(v));
    } catch {
      return v;
    }
  }
  return JSON.stringify(v);
}

function commandTag(status?: string) {
  if (status === 'success' || status === 'executed' || status === 'completed') {
    return { label: '成功', variant: 'success' as const };
  }
  if (status === 'failed' || status === 'error') {
    return { label: '失败', variant: 'danger' as const };
  }
  if (status === 'pending') {
    return { label: '待执行', variant: 'warning' as const };
  }
  return { label: status || '-', variant: 'default' as const };
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

export default function Device() {
  const { toast } = useToast();
  const [devices, setDevices] = useState<EdgeDevice[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);

  // 注册设备
  const [registerOpen, setRegisterOpen] = useState(false);
  const [regForm, setRegForm] = useState({ device_id: '', device_type: 'gateway', ip: '' });
  const [regSaving, setRegSaving] = useState(false);

  // 下发指令
  const [commandOpen, setCommandOpen] = useState(false);
  const [commandDevice, setCommandDevice] = useState<EdgeDevice | null>(null);
  const [commandForm, setCommandForm] = useState({ command: '', params: '' });
  const [commandSaving, setCommandSaving] = useState(false);

  // 设备详情 + 指令历史
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailDevice, setDetailDevice] = useState<EdgeDevice | null>(null);
  const [commandHistory, setCommandHistory] = useState<DeviceCommand[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const loadDevices = useCallback(async () => {
    setLoading(true);
    try {
      const data = await deviceApi.list({ page: 1, pageSize: 100 });
      setDevices(extractList<EdgeDevice>(data));
    } catch {
      setDevices([]);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadDevices();
  }, [loadDevices]);

  // WS 订阅：设备相关消息到达时刷新列表（连接由 MainLayout / ws store 管理，此处不清理）
  const lastMessage = useWsStore((s) => s.lastMessage);
  useEffect(() => {
    const type = lastMessage && typeof lastMessage.type === 'string' ? lastMessage.type : '';
    if (type.includes('device') || type.includes('heartbeat')) {
      loadDevices();
    }
  }, [lastMessage, loadDevices]);

  const paginatedDevices = useMemo(() => {
    const s = (page - 1) * PAGE_SIZE;
    return devices.slice(s, s + PAGE_SIZE);
  }, [devices, page]);

  function openRegister() {
    setRegForm({ device_id: '', device_type: 'gateway', ip: '' });
    setRegisterOpen(true);
  }

  async function submitRegister() {
    if (!regForm.device_id.trim()) {
      toast({ title: '请输入设备ID', variant: 'warning' });
      return;
    }
    setRegSaving(true);
    try {
      await deviceApi.register({
        device_id: regForm.device_id.trim(),
        device_type: regForm.device_type.trim() || 'gateway',
        ip: regForm.ip.trim()
      });
      toast({ title: '设备注册成功', variant: 'success' });
      setRegisterOpen(false);
      loadDevices();
    } catch {
      // http 拦截器已提示
    }
    setRegSaving(false);
  }

  function openCommand(device: EdgeDevice) {
    setCommandDevice(device);
    setCommandForm({ command: '', params: '' });
    setCommandOpen(true);
  }

  async function submitCommand() {
    if (!commandDevice) return;
    if (!commandForm.command) {
      toast({ title: '请选择指令类型', variant: 'warning' });
      return;
    }
    let params: Record<string, unknown> = {};
    const raw = commandForm.params.trim();
    if (raw) {
      try {
        const parsed = JSON.parse(raw) as unknown;
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          params = parsed as Record<string, unknown>;
        } else {
          toast({ title: '参数需为 JSON 对象', variant: 'warning' });
          return;
        }
      } catch {
        toast({ title: '参数 JSON 格式不正确', variant: 'warning' });
        return;
      }
    }
    setCommandSaving(true);
    try {
      await deviceApi.sendCommand(commandDevice.device_id, commandForm.command, params);
      toast({ title: '指令已下发', variant: 'success' });
      setCommandOpen(false);
    } catch {
      // http 拦截器已提示
    }
    setCommandSaving(false);
  }

  async function openDetail(device: EdgeDevice) {
    setDetailDevice(device);
    setDetailOpen(true);
    setHistoryLoading(true);
    setCommandHistory([]);
    try {
      const data = await deviceApi.commands(device.device_id, { page: 1, pageSize: 50 });
      setCommandHistory(extractList<DeviceCommand>(data));
    } catch {
      setCommandHistory([]);
    }
    setHistoryLoading(false);
  }

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">边缘设备管理</h2>
          <p className="mt-1 text-sm text-gray-400">管理和监控所有接入的安全边缘设备</p>
        </div>
        <Button size="sm" onClick={openRegister}>
          注册设备
        </Button>
      </div>

      {/* 设备列表 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 text-sm font-semibold text-cyan-200/80">设备列表</div>
        <Table>
          <thead>
            <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
              <th className="px-2 py-2 font-medium">设备ID</th>
              <th className="px-2 py-2 font-medium">IP地址</th>
              <th className="px-2 py-2 font-medium">设备类型</th>
              <th className="px-2 py-2 font-medium">在线状态</th>
              <th className="px-2 py-2 font-medium">Agent版本</th>
              <th className="px-2 py-2 font-medium">最后心跳</th>
              <th className="px-2 py-2 font-medium">注册时间</th>
              <th className="px-2 py-2 font-medium">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {paginatedDevices.map((d) => {
              const online = !!d.online_status;
              return (
                <tr key={d.device_id} className="hover:bg-white/5">
                  <td className="px-2 py-2 font-mono text-xs text-gray-400">{d.device_id}</td>
                  <td className="px-2 py-2 text-gray-300">{d.ip || '-'}</td>
                  <td className="px-2 py-2 text-gray-300">{d.device_type || '-'}</td>
                  <td className="px-2 py-2">
                    <Badge variant={online ? 'success' : 'default'}>{online ? '在线' : '离线'}</Badge>
                  </td>
                  <td className="px-2 py-2 text-gray-400">{d.agent_version || '-'}</td>
                  <td className="px-2 py-2 text-gray-400">{formatTime(d.last_heartbeat)}</td>
                  <td className="px-2 py-2 text-gray-400">{formatTime(d.registered_at)}</td>
                  <td className="px-2 py-2">
                    <div className="flex gap-3">
                      <button
                        type="button"
                        onClick={() => openDetail(d)}
                        className="text-xs text-cyan-400 transition-colors hover:text-cyan-300"
                      >
                        详情
                      </button>
                      <button
                        type="button"
                        onClick={() => openCommand(d)}
                        className="text-xs text-amber-400 transition-colors hover:text-amber-300"
                      >
                        指令
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {paginatedDevices.length === 0 && (
              <tr>
                <td colSpan={8} className="px-2 py-6 text-center text-gray-500">
                  {loading ? '加载中…' : '暂无设备，点击右上角「注册设备」'}
                </td>
              </tr>
            )}
          </tbody>
        </Table>
        <Pagination page={page} total={devices.length} pageSize={PAGE_SIZE} onChange={setPage} />
      </div>

      {/* 注册设备 */}
      <Dialog
        open={registerOpen}
        onOpenChange={(open) => !open && setRegisterOpen(false)}
        title="注册新设备"
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setRegisterOpen(false)}>
              取消
            </Button>
            <Button size="sm" disabled={regSaving} onClick={submitRegister}>
              {regSaving ? '注册中…' : '注册'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <div>
            <label className="mb-1 block text-xs text-gray-400">设备ID（必填）</label>
            <input
              className={`${fieldCls} w-full`}
              value={regForm.device_id}
              placeholder="例如 DEV-5001"
              onChange={(e) => setRegForm({ ...regForm, device_id: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">设备类型</label>
            <input
              className={`${fieldCls} w-full`}
              value={regForm.device_type}
              placeholder="gateway / linux / windows …"
              onChange={(e) => setRegForm({ ...regForm, device_type: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-gray-400">IP 地址</label>
            <input
              className={`${fieldCls} w-full`}
              value={regForm.ip}
              placeholder="例如 10.0.1.10"
              onChange={(e) => setRegForm({ ...regForm, ip: e.target.value })}
            />
          </div>
        </div>
      </Dialog>

      {/* 下发指令 */}
      <Dialog
        open={commandOpen}
        onOpenChange={(open) => !open && setCommandOpen(false)}
        title="下发指令"
        footer={
          <>
            <Button size="sm" variant="outline" onClick={() => setCommandOpen(false)}>
              取消
            </Button>
            <Button size="sm" disabled={commandSaving} onClick={submitCommand}>
              {commandSaving ? '下发中…' : '下发'}
            </Button>
          </>
        }
      >
        {commandDevice && (
          <div className="space-y-4">
            <div>
              <label className="mb-1 block text-xs text-gray-400">目标设备</label>
              <input className={`${fieldCls} w-full`} value={commandDevice.device_id} disabled />
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-400">指令类型（必选）</label>
              <select
                className={`${fieldCls} w-full`}
                value={commandForm.command}
                onChange={(e) => setCommandForm({ ...commandForm, command: e.target.value })}
              >
                <option value="">请选择指令</option>
                {COMMAND_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs text-gray-400">参数（JSON 对象，可选）</label>
              <textarea
                className={`${fieldCls} w-full resize-none font-mono text-xs`}
                rows={3}
                value={commandForm.params}
                placeholder={'例如：{"target_ip": "10.0.1.20"}'}
                onChange={(e) => setCommandForm({ ...commandForm, params: e.target.value })}
              />
            </div>
          </div>
        )}
      </Dialog>

      {/* 设备详情 + 指令历史 */}
      <Dialog
        open={detailOpen}
        onOpenChange={(open) => !open && setDetailOpen(false)}
        title="设备详情"
        footer={
          <Button size="sm" variant="outline" onClick={() => setDetailOpen(false)}>
            关闭
          </Button>
        }
      >
        {detailDevice && (
          <div className="max-h-[65vh] space-y-4 overflow-y-auto pr-1">
            <div className="grid grid-cols-2 gap-x-4 gap-y-2 rounded-md border border-white/10 p-3 text-xs">
              <div>
                <span className="text-gray-500">设备ID</span>
                <div className="font-mono text-gray-300">{detailDevice.device_id}</div>
              </div>
              <div>
                <span className="text-gray-500">IP地址</span>
                <div className="text-gray-300">{detailDevice.ip || '-'}</div>
              </div>
              <div>
                <span className="text-gray-500">设备类型</span>
                <div className="text-gray-300">{detailDevice.device_type || '-'}</div>
              </div>
              <div>
                <span className="text-gray-500">在线状态</span>
                <div className="mt-1">
                  <Badge variant={detailDevice.online_status ? 'success' : 'default'}>
                    {detailDevice.online_status ? '在线' : '离线'}
                  </Badge>
                </div>
              </div>
              <div>
                <span className="text-gray-500">Agent版本</span>
                <div className="text-gray-300">{detailDevice.agent_version || '-'}</div>
              </div>
              <div>
                <span className="text-gray-500">最后心跳</span>
                <div className="text-gray-300">{formatTime(detailDevice.last_heartbeat)}</div>
              </div>
              <div>
                <span className="text-gray-500">注册时间</span>
                <div className="text-gray-300">{formatTime(detailDevice.registered_at)}</div>
              </div>
            </div>

            <div>
              <div className="mb-2 text-sm font-semibold text-cyan-200/80">指令执行历史</div>
              <Table>
                <thead>
                  <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                    <th className="px-2 py-2 font-medium">指令ID</th>
                    <th className="px-2 py-2 font-medium">指令</th>
                    <th className="px-2 py-2 font-medium">参数</th>
                    <th className="px-2 py-2 font-medium">状态</th>
                    <th className="px-2 py-2 font-medium">结果</th>
                    <th className="px-2 py-2 font-medium">时间</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {commandHistory.map((c) => {
                    const tag = commandTag(c.status);
                    return (
                      <tr key={c.id} className="hover:bg-white/5">
                        <td className="px-2 py-2 font-mono text-xs text-gray-400">CMD-{c.id}</td>
                        <td className="px-2 py-2 text-gray-300">{c.command || '-'}</td>
                        <td className="max-w-[160px] truncate px-2 py-2 text-gray-400" title={jsonText(c.params)}>
                          {jsonText(c.params)}
                        </td>
                        <td className="px-2 py-2">
                          <Badge variant={tag.variant}>{tag.label}</Badge>
                        </td>
                        <td className="max-w-[200px] truncate px-2 py-2 text-gray-400" title={jsonText(c.result)}>
                          {jsonText(c.result)}
                        </td>
                        <td className="px-2 py-2 text-gray-400">{formatTime(c.created_at)}</td>
                      </tr>
                    );
                  })}
                  {commandHistory.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-2 py-6 text-center text-gray-500">
                        {historyLoading ? '加载中…' : '暂无指令记录'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </Table>
            </div>
          </div>
        )}
      </Dialog>
    </div>
  );
}
