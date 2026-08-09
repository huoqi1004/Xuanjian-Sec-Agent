import { useCallback, useEffect, useRef, useState } from 'react';
import { scanApi } from '@/api';
import type { ScanResult, ScanTask } from '@/api';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import Dialog from '@/components/ui/dialog';
import { Table } from '@/components/ui/table';
import { useToast } from '@/components/ui/use-toast';

const PAGE_SIZE = 10;
const POLL_INTERVAL = 5000;
const CIDR_PATTERN = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

const fieldCls =
  'rounded-md border border-cyan-500/20 bg-[#1a2340] px-3 py-2 text-sm text-gray-300 outline-none transition-colors placeholder:text-gray-500 focus:border-cyan-500/60';

interface TagInfo {
  label: string;
  variant: 'default' | 'success' | 'warning' | 'danger';
}

interface ScanTaskRow {
  id: string;
  target: string;
  mode: string;
  ports: string;
  status: string;
  progress: number;
  createTime: string;
}

function getStatusTag(status: string): TagInfo {
  const map: Record<string, TagInfo> = {
    pending: { label: '等待中', variant: 'default' },
    pending_approval: { label: '待审批', variant: 'warning' },
    running: { label: '运行中', variant: 'default' },
    completed: { label: '已完成', variant: 'success' },
    failed: { label: '失败', variant: 'danger' },
    rejected: { label: '已拒绝', variant: 'danger' }
  };
  return map[status] || { label: status, variant: 'default' };
}

function modeLabel(mode?: string): string {
  if (mode === 'tcp_connect') return 'TCP Connect';
  if (mode === 'syn') return 'SYN';
  return mode || '-';
}

function mapTask(t: ScanTask): ScanTaskRow {
  return {
    id: t.id,
    target: t.target_cidr,
    mode: modeLabel(t.scan_mode),
    ports: t.port_range || '-',
    status: t.status,
    progress: t.progress || (t.status === 'completed' ? 100 : 0),
    createTime: t.created_at ? new Date(t.created_at).toLocaleString('zh-CN') : '-'
  };
}

function demoScanTasks(): ScanTaskRow[] {
  const statuses = ['running', 'completed', 'pending', 'failed', 'pending_approval'];
  const targets = ['192.168.1.0/24', '10.0.0.0/16', '172.16.0.0/24', '192.168.100.0/22'];
  return Array.from({ length: 20 }, (_, i) => {
    const status = statuses[Math.floor(Math.random() * statuses.length)];
    return {
      id: 'SCAN-' + (2000 + i),
      target: targets[Math.floor(Math.random() * targets.length)],
      mode: Math.random() > 0.5 ? 'TCP Connect' : 'SYN',
      ports: '1-1024',
      status,
      progress: status === 'completed' ? 100 : Math.floor(Math.random() * 100),
      createTime: new Date(Date.now() - Math.random() * 3 * 86400000).toLocaleString('zh-CN')
    };
  });
}

function demoScanResults(): ScanResult[] {
  const services = ['SSH', 'HTTP', 'HTTPS', 'FTP', 'MySQL', 'Redis', 'MongoDB', 'RDP', 'SMTP', 'DNS'];
  const versions = ['2.0', '5.7.32', '6.2.6', '4.8.1', '1.1.1', '3.0', '8.0.28', '2.4.51', 'latest', '9.16.1'];
  return Array.from({ length: 80 }, (_, i) => ({
    task_id: 'demo',
    ip: `192.168.1.${(i % 50) + 1}`,
    port: [22, 80, 443, 21, 3306, 6379, 27017, 3389, 25, 53][Math.floor(Math.random() * 10)],
    service: services[Math.floor(Math.random() * services.length)],
    version: versions[Math.floor(Math.random() * versions.length)],
    banner: '',
    state: Math.random() > 0.1 ? 'open' : 'filtered'
  }));
}

export default function Scan() {
  const { toast } = useToast();
  const [starting, setStarting] = useState(false);
  const [tasks, setTasks] = useState<ScanTaskRow[]>([]);
  const [taskPage, setTaskPage] = useState(1);
  const [form, setForm] = useState({ target_cidr: '192.168.1.0/24', scan_mode: 'tcp_connect', port_range: '1-1024' });

  // 详情弹窗
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailTask, setDetailTask] = useState<ScanTaskRow | null>(null);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [resultPage, setResultPage] = useState(1);

  // 删除确认
  const [deleteTarget, setDeleteTarget] = useState<ScanTaskRow | null>(null);
  const [deleting, setDeleting] = useState(false);

  // 存在进行中任务时，5s 轮询刷新列表（代替 ws 进度订阅）
  const hasActiveRef = useRef(false);
  useEffect(() => {
    hasActiveRef.current = tasks.some((t) => t.status === 'running' || t.status === 'pending_approval');
  }, [tasks]);

  const loadTasks = useCallback(async (fallbackToDemo = false) => {
    try {
      const data = await scanApi.tasks({ page: 1, pageSize: 100 });
      const list = Array.isArray(data) ? data : data.list || [];
      setTasks(list.map(mapTask));
    } catch {
      // http 拦截器已提示；首次加载/手动刷新失败时兜底演示数据
      if (fallbackToDemo) setTasks(demoScanTasks());
    }
  }, []);

  useEffect(() => {
    loadTasks(true);
    const timer = setInterval(() => {
      if (hasActiveRef.current) loadTasks(false);
    }, POLL_INTERVAL);
    return () => clearInterval(timer);
  }, [loadTasks]);

  async function startScan() {
    const cidr = form.target_cidr.trim();
    const ports = form.port_range.trim();
    if (!cidr) {
      toast({ title: '请输入目标CIDR', variant: 'warning' });
      return;
    }
    if (!CIDR_PATTERN.test(cidr)) {
      toast({ title: '请输入有效的CIDR格式', variant: 'warning' });
      return;
    }
    if (!ports) {
      toast({ title: '请输入端口范围', variant: 'warning' });
      return;
    }
    setStarting(true);
    try {
      const t = await scanApi.start({ target_cidr: cidr, scan_mode: form.scan_mode, port_range: ports });
      // N-04 后 start 可能返回 pending_approval，data 含 status 字段则按返回展示
      const status = t.status || 'running';
      setTasks((prev) => [
        {
          id: t.task_id,
          target: t.target_cidr || cidr,
          mode: modeLabel(t.scan_mode || form.scan_mode),
          ports: t.port_range || ports,
          status,
          progress: 0,
          createTime: new Date().toLocaleString('zh-CN')
        },
        ...prev
      ]);
      setTaskPage(1);
      toast({
        title: status === 'pending_approval' ? '扫描任务已提交，等待管理员审批' : '扫描任务已启动',
        variant: status === 'pending_approval' ? 'warning' : 'success'
      });
    } catch {
      toast({ title: '启动扫描失败', variant: 'error' });
    }
    setStarting(false);
  }

  async function viewResults(row: ScanTaskRow) {
    setDetailTask(row);
    setDetailOpen(true);
    setDetailLoading(true);
    setResults([]);
    setResultPage(1);
    try {
      const detail = await scanApi.detail(row.id);
      setResults(detail.results || []);
    } catch {
      setResults(demoScanResults());
    } finally {
      setDetailLoading(false);
    }
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await scanApi.remove(deleteTarget.id);
    } catch {
      // 忽略删除接口错误，本地直接移除（与 Vue 版一致）
    }
    setTasks((prev) => prev.filter((t) => t.id !== deleteTarget.id));
    setTaskPage(1);
    toast({ title: '已删除', variant: 'success' });
    setDeleting(false);
    setDeleteTarget(null);
  }

  const paginatedTasks = tasks.slice((taskPage - 1) * PAGE_SIZE, taskPage * PAGE_SIZE);
  const paginatedResults = results.slice((resultPage - 1) * PAGE_SIZE, resultPage * PAGE_SIZE);
  const taskTotalPages = Math.max(1, Math.ceil(tasks.length / PAGE_SIZE));
  const resultTotalPages = Math.max(1, Math.ceil(results.length / PAGE_SIZE));

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">网络扫描</h2>
          <p className="mt-1 text-sm text-gray-400">对目标网络进行端口扫描和服务识别</p>
        </div>
      </div>

      {/* 扫描参数 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 text-sm font-semibold text-cyan-300">扫描参数</div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">目标CIDR</label>
            <input
              className={`${fieldCls} w-[220px]`}
              value={form.target_cidr}
              placeholder="例: 192.168.1.0/24"
              onChange={(e) => setForm({ ...form, target_cidr: e.target.value })}
            />
          </div>
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">扫描模式</label>
            <select
              className={`${fieldCls} w-[160px]`}
              value={form.scan_mode}
              onChange={(e) => setForm({ ...form, scan_mode: e.target.value })}
            >
              <option value="tcp_connect">TCP Connect</option>
              <option value="syn">SYN</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">端口范围</label>
            <input
              className={`${fieldCls} w-[160px]`}
              value={form.port_range}
              placeholder="例: 1-1024"
              onChange={(e) => setForm({ ...form, port_range: e.target.value })}
            />
          </div>
          <Button size="sm" disabled={starting} onClick={startScan}>
            {starting ? '启动中…' : '启动扫描'}
          </Button>
        </div>
      </div>

      {/* 扫描任务列表 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 flex items-center justify-between">
          <div className="text-sm font-semibold text-cyan-300">扫描任务列表</div>
          <Button size="sm" variant="outline" disabled={starting} onClick={() => loadTasks(true)}>
            刷新
          </Button>
        </div>
        <Table>
          <thead>
            <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
              <th className="px-2 py-2 font-medium">任务ID</th>
              <th className="px-2 py-2 font-medium">目标</th>
              <th className="px-2 py-2 font-medium">模式</th>
              <th className="px-2 py-2 font-medium">端口范围</th>
              <th className="px-2 py-2 font-medium">状态</th>
              <th className="px-2 py-2 font-medium">进度</th>
              <th className="px-2 py-2 font-medium">创建时间</th>
              <th className="px-2 py-2 font-medium">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {paginatedTasks.map((t) => (
              <tr key={t.id} className="hover:bg-white/5">
                <td className="px-2 py-2 text-gray-400">{t.id}</td>
                <td className="px-2 py-2 text-gray-300">{t.target}</td>
                <td className="px-2 py-2 text-gray-300">{t.mode}</td>
                <td className="px-2 py-2 text-gray-300">{t.ports}</td>
                <td className="px-2 py-2">
                  <Badge variant={getStatusTag(t.status).variant}>{getStatusTag(t.status).label}</Badge>
                </td>
                <td className="px-2 py-2">
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-24 overflow-hidden rounded-full bg-white/10">
                      <div
                        className={`h-full rounded-full ${t.status === 'completed' ? 'bg-green-500' : 'bg-cyan-400'}`}
                        style={{ width: `${Math.min(100, Math.max(0, t.progress))}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-400">{t.progress}%</span>
                  </div>
                </td>
                <td className="px-2 py-2 text-gray-400">{t.createTime}</td>
                <td className="px-2 py-2">
                  <div className="flex gap-3">
                    <button
                      type="button"
                      disabled={t.status !== 'completed'}
                      onClick={() => viewResults(t)}
                      className="text-xs text-cyan-400 transition-colors hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      查看结果
                    </button>
                    <button
                      type="button"
                      onClick={() => setDeleteTarget(t)}
                      className="text-xs text-red-400 transition-colors hover:text-red-300"
                    >
                      删除
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {paginatedTasks.length === 0 && (
              <tr>
                <td colSpan={8} className="px-2 py-6 text-center text-gray-500">暂无扫描任务</td>
              </tr>
            )}
          </tbody>
        </Table>
        <div className="mt-4 flex items-center justify-end gap-3">
          <Button size="sm" variant="outline" disabled={taskPage <= 1} onClick={() => setTaskPage((p) => p - 1)}>
            上一页
          </Button>
          <span className="text-xs text-gray-400">
            第 {taskPage} / {taskTotalPages} 页（共 {tasks.length} 条）
          </span>
          <Button size="sm" variant="outline" disabled={taskPage >= taskTotalPages} onClick={() => setTaskPage((p) => p + 1)}>
            下一页
          </Button>
        </div>
      </div>

      {/* 扫描结果详情弹窗 */}
      {detailOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60" onClick={() => setDetailOpen(false)} />
          <div className="relative z-10 flex max-h-[80vh] w-full max-w-5xl flex-col rounded-lg border border-cyan-500/20 bg-[#0f1a33] shadow-xl">
            <div className="flex items-center justify-between border-b border-white/5 px-5 py-4">
              <h3 className="text-base font-semibold text-white">扫描结果 - {detailTask?.id || ''}</h3>
              <button
                type="button"
                onClick={() => setDetailOpen(false)}
                className="text-xl leading-none text-gray-400 hover:text-gray-200"
                aria-label="关闭"
              >
                ×
              </button>
            </div>
            <div className="flex-1 overflow-y-auto px-5 py-4">
              {detailLoading ? (
                <div className="py-8 text-center text-sm text-cyan-300/70">加载中…</div>
              ) : (
                <Table>
                  <thead>
                    <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                      <th className="px-2 py-2 font-medium">IP地址</th>
                      <th className="px-2 py-2 font-medium">端口</th>
                      <th className="px-2 py-2 font-medium">服务</th>
                      <th className="px-2 py-2 font-medium">版本</th>
                      <th className="px-2 py-2 font-medium">Banner</th>
                      <th className="px-2 py-2 font-medium">状态</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {paginatedResults.map((r, i) => (
                      <tr key={i} className="hover:bg-white/5">
                        <td className="px-2 py-2 text-gray-300">{r.ip}</td>
                        <td className="px-2 py-2 text-gray-300">{r.port}</td>
                        <td className="px-2 py-2 text-gray-300">{r.service || '-'}</td>
                        <td className="px-2 py-2 text-gray-300">{r.version || '-'}</td>
                        <td className="max-w-[260px] truncate px-2 py-2 text-gray-400">{r.banner || '-'}</td>
                        <td className="px-2 py-2">
                          {r.state === 'open' ? <Badge variant="success">开放</Badge> : <Badge variant="default">{r.state || '-'}</Badge>}
                        </td>
                      </tr>
                    ))}
                    {paginatedResults.length === 0 && (
                      <tr>
                        <td colSpan={6} className="px-2 py-6 text-center text-gray-500">该任务暂无扫描结果</td>
                      </tr>
                    )}
                  </tbody>
                </Table>
              )}
              <div className="mt-4 flex items-center justify-end gap-3">
                <Button size="sm" variant="outline" disabled={resultPage <= 1} onClick={() => setResultPage((p) => p - 1)}>
                  上一页
                </Button>
                <span className="text-xs text-gray-400">第 {resultPage} / {resultTotalPages} 页</span>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={resultPage >= resultTotalPages}
                  onClick={() => setResultPage((p) => p + 1)}
                >
                  下一页
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 删除确认 */}
      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)} title="删除确认">
        <p className="text-sm text-gray-600">确定要删除扫描任务 {deleteTarget?.id} 吗？删除后无法恢复。</p>
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
