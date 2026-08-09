import { useCallback, useEffect, useState } from 'react';
import { reportsApi, situationalApi } from '@/api';
import type { ReportItem, ReportStats } from '@/api';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import { useToast } from '@/components/ui/use-toast';
import { useUserStore } from '@/stores/user';

const fieldCls =
  'rounded-md border border-cyan-500/20 bg-[#1a2340] px-3 py-2 text-sm text-gray-300 outline-none transition-colors placeholder:text-gray-500 focus:border-cyan-500/60';

type BadgeVariant = 'default' | 'success' | 'warning' | 'danger';

const TYPE_BADGE: Record<string, { label: string; variant: BadgeVariant }> = {
  djpp: { label: '等保测评', variant: 'danger' },
  virus: { label: '病毒查杀', variant: 'success' },
  baseline: { label: '基线检查', variant: 'warning' },
  scan: { label: '安全扫描', variant: 'default' },
  weekly: { label: '安全周报', variant: 'default' },
  monthly: { label: '安全月报', variant: 'default' },
  daily: { label: '安全日报', variant: 'default' },
  patrol: { label: '巡检报告', variant: 'default' }
};

const GEN_TYPES: Array<{ value: string; label: string }> = [
  { value: 'daily', label: '日报' },
  { value: 'weekly', label: '周报' },
  { value: 'monthly', label: '月报' },
  { value: 'patrol', label: '巡检' }
];

const CSV_TYPES: Array<{ value: string; label: string }> = [
  { value: 'alerts', label: '安全告警' },
  { value: 'scan', label: '扫描结果' },
  { value: 'baseline', label: '基线检查' },
  { value: 'reports', label: '报告列表' }
];

interface ReportRow extends ReportItem {
  hasDOCX: boolean;
}

/** 详情 content 可能是对象或字符串，统一转为纯文本展示（防 XSS） */
function contentToText(content: unknown): string {
  if (content == null) return '暂无内容';
  if (typeof content === 'string') return content || '暂无内容';
  if (typeof content === 'object') {
    const obj = content as Record<string, unknown>;
    if (typeof obj.content === 'string' && obj.content) return obj.content;
    return JSON.stringify(content, null, 2);
  }
  return String(content);
}

export default function Reports() {
  const { toast } = useToast();

  // 统计
  const [stats, setStats] = useState<ReportStats | null>(null);
  // 列表
  const [reports, setReports] = useState<ReportRow[]>([]);
  const [loading, setLoading] = useState(true);
  // 生成新报告
  const [genType, setGenType] = useState('weekly');
  const [generating, setGenerating] = useState(false);
  // 详情
  const [detail, setDetail] = useState<{ title: string; content: string } | null>(null);
  // 导出 CSV
  const [csvType, setCsvType] = useState('alerts');
  const [exportingCsv, setExportingCsv] = useState(false);
  // DOCX 生成中
  const [docxGeneratingId, setDocxGeneratingId] = useState<number | null>(null);

  const loadReports = useCallback(async () => {
    setLoading(true);
    try {
      const res = await reportsApi.list({ page: 1, pageSize: 100 });
      setReports((res.reports || []).map((r) => ({ ...r, hasDOCX: Boolean(r.hasDOCX) })));
    } catch {
      setReports([]);
    }
    setLoading(false);
  }, []);

  const loadStats = useCallback(async () => {
    try {
      const data = await reportsApi.stats();
      setStats(data || null);
    } catch {
      setStats(null);
    }
  }, []);

  useEffect(() => {
    loadReports();
    loadStats();
  }, [loadReports, loadStats]);

  /** 带鉴权头的流式下载（CSV/DOCX 均要求 Bearer token） */
  async function downloadWithAuth(url: string, fallbackName: string) {
    const token = useUserStore.getState().token;
    const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    if (!resp.ok) throw new Error('下载失败');
    const blob = await resp.blob();
    const disposition = resp.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="?([^";]+)"?/);
    const filename = match ? match[1] : fallbackName;
    const objUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = objUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(objUrl);
  }

  /** 批量导出 CSV */
  async function exportCsv() {
    setExportingCsv(true);
    try {
      await reportsApi.exportCsv(csvType);
      const url = `/api/reports/export/csv?type=${csvType}`;
      await downloadWithAuth(url, `${csvType}_export_${new Date().toISOString().slice(0, 10)}.csv`);
      const label = CSV_TYPES.find((t) => t.value === csvType)?.label || csvType;
      toast({ title: `${label}数据已导出`, variant: 'success' });
    } catch {
      toast({ title: 'CSV 导出失败', variant: 'error' });
    }
    setExportingCsv(false);
  }

  /** 生成新报告（日报/周报/月报/巡检） */
  async function handleGenerate() {
    const opt = GEN_TYPES.find((t) => t.value === genType);
    const label = opt?.label || genType;
    setGenerating(true);
    try {
      await situationalApi.generateReport(genType, `${label} - ${new Date().toLocaleDateString('zh-CN')}`);
      toast({ title: `${label}已生成`, variant: 'success' });
      loadReports();
      loadStats();
    } catch {
      toast({ title: '报告生成失败', variant: 'error' });
    }
    setGenerating(false);
  }

  /** 查看详情 */
  async function viewReport(row: ReportRow) {
    try {
      const data = await reportsApi.detail(row.id);
      const content = contentToText((data as { content?: unknown }).content);
      setDetail({ title: row.title || '报告详情', content });
    } catch {
      setDetail({ title: row.title || '报告详情', content: '暂无内容' });
    }
  }

  /** 生成 DOCX 并下载（后端存在 /reports/download/:filename 真实路由） */
  async function generateDocx(row: ReportRow) {
    setDocxGeneratingId(row.id);
    toast({ title: '正在生成 DOCX 报告，请稍候...', variant: 'default' });
    try {
      const res = await reportsApi.generateDocx(row.id);
      if (res.downloadUrl) {
        await downloadWithAuth(res.downloadUrl, `report_${row.id}.docx`);
        toast({ title: 'DOCX 报告已下载', variant: 'success' });
        loadReports();
      } else {
        toast({ title: 'DOCX 生成失败', variant: 'error' });
      }
    } catch {
      toast({ title: 'DOCX 生成失败', variant: 'error' });
    }
    setDocxGeneratingId(null);
  }

  /** 删除报告 */
  async function deleteReport(row: ReportRow) {
    try {
      await reportsApi.remove(row.id);
      toast({ title: '报告已删除', variant: 'success' });
      loadReports();
      loadStats();
    } catch {
      toast({ title: '删除失败', variant: 'error' });
    }
  }

  const statCards: Array<{ label: string; value: number; color: string }> = [
    { label: '总报告数', value: stats?.total || 0, color: 'text-cyan-400' },
    { label: '等保测评报告', value: stats?.djpp || 0, color: 'text-red-400' },
    { label: '病毒查杀报告', value: stats?.virus || 0, color: 'text-green-400' },
    { label: '基线检查报告', value: stats?.baseline || 0, color: 'text-amber-400' }
  ];

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-white">报告管理</h2>
          <p className="mt-1 text-sm text-gray-400">集中管理安全日报、周报、月报、巡检及各类专项报告</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <select className={`${fieldCls} w-[130px]`} value={csvType} onChange={(e) => setCsvType(e.target.value)}>
              {CSV_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
            <Button size="sm" variant="outline" disabled={exportingCsv} onClick={exportCsv}>
              {exportingCsv ? '导出中...' : '批量导出 CSV'}
            </Button>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              loadReports();
              loadStats();
            }}
          >
            刷新
          </Button>
        </div>
      </div>

      {/* 统计卡 */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {statCards.map((s) => (
          <div key={s.label} className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-4">
            <div className={`text-3xl font-bold ${s.color}`}>{s.value}</div>
            <div className="mt-1 text-sm text-gray-400">{s.label}</div>
          </div>
        ))}
      </div>

      {/* 生成新报告 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 text-sm font-semibold text-cyan-300">生成新报告</div>
        <div className="flex flex-wrap items-center gap-3">
          <select className={`${fieldCls} w-[140px]`} value={genType} onChange={(e) => setGenType(e.target.value)}>
            {GEN_TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
          <Button size="md" disabled={generating} onClick={handleGenerate}>
            {generating ? '生成中...' : '生成报告'}
          </Button>
        </div>
      </div>

      {/* 报告列表 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 text-sm font-semibold text-cyan-300">报告列表</div>
        <div className="w-full overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                <th className="px-2 py-2 font-medium">ID</th>
                <th className="px-2 py-2 font-medium">报告标题</th>
                <th className="px-2 py-2 font-medium">类型</th>
                <th className="px-2 py-2 font-medium">生成者</th>
                <th className="px-2 py-2 font-medium">DOCX</th>
                <th className="px-2 py-2 font-medium">生成时间</th>
                <th className="px-2 py-2 font-medium">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {reports.map((r) => {
                const badge = TYPE_BADGE[r.type] || { label: r.typeLabel || r.type, variant: 'default' as BadgeVariant };
                return (
                  <tr key={r.id} className="hover:bg-white/5">
                    <td className="px-2 py-2 text-gray-400">{r.id}</td>
                    <td className="max-w-[280px] truncate px-2 py-2 text-gray-300">{r.title}</td>
                    <td className="px-2 py-2">
                      <Badge variant={badge.variant}>{badge.label}</Badge>
                    </td>
                    <td className="px-2 py-2 text-gray-400">{r.generatedBy || '-'}</td>
                    <td className="px-2 py-2">
                      {r.hasDOCX ? (
                        <Badge variant="success">已生成</Badge>
                      ) : (
                        <span className="text-xs text-gray-500">未生成</span>
                      )}
                    </td>
                    <td className="px-2 py-2 text-gray-400">
                      {r.generatedAt ? new Date(r.generatedAt).toLocaleString('zh-CN') : '-'}
                    </td>
                    <td className="px-2 py-2">
                      <div className="flex gap-3">
                        <button
                          type="button"
                          onClick={() => viewReport(r)}
                          className="text-xs text-cyan-400 transition-colors hover:text-cyan-300"
                        >
                          查看
                        </button>
                        <button
                          type="button"
                          disabled={docxGeneratingId !== null}
                          onClick={() => generateDocx(r)}
                          className="text-xs text-amber-400 transition-colors hover:text-amber-300 disabled:opacity-50"
                        >
                          {docxGeneratingId === r.id ? '生成中...' : '生成 DOCX'}
                        </button>
                        <button
                          type="button"
                          onClick={() => deleteReport(r)}
                          className="text-xs text-red-400 transition-colors hover:text-red-300"
                        >
                          删除
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {!loading && reports.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-2 py-6 text-center text-gray-500">
                    暂无报告
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 报告详情弹窗 */}
      {detail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60" onClick={() => setDetail(null)} />
          <div className="relative z-10 flex max-h-[85vh] w-full max-w-4xl flex-col rounded-lg border border-cyan-500/20 bg-[#0f1a33] shadow-xl">
            <div className="flex items-center justify-between border-b border-white/5 px-5 py-4">
              <h3 className="text-base font-semibold text-white">{detail.title}</h3>
              <button
                type="button"
                onClick={() => setDetail(null)}
                className="text-xl leading-none text-gray-400 hover:text-gray-200"
                aria-label="关闭"
              >
                ×
              </button>
            </div>
            <div className="flex-1 overflow-y-auto px-5 py-4">
              <pre className="whitespace-pre-wrap text-sm leading-relaxed text-gray-200">{detail.content}</pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
