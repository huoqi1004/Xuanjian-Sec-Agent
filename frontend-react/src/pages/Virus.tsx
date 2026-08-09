import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { virusApi } from '@/api';
import type { VirusHash, VirusScanReport } from '@/api';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import { Table } from '@/components/ui/table';
import { useToast } from '@/components/ui/use-toast';

const PAGE_SIZE = 10;

const fieldCls =
  'rounded-md border border-cyan-500/20 bg-[#1a2340] px-3 py-2 text-sm text-gray-300 outline-none transition-colors placeholder:text-gray-500 focus:border-cyan-500/60';

interface TagInfo {
  label: string;
  variant: 'default' | 'success' | 'warning' | 'danger';
}

function verdictTag(v?: string): TagInfo {
  if (v === 'malicious') return { label: '恶意', variant: 'danger' };
  if (v === 'poisoned') return { label: '投毒', variant: 'danger' };
  if (v === 'suspicious') return { label: '疑似', variant: 'warning' };
  return { label: '安全', variant: 'success' };
}

function verdictText(v?: string): string {
  if (v === 'malicious') return '恶意';
  if (v === 'suspicious') return '疑似';
  if (v === 'poisoned') return '投毒';
  if (v === 'clean') return '安全';
  return '未知';
}

function severityTag(s?: string): TagInfo {
  const map: Record<string, TagInfo> = {
    critical: { label: '严重', variant: 'danger' },
    high: { label: '高危', variant: 'warning' },
    medium: { label: '中危', variant: 'default' },
    low: { label: '低危', variant: 'success' }
  };
  return map[s || ''] || { label: s || '-', variant: 'default' };
}

function formatSize(bytes?: number): string {
  if (bytes === undefined || bytes === null) return '-';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

/** 引擎进度（与 Vue 版一致的前 5 个引擎） */
interface EngineProgress {
  name: string;
  status: 'pending' | 'scanning' | 'done' | 'skipped' | 'error';
  verdict: string;
  confidence: number;
  detail: string;
  time: string;
}

const ENGINE_MAP: Record<string, number> = {
  local_hash: 0,
  '360_ti': 1,
  kaspersky: 2,
  ai_malware: 3,
  ai_poisoning: 4
};

const INITIAL_ENGINES: EngineProgress[] = [
  { name: '本地哈希库', status: 'pending', verdict: '', confidence: 0, detail: '', time: '' },
  { name: '360天眼', status: 'pending', verdict: '', confidence: 0, detail: '', time: '' },
  { name: '卡巴斯基', status: 'pending', verdict: '', confidence: 0, detail: '', time: '' },
  { name: 'AI恶意检测', status: 'pending', verdict: '', confidence: 0, detail: '', time: '' },
  { name: 'AI投毒检测', status: 'pending', verdict: '', confidence: 0, detail: '', time: '' }
];

interface HistoryRow {
  id: string;
  filename: string;
  filesize: number;
  hash: string;
  verdict: string;
  source: string;
  confidence: string;
  time: string;
  scanId?: string;
}

interface DetectResult {
  filename: string;
  filesize: number;
  hash: string;
  verdict: string;
  confidence: number;
  primaryEngine: string;
  recommendation: string;
  scanId?: string;
  totalTime: number;
}

function demoVirusRecords(): HistoryRow[] {
  const conclusions = ['malicious', 'benign', 'suspicious'];
  const sources = ['哈希匹配', 'VirusTotal', 'AI模型分析'];
  const filenames = [
    'update_v2.exe',
    'report.pdf.exe',
    'tool_setup.msi',
    'config.xml',
    'backup.zip',
    'patch.bat',
    'service.dll',
    'driver.sys'
  ];
  return Array.from({ length: 30 }, (_, i) => ({
    id: 'VIR-' + (3000 + i),
    filename: filenames[Math.floor(Math.random() * filenames.length)],
    filesize: Math.floor(Math.random() * 50000) + 100,
    hash: Array.from({ length: 32 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join(''),
    verdict: conclusions[Math.floor(Math.random() * conclusions.length)],
    source: sources[Math.floor(Math.random() * sources.length)],
    confidence: (60 + Math.random() * 40).toFixed(1),
    time: new Date(Date.now() - Math.random() * 30 * 86400000).toLocaleString('zh-CN')
  }));
}

export default function Virus() {
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [detecting, setDetecting] = useState(false);
  const [detectResult, setDetectResult] = useState<DetectResult | null>(null);
  const [engines, setEngines] = useState<EngineProgress[]>(INITIAL_ENGINES);
  const [records, setRecords] = useState<HistoryRow[]>([]);
  const [recordPage, setRecordPage] = useState(1);

  // 报告对话框
  const [showReport, setShowReport] = useState(false);
  const [reportContent, setReportContent] = useState('');

  // 哈希查询
  const [hashInput, setHashInput] = useState('');
  const [hashType, setHashType] = useState('md5');
  const [hashResults, setHashResults] = useState<VirusHash[] | null>(null);
  const [analyzing, setAnalyzing] = useState(false);

  const loadRecords = useCallback(async () => {
    try {
      const data = await virusApi.scanHistory(1, 50);
      const list = data?.list || [];
      setRecords(
        list.map((r) => ({
          id: 'VIR-' + r.id,
          filename: r.file_name || '',
          filesize: r.file_size || 0,
          hash: r.file_hash_md5 || '',
          verdict: r.detection_result || 'benign',
          source: r.detection_source || '未知',
          confidence: r.model_score ? (r.model_score * 100).toFixed(1) : '-',
          time: r.created_at ? new Date(r.created_at).toLocaleString('zh-CN') : '-'
        }))
      );
    } catch {
      // 接口不可用时兜底演示数据（与 Vue 版一致）
      setRecords(demoVirusRecords());
    }
  }, []);

  useEffect(() => {
    loadRecords();
  }, [loadRecords]);

  async function handleUpload() {
    if (!selectedFile) {
      toast({ title: '请先选择文件', variant: 'warning' });
      return;
    }
    setUploading(true);
    setDetecting(true);
    setDetectResult(null);
    setEngines(INITIAL_ENGINES.map((e) => ({ ...e, status: 'scanning' })));

    try {
      const d = await virusApi.upload(selectedFile);

      // 更新引擎结果
      const engineResults = d.engines;
      if (engineResults) {
        setEngines((prev) => {
          const next = prev.map((e) => ({ ...e }));
          for (const [key, r] of Object.entries(engineResults)) {
            const idx = ENGINE_MAP[key];
            if (idx === undefined) continue;
            next[idx].status = r.status === 'completed' ? 'done' : r.status === 'skipped' ? 'skipped' : 'error';
            next[idx].verdict = r.verdict || '';
            next[idx].confidence = r.confidence || 0;
            next[idx].detail = r.detail || '';
            next[idx].time = r.responseTime ? (r.responseTime / 1000).toFixed(1) + 's' : '';
          }
          return next;
        });
      }

      // 最终决策结果
      const result: DetectResult = {
        filename: d.fileName || '',
        filesize: d.fileSize || 0,
        hash: d.hashes?.sha256 || d.hashes?.md5 || '',
        verdict: d.decision?.verdict || 'clean',
        confidence: d.decision?.confidence || 0,
        primaryEngine: d.decision?.primaryEngine || '',
        recommendation: d.decision?.recommendation || '',
        scanId: d.scanId,
        totalTime: d.totalTime || 0
      };
      setDetectResult(result);

      // 添加到历史记录
      setRecords((prev) => [
        {
          id: 'VIR-' + d.recordId,
          filename: d.fileName || selectedFile.name,
          filesize: d.fileSize || 0,
          hash: d.hashes?.md5 || '',
          verdict: result.verdict,
          source: d.decision?.primaryEngine || '多引擎',
          confidence: (result.confidence * 100).toFixed(1),
          time: new Date().toLocaleString('zh-CN'),
          scanId: d.scanId
        },
        ...prev
      ]);
      setRecordPage(1);
    } catch {
      setEngines((prev) => prev.map((e) => ({ ...e, status: 'error', detail: '调用失败' })));
      toast({ title: '扫描失败，请重试', variant: 'error' });
    }
    setDetecting(false);
    setUploading(false);
  }

  async function viewReport(scanId?: string) {
    if (!scanId) {
      toast({ title: '无报告ID', variant: 'warning' });
      return;
    }
    try {
      const data = await virusApi.report(scanId);
      const report = (data as VirusScanReport).report;
      setReportContent(report?.aiSummary || report?.title || '无报告内容');
      setShowReport(true);
    } catch {
      toast({ title: '获取报告失败', variant: 'error' });
    }
  }

  function downloadReport() {
    if (!reportContent) return;
    const blob = new Blob([reportContent], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = (detectResult?.filename || 'scan_report') + '_查杀报告.md';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({ title: '报告已下载', variant: 'success' });
  }

  async function analyzeHash() {
    const hash = hashInput.trim();
    if (!hash) {
      toast({ title: '请输入文件哈希', variant: 'warning' });
      return;
    }
    setAnalyzing(true);
    try {
      const list = await virusApi.analyzeHash(hash, hashType);
      setHashResults(list || []);
      if (!list || list.length === 0) {
        toast({ title: '未在病毒库中匹配到该哈希', variant: 'default' });
      }
    } catch {
      setHashResults([]);
    }
    setAnalyzing(false);
  }

  const paginatedRecords = useMemo(() => {
    const s = (recordPage - 1) * PAGE_SIZE;
    return records.slice(s, s + PAGE_SIZE);
  }, [records, recordPage]);
  const recordTotalPages = Math.max(1, Math.ceil(records.length / PAGE_SIZE));

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">病毒查杀 - 多引擎协同检测</h2>
          <p className="mt-1 text-sm text-gray-400">本地哈希 + 360天眼 + 卡巴斯基 + AI恶意检测 + AI投毒检测</p>
        </div>
      </div>

      {/* 文件上传 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 text-sm font-semibold text-cyan-300">文件上传检测</div>
        <div
          role="button"
          tabIndex={0}
          onClick={() => fileInputRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click();
          }}
          className="flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-cyan-500/30 bg-[#0f1a33]/60 px-6 py-10 transition-colors hover:border-cyan-500/60"
        >
          <div className="text-4xl">📁</div>
          <div className="mt-2 text-sm text-gray-300">
            {selectedFile
              ? `已选择: ${selectedFile.name} (${formatSize(selectedFile.size)})`
              : '将文件拖到此处，或点击上传'}
          </div>
          <div className="mt-1 text-xs text-gray-500">
            支持所有文件类型，多引擎并行扫描
            {selectedFile && (
              <span
                className="ml-2 cursor-pointer text-cyan-400"
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedFile(null);
                  if (fileInputRef.current) fileInputRef.current.value = '';
                }}
              >
                移除
              </span>
            )}
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept=".exe,.dll,.bat,.msi,.sys,.pdf,.doc,.xls,.zip,.rar,.py,.sh"
            className="hidden"
            onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
          />
        </div>
        <div className="mt-4">
          <Button size="sm" disabled={uploading || !selectedFile} onClick={handleUpload}>
            {uploading ? '扫描中…' : '开始多引擎扫描'}
          </Button>
        </div>
      </div>

      {/* 多引擎扫描进度 */}
      {(detecting || detectResult) && (
        <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
          <div className="mb-4 text-sm font-semibold text-cyan-300">扫描引擎状态</div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
            {engines.map((eng, idx) => (
              <div
                key={idx}
                className="rounded-lg border p-3"
                style={{
                  background: 'rgba(26,26,46,0.8)',
                  borderColor:
                    eng.status === 'done' && (eng.verdict === 'malicious' || eng.verdict === 'poisoned')
                      ? '#f56c6c'
                      : eng.status === 'done'
                        ? '#67c23a'
                        : eng.status === 'scanning'
                          ? '#e6a23c'
                          : '#444'
                }}
              >
                <div className="mb-2 flex items-center gap-2">
                  <span className="text-sm font-bold text-gray-200">{eng.name}</span>
                  {eng.status === 'scanning' && (
                    <span className="ml-auto inline-block h-3 w-3 animate-spin rounded-full border-2 border-amber-400 border-t-transparent" />
                  )}
                  {eng.status === 'done' && <span className="ml-auto text-sm text-green-500">✓</span>}
                  {eng.status === 'skipped' && <span className="ml-auto text-sm text-gray-400">⊘</span>}
                  {eng.status === 'error' && <span className="ml-auto text-sm text-red-500">✗</span>}
                  {eng.status === 'pending' && <span className="ml-auto text-sm text-gray-500">○</span>}
                </div>
                {eng.verdict && eng.status === 'done' && (
                  <div className="text-xs">
                    <span
                      style={{
                        color:
                          eng.verdict === 'malicious' || eng.verdict === 'poisoned'
                            ? '#f56c6c'
                            : eng.verdict === 'suspicious'
                              ? '#e6a23c'
                              : '#67c23a'
                      }}
                    >
                      {verdictText(eng.verdict)}
                    </span>
                    {eng.confidence ? (
                      <span className="ml-1 text-gray-400">({(eng.confidence * 100).toFixed(0)}%)</span>
                    ) : null}
                  </div>
                )}
                {eng.time && <div className="mt-1 text-[11px] text-gray-500">{eng.time}</div>}
                {eng.detail && eng.status !== 'scanning' && (
                  <div className="mt-1 break-all text-[11px] text-gray-400">{eng.detail}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI 决策结果 */}
      {detectResult && !detecting && (
        <div
          className="rounded-xl p-5"
          style={{
            background: 'rgba(26,26,46,0.8)',
            border:
              '2px solid ' +
              (detectResult.verdict === 'malicious'
                ? '#f56c6c'
                : detectResult.verdict === 'suspicious'
                  ? '#e6a23c'
                  : '#67c23a')
          }}
        >
          <div className="mb-4 flex items-center gap-4">
            <span className="text-4xl">
              {detectResult.verdict === 'malicious' ? '🔴' : detectResult.verdict === 'suspicious' ? '🟡' : '🟢'}
            </span>
            <div>
              <div
                className="text-lg font-bold"
                style={{
                  color:
                    detectResult.verdict === 'malicious'
                      ? '#f56c6c'
                      : detectResult.verdict === 'suspicious'
                        ? '#e6a23c'
                        : '#67c23a'
                }}
              >
                {detectResult.verdict === 'malicious'
                  ? '检测到恶意文件'
                  : detectResult.verdict === 'suspicious'
                    ? '检测到疑似威胁'
                    : '文件安全'}
              </div>
              <div className="text-[13px] text-gray-400">
                置信度: {(detectResult.confidence * 100).toFixed(1)}% | 主要引擎: {detectResult.primaryEngine} | 耗时:{' '}
                {detectResult.totalTime}s
              </div>
            </div>
          </div>
          <div className="text-[13px] leading-relaxed text-gray-200">
            <strong>处置建议:</strong> {detectResult.recommendation}
          </div>
          <div className="mt-3 flex gap-2">
            <Button size="sm" onClick={() => viewReport(detectResult.scanId)}>
              查看详细报告
            </Button>
            <Button size="sm" variant="outline" disabled={!reportContent} onClick={downloadReport}>
              下载报告
            </Button>
          </div>
        </div>
      )}

      {/* 哈希查询 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 text-sm font-semibold text-cyan-300">哈希威胁情报查询</div>
        <div className="flex flex-wrap items-center gap-3">
          <input
            className={`${fieldCls} w-[360px]`}
            value={hashInput}
            placeholder="输入 MD5 / SHA1 / SHA256 哈希"
            onChange={(e) => setHashInput(e.target.value)}
          />
          <select className={`${fieldCls} w-[120px]`} value={hashType} onChange={(e) => setHashType(e.target.value)}>
            <option value="md5">MD5</option>
            <option value="sha1">SHA1</option>
            <option value="sha256">SHA256</option>
          </select>
          <Button size="sm" disabled={analyzing} onClick={analyzeHash}>
            {analyzing ? '查询中…' : '分析哈希'}
          </Button>
        </div>
        {hashResults !== null && (
          <div className="mt-4">
            <Table>
              <thead>
                <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                  <th className="px-2 py-2 font-medium">哈希值</th>
                  <th className="px-2 py-2 font-medium">类型</th>
                  <th className="px-2 py-2 font-medium">威胁名称</th>
                  <th className="px-2 py-2 font-medium">威胁级别</th>
                  <th className="px-2 py-2 font-medium">情报来源</th>
                  <th className="px-2 py-2 font-medium">收录时间</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {hashResults.map((h, i) => (
                  <tr key={i} className="hover:bg-white/5">
                    <td className="max-w-[260px] truncate px-2 py-2 font-mono text-xs text-gray-300">{h.hash_value}</td>
                    <td className="px-2 py-2 text-gray-400">{h.hash_type || '-'}</td>
                    <td className="px-2 py-2 text-gray-300">{h.threat_name || h.virus_name || '-'}</td>
                    <td className="px-2 py-2">
                      <Badge variant={severityTag(h.severity || h.threat_level).variant}>
                        {severityTag(h.severity || h.threat_level).label}
                      </Badge>
                    </td>
                    <td className="px-2 py-2 text-gray-400">{h.source || '-'}</td>
                    <td className="px-2 py-2 text-gray-400">
                      {h.created_at ? new Date(h.created_at).toLocaleString('zh-CN') : '-'}
                    </td>
                  </tr>
                ))}
                {hashResults.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-2 py-6 text-center text-gray-500">
                      未查询到该哈希的威胁情报记录
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
          </div>
        )}
      </div>

      {/* 扫描历史记录 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 flex items-center justify-between">
          <div className="text-sm font-semibold text-cyan-300">扫描历史记录</div>
          <Button size="sm" variant="outline" onClick={loadRecords}>
            刷新
          </Button>
        </div>
        <Table>
          <thead>
            <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
              <th className="px-2 py-2 font-medium">文件名</th>
              <th className="px-2 py-2 font-medium">MD5</th>
              <th className="px-2 py-2 font-medium">大小</th>
              <th className="px-2 py-2 font-medium">判定</th>
              <th className="px-2 py-2 font-medium">主要引擎</th>
              <th className="px-2 py-2 font-medium">置信度</th>
              <th className="px-2 py-2 font-medium">时间</th>
              <th className="px-2 py-2 font-medium">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {paginatedRecords.map((r) => (
              <tr key={r.id} className="hover:bg-white/5">
                <td className="max-w-[200px] truncate px-2 py-2 text-gray-300">{r.filename}</td>
                <td className="px-2 py-2 font-mono text-[11px] text-gray-400">
                  {r.hash ? r.hash.substring(0, 12) + '...' : '-'}
                </td>
                <td className="px-2 py-2 text-gray-400">{formatSize(r.filesize)}</td>
                <td className="px-2 py-2">
                  <Badge variant={verdictTag(r.verdict).variant}>{verdictTag(r.verdict).label}</Badge>
                </td>
                <td className="px-2 py-2 text-gray-300">{r.source}</td>
                <td className="px-2 py-2 text-gray-400">{r.confidence}</td>
                <td className="px-2 py-2 text-gray-400">{r.time}</td>
                <td className="px-2 py-2">
                  {r.scanId && (
                    <button
                      type="button"
                      onClick={() => viewReport(r.scanId)}
                      className="text-xs text-cyan-400 transition-colors hover:text-cyan-300"
                    >
                      报告
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {paginatedRecords.length === 0 && (
              <tr>
                <td colSpan={8} className="px-2 py-6 text-center text-gray-500">
                  暂无扫描记录
                </td>
              </tr>
            )}
          </tbody>
        </Table>
        <div className="mt-4 flex items-center justify-end gap-3">
          <Button size="sm" variant="outline" disabled={recordPage <= 1} onClick={() => setRecordPage((p) => p - 1)}>
            上一页
          </Button>
          <span className="text-xs text-gray-400">
            第 {recordPage} / {recordTotalPages} 页（共 {records.length} 条）
          </span>
          <Button
            size="sm"
            variant="outline"
            disabled={recordPage >= recordTotalPages}
            onClick={() => setRecordPage((p) => p + 1)}
          >
            下一页
          </Button>
        </div>
      </div>

      {/* 查杀报告弹窗 */}
      {showReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60" onClick={() => setShowReport(false)} />
          <div className="relative z-10 flex max-h-[80vh] w-full max-w-3xl flex-col rounded-lg border border-cyan-500/20 bg-[#0f1a33] shadow-xl">
            <div className="flex items-center justify-between border-b border-white/5 px-5 py-4">
              <h3 className="text-base font-semibold text-white">查杀报告</h3>
              <button
                type="button"
                onClick={() => setShowReport(false)}
                className="text-xl leading-none text-gray-400 hover:text-gray-200"
                aria-label="关闭"
              >
                ×
              </button>
            </div>
            <div className="flex-1 overflow-y-auto px-5 py-4">
              <pre className="whitespace-pre-wrap font-mono text-[13px] leading-relaxed text-gray-200">
                {reportContent}
              </pre>
            </div>
            <div className="flex justify-end gap-2 border-t border-white/5 px-5 py-4">
              <Button size="sm" variant="outline" onClick={() => setShowReport(false)}>
                关闭
              </Button>
              <Button size="sm" onClick={downloadReport}>
                下载Markdown
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
