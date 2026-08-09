import { useCallback, useEffect, useRef, useState } from 'react';
import { djppApi } from '@/api';
import type { DjppCategory, DjppCheck, DjppLevel, DjppReport, DjppReportData, DjppResult, DjppTask, DjppTaskDetail } from '@/api';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import Dialog from '@/components/ui/dialog';
import { Table } from '@/components/ui/table';
import { useToast } from '@/components/ui/use-toast';

const POLL_INTERVAL = 3000;

const fieldCls =
  'rounded-md border border-cyan-500/20 bg-[#1a2340] px-3 py-2 text-sm text-gray-300 outline-none transition-colors placeholder:text-gray-500 focus:border-cyan-500/60';

type TabKey = 'levels' | 'tasks' | 'reports';

interface TagInfo {
  label: string;
  variant: 'default' | 'success' | 'warning' | 'danger';
}

function taskStatusTag(status: string): TagInfo {
  if (status === 'pending') return { label: '待执行', variant: 'warning' };
  if (status === 'running') return { label: '执行中', variant: 'default' };
  if (status === 'completed') return { label: '已完成', variant: 'success' };
  return { label: '失败', variant: 'danger' };
}

function resultStatusTag(status?: string): TagInfo {
  if (status === 'pass') return { label: '通过', variant: 'success' };
  if (status === 'fail') return { label: '失败', variant: 'danger' };
  return { label: '警告', variant: 'warning' };
}

function severityTag(s?: string): TagInfo {
  const map: Record<string, TagInfo> = {
    critical: { label: '严重', variant: 'danger' },
    high: { label: '高', variant: 'warning' },
    medium: { label: '中', variant: 'default' },
    low: { label: '低', variant: 'success' }
  };
  return map[s || ''] || { label: s || '-', variant: 'default' };
}

const DEMO_LEVELS: DjppLevel[] = [
  { id: 1, level: 1, name: '第一级', description: '自主保护级' },
  { id: 2, level: 2, name: '第二级', description: '指导保护级' },
  { id: 3, level: 3, name: '第三级', description: '监督保护级' },
  { id: 4, level: 4, name: '第四级', description: '强制保护级' },
  { id: 5, level: 5, name: '第五级', description: '专控保护级' }
];

interface ReportView {
  reportId: string;
  title: string;
  level?: number;
  taskName?: string;
  content: string;
}

function parseReportContent(row: DjppReport): { parsed: DjppReportData; content: string } {
  let parsed: DjppReportData = {};
  let content = row.content || '';
  if (row.content) {
    try {
      parsed = JSON.parse(row.content) as DjppReportData;
      content = parsed.aiAnalysis || content;
    } catch {
      // 非 JSON 内容，原样展示
    }
  }
  return { parsed, content: content || '无报告内容' };
}

export default function Djpp() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState<TabKey>('levels');

  // 等级 / 分类 / 检查项浏览
  const [levels, setLevels] = useState<DjppLevel[]>([]);
  const [selectedLevel, setSelectedLevel] = useState<number>(3);
  const [categories, setCategories] = useState<DjppCategory[]>([]);
  const [selectedCategoryId, setSelectedCategoryId] = useState<number | null>(null);
  const [checks, setChecks] = useState<DjppCheck[]>([]);

  // 创建任务表单
  const [taskForm, setTaskForm] = useState({ level: 3, name: '', description: '' });
  const [creatingTask, setCreatingTask] = useState(false);

  // 任务列表
  const [tasks, setTasks] = useState<DjppTask[]>([]);
  const [loadingTasks, setLoadingTasks] = useState(true);

  // 任务详情
  const [showTaskDetail, setShowTaskDetail] = useState(false);
  const [taskDetail, setTaskDetail] = useState<DjppTaskDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // 报告
  const [generatingReportId, setGeneratingReportId] = useState<string | null>(null);
  const [reports, setReports] = useState<DjppReport[]>([]);
  const [showReportDetail, setShowReportDetail] = useState(false);
  const [currentReport, setCurrentReport] = useState<ReportView | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<DjppReport | null>(null);
  const [deleting, setDeleting] = useState(false);

  const loadLevels = useCallback(async () => {
    try {
      const list = await djppApi.levels();
      setLevels(list || []);
    } catch {
      setLevels(DEMO_LEVELS);
    }
  }, []);

  async function loadLevelBrowse(level: number) {
    try {
      const catList = await djppApi.categories(level);
      setCategories(catList || []);
      setSelectedCategoryId(null);
    } catch {
      setCategories([]);
      setSelectedCategoryId(null);
    }
    try {
      const checkList = await djppApi.levelChecks(level);
      setChecks(checkList || []);
    } catch {
      setChecks([]);
    }
  }

  async function loadCategoryChecks(categoryId: number) {
    try {
      const checkList = await djppApi.checks(categoryId);
      setChecks(checkList || []);
    } catch {
      setChecks([]);
    }
  }

  const loadTasks = useCallback(async () => {
    setLoadingTasks(true);
    try {
      const data = await djppApi.tasks({ page: 1, pageSize: 50 });
      setTasks(data?.tasks || []);
    } catch {
      setTasks([]);
    }
    setLoadingTasks(false);
  }, []);

  const loadReports = useCallback(async () => {
    try {
      const data = await djppApi.reports({ page: 1, pageSize: 50 });
      setReports(data?.reports || []);
    } catch {
      setReports([]);
    }
  }, []);

  useEffect(() => {
    loadLevels();
    loadTasks();
    loadReports();
  }, [loadLevels, loadTasks, loadReports]);

  useEffect(() => {
    if (levels.length > 0) {
      loadLevelBrowse(selectedLevel);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedLevel, levels]);

  // 存在执行中/待执行任务时，3s 轮询刷新进度
  const hasActiveRef = useRef(false);
  useEffect(() => {
    hasActiveRef.current = tasks.some((t) => t.status === 'running' || t.status === 'pending');
  }, [tasks]);
  useEffect(() => {
    const timer = setInterval(() => {
      if (hasActiveRef.current) loadTasks();
    }, POLL_INTERVAL);
    return () => clearInterval(timer);
  }, [loadTasks]);

  function changeCategory(categoryId: string) {
    if (categoryId === '') {
      setSelectedCategoryId(null);
      loadLevelBrowse(selectedLevel);
    } else {
      const id = Number(categoryId);
      setSelectedCategoryId(id);
      loadCategoryChecks(id);
    }
  }

  async function startTask() {
    if (!taskForm.name.trim()) {
      toast({ title: '请输入任务名称', variant: 'warning' });
      return;
    }
    setCreatingTask(true);
    try {
      await djppApi.create({
        level: taskForm.level,
        name: taskForm.name.trim(),
        description: taskForm.description.trim()
      });
      toast({ title: '测评任务已启动', variant: 'success' });
      setTaskForm((f) => ({ ...f, name: '', description: '' }));
      loadTasks();
    } catch {
      toast({ title: '任务创建失败', variant: 'error' });
    }
    setCreatingTask(false);
  }

  async function viewTask(taskId: string) {
    setShowTaskDetail(true);
    setDetailLoading(true);
    setTaskDetail(null);
    try {
      const detail = await djppApi.detail(taskId);
      setTaskDetail(detail);
    } catch {
      toast({ title: '获取任务详情失败', variant: 'error' });
    }
    setDetailLoading(false);
  }

  async function generateReport(taskId: string) {
    if (generatingReportId) {
      toast({ title: '报告正在生成中，请稍候...', variant: 'warning' });
      return;
    }
    setGeneratingReportId(taskId);
    toast({ title: '正在调用AI生成测评报告，预计需要30-60秒，请耐心等待...', variant: 'default' });
    try {
      const data = await djppApi.report(taskId);
      setCurrentReport({
        reportId: data.reportId || String(taskId),
        title: data.taskName ? `${data.taskName} - 等级保护${data.level}级测评报告` : '等保测评报告',
        level: data.level,
        taskName: data.taskName,
        content: data.aiAnalysis || data.content || '无报告内容'
      });
      setShowReportDetail(true);
      toast({ title: '报告生成成功', variant: 'success' });
      loadTasks();
    } catch {
      toast({ title: '报告生成失败', variant: 'error' });
    }
    setGeneratingReportId(null);
  }

  function viewReport(row: DjppReport) {
    const { parsed, content } = parseReportContent(row);
    setCurrentReport({
      reportId: row.id,
      title: row.title,
      level: parsed.level,
      taskName: parsed.taskName,
      content
    });
    setShowReportDetail(true);
  }

  function downloadReportMD() {
    if (!currentReport) return;
    const md = currentReport.taskName
      ? `# ${currentReport.taskName} - 等级保护${currentReport.level}级测评报告\n\n${currentReport.content}`
      : `# ${currentReport.title}\n\n${currentReport.content}`;
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `等保${currentReport.level || ''}级测评报告_${currentReport.reportId}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({ title: '报告已下载', variant: 'success' });
  }

  function downloadReportTxt(row: DjppReport) {
    const { content } = parseReportContent(row);
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${row.title || '等保报告'}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  async function downloadReportDOCX() {
    if (!currentReport?.reportId) {
      toast({ title: '报告ID不存在，无法下载DOCX', variant: 'warning' });
      return;
    }
    toast({ title: '正在生成DOCX报告，请稍候...', variant: 'default' });
    try {
      const res = await djppApi.generateDocx(currentReport.reportId);
      if (res.downloadUrl) {
        window.open('/api' + res.downloadUrl, '_blank');
        toast({ title: 'DOCX报告已开始下载', variant: 'success' });
      } else {
        toast({ title: 'DOCX生成失败', variant: 'error' });
      }
    } catch {
      toast({ title: 'DOCX下载失败', variant: 'error' });
    }
  }

  async function confirmDeleteReport() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await djppApi.deleteReport(deleteTarget.id);
      toast({ title: '删除成功', variant: 'success' });
      loadReports();
    } catch {
      toast({ title: '删除失败', variant: 'error' });
    }
    setDeleting(false);
    setDeleteTarget(null);
  }

  const stats = taskDetail?.stats;

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">等级保护测评</h2>
          <p className="mt-1 text-sm text-gray-400">按照等级保护一二三四五级测评流程进行各项安全测试</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-4 border-b border-white/10">
        {(
          [
            ['levels', '测评级别'],
            ['tasks', '任务管理'],
            ['reports', '报告管理']
          ] as Array<[TabKey, string]>
        ).map(([key, label]) => (
          <button
            key={key}
            type="button"
            onClick={() => setActiveTab(key)}
            className={`border-b-2 px-1 pb-2 text-sm transition-colors ${
              activeTab === key ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {activeTab === 'levels' && (
        <div className="space-y-5">
          {/* 测评级别选择 */}
          <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
            <div className="mb-4 text-sm font-semibold text-cyan-300">选择测评级别</div>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
              {levels.map((level) => (
                <div
                  key={level.id}
                  role="button"
                  tabIndex={0}
                  onClick={() => setSelectedLevel(level.id)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') setSelectedLevel(level.id);
                  }}
                  className={`cursor-pointer rounded-lg border p-4 transition-colors ${
                    selectedLevel === level.id
                      ? 'border-cyan-400/80 bg-cyan-500/10'
                      : 'border-white/10 bg-[#1a2340]/60 hover:border-cyan-500/40'
                  }`}
                >
                  <div className="mb-2 flex items-center justify-between">
                    <span
                      className={`text-lg font-bold ${selectedLevel === level.id ? 'text-cyan-300' : 'text-gray-200'}`}
                    >
                      第{level.level}级
                    </span>
                    <Badge variant={selectedLevel === level.id ? 'default' : 'default'}>{level.name}</Badge>
                  </div>
                  <div className="text-sm text-gray-400">{level.description}</div>
                </div>
              ))}
            </div>
          </div>

          {/* 等级 / 分类 / 检查项浏览 */}
          <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
            <div className="mb-4 text-sm font-semibold text-cyan-300">检查项浏览</div>
            <div className="flex flex-wrap items-center gap-3">
              <select
                className={`${fieldCls} w-[200px]`}
                value={selectedLevel}
                onChange={(e) => setSelectedLevel(Number(e.target.value))}
              >
                {levels.map((l) => (
                  <option key={l.id} value={l.level}>
                    第{l.level}级 · {l.name}
                  </option>
                ))}
              </select>
              <select
                className={`${fieldCls} w-[220px]`}
                value={selectedCategoryId === null ? '' : String(selectedCategoryId)}
                onChange={(e) => changeCategory(e.target.value)}
              >
                <option value="">全部检查项</option>
                {categories.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.category_code} {c.category_name}
                  </option>
                ))}
              </select>
              <span className="text-xs text-gray-500">共 {checks.length} 个检查项</span>
            </div>
            <div className="mt-4">
              <Table>
                <thead>
                  <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                    <th className="px-2 py-2 font-medium">编码</th>
                    <th className="px-2 py-2 font-medium">检查项名称</th>
                    <th className="px-2 py-2 font-medium">安全类别</th>
                    <th className="px-2 py-2 font-medium">严重级别</th>
                    <th className="px-2 py-2 font-medium">期望值</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {checks.map((c) => (
                    <tr key={c.id} className="hover:bg-white/5">
                      <td className="px-2 py-2 font-mono text-xs text-gray-400">{c.check_code}</td>
                      <td className="px-2 py-2 text-gray-300">{c.check_name}</td>
                      <td className="px-2 py-2 text-gray-400">{c.category_name || '-'}</td>
                      <td className="px-2 py-2">
                        <Badge variant={severityTag(c.severity).variant}>{severityTag(c.severity).label}</Badge>
                      </td>
                      <td className="max-w-[280px] truncate px-2 py-2 text-gray-400">{c.expected_value || '-'}</td>
                    </tr>
                  ))}
                  {checks.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-2 py-6 text-center text-gray-500">
                        该级别暂无检查项
                      </td>
                    </tr>
                  )}
                </tbody>
              </Table>
            </div>
          </div>

          {/* 开始测评任务 */}
          <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
            <div className="mb-4 text-sm font-semibold text-cyan-300">开始测评任务</div>
            <div className="max-w-[600px] space-y-4">
              <div className="flex items-center gap-3">
                <label className="w-[80px] shrink-0 text-sm text-gray-400">测评级别</label>
                <select
                  className={`${fieldCls} w-[220px]`}
                  value={taskForm.level}
                  onChange={(e) => setTaskForm({ ...taskForm, level: Number(e.target.value) })}
                >
                  {levels.map((l) => (
                    <option key={l.id} value={l.level}>
                      {l.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-3">
                <label className="w-[80px] shrink-0 text-sm text-gray-400">任务名称</label>
                <input
                  className={`${fieldCls} flex-1`}
                  value={taskForm.name}
                  placeholder="请输入测评任务名称"
                  onChange={(e) => setTaskForm({ ...taskForm, name: e.target.value })}
                />
              </div>
              <div className="flex items-start gap-3">
                <label className="w-[80px] shrink-0 pt-2 text-sm text-gray-400">任务描述</label>
                <textarea
                  className={`${fieldCls} flex-1`}
                  rows={3}
                  value={taskForm.description}
                  placeholder="请输入任务描述"
                  onChange={(e) => setTaskForm({ ...taskForm, description: e.target.value })}
                />
              </div>
              <div>
                <Button size="sm" disabled={creatingTask} onClick={startTask}>
                  {creatingTask ? '启动中…' : '启动测评'}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'tasks' && (
        <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
          <div className="mb-4 flex items-center justify-between">
            <div className="text-sm font-semibold text-cyan-300">测评任务列表</div>
            <Button size="sm" variant="outline" onClick={loadTasks}>
              刷新
            </Button>
          </div>
          <Table>
            <thead>
              <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                <th className="px-2 py-2 font-medium">任务ID</th>
                <th className="px-2 py-2 font-medium">任务名称</th>
                <th className="px-2 py-2 font-medium">测评级别</th>
                <th className="px-2 py-2 font-medium">状态</th>
                <th className="px-2 py-2 font-medium">进度</th>
                <th className="px-2 py-2 font-medium">创建人</th>
                <th className="px-2 py-2 font-medium">创建时间</th>
                <th className="px-2 py-2 font-medium">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {tasks.map((t) => (
                <tr key={t.id} className="hover:bg-white/5">
                  <td className="px-2 py-2 font-mono text-xs text-gray-400">{t.id}</td>
                  <td className="px-2 py-2 text-gray-300">{t.name}</td>
                  <td className="px-2 py-2">
                    <Badge variant="default">第{t.level}级</Badge>
                  </td>
                  <td className="px-2 py-2">
                    <Badge variant={taskStatusTag(t.status).variant}>{taskStatusTag(t.status).label}</Badge>
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-24 overflow-hidden rounded-full bg-white/10">
                        <div
                          className={`h-full rounded-full ${t.status === 'completed' ? 'bg-green-500' : 'bg-cyan-400'}`}
                          style={{ width: `${Math.min(100, Math.max(0, t.progress || 0))}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-400">{t.progress || 0}%</span>
                    </div>
                  </td>
                  <td className="px-2 py-2 text-gray-400">{t.created_by_name || '-'}</td>
                  <td className="px-2 py-2 text-gray-400">
                    {t.created_at ? new Date(t.created_at).toLocaleString('zh-CN') : '-'}
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex gap-3">
                      <button
                        type="button"
                        onClick={() => viewTask(t.id)}
                        className="text-xs text-cyan-400 transition-colors hover:text-cyan-300"
                      >
                        查看
                      </button>
                      {t.status === 'completed' && (
                        <button
                          type="button"
                          disabled={generatingReportId === t.id}
                          onClick={() => generateReport(t.id)}
                          className="text-xs text-green-400 transition-colors hover:text-green-300 disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          {generatingReportId === t.id ? '生成中…' : '生成报告'}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {tasks.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-2 py-6 text-center text-gray-500">
                    {loadingTasks ? '加载中…' : '暂无测评任务'}
                  </td>
                </tr>
              )}
            </tbody>
          </Table>
        </div>
      )}

      {activeTab === 'reports' && (
        <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
          <div className="mb-4 flex items-center justify-between">
            <div className="text-sm font-semibold text-cyan-300">等保报告列表</div>
            <Button size="sm" variant="outline" onClick={loadReports}>
              刷新
            </Button>
          </div>
          <Table>
            <thead>
              <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                <th className="px-2 py-2 font-medium">报告名称</th>
                <th className="px-2 py-2 font-medium">生成人</th>
                <th className="px-2 py-2 font-medium">生成时间</th>
                <th className="px-2 py-2 font-medium">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {reports.map((r) => (
                <tr key={r.id} className="hover:bg-white/5">
                  <td className="px-2 py-2 text-gray-300">{r.title}</td>
                  <td className="px-2 py-2 text-gray-400">{r.generated_by_name || '-'}</td>
                  <td className="px-2 py-2 text-gray-400">
                    {r.created_at ? new Date(r.created_at).toLocaleString('zh-CN') : '-'}
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
                        onClick={() => downloadReportTxt(r)}
                        className="text-xs text-green-400 transition-colors hover:text-green-300"
                      >
                        下载
                      </button>
                      <button
                        type="button"
                        onClick={() => setDeleteTarget(r)}
                        className="text-xs text-red-400 transition-colors hover:text-red-300"
                      >
                        删除
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {reports.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-2 py-6 text-center text-gray-500">
                    暂无等保报告
                  </td>
                </tr>
              )}
            </tbody>
          </Table>
        </div>
      )}

      {/* 任务详情弹窗 */}
      {showTaskDetail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60" onClick={() => setShowTaskDetail(false)} />
          <div className="relative z-10 flex max-h-[85vh] w-full max-w-5xl flex-col rounded-lg border border-cyan-500/20 bg-[#0f1a33] shadow-xl">
            <div className="flex items-center justify-between border-b border-white/5 px-5 py-4">
              <h3 className="text-base font-semibold text-white">{taskDetail?.task?.name || '任务详情'}</h3>
              <button
                type="button"
                onClick={() => setShowTaskDetail(false)}
                className="text-xl leading-none text-gray-400 hover:text-gray-200"
                aria-label="关闭"
              >
                ×
              </button>
            </div>
            <div className="flex-1 overflow-y-auto px-5 py-4">
              {detailLoading || !taskDetail ? (
                <div className="py-8 text-center text-sm text-cyan-300/70">加载中…</div>
              ) : (
                <div className="space-y-5">
                  {/* 任务概要 */}
                  <div className="grid grid-cols-2 gap-x-6 gap-y-2 rounded-lg border border-white/5 bg-[#16213e]/60 p-4 text-sm lg:grid-cols-3">
                    <div>
                      <span className="text-gray-500">任务ID: </span>
                      <span className="text-gray-300">{taskDetail.task.id}</span>
                    </div>
                    <div>
                      <span className="text-gray-500">测评级别: </span>
                      <span className="text-gray-300">第{taskDetail.task.level}级</span>
                    </div>
                    <div>
                      <span className="text-gray-500">状态: </span>
                      <Badge variant={taskStatusTag(taskDetail.task.status).variant}>
                        {taskStatusTag(taskDetail.task.status).label}
                      </Badge>
                    </div>
                    <div>
                      <span className="text-gray-500">进度: </span>
                      <span className="text-gray-300">{taskDetail.task.progress || 0}%</span>
                    </div>
                    <div>
                      <span className="text-gray-500">创建时间: </span>
                      <span className="text-gray-300">
                        {taskDetail.task.created_at
                          ? new Date(taskDetail.task.created_at).toLocaleString('zh-CN')
                          : '-'}
                      </span>
                    </div>
                    <div>
                      <span className="text-gray-500">完成时间: </span>
                      <span className="text-gray-300">
                        {taskDetail.task.completed_at
                          ? new Date(taskDetail.task.completed_at).toLocaleString('zh-CN')
                          : '-'}
                      </span>
                    </div>
                  </div>

                  {/* 统计 */}
                  <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                    <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-4">
                      <div className="text-xs text-gray-400">总检查项</div>
                      <div className="mt-2 text-2xl font-bold text-cyan-400">{stats?.total ?? 0}</div>
                    </div>
                    <div className="rounded-lg border border-green-500/20 bg-green-500/5 p-4">
                      <div className="text-xs text-gray-400">通过</div>
                      <div className="mt-2 text-2xl font-bold text-green-400">{stats?.pass ?? 0}</div>
                    </div>
                    <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-4">
                      <div className="text-xs text-gray-400">失败</div>
                      <div className="mt-2 text-2xl font-bold text-red-400">{stats?.fail ?? 0}</div>
                    </div>
                    <div className="rounded-lg border border-purple-500/20 bg-purple-500/5 p-4">
                      <div className="text-xs text-gray-400">合规率</div>
                      <div className="mt-2 text-2xl font-bold text-purple-400">{stats?.complianceRate ?? '0.0'}%</div>
                    </div>
                  </div>

                  {/* 检查项结果 */}
                  <Table>
                    <thead>
                      <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                        <th className="px-2 py-2 font-medium">安全类别</th>
                        <th className="px-2 py-2 font-medium">检查项编码</th>
                        <th className="px-2 py-2 font-medium">检查项名称</th>
                        <th className="px-2 py-2 font-medium">实际值</th>
                        <th className="px-2 py-2 font-medium">状态</th>
                        <th className="px-2 py-2 font-medium">严重级别</th>
                        <th className="px-2 py-2 font-medium">备注</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5">
                      {taskDetail.results.map((r: DjppResult) => (
                        <tr key={r.id || r.check_id} className="hover:bg-white/5">
                          <td className="px-2 py-2 text-gray-400">{r.category_name || '-'}</td>
                          <td className="px-2 py-2 font-mono text-xs text-gray-400">{r.check_code || '-'}</td>
                          <td className="px-2 py-2 text-gray-300">{r.check_name}</td>
                          <td className="max-w-[240px] truncate px-2 py-2 text-gray-400">{r.actual_value || '-'}</td>
                          <td className="px-2 py-2">
                            <Badge variant={resultStatusTag(r.status).variant}>
                              {resultStatusTag(r.status).label}
                            </Badge>
                          </td>
                          <td className="px-2 py-2">
                            <Badge variant={severityTag(r.severity).variant}>{severityTag(r.severity).label}</Badge>
                          </td>
                          <td className="max-w-[200px] truncate px-2 py-2 text-gray-400">{r.comment || '-'}</td>
                        </tr>
                      ))}
                      {taskDetail.results.length === 0 && (
                        <tr>
                          <td colSpan={7} className="px-2 py-6 text-center text-gray-500">
                            暂无检查结果
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </Table>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 报告详情弹窗 */}
      {showReportDetail && currentReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60" onClick={() => setShowReportDetail(false)} />
          <div className="relative z-10 flex max-h-[85vh] w-full max-w-4xl flex-col rounded-lg border border-cyan-500/20 bg-[#0f1a33] shadow-xl">
            <div className="flex items-center justify-between border-b border-white/5 px-5 py-4">
              <h3 className="text-base font-semibold text-white">{currentReport.title} - 等保测评报告</h3>
              <button
                type="button"
                onClick={() => setShowReportDetail(false)}
                className="text-xl leading-none text-gray-400 hover:text-gray-200"
                aria-label="关闭"
              >
                ×
              </button>
            </div>
            <div className="flex-1 overflow-y-auto px-5 py-4">
              <div className="mb-4 flex gap-2">
                <Button size="sm" variant="outline" onClick={downloadReportMD}>
                  下载MD报告
                </Button>
                <Button size="sm" variant="outline" onClick={downloadReportDOCX}>
                  下载DOCX报告
                </Button>
              </div>
              <pre className="whitespace-pre-wrap text-sm leading-relaxed text-gray-200">{currentReport.content}</pre>
            </div>
          </div>
        </div>
      )}

      {/* 删除报告确认 */}
      <Dialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)} title="删除确认">
        <p className="text-sm text-gray-600">确定要删除报告「{deleteTarget?.title}」吗？删除后无法恢复。</p>
        <div className="mt-4 flex justify-end gap-2">
          <Button size="sm" variant="outline" onClick={() => setDeleteTarget(null)}>
            取消
          </Button>
          <Button size="sm" variant="destructive" disabled={deleting} onClick={confirmDeleteReport}>
            {deleting ? '删除中…' : '删除'}
          </Button>
        </div>
      </Dialog>
    </div>
  );
}
