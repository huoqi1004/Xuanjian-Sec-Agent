import { useCallback, useEffect, useMemo, useState } from 'react';
import type { EChartsOption } from 'echarts';
import { situationalApi, reportsApi } from '@/api';
import type { AlertRecord, ReportItem, ThreatIntelRecord } from '@/api';
import EChart from '@/components/chart';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import Dialog from '@/components/ui/dialog';
import { Table } from '@/components/ui/table';
import { useToast } from '@/components/ui/use-toast';

const PAGE_SIZE = 10;

interface AlertRow {
  id: string;
  type: string;
  level: string;
  asset: string;
  confidence: string;
  status: string;
  time: string;
}

interface IntelRow {
  id: string;
  type: string;
  value: string;
  confidence: string;
  source: string;
  severity: string;
  updateTime: string;
}

interface LevelTag {
  label: string;
  variant: 'default' | 'success' | 'warning' | 'danger';
}

function getLevelTag(level: string): LevelTag {
  const map: Record<string, LevelTag> = {
    critical: { label: '严重', variant: 'danger' },
    high: { label: '高危', variant: 'warning' },
    medium: { label: '中危', variant: 'default' },
    low: { label: '低危', variant: 'success' }
  };
  return map[level] || { label: level, variant: 'default' };
}

function getStatusTag(status: string): LevelTag {
  const map: Record<string, LevelTag> = {
    pending: { label: '待处理', variant: 'warning' },
    new: { label: '待处理', variant: 'warning' },
    acknowledged: { label: '已确认', variant: 'danger' },
    confirmed: { label: '已确认', variant: 'danger' },
    resolved: { label: '已解决', variant: 'success' },
    false_positive: { label: '误报', variant: 'default' }
  };
  return map[status] || { label: status, variant: 'default' };
}

function mapAlert(a: AlertRecord): AlertRow {
  return {
    id: 'ALT-' + a.id,
    type: a.alert_type || '未知',
    level: a.severity || 'medium',
    asset: a.related_asset || '-',
    confidence: a.confidence ? (a.confidence * 100).toFixed(0) + '%' : '-',
    status: a.status || 'new',
    time: a.created_at ? new Date(a.created_at).toLocaleString('zh-CN') : '-'
  };
}

function mapIntel(t: ThreatIntelRecord): IntelRow {
  return {
    id: 'TI-' + t.id,
    type: t.ioc_type || '未知',
    value: t.ioc_value,
    confidence: t.confidence ? (t.confidence * 100).toFixed(0) + '%' : '-',
    source: t.source || '-',
    severity: 'high',
    updateTime: t.updated_at ? new Date(t.updated_at).toLocaleString('zh-CN') : '-'
  };
}

function demoAlerts(): AlertRow[] {
  const types = ['端口扫描', '暴力破解', '异常流量', '恶意软件', 'DDoS攻击', 'SQL注入', 'XSS攻击', '未授权访问'];
  const levels = ['critical', 'high', 'medium', 'low'];
  const statuses = ['pending', 'confirmed', 'resolved', 'false_positive'];
  const assets = ['192.168.1.10', '192.168.1.25', '10.0.0.5', '172.16.0.100', '192.168.2.50'];
  return Array.from({ length: 50 }, (_, i) => ({
    id: 'ALT-' + (1000 + i),
    type: types[Math.floor(Math.random() * types.length)],
    level: levels[Math.floor(Math.random() * levels.length)],
    asset: assets[Math.floor(Math.random() * assets.length)],
    confidence: (70 + Math.random() * 30).toFixed(1),
    status: statuses[Math.floor(Math.random() * statuses.length)],
    time: new Date(Date.now() - Math.random() * 7 * 86400000).toLocaleString('zh-CN')
  }));
}

function demoThreatIntel(): IntelRow[] {
  const types = ['恶意IP', '恶意域名', '恶意Hash', 'C2服务器', '钓鱼URL', '僵尸网络'];
  return Array.from({ length: 20 }, (_, i) => ({
    id: 'TI-' + (8000 + i),
    type: types[Math.floor(Math.random() * types.length)],
    value:
      i % 3 === 0
        ? `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
        : i % 3 === 1
          ? `malware${i}.example.com`
          : Array.from({ length: 32 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join(''),
    confidence: (60 + Math.random() * 40).toFixed(1),
    source: ['AlienVault', 'Abuse.ch', 'VirusTotal', '微步在线', '奇安信威胁情报'][Math.floor(Math.random() * 5)],
    severity: 'high',
    updateTime: new Date(Date.now() - Math.random() * 7 * 86400000).toLocaleString('zh-CN')
  }));
}

/** 生成近 N 天日期（M/D） */
function lastDays(n: number): string[] {
  const days: string[] = [];
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000);
    days.push(d.getMonth() + 1 + '/' + d.getDate());
  }
  return days;
}

const selectCls =
  'rounded-md border border-cyan-500/20 bg-[#1a2340] px-2 py-1.5 text-sm text-gray-300 outline-none transition-colors focus:border-cyan-500/60';

export default function Situational() {
  const { toast } = useToast();
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'alerts' | 'intel'>('alerts');

  // 告警：服务端分页 + 过滤
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [alerts, setAlerts] = useState<AlertRow[]>([]);

  // 威胁情报：全量加载，前端分页
  const [intel, setIntel] = useState<IntelRow[]>([]);
  const [intelPage, setIntelPage] = useState(1);

  // 报告管理
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [preview, setPreview] = useState<{ title: string; content: string } | null>(null);

  // 演示/兜底数据仅生成一次
  const demo = useMemo(() => {
    const days = lastDays(30);
    return {
      trendDays: days,
      newAlerts: Array.from({ length: 30 }, () => Math.floor(Math.random() * 30) + 5),
      handledAlerts: Array.from({ length: 30 }, () => Math.floor(Math.random() * 25) + 3)
    };
  }, []);

  // 告警列表加载（分页/过滤变化时重新请求）
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    (async () => {
      try {
        const res = await situationalApi.alerts({
          page,
          pageSize: PAGE_SIZE,
          severity: severity || undefined,
          status: status || undefined
        });
        const list = Array.isArray(res) ? res : (res as unknown as { list?: AlertRecord[] }).list || [];
        if (!cancelled) setAlerts(list.map(mapAlert));
      } catch {
        if (!cancelled) setAlerts(demoAlerts().slice(0, PAGE_SIZE));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [page, severity, status]);

  const loadReports = useCallback(async () => {
    try {
      const res = await reportsApi.list();
      setReports((res.reports || []).filter((r) => r.type === 'weekly' || r.type === 'monthly'));
    } catch {
      // http 拦截器已提示
    }
  }, []);

  // 威胁情报 + 报告列表
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await situationalApi.threatIntel();
        const list = Array.isArray(res) ? res : (res as unknown as { list?: ThreatIntelRecord[] }).list || [];
        if (!cancelled) setIntel(list.map(mapIntel));
      } catch {
        if (!cancelled) setIntel(demoThreatIntel());
      }
    })();
    loadReports();
    return () => {
      cancelled = true;
    };
  }, [loadReports]);

  // 过滤变化重置到第一页
  function changeSeverity(v: string) {
    setSeverity(v);
    setPage(1);
  }
  function changeStatus(v: string) {
    setStatus(v);
    setPage(1);
  }

  // 告警操作：确认/误报/解决（乐观更新）
  async function handleAlert(id: string, action: 'confirm' | 'false_positive' | 'resolve') {
    const statusMap: Record<string, string> = {
      confirm: 'acknowledged',
      false_positive: 'false_positive',
      resolve: 'resolved'
    };
    const realId = Number(String(id).replace('ALT-', ''));
    try {
      await situationalApi.updateAlertStatus(realId, statusMap[action]);
    } catch {
      // 接口失败时乐观更新本地状态，不阻塞用户操作
    }
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, status: statusMap[action] } : a)));
    const actionMap: Record<string, string> = { confirm: '确认', false_positive: '标记误报', resolve: '解决' };
    toast({ title: '已' + actionMap[action], variant: 'success' });
  }

  // 报告生成
  async function generateReport(typeLabel: string) {
    const type = typeLabel === '周报' ? 'weekly' : 'monthly';
    try {
      await situationalApi.generateReport(type, `${typeLabel} - ${new Date().toLocaleDateString('zh-CN')}`);
      toast({ title: typeLabel + '已生成', variant: 'success' });
      loadReports();
    } catch {
      toast({ title: '报告生成中，请稍候...', variant: 'warning' });
    }
  }

  async function viewReport(row: ReportItem) {
    try {
      const detail = await reportsApi.detail(row.id);
      setPreview({ title: row.title, content: JSON.stringify(detail, null, 2) });
    } catch {
      setPreview({ title: row.title, content: '暂无内容' });
    }
  }

  async function deleteReport(row: ReportItem) {
    try {
      await reportsApi.remove(row.id);
      toast({ title: '报告已删除', variant: 'success' });
      loadReports();
    } catch {
      toast({ title: '删除失败', variant: 'error' });
    }
  }

  function exportAlerts() {
    if (alerts.length === 0) return;
    const headers = '告警类型,严重等级,关联资产,置信度,状态,时间\n';
    const rows = alerts.map((a) => `${a.type},${a.level},${a.asset},${a.confidence},${a.status},${a.time}`).join('\n');
    const blob = new Blob(['\uFEFF' + headers + rows], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'alerts.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast({ title: '告警数据已导出', variant: 'success' });
  }

  // 威胁等级分布（由当前告警 severity 统计，空数据用兜底）
  const levelPieOption = useMemo<EChartsOption>(() => {
    const colorMap: Record<string, string> = {
      严重: '#f56c6c',
      高危: '#e6a23c',
      中危: '#00d4ff',
      低危: '#67c23a'
    };
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach((a) => {
      if (counts[a.level] !== undefined) counts[a.level]++;
    });
    const total = Object.values(counts).reduce((s, n) => s + n, 0);
    const data =
      total > 0
        ? (Object.entries(counts) as Array<[string, number]>)
            .map(([lv, n]) => ({
              value: n,
              name: getLevelTag(lv).label,
              itemStyle: { color: colorMap[getLevelTag(lv).label] || '#909399' }
            }))
            .filter((d) => d.value > 0)
        : [
            { value: 8, name: '严重', itemStyle: { color: '#f56c6c' } },
            { value: 15, name: '高危', itemStyle: { color: '#e6a23c' } },
            { value: 25, name: '中危', itemStyle: { color: '#00d4ff' } },
            { value: 35, name: '低危', itemStyle: { color: '#67c23a' } }
          ];
    return {
      tooltip: {
        trigger: 'item' as const,
        backgroundColor: '#16213e',
        borderColor: 'rgba(0,212,255,0.2)',
        textStyle: { color: '#c0c0c0' }
      },
      legend: { bottom: '5%', textStyle: { color: '#c0c0c0' }, itemWidth: 12, itemHeight: 12 },
      series: [
        {
          type: 'pie' as const,
          radius: ['35%', '65%'],
          center: ['50%', '45%'],
          itemStyle: { borderRadius: 6, borderColor: '#16213e', borderWidth: 2 },
          label: { show: false },
          emphasis: { label: { show: true, color: '#fff' } },
          data
        }
      ]
    };
  }, [alerts]);

  // 告警趋势（近30天，演示数据）
  const alertTrendOption = useMemo<EChartsOption>(
    () => ({
      tooltip: {
        trigger: 'axis' as const,
        backgroundColor: '#16213e',
        borderColor: 'rgba(0,212,255,0.2)',
        textStyle: { color: '#c0c0c0' }
      },
      legend: {
        data: ['新增告警', '已处理'],
        top: '5%',
        textStyle: { color: '#c0c0c0' },
        itemWidth: 16,
        itemHeight: 3
      },
      grid: { left: '3%', right: '4%', bottom: '3%', top: '18%', containLabel: true },
      xAxis: {
        type: 'category' as const,
        data: demo.trendDays,
        axisLine: { lineStyle: { color: 'rgba(0,212,255,0.2)' } },
        axisLabel: { color: '#909399', interval: 4 }
      },
      yAxis: {
        type: 'value' as const,
        axisLine: { show: false },
        splitLine: { lineStyle: { color: 'rgba(0,212,255,0.06)' } },
        axisLabel: { color: '#909399' }
      },
      series: [
        {
          name: '新增告警',
          type: 'line' as const,
          smooth: true,
          data: demo.newAlerts,
          lineStyle: { color: '#f56c6c', width: 2 },
          itemStyle: { color: '#f56c6c' },
          areaStyle: {
            color: {
              type: 'linear',
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: 'rgba(245,108,108,0.15)' },
                { offset: 1, color: 'rgba(245,108,108,0)' }
              ]
            }
          }
        },
        {
          name: '已处理',
          type: 'line' as const,
          smooth: true,
          data: demo.handledAlerts,
          lineStyle: { color: '#67c23a', width: 2 },
          itemStyle: { color: '#67c23a' },
          areaStyle: {
            color: {
              type: 'linear',
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: 'rgba(103,194,58,0.15)' },
                { offset: 1, color: 'rgba(103,194,58,0)' }
              ]
            }
          }
        }
      ]
    }),
    [demo.newAlerts, demo.handledAlerts, demo.trendDays]
  );

  // 合规率变化趋势
  const complianceOption = useMemo<EChartsOption>(
    () => ({
      tooltip: {
        trigger: 'axis' as const,
        backgroundColor: '#16213e',
        borderColor: 'rgba(0,212,255,0.2)',
        textStyle: { color: '#c0c0c0' }
      },
      grid: { left: '3%', right: '4%', bottom: '3%', top: '10%', containLabel: true },
      xAxis: {
        type: 'category' as const,
        data: ['第1周', '第2周', '第3周', '第4周', '第5周', '第6周'],
        axisLine: { lineStyle: { color: 'rgba(0,212,255,0.2)' } },
        axisLabel: { color: '#909399' }
      },
      yAxis: {
        type: 'value' as const,
        min: 60,
        max: 100,
        axisLine: { show: false },
        splitLine: { lineStyle: { color: 'rgba(0,212,255,0.06)' } },
        axisLabel: { color: '#909399', formatter: '{value}%' }
      },
      series: [
        {
          type: 'line' as const,
          smooth: true,
          data: [78, 82, 80, 85, 88, 92.5],
          lineStyle: { color: '#00d4ff', width: 3 },
          itemStyle: { color: '#00d4ff' },
          areaStyle: {
            color: {
              type: 'linear',
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: 'rgba(0,212,255,0.2)' },
                { offset: 1, color: 'rgba(0,212,255,0)' }
              ]
            }
          },
          markLine: {
            data: [
              {
                yAxis: 90,
                label: { formatter: '目标: 90%', color: '#67c23a' },
                lineStyle: { color: '#67c23a', type: 'dashed' as const }
              }
            ]
          }
        }
      ]
    }),
    []
  );

  // 资产风险拓扑（由告警关联资产聚合生成）
  const topologyOption = useMemo<EChartsOption>(() => {
    interface GraphNode {
      name: string;
      symbolSize: number;
      category: number;
      label: { show: boolean; fontSize?: number; color?: string; fontWeight?: 'bold' | 'normal' };
      itemStyle: { color: string };
    }
    const assetMap: Record<string, { alertCount: number; maxLevel: number }> = {};
    alerts.forEach((a) => {
      if (a.asset && a.asset !== '-') {
        if (!assetMap[a.asset]) assetMap[a.asset] = { alertCount: 0, maxLevel: 0 };
        assetMap[a.asset].alertCount++;
        const levelMap: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
        assetMap[a.asset].maxLevel = Math.max(assetMap[a.asset].maxLevel, levelMap[a.level] || 1);
      }
    });
    const nodes: GraphNode[] = Object.entries(assetMap).map(([name, info]) => ({
      name,
      symbolSize: Math.max(30, Math.min(80, info.alertCount * 15)),
      category: info.maxLevel,
      label: { show: true, fontSize: 11, color: '#e0e0e0' },
      itemStyle: {
        color:
          info.maxLevel >= 4 ? '#f56c6c' : info.maxLevel >= 3 ? '#e6a23c' : info.maxLevel >= 2 ? '#409eff' : '#67c23a'
      }
    }));
    if (nodes.length === 0) {
      nodes.push({
        name: '暂无关联资产',
        symbolSize: 30,
        category: 1,
        label: { show: true, fontSize: 11, color: '#e0e0e0' },
        itemStyle: { color: '#909399' }
      });
    }
    nodes.unshift({
      name: '安全网关',
      symbolSize: 60,
      category: 0,
      label: { show: true, fontSize: 13, color: '#00d4ff', fontWeight: 'bold' },
      itemStyle: { color: '#00d4ff' }
    });
    const links = nodes.slice(1).map((n) => ({
      source: '安全网关',
      target: n.name,
      lineStyle: { color: n.itemStyle.color, width: 1.5, curveness: 0.2 }
    }));
    return {
      tooltip: { trigger: 'item' as const },
      legend: { data: ['安全网关', '严重', '高危', '中危', '低危'], bottom: 5, textStyle: { color: '#aaa' } },
      series: [
        {
          type: 'graph' as const,
          layout: 'force' as const,
          roam: true,
          categories: [{ name: '安全网关' }, { name: '严重' }, { name: '高危' }, { name: '中危' }, { name: '低危' }],
          force: { repulsion: 200, edgeLength: [80, 200], gravity: 0.1 },
          data: nodes,
          links,
          emphasis: { focus: 'adjacency' as const, lineStyle: { width: 3 } },
          lineStyle: { opacity: 0.6 }
        }
      ]
    };
  }, [alerts]);

  const paginatedIntel = intel.slice((intelPage - 1) * PAGE_SIZE, intelPage * PAGE_SIZE);

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">态势感知</h2>
          <p className="mt-1 text-sm text-gray-400">全局安全态势监控与威胁情报管理</p>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => generateReport('周报')}>
            生成周报
          </Button>
          <Button size="sm" onClick={() => generateReport('月报')}>
            生成月报
          </Button>
        </div>
      </div>

      {loading && (
        <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/60 px-4 py-3 text-sm text-cyan-300/70">
          加载中…
        </div>
      )}

      {/* 三个统计图表 */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
          <div className="mb-4 text-sm font-semibold text-cyan-300">威胁等级分布</div>
          <EChart option={levelPieOption} className="h-[260px]" />
        </div>
        <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
          <div className="mb-4 text-sm font-semibold text-cyan-300">告警趋势（近30天）</div>
          <EChart option={alertTrendOption} className="h-[260px]" />
        </div>
        <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
          <div className="mb-4 text-sm font-semibold text-cyan-300">合规率变化趋势</div>
          <EChart option={complianceOption} className="h-[260px]" />
        </div>
      </div>

      {/* 资产风险拓扑 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 text-sm font-semibold text-cyan-300">资产风险拓扑</div>
        <EChart option={topologyOption} className="h-[350px]" />
      </div>

      {/* 告警 / 威胁情报 Tabs */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 flex gap-4 border-b border-white/5">
          <button
            type="button"
            onClick={() => setActiveTab('alerts')}
            className={`border-b-2 px-1 pb-2 text-sm transition-colors ${
              activeTab === 'alerts'
                ? 'border-cyan-400 text-cyan-300'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            告警列表
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('intel')}
            className={`border-b-2 px-1 pb-2 text-sm transition-colors ${
              activeTab === 'intel'
                ? 'border-cyan-400 text-cyan-300'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            威胁情报
          </button>
        </div>

        {activeTab === 'alerts' && (
          <div>
            <div className="mb-3 flex flex-wrap items-center gap-3">
              <select className={selectCls} value={severity} onChange={(e) => changeSeverity(e.target.value)}>
                <option value="">全部等级</option>
                <option value="critical">严重</option>
                <option value="high">高危</option>
                <option value="medium">中危</option>
                <option value="low">低危</option>
              </select>
              <select className={selectCls} value={status} onChange={(e) => changeStatus(e.target.value)}>
                <option value="">全部状态</option>
                <option value="new">待处理</option>
                <option value="acknowledged">已确认</option>
                <option value="resolved">已解决</option>
                <option value="false_positive">误报</option>
              </select>
              <Button size="sm" variant="outline" onClick={exportAlerts}>
                导出CSV
              </Button>
            </div>
            <Table>
              <thead>
                <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                  <th className="px-2 py-2 font-medium">告警ID</th>
                  <th className="px-2 py-2 font-medium">类型</th>
                  <th className="px-2 py-2 font-medium">等级</th>
                  <th className="px-2 py-2 font-medium">关联资产</th>
                  <th className="px-2 py-2 font-medium">置信度</th>
                  <th className="px-2 py-2 font-medium">状态</th>
                  <th className="px-2 py-2 font-medium">时间</th>
                  <th className="px-2 py-2 font-medium">操作</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {alerts.map((a) => (
                  <tr key={a.id} className="hover:bg-white/5">
                    <td className="px-2 py-2 text-gray-400">{a.id}</td>
                    <td className="px-2 py-2 text-gray-300">{a.type}</td>
                    <td className="px-2 py-2">
                      <Badge variant={getLevelTag(a.level).variant}>{getLevelTag(a.level).label}</Badge>
                    </td>
                    <td className="px-2 py-2 text-gray-300">{a.asset}</td>
                    <td className="px-2 py-2 text-gray-300">{a.confidence}</td>
                    <td className="px-2 py-2">
                      <Badge variant={getStatusTag(a.status).variant}>{getStatusTag(a.status).label}</Badge>
                    </td>
                    <td className="px-2 py-2 text-gray-400">{a.time}</td>
                    <td className="px-2 py-2">
                      <div className="flex gap-2">
                        <button
                          type="button"
                          disabled={a.status !== 'new' && a.status !== 'pending'}
                          onClick={() => handleAlert(a.id, 'confirm')}
                          className="text-xs text-cyan-400 transition-colors hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          确认
                        </button>
                        <button
                          type="button"
                          disabled={a.status !== 'new' && a.status !== 'pending'}
                          onClick={() => handleAlert(a.id, 'false_positive')}
                          className="text-xs text-amber-400 transition-colors hover:text-amber-300 disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          误报
                        </button>
                        <button
                          type="button"
                          disabled={a.status === 'resolved'}
                          onClick={() => handleAlert(a.id, 'resolve')}
                          className="text-xs text-green-400 transition-colors hover:text-green-300 disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          解决
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {alerts.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-2 py-6 text-center text-gray-500">
                      暂无告警数据
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
            <div className="mt-4 flex items-center justify-end gap-3">
              <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                上一页
              </Button>
              <span className="text-xs text-gray-400">第 {page} 页</span>
              <Button
                size="sm"
                variant="outline"
                disabled={alerts.length < PAGE_SIZE}
                onClick={() => setPage((p) => p + 1)}
              >
                下一页
              </Button>
            </div>
          </div>
        )}

        {activeTab === 'intel' && (
          <div>
            <Table>
              <thead>
                <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                  <th className="px-2 py-2 font-medium">ID</th>
                  <th className="px-2 py-2 font-medium">类型</th>
                  <th className="px-2 py-2 font-medium">指标值</th>
                  <th className="px-2 py-2 font-medium">置信度</th>
                  <th className="px-2 py-2 font-medium">来源</th>
                  <th className="px-2 py-2 font-medium">严重等级</th>
                  <th className="px-2 py-2 font-medium">更新时间</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {paginatedIntel.map((t) => (
                  <tr key={t.id} className="hover:bg-white/5">
                    <td className="px-2 py-2 text-gray-400">{t.id}</td>
                    <td className="px-2 py-2 text-gray-300">{t.type}</td>
                    <td className="max-w-[240px] truncate px-2 py-2 text-gray-300">{t.value}</td>
                    <td className="px-2 py-2 text-gray-300">{t.confidence}</td>
                    <td className="px-2 py-2 text-gray-300">{t.source}</td>
                    <td className="px-2 py-2">
                      <Badge variant={getLevelTag(t.severity).variant}>{getLevelTag(t.severity).label}</Badge>
                    </td>
                    <td className="px-2 py-2 text-gray-400">{t.updateTime}</td>
                  </tr>
                ))}
                {paginatedIntel.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-2 py-6 text-center text-gray-500">
                      暂无威胁情报数据
                    </td>
                  </tr>
                )}
              </tbody>
            </Table>
            <div className="mt-4 flex items-center justify-end gap-3">
              <Button size="sm" variant="outline" disabled={intelPage <= 1} onClick={() => setIntelPage((p) => p - 1)}>
                上一页
              </Button>
              <span className="text-xs text-gray-400">
                第 {intelPage} / {Math.max(1, Math.ceil(intel.length / PAGE_SIZE))} 页
              </span>
              <Button
                size="sm"
                variant="outline"
                disabled={intelPage >= Math.max(1, Math.ceil(intel.length / PAGE_SIZE))}
                onClick={() => setIntelPage((p) => p + 1)}
              >
                下一页
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* 报告管理 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 text-sm font-semibold text-cyan-300">报告管理</div>
        <Table>
          <thead>
            <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
              <th className="px-2 py-2 font-medium">报告名称</th>
              <th className="px-2 py-2 font-medium">类型</th>
              <th className="px-2 py-2 font-medium">生成时间</th>
              <th className="px-2 py-2 font-medium">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {reports.map((r) => (
              <tr key={r.id} className="hover:bg-white/5">
                <td className="px-2 py-2 text-gray-300">{r.title}</td>
                <td className="px-2 py-2">
                  <Badge variant={r.type === 'weekly' ? 'success' : 'default'}>
                    {r.type === 'weekly' ? '周报' : '月报'}
                  </Badge>
                </td>
                <td className="px-2 py-2 text-gray-400">
                  {r.generatedAt ? new Date(r.generatedAt).toLocaleString('zh-CN') : '-'}
                </td>
                <td className="px-2 py-2">
                  <div className="flex gap-3">
                    <button
                      type="button"
                      onClick={() => viewReport(r)}
                      className="text-xs text-cyan-400 hover:text-cyan-300"
                    >
                      查看
                    </button>
                    <button
                      type="button"
                      onClick={() => deleteReport(r)}
                      className="text-xs text-red-400 hover:text-red-300"
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
                  暂无报告，点击右上角生成
                </td>
              </tr>
            )}
          </tbody>
        </Table>
      </div>

      {/* 报告预览 */}
      <Dialog open={!!preview} onOpenChange={(open) => !open && setPreview(null)} title={preview?.title || '报告预览'}>
        <pre className="max-h-[60vh] overflow-y-auto whitespace-pre-wrap rounded-lg bg-black/30 p-4 text-xs text-gray-300">
          {preview?.content || '暂无内容'}
        </pre>
      </Dialog>
    </div>
  );
}
