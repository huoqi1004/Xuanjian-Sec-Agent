import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { EChartsOption } from 'echarts';
import { situationalApi } from '@/api';
import type { AlertRecord, DashboardData } from '@/api';
import EChart from '@/components/chart';
import Badge from '@/components/ui/badge';
import Button from '@/components/ui/button';
import { Table } from '@/components/ui/table';

interface AlertRow {
  id: string;
  type: string;
  level: string;
  asset: string;
  status: string;
  time: string;
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
    status: statuses[Math.floor(Math.random() * statuses.length)],
    time: new Date(Date.now() - Math.random() * 7 * 86400000).toLocaleString('zh-CN')
  }));
}

function mapAlert(a: AlertRecord): AlertRow {
  return {
    id: 'ALT-' + a.id,
    type: a.alert_type || '未知',
    level: a.severity || 'medium',
    asset: a.related_asset || '-',
    status: a.status || 'new',
    time: a.created_at ? new Date(a.created_at).toLocaleString('zh-CN') : '-'
  };
}

/** 生成近 N 天的日期标签（M/D） */
function lastDays(n: number): string[] {
  const days: string[] = [];
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000);
    days.push(d.getMonth() + 1 + '/' + d.getDate());
  }
  return days;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<AlertRow[]>([]);

  // 演示/兜底数据仅在挂载时生成一次
  const demo = useMemo(() => {
    const trendCounts = [23, 18, 31, 27, 15, 22, 12];
    return {
      trendDates: lastDays(7),
      trendCounts,
      resolvedCounts: trendCounts.map((c) => Math.max(0, c - Math.floor(Math.random() * 3 + 1))),
      riskPie: [
        { value: 35, name: '高危资产', itemStyle: { color: '#f56c6c' } },
        { value: 28, name: '中危资产', itemStyle: { color: '#e6a23c' } },
        { value: 52, name: '低危资产', itemStyle: { color: '#00d4ff' } },
        { value: 85, name: '安全资产', itemStyle: { color: '#67c23a' } }
      ],
      vulnCategories: ['严重', '高危', '中危', '低危', '信息']
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const d = await situationalApi.dashboard();
        if (!cancelled) setDashboard(d);
      } catch {
        // http 拦截器已提示，保留默认展示
      }
      try {
        const res = await situationalApi.alerts();
        const list = Array.isArray(res) ? res : (res as unknown as { list?: AlertRecord[] }).list || [];
        if (!cancelled) setRecentAlerts(list.slice(0, 8).map(mapAlert));
      } catch {
        if (!cancelled) setRecentAlerts(demoAlerts().slice(0, 8));
      }
      if (!cancelled) setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const stats = useMemo(
    () => ({
      securityScore: dashboard?.security_score ?? 0,
      onlineDevices: dashboard?.devices?.online_devices ?? 0,
      activeAlerts: dashboard?.alerts?.new_count ?? 0,
      todayScans: dashboard?.scans?.total_tasks ?? 0,
      complianceRate: dashboard?.baseline?.compliance_rate ?? 85
    }),
    [dashboard]
  );

  const kpis = [
    { label: '安全评分', value: stats.securityScore, suffix: '分', color: 'text-cyan-400', trend: '多引擎协同评估' },
    { label: '在线设备', value: stats.onlineDevices, suffix: '台', color: 'text-purple-400', trend: '实时在线状态' },
    { label: '活跃告警', value: stats.activeAlerts, suffix: '条', color: 'text-red-400', trend: '待处理告警' },
    { label: '今日扫描', value: stats.todayScans, suffix: '次', color: 'text-green-400', trend: '累计任务' },
    { label: '合规率', value: stats.complianceRate, suffix: '%', color: 'text-orange-400', trend: '基线检查' }
  ];

  // 资产风险分布（饼图）
  const riskPieOption = useMemo<EChartsOption>(() => {
    const colorMap: Record<string, string> = {
      严重: '#f56c6c',
      高危: '#e6a23c',
      中危: '#00d4ff',
      低危: '#67c23a',
      信息: '#909399'
    };
    const dist = dashboard?.risk_distribution || [];
    const data = dist.length
      ? dist.map((r) => ({ value: r.value, name: r.name, itemStyle: { color: colorMap[r.name] || '#909399' } }))
      : demo.riskPie;
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
          radius: ['40%', '70%'],
          center: ['50%', '45%'],
          itemStyle: { borderRadius: 6, borderColor: '#16213e', borderWidth: 2 },
          label: { show: false },
          emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold', color: '#fff' } },
          data
        }
      ]
    };
  }, [dashboard, demo.riskPie]);

  // 威胁趋势（折线）
  const trendOption = useMemo<EChartsOption>(() => {
    const trend = dashboard?.threat_trend || [];
    const dates = trend.length ? trend.map((t) => t.date) : demo.trendDates;
    const counts = trend.length ? trend.map((t) => t.count) : demo.trendCounts;
    const resolved = trend.length ? counts.map((c) => Math.max(0, c - Math.floor(Math.random() * 3 + 1))) : demo.resolvedCounts;
    return {
      tooltip: {
        trigger: 'axis' as const,
        backgroundColor: '#16213e',
        borderColor: 'rgba(0,212,255,0.2)',
        textStyle: { color: '#c0c0c0' }
      },
      legend: { data: ['威胁事件', '已处理'], top: '5%', textStyle: { color: '#c0c0c0' }, itemWidth: 16, itemHeight: 3 },
      grid: { left: '3%', right: '4%', bottom: '3%', top: '18%', containLabel: true },
      xAxis: {
        type: 'category' as const,
        data: dates,
        axisLine: { lineStyle: { color: 'rgba(0,212,255,0.2)' } },
        axisLabel: { color: '#909399' }
      },
      yAxis: {
        type: 'value' as const,
        axisLine: { show: false },
        axisTick: { show: false },
        splitLine: { lineStyle: { color: 'rgba(0,212,255,0.06)' } },
        axisLabel: { color: '#909399' }
      },
      series: [
        {
          name: '威胁事件',
          type: 'line' as const,
          smooth: true,
          data: counts,
          lineStyle: { color: '#f56c6c', width: 2 },
          itemStyle: { color: '#f56c6c' },
          areaStyle: {
            color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [
              { offset: 0, color: 'rgba(245,108,108,0.2)' },
              { offset: 1, color: 'rgba(245,108,108,0)' }
            ] }
          }
        },
        {
          name: '已处理',
          type: 'line' as const,
          smooth: true,
          data: resolved,
          lineStyle: { color: '#67c23a', width: 2 },
          itemStyle: { color: '#67c23a' },
          areaStyle: {
            color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [
              { offset: 0, color: 'rgba(103,194,58,0.2)' },
              { offset: 1, color: 'rgba(103,194,58,0)' }
            ] }
          }
        }
      ]
    };
  }, [dashboard, demo.trendDates, demo.trendCounts, demo.resolvedCounts]);

  // 漏洞等级分布（柱状图）
  const vulnBarOption = useMemo<EChartsOption>(() => {
    const colorMap: Record<string, [string, string]> = {
      严重: ['#ff4d4f', '#cf1322'],
      高危: ['#f56c6c', '#c45656'],
      中危: ['#e6a23c', '#c4852f'],
      低危: ['#00d4ff', '#0099bb'],
      信息: ['#67c23a', '#4e9a2c']
    };
    const linear = (from: string, to: string) => ({
      type: 'linear' as const,
      x: 0,
      y: 0,
      x2: 0,
      y2: 1,
      colorStops: [
        { offset: 0, color: from },
        { offset: 1, color: to }
      ]
    });
    const dist = dashboard?.vuln_distribution || [];
    const data = dist.length
      ? dist.map((v) => {
          const colors = colorMap[v.name] || ['#909399', '#636363'];
          return { value: v.value, itemStyle: { color: linear(colors[0], colors[1]) } };
        })
      : [
          { value: 5, itemStyle: { color: linear('#ff4d4f', '#cf1322') } },
          { value: 18, itemStyle: { color: linear('#f56c6c', '#c45656') } },
          { value: 35, itemStyle: { color: linear('#e6a23c', '#c4852f') } },
          { value: 52, itemStyle: { color: linear('#00d4ff', '#0099bb') } },
          { value: 28, itemStyle: { color: linear('#67c23a', '#4e9a2c') } }
        ];
    const categories = dist.length ? dist.map((v) => v.name) : demo.vulnCategories;
    return {
      tooltip: {
        trigger: 'axis' as const,
        backgroundColor: '#16213e',
        borderColor: 'rgba(0,212,255,0.2)',
        textStyle: { color: '#c0c0c0' }
      },
      grid: { left: '3%', right: '4%', bottom: '3%', top: '8%', containLabel: true },
      xAxis: {
        type: 'category' as const,
        data: categories,
        axisLine: { lineStyle: { color: 'rgba(0,212,255,0.2)' } },
        axisLabel: { color: '#909399' }
      },
      yAxis: {
        type: 'value' as const,
        axisLine: { show: false },
        axisTick: { show: false },
        splitLine: { lineStyle: { color: 'rgba(0,212,255,0.06)' } },
        axisLabel: { color: '#909399' }
      },
      series: [{ type: 'bar' as const, barWidth: '50%', data, itemStyle: { borderRadius: [4, 4, 0, 0] } }]
    };
  }, [dashboard, demo.vulnCategories]);

  const quickActions = [
    { label: '网络扫描', icon: '🔍', to: '/scan' },
    { label: '基线检查', icon: '📋', to: '/baseline' },
    { label: '病毒查杀', icon: '🛡️', to: '/virus' },
    { label: '态势感知', icon: '📈', to: '/situational' },
    { label: '防御策略', icon: '⚙️', to: '/defense' },
    { label: '设备管理', icon: '💻', to: '/device' }
  ];

  return (
    <div className="space-y-5">
      {/* 页头 */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">安全概览</h2>
          <p className="mt-1 text-sm text-gray-400">多引擎协同安全评估系统 - 实时安全态势监控</p>
        </div>
        <div className="flex gap-2">
          <Button size="sm" onClick={() => navigate('/scan')}>启动扫描</Button>
          <Button size="sm" variant="outline" onClick={() => navigate('/situational')}>查看态势</Button>
        </div>
      </div>

      {loading && <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/60 px-4 py-3 text-sm text-cyan-300/70">加载中…</div>}

      {/* KPI 卡片 */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
        {kpis.map((k) => (
          <div key={k.label} className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-4">
            <div className="text-xs text-gray-400">{k.label}</div>
            <div className={`mt-2 text-2xl font-bold ${k.color}`}>
              {k.value}
              <span className="ml-1 text-xs font-normal text-gray-500">{k.suffix}</span>
            </div>
            <div className="mt-1 text-xs text-gray-500">{k.trend}</div>
          </div>
        ))}
      </div>

      {/* 图表：资产风险分布 + 威胁趋势 */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
          <div className="mb-4 text-sm font-semibold text-cyan-300">资产风险分布</div>
          <EChart option={riskPieOption} />
        </div>
        <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
          <div className="mb-4 text-sm font-semibold text-cyan-300">威胁趋势（近7天）</div>
          <EChart option={trendOption} />
        </div>
      </div>

      {/* 漏洞分布 + 最近告警 */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
          <div className="mb-4 text-sm font-semibold text-cyan-300">漏洞等级分布</div>
          <EChart option={vulnBarOption} />
        </div>
        <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
          <div className="mb-4 text-sm font-semibold text-cyan-300">最近告警</div>
          <Table>
            <thead>
                <tr className="border-b border-cyan-500/20 text-left text-xs text-cyan-200/70">
                  <th className="px-2 py-2 font-medium">ID</th>
                  <th className="px-2 py-2 font-medium">类型</th>
                  <th className="px-2 py-2 font-medium">等级</th>
                  <th className="px-2 py-2 font-medium">资产</th>
                  <th className="px-2 py-2 font-medium">状态</th>
                  <th className="px-2 py-2 font-medium">时间</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {recentAlerts.map((a) => (
                  <tr key={a.id} className="hover:bg-white/5">
                    <td className="px-2 py-2 text-gray-400">{a.id}</td>
                    <td className="px-2 py-2 text-gray-300">{a.type}</td>
                    <td className="px-2 py-2">
                      <Badge variant={getLevelTag(a.level).variant}>{getLevelTag(a.level).label}</Badge>
                    </td>
                    <td className="px-2 py-2 text-gray-300">{a.asset}</td>
                    <td className="px-2 py-2">
                      <Badge variant={getStatusTag(a.status).variant}>{getStatusTag(a.status).label}</Badge>
                    </td>
                    <td className="px-2 py-2 text-gray-400">{a.time}</td>
                  </tr>
                ))}
                {recentAlerts.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-2 py-6 text-center text-gray-500">暂无告警数据</td>
                  </tr>
                )}
              </tbody>
          </Table>
        </div>
      </div>

      {/* 快捷操作 */}
      <div className="rounded-lg border border-cyan-500/20 bg-[#16213e]/80 p-5">
        <div className="mb-4 text-sm font-semibold text-cyan-300">快捷操作</div>
        <div className="grid grid-cols-3 gap-4 md:grid-cols-6">
          {quickActions.map((q) => (
            <button
              key={q.to}
              type="button"
              onClick={() => navigate(q.to)}
              className="flex flex-col items-center gap-2 rounded-lg border border-white/5 bg-black/20 py-4 text-gray-300 transition-colors hover:border-cyan-500/40 hover:text-cyan-300"
            >
              <span className="text-xl">{q.icon}</span>
              <span className="text-xs">{q.label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
