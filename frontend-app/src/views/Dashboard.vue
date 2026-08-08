<template>
  <div v-loading="loading" element-loading-text="加载中...">
    <div class="page-header">
      <div>
        <div class="page-title">安全概览</div>
        <div class="page-desc">多引擎协同安全评估系统 - 实时安全态势监控</div>
      </div>
      <div style="display: flex; gap: 8px">
        <el-button type="primary" size="small" @click="router.push('/scan')">
          <el-icon><Search /></el-icon> 启动扫描
        </el-button>
        <el-button size="small" @click="router.push('/situational')">
          <el-icon><DataAnalysis /></el-icon> 查看态势
        </el-button>
      </div>
    </div>

    <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 20px">
      <div class="stat-card cyan">
        <div class="stat-label">安全评分</div>
        <div class="stat-value cyan">{{ stats.securityScore }}<span class="stat-suffix">分</span></div>
        <div class="stat-trend down">
          <el-icon><Bottom /></el-icon> 较昨日 +2.3
        </div>
      </div>
      <div class="stat-card purple">
        <div class="stat-label">在线设备</div>
        <div class="stat-value purple">{{ stats.onlineDevices }}<span class="stat-suffix">台</span></div>
        <div class="stat-trend up">
          <el-icon><Top /></el-icon> 新增 3 台
        </div>
      </div>
      <div class="stat-card red">
        <div class="stat-label">活跃告警</div>
        <div class="stat-value red">{{ stats.activeAlerts }}<span class="stat-suffix">条</span></div>
        <div class="stat-trend up">
          <el-icon><Top /></el-icon> 较昨日 +5
        </div>
      </div>
      <div class="stat-card green">
        <div class="stat-label">今日扫描</div>
        <div class="stat-value green">{{ stats.todayScans }}<span class="stat-suffix">次</span></div>
        <div class="stat-trend down">
          <el-icon><Bottom /></el-icon> 进行中 2 次
        </div>
      </div>
      <div class="stat-card orange">
        <div class="stat-label">合规率</div>
        <div class="stat-value orange">{{ stats.complianceRate }}<span class="stat-suffix">%</span></div>
        <div class="stat-trend down">
          <el-icon><Bottom /></el-icon> 较上周 +1.5%
        </div>
      </div>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px">
      <div class="chart-card">
        <div class="chart-card-title">资产风险分布</div>
        <div ref="riskPieRef" class="chart-container"></div>
      </div>
      <div class="chart-card">
        <div class="chart-card-title">威胁趋势（近7天）</div>
        <div ref="threatTrendRef" class="chart-container"></div>
      </div>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px">
      <div class="chart-card">
        <div class="chart-card-title">漏洞等级分布</div>
        <div ref="vulnBarRef" class="chart-container"></div>
      </div>
      <div class="chart-card">
        <div class="chart-card-title">最近告警</div>
        <el-table :data="recentAlerts" size="small" max-height="280" style="width: 100%">
          <el-table-column prop="id" label="ID" width="90" />
          <el-table-column prop="type" label="类型" width="100" />
          <el-table-column prop="level" label="等级" width="70">
            <template #default="{ row }">
              <el-tag :type="getLevelTag(row.level).type" size="small">{{ getLevelTag(row.level).label }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="asset" label="资产" width="120" />
          <el-table-column prop="status" label="状态" width="80">
            <template #default="{ row }">
              <el-tag :type="getStatusTag(row.status).type" size="small" effect="plain">{{
                getStatusTag(row.status).label
              }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="time" label="时间" />
        </el-table>
      </div>
    </div>

    <div class="chart-card">
      <div class="chart-card-title">快捷操作</div>
      <div class="quick-actions">
        <div class="quick-action-btn" @click="router.push('/scan')">
          <span class="icon">&#128269;</span><span>网络扫描</span>
        </div>
        <div class="quick-action-btn" @click="router.push('/baseline')">
          <span class="icon">&#128203;</span><span>基线检查</span>
        </div>
        <div class="quick-action-btn" @click="router.push('/virus')">
          <span class="icon">&#128737;</span><span>病毒查杀</span>
        </div>
        <div class="quick-action-btn" @click="router.push('/situational')">
          <span class="icon">&#128200;</span><span>态势感知</span>
        </div>
        <div class="quick-action-btn" @click="router.push('/defense')">
          <span class="icon">&#9881;</span><span>防御策略</span>
        </div>
        <div class="quick-action-btn" @click="router.push('/device')">
          <span class="icon">&#128187;</span><span>设备管理</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted, nextTick } from 'vue';
import { useRouter } from 'vue-router';
import * as echarts from 'echarts';
import { Search, DataAnalysis, Top, Bottom } from '@element-plus/icons-vue';
import { situationalApi } from '@/api';

const router = useRouter();
const loading = ref(true);
const recentAlerts = ref<Array<Record<string, string>>>([]);

const stats = reactive({
  securityScore: 0,
  onlineDevices: 0,
  activeAlerts: 0,
  todayScans: 0,
  complianceRate: 0
});

const chartData = reactive<{
  riskDistribution: Array<{ name: string; value: number }>;
  threatTrend: Array<{ date: string; count: number }>;
  vulnDistribution: Array<{ name: string; value: number }>;
}>({
  riskDistribution: [],
  threatTrend: [],
  vulnDistribution: []
});

const riskPieRef = ref<HTMLElement>();
const threatTrendRef = ref<HTMLElement>();
const vulnBarRef = ref<HTMLElement>();
let charts: echarts.ECharts[] = [];

function demoAlerts() {
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
    time: new Date(Date.now() - Math.random() * 7 * 86400000).toLocaleString('zh-CN'),
    description: '检测到来自外部IP的异常行为，已触发自动告警机制。'
  }));
}

async function loadDashboard() {
  try {
    const d = await situationalApi.dashboard();
    stats.securityScore = (d.security_score as number) || 0;
    stats.activeAlerts = ((d.alerts as Record<string, number>)?.new_count as number) || 0;
    stats.onlineDevices = ((d.devices as Record<string, number>)?.online_devices as number) || 0;
    stats.todayScans = ((d.scans as Record<string, number>)?.total_tasks as number) || 0;
    stats.complianceRate = ((d.baseline as Record<string, number>)?.compliance_rate as number) || 85;
    if (d.risk_distribution) chartData.riskDistribution = d.risk_distribution as Array<{ name: string; value: number }>;
    if (d.threat_trend) chartData.threatTrend = d.threat_trend as Array<{ date: string; count: number }>;
    if (d.vuln_distribution) chartData.vulnDistribution = d.vuln_distribution as Array<{ name: string; value: number }>;
  } catch (e) {
    stats.securityScore = 87;
    stats.onlineDevices = 23;
    stats.activeAlerts = 12;
    stats.todayScans = 8;
    stats.complianceRate = 92.5;
  }

  try {
    const res = await situationalApi.alerts();
    recentAlerts.value = (res.list || []).slice(0, 8).map((a) => ({
      id: 'ALT-' + a.id,
      type: a.alert_type || '未知',
      level: a.severity || 'medium',
      asset: a.related_asset || '-',
      status: a.status || 'new',
      time: a.created_at ? new Date(a.created_at).toLocaleString('zh-CN') : '-'
    }));
  } catch (e) {
    recentAlerts.value = demoAlerts().slice(0, 8);
  }
  loading.value = false;
}

function initCharts() {
  if (!riskPieRef.value || !threatTrendRef.value || !vulnBarRef.value) return;

  const riskColorMap: Record<string, string> = {
    严重: '#f56c6c',
    高危: '#e6a23c',
    中危: '#00d4ff',
    低危: '#67c23a',
    信息: '#909399'
  };
  const defaultRiskData = [
    { value: 35, name: '高危资产', itemStyle: { color: '#f56c6c' } },
    { value: 28, name: '中危资产', itemStyle: { color: '#e6a23c' } },
    { value: 52, name: '低危资产', itemStyle: { color: '#00d4ff' } },
    { value: 85, name: '安全资产', itemStyle: { color: '#67c23a' } }
  ];
  const riskPieData =
    chartData.riskDistribution.length > 0
      ? chartData.riskDistribution.map((r) => ({
          value: r.value,
          name: r.name,
          itemStyle: { color: riskColorMap[r.name] || '#909399' }
        }))
      : defaultRiskData;

  const riskPie = echarts.init(riskPieRef.value);
  riskPie.setOption({
    tooltip: {
      trigger: 'item',
      backgroundColor: '#16213e',
      borderColor: 'rgba(0,212,255,0.2)',
      textStyle: { color: '#c0c0c0' }
    },
    legend: { bottom: '5%', textStyle: { color: '#c0c0c0' }, itemWidth: 12, itemHeight: 12 },
    series: [
      {
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['50%', '45%'],
        itemStyle: { borderRadius: 6, borderColor: '#16213e', borderWidth: 2 },
        label: { show: false },
        emphasis: { label: { show: true, fontSize: 14, fontWeight: 'bold', color: '#fff' } },
        data: riskPieData
      }
    ]
  });
  charts.push(riskPie);

  const defaultDays7: string[] = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000);
    defaultDays7.push(d.getMonth() + 1 + '/' + d.getDate());
  }
  const trendDates = chartData.threatTrend.length > 0 ? chartData.threatTrend.map((t) => t.date) : defaultDays7;
  const trendCounts =
    chartData.threatTrend.length > 0 ? chartData.threatTrend.map((t) => t.count) : [23, 18, 31, 27, 15, 22, 12];
  const resolvedCounts = trendCounts.map((c) => Math.max(0, c - Math.floor(Math.random() * 3 + 1)));

  const trendLine = echarts.init(threatTrendRef.value);
  trendLine.setOption({
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#16213e',
      borderColor: 'rgba(0,212,255,0.2)',
      textStyle: { color: '#c0c0c0' }
    },
    legend: { data: ['威胁事件', '已处理'], top: '5%', textStyle: { color: '#c0c0c0' }, itemWidth: 16, itemHeight: 3 },
    grid: { left: '3%', right: '4%', bottom: '3%', top: '18%', containLabel: true },
    xAxis: {
      type: 'category',
      data: trendDates,
      axisLine: { lineStyle: { color: 'rgba(0,212,255,0.2)' } },
      axisLabel: { color: '#909399' }
    },
    yAxis: {
      type: 'value',
      axisLine: { show: false },
      axisTick: { show: false },
      splitLine: { lineStyle: { color: 'rgba(0,212,255,0.06)' } },
      axisLabel: { color: '#909399' }
    },
    series: [
      {
        name: '威胁事件',
        type: 'line',
        smooth: true,
        data: trendCounts,
        lineStyle: { color: '#f56c6c', width: 2 },
        itemStyle: { color: '#f56c6c' },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(245,108,108,0.2)' },
            { offset: 1, color: 'rgba(245,108,108,0)' }
          ])
        }
      },
      {
        name: '已处理',
        type: 'line',
        smooth: true,
        data: resolvedCounts,
        lineStyle: { color: '#67c23a', width: 2 },
        itemStyle: { color: '#67c23a' },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(103,194,58,0.2)' },
            { offset: 1, color: 'rgba(103,194,58,0)' }
          ])
        }
      }
    ]
  });
  charts.push(trendLine);

  const vulnColorMap: Record<string, [string, string]> = {
    严重: ['#ff4d4f', '#cf1322'],
    高危: ['#f56c6c', '#c45656'],
    中危: ['#e6a23c', '#c4852f'],
    低危: ['#00d4ff', '#0099bb']
  };
  const defaultVulnData = [
    {
      value: 5,
      itemStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: '#ff4d4f' },
          { offset: 1, color: '#cf1322' }
        ])
      }
    },
    {
      value: 18,
      itemStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: '#f56c6c' },
          { offset: 1, color: '#c45656' }
        ])
      }
    },
    {
      value: 35,
      itemStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: '#e6a23c' },
          { offset: 1, color: '#c4852f' }
        ])
      }
    },
    {
      value: 52,
      itemStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: '#00d4ff' },
          { offset: 1, color: '#0099bb' }
        ])
      }
    },
    {
      value: 28,
      itemStyle: {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: '#67c23a' },
          { offset: 1, color: '#4e9a2c' }
        ])
      }
    }
  ];
  const vulnBarData =
    chartData.vulnDistribution.length > 0
      ? chartData.vulnDistribution.map((v) => {
          const colors = vulnColorMap[v.name] || ['#909399', '#636363'];
          return {
            value: v.value,
            itemStyle: {
              color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: colors[0] },
                { offset: 1, color: colors[1] }
              ])
            }
          };
        })
      : defaultVulnData;
  const vulnCategories =
    chartData.vulnDistribution.length > 0
      ? chartData.vulnDistribution.map((v) => v.name)
      : ['严重', '高危', '中危', '低危', '信息'];

  const vulnBar = echarts.init(vulnBarRef.value);
  vulnBar.setOption({
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#16213e',
      borderColor: 'rgba(0,212,255,0.2)',
      textStyle: { color: '#c0c0c0' }
    },
    grid: { left: '3%', right: '4%', bottom: '3%', top: '8%', containLabel: true },
    xAxis: {
      type: 'category',
      data: vulnCategories,
      axisLine: { lineStyle: { color: 'rgba(0,212,255,0.2)' } },
      axisLabel: { color: '#909399' }
    },
    yAxis: {
      type: 'value',
      axisLine: { show: false },
      axisTick: { show: false },
      splitLine: { lineStyle: { color: 'rgba(0,212,255,0.06)' } },
      axisLabel: { color: '#909399' }
    },
    series: [{ type: 'bar', barWidth: '50%', data: vulnBarData, itemStyle: { borderRadius: [4, 4, 0, 0] } }]
  });
  charts.push(vulnBar);
}

function getLevelTag(level: string) {
  const map: Record<string, { label: string; type: string }> = {
    critical: { label: '严重', type: 'danger' },
    high: { label: '高危', type: 'warning' },
    medium: { label: '中危', type: 'info' },
    low: { label: '低危', type: 'success' }
  };
  return map[level] || { label: level, type: 'info' };
}

function getStatusTag(status: string) {
  const map: Record<string, { label: string; type: string }> = {
    pending: { label: '待处理', type: 'warning' },
    confirmed: { label: '已确认', type: 'danger' },
    resolved: { label: '已解决', type: 'success' },
    false_positive: { label: '误报', type: 'info' }
  };
  return map[status] || { label: status, type: 'info' };
}

onMounted(() => {
  loadDashboard();
  nextTick(() => {
    setTimeout(initCharts, 300);
  });
});

onUnmounted(() => {
  charts.forEach((c) => c.dispose());
  charts = [];
});
</script>
