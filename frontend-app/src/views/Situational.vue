<template>
  <div v-loading="loading">
    <div class="page-header">
      <div>
        <div class="page-title">态势感知</div>
        <div class="page-desc">全局安全态势监控与威胁情报管理</div>
      </div>
      <div style="display: flex; gap: 8px">
        <el-button size="small" @click="generateReport('周报')"
          ><el-icon><Document /></el-icon> 生成周报</el-button
        >
        <el-button type="primary" size="small" @click="generateReport('月报')"
          ><el-icon><Document /></el-icon> 生成月报</el-button
        >
      </div>
    </div>
    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin-bottom: 20px">
      <div class="chart-card">
        <div class="chart-card-title">威胁等级分布</div>
        <div id="sa-threat-pie" style="width: 100%; height: 260px"></div>
      </div>
      <div class="chart-card">
        <div class="chart-card-title">告警趋势（近30天）</div>
        <div id="sa-alert-trend" style="width: 100%; height: 260px"></div>
      </div>
      <div class="chart-card">
        <div class="chart-card-title">合规率变化趋势</div>
        <div id="sa-compliance-trend" style="width: 100%; height: 260px"></div>
      </div>
    </div>
    <div
      id="topology-chart"
      style="
        width: 100%;
        height: 350px;
        background: rgba(26, 26, 46, 0.6);
        border-radius: 8px;
        border: 1px solid rgba(0, 212, 255, 0.2);
        margin-bottom: 20px;
      "
    ></div>
    <div class="chart-card" style="margin-bottom: 20px">
      <div class="chart-card-title" style="margin-bottom: 12px">报告管理</div>
      <el-table :data="reports" size="small" style="width: 100%">
        <el-table-column prop="title" label="报告名称" min-width="200" />
        <el-table-column prop="type" label="类型" width="80"
          ><template #default="{ row }"
            ><el-tag :type="row.type === 'weekly' ? 'success' : 'primary'" size="small">{{
              row.type === 'weekly' ? '周报' : '月报'
            }}</el-tag></template
          ></el-table-column
        >
        <el-table-column prop="created_at" label="生成时间" width="180" />
        <el-table-column label="操作" width="250" fixed="right"
          ><template #default="{ row }"
            ><el-button type="primary" link size="small" @click="viewReport(row)">查看</el-button
            ><el-button type="success" link size="small" @click="downloadMarkdownReport(row)">下载MD</el-button
            ><el-button type="warning" link size="small" :loading="generatingPDF" @click="generateAndDownloadDOCX(row)"
              >下载DOCX</el-button
            ><el-button type="danger" link size="small" @click="deleteReport(row)">删除</el-button></template
          ></el-table-column
        >
      </el-table>
    </div>
    <div class="chart-card">
      <el-tabs v-model="activeTab">
        <el-tab-pane label="告警列表" name="alerts">
          <div style="margin-bottom: 12px">
            <el-button type="success" size="small" @click="exportAlerts">导出CSV</el-button>
          </div>
          <el-table :data="paginatedAlerts" size="small" style="width: 100%">
            <el-table-column prop="id" label="告警ID" width="100" /><el-table-column
              prop="type"
              label="类型"
              width="100"
            />
            <el-table-column prop="level" label="等级" width="80"
              ><template #default="{ row }"
                ><el-tag :type="getLevelTag(row.level).type" size="small">{{
                  getLevelTag(row.level).label
                }}</el-tag></template
              ></el-table-column
            >
            <el-table-column prop="asset" label="关联资产" width="130" /><el-table-column
              prop="confidence"
              label="置信度"
              width="80"
            />
            <el-table-column prop="status" label="状态" width="80"
              ><template #default="{ row }"
                ><el-tag :type="getStatusTag(row.status).type" size="small" effect="plain">{{
                  getStatusTag(row.status).label
                }}</el-tag></template
              ></el-table-column
            >
            <el-table-column prop="time" label="时间" width="160" />
            <el-table-column label="操作" width="200" fixed="right"
              ><template #default="{ row }"
                ><el-button
                  type="primary"
                  link
                  size="small"
                  :disabled="row.status !== 'pending'"
                  @click="handleAlert(row.id, 'confirm')"
                  >确认</el-button
                ><el-button
                  type="warning"
                  link
                  size="small"
                  :disabled="row.status !== 'pending'"
                  @click="handleAlert(row.id, 'false_positive')"
                  >误报</el-button
                ><el-button
                  type="success"
                  link
                  size="small"
                  :disabled="row.status === 'resolved'"
                  @click="handleAlert(row.id, 'resolve')"
                  >解决</el-button
                ></template
              ></el-table-column
            >
          </el-table>
          <div style="margin-top: 16px; display: flex; justify-content: flex-end">
            <el-pagination
              v-model:current-page="alertPagination.page"
              small
              layout="total, prev, pager, next"
              :total="alerts.length"
              :page-size="alertPagination.pageSize"
            />
          </div>
        </el-tab-pane>
        <el-tab-pane label="威胁情报" name="intel">
          <el-table :data="paginatedIntel" size="small" style="width: 100%">
            <el-table-column prop="id" label="ID" width="100" /><el-table-column
              prop="type"
              label="类型"
              width="100"
            /><el-table-column prop="value" label="指标值" min-width="200" /><el-table-column
              prop="confidence"
              label="置信度"
              width="80"
            /><el-table-column prop="source" label="来源" width="120" />
            <el-table-column prop="severity" label="严重等级" width="90"
              ><template #default="{ row }"
                ><el-tag :type="getLevelTag(row.severity).type" size="small">{{
                  getLevelTag(row.severity).label
                }}</el-tag></template
              ></el-table-column
            >
            <el-table-column prop="updateTime" label="更新时间" />
          </el-table>
          <div style="margin-top: 16px; display: flex; justify-content: flex-end">
            <el-pagination
              v-model:current-page="intelPagination.page"
              small
              layout="total, prev, pager, next"
              :total="threatIntel.length"
              :page-size="intelPagination.pageSize"
            />
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>
  <el-drawer v-model="showReport" title="报告预览" size="50%">
    <div v-if="currentReport">
      <h3>{{ currentReport.title }}</h3>
      <pre
        style="
          white-space: pre-wrap;
          background: rgba(0, 0, 0, 0.3);
          padding: 16px;
          border-radius: 8px;
          margin-top: 12px;
          max-height: 60vh;
          overflow-y: auto;
        "
        >{{ currentReport.content || '暂无内容' }}</pre>
    </div>
  </el-drawer>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted, nextTick } from 'vue';
import * as echarts from 'echarts';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Document } from '@element-plus/icons-vue';
import { legacyApi } from '@/api';

const loading = ref(true);
const alerts = ref<Array<Record<string, any>>>([]);
const threatIntel = ref<Array<Record<string, any>>>([]);
const alertPagination = reactive({ page: 1, pageSize: 10 });
const intelPagination = reactive({ page: 1, pageSize: 10 });
const activeTab = ref('alerts');
const reports = ref<Array<Record<string, any>>>([]);
const currentReport = ref<Record<string, any> | null>(null);
const showReport = ref(false);
const generatingPDF = ref(false);

const paginatedAlerts = computed(() => {
  const s = (alertPagination.page - 1) * alertPagination.pageSize;
  return alerts.value.slice(s, s + alertPagination.pageSize);
});
const paginatedIntel = computed(() => {
  const s = (intelPagination.page - 1) * intelPagination.pageSize;
  return threatIntel.value.slice(s, s + intelPagination.pageSize);
});

let charts: echarts.ECharts[] = [];

function initTopologyChart() {
  const chartDom = document.getElementById('topology-chart');
  if (!chartDom) return;
  const chart = echarts.init(chartDom as HTMLElement, 'dark');

  // 从告警数据生成拓扑
  const assetMap: Record<string, { alertCount: number; maxLevel: number }> = {};
  alerts.value.forEach((a) => {
    if (a.asset && a.asset !== '-') {
      if (!assetMap[a.asset]) assetMap[a.asset] = { alertCount: 0, maxLevel: 0 };
      assetMap[a.asset].alertCount++;
      const levelMap: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
      assetMap[a.asset].maxLevel = Math.max(assetMap[a.asset].maxLevel, levelMap[a.level] || 1);
    }
  });

  const nodes: Array<Record<string, any>> = Object.entries(assetMap).map(([name, info]) => ({
    name,
    symbolSize: Math.max(30, Math.min(80, info.alertCount * 15)),
    category: info.maxLevel,
    label: { show: true, fontSize: 11, color: '#e0e0e0' },
    itemStyle: {
      color:
        info.maxLevel >= 4 ? '#f56c6c' : info.maxLevel >= 3 ? '#e6a23c' : info.maxLevel >= 2 ? '#409eff' : '#67c23a'
    }
  }));

  // 添加中心节点
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

  chart.setOption({
    backgroundColor: 'transparent',
    title: { text: '资产风险拓扑', left: 'center', top: 5, textStyle: { color: '#00d4ff', fontSize: 14 } },
    tooltip: { trigger: 'item' },
    legend: { data: ['安全网关', '严重', '高危', '中危', '低危'], bottom: 5, textStyle: { color: '#aaa' } },
    series: [
      {
        type: 'graph',
        layout: 'force',
        roam: true,
        categories: [{ name: '安全网关' }, { name: '严重' }, { name: '高危' }, { name: '中危' }, { name: '低危' }],
        force: { repulsion: 200, edgeLength: [80, 200], gravity: 0.1 },
        data: nodes,
        links,
        emphasis: { focus: 'adjacency', lineStyle: { width: 3 } },
        lineStyle: { opacity: 0.6 }
      }
    ]
  });

  window.addEventListener('resize', () => chart.resize());
}

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

function demoThreatIntel() {
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
    updateTime: new Date(Date.now() - Math.random() * 7 * 86400000).toLocaleString('zh-CN'),
    severity: ['critical', 'high', 'medium', 'low'][Math.floor(Math.random() * 4)]
  }));
}

async function loadData() {
  try {
    const [alertRes, intelRes] = await Promise.all([
      legacyApi.get<Array<Record<string, any>>>('/situational/alerts'),
      legacyApi.get<Array<Record<string, any>>>('/situational/threat-intel')
    ]);
    if (alertRes && alertRes.code === 0) {
      alerts.value = (alertRes.data || []).map((a) => ({
        id: 'ALT-' + a.id,
        type: a.alert_type || '未知',
        level: a.severity || 'medium',
        asset: a.related_asset || '-',
        confidence: a.confidence ? (a.confidence * 100).toFixed(0) + '%' : '-',
        status: a.status || 'new',
        time: a.created_at ? new Date(a.created_at).toLocaleString('zh-CN') : '-'
      }));
    }
    if (intelRes && intelRes.code === 0) {
      threatIntel.value = (intelRes.data || []).map((t) => ({
        id: 'TI-' + t.id,
        type: t.ioc_type || '未知',
        value: t.ioc_value,
        confidence: t.confidence ? (t.confidence * 100).toFixed(0) + '%' : '-',
        source: t.source || '-',
        severity: 'high',
        updateTime: t.updated_at ? new Date(t.updated_at).toLocaleString('zh-CN') : '-'
      }));
    }
  } catch (e) {
    alerts.value = demoAlerts();
    threatIntel.value = demoThreatIntel();
  }
  loading.value = false;
}

onMounted(() => {
  loadData();
  nextTick(() => {
    setTimeout(() => initCharts(), 300);
  });
});
onUnmounted(() => {
  charts.forEach((c) => c.dispose());
  charts = [];
});

function initCharts() {
  const pie = echarts.init(document.getElementById('sa-threat-pie') as HTMLElement);
  pie.setOption({
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
        radius: ['35%', '65%'],
        center: ['50%', '45%'],
        itemStyle: { borderRadius: 6, borderColor: '#16213e', borderWidth: 2 },
        label: { show: false },
        emphasis: { label: { show: true, color: '#fff' } },
        data: [
          { value: 8, name: '严重', itemStyle: { color: '#f56c6c' } },
          { value: 15, name: '高危', itemStyle: { color: '#e6a23c' } },
          { value: 25, name: '中危', itemStyle: { color: '#00d4ff' } },
          { value: 35, name: '低危', itemStyle: { color: '#67c23a' } }
        ]
      }
    ]
  });
  charts.push(pie);

  const trend = echarts.init(document.getElementById('sa-alert-trend') as HTMLElement);
  const days: string[] = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000);
    days.push(d.getMonth() + 1 + '/' + d.getDate());
  }
  trend.setOption({
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#16213e',
      borderColor: 'rgba(0,212,255,0.2)',
      textStyle: { color: '#c0c0c0' }
    },
    legend: { data: ['新增告警', '已处理'], top: '5%', textStyle: { color: '#c0c0c0' }, itemWidth: 16, itemHeight: 3 },
    grid: { left: '3%', right: '4%', bottom: '3%', top: '18%', containLabel: true },
    xAxis: {
      type: 'category',
      data: days,
      axisLine: { lineStyle: { color: 'rgba(0,212,255,0.2)' } },
      axisLabel: { color: '#909399', interval: 4 }
    },
    yAxis: {
      type: 'value',
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(0,212,255,0.06)' } },
      axisLabel: { color: '#909399' }
    },
    series: [
      {
        name: '新增告警',
        type: 'line',
        smooth: true,
        data: Array.from({ length: 30 }, () => Math.floor(Math.random() * 30) + 5),
        lineStyle: { color: '#f56c6c', width: 2 },
        itemStyle: { color: '#f56c6c' },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(245,108,108,0.15)' },
            { offset: 1, color: 'rgba(245,108,108,0)' }
          ])
        }
      },
      {
        name: '已处理',
        type: 'line',
        smooth: true,
        data: Array.from({ length: 30 }, () => Math.floor(Math.random() * 25) + 3),
        lineStyle: { color: '#67c23a', width: 2 },
        itemStyle: { color: '#67c23a' },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(103,194,58,0.15)' },
            { offset: 1, color: 'rgba(103,194,58,0)' }
          ])
        }
      }
    ]
  });
  charts.push(trend);

  const comp = echarts.init(document.getElementById('sa-compliance-trend') as HTMLElement);
  comp.setOption({
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#16213e',
      borderColor: 'rgba(0,212,255,0.2)',
      textStyle: { color: '#c0c0c0' }
    },
    grid: { left: '3%', right: '4%', bottom: '3%', top: '10%', containLabel: true },
    xAxis: {
      type: 'category',
      data: ['第1周', '第2周', '第3周', '第4周', '第5周', '第6周'],
      axisLine: { lineStyle: { color: 'rgba(0,212,255,0.2)' } },
      axisLabel: { color: '#909399' }
    },
    yAxis: {
      type: 'value',
      min: 60,
      max: 100,
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(0,212,255,0.06)' } },
      axisLabel: { color: '#909399', formatter: '{value}%' }
    },
    series: [
      {
        type: 'line',
        smooth: true,
        data: [78, 82, 80, 85, 88, 92.5],
        lineStyle: { color: '#00d4ff', width: 3 },
        itemStyle: { color: '#00d4ff' },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: 'rgba(0,212,255,0.2)' },
            { offset: 1, color: 'rgba(0,212,255,0)' }
          ])
        },
        markLine: {
          data: [
            {
              yAxis: 90,
              label: { formatter: '目标: 90%', color: '#67c23a' },
              lineStyle: { color: '#67c23a', type: 'dashed' }
            }
          ]
        }
      }
    ]
  });
  charts.push(comp);

  setTimeout(() => initTopologyChart(), 100);
}

async function handleAlert(id: string, action: string) {
  const statusMap: Record<string, string> = {
    confirm: 'acknowledged',
    false_positive: 'false_positive',
    resolve: 'resolved'
  };
  const realId = String(id).replace('ALT-', '');
  try {
    await legacyApi.put('/situational/alerts/' + realId, { status: statusMap[action] });
  } catch (e) {
    // 接口失败时乐观更新本地状态，不阻塞用户操作
  }
  const alert = alerts.value.find((a) => a.id === id);
  if (alert) {
    alert.status = statusMap[action];
  }
  const actionMap: Record<string, string> = { confirm: '确认', false_positive: '标记误报', resolve: '解决' };
  ElMessage.success('已' + actionMap[action]);
}

async function generateReport(type: string) {
  try {
    const res = await legacyApi.post('/situational/report', {
      type: type === '周报' ? 'weekly' : 'monthly',
      title: type + ' - ' + new Date().toLocaleDateString('zh-CN')
    });
    if (res && res.code === 0) {
      ElMessage.success(type + '已生成');
      loadReports();
    }
  } catch (e) {
    ElMessage.info('报告生成中，请稍候...');
  }
}

async function loadReports() {
  try {
    const res = await legacyApi.get<{ reports: Array<Record<string, any>> }>('/reports/list');
    if (res && res.code === 0) {
      reports.value = (res.data?.reports || []).filter((r) => r.type === 'weekly' || r.type === 'monthly');
    }
  } catch (e) {
    console.error('加载报告列表失败:', e);
  }
}

function viewReport(row: Record<string, any>) {
  currentReport.value = row;
  showReport.value = true;
}

async function downloadMarkdownReport(row: Record<string, any>) {
  try {
    const res = await legacyApi.get(`/reports/${row.id}/download-md`);
    const blob = new Blob([res as unknown as string], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = row.title + '.md';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    ElMessage.success('MD报告已下载');
  } catch (e: any) {
    ElMessage.error('MD下载失败: ' + (e.response?.data?.message || e.message));
  }
}

async function generateAndDownloadDOCX(row: Record<string, any>) {
  generatingPDF.value = true;
  try {
    ElMessage.info('正在生成DOCX报告，请稍候...');
    const res = await legacyApi.post<{ filename?: string }>(`/reports/${row.id}/generate-docx`, {});
    if (res && res.code === 0 && res.data?.filename) {
      const dlRes = await legacyApi.get(`/reports/download/${res.data.filename}`);
      const blob = new Blob([dlRes as unknown as string], {
        type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = row.title + '.docx';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      ElMessage.success('DOCX报告已下载');
    }
  } catch (e: any) {
    console.error('DOCX下载失败:', e);
    ElMessage.error('DOCX下载失败: ' + (e.response?.data?.message || e.message));
  } finally {
    generatingPDF.value = false;
  }
}

async function deleteReport(row: Record<string, any>) {
  try {
    await ElMessageBox.confirm('确定删除该报告？', '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    });
    await legacyApi.delete(`/reports/${row.id}`);
    ElMessage.success('报告已删除');
    loadReports();
  } catch (e: any) {
    if (e !== 'cancel') ElMessage.error('删除失败');
  }
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

function exportAlerts() {
  if (alerts.value.length === 0) return;
  const headers = '告警类型,严重等级,关联资产,置信度,状态,时间\n';
  const rows = alerts.value
    .map((a) => `${a.type},${a.level},${a.asset},${a.confidence},${a.status},${a.time}`)
    .join('\n');
  const blob = new Blob(['\uFEFF' + headers + rows], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'alerts.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  ElMessage.success('告警数据已导出');
}
</script>
