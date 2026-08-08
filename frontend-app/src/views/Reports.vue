<template>
  <div class="page-container">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px">
      <h2 style="color: #00d4ff; margin: 0">报告管理</h2>
      <div>
        <el-dropdown style="margin-right: 8px" @command="downloadCsv">
          <el-button type="warning" :icon="Download">批量导出 CSV</el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="alerts">安全告警</el-dropdown-item>
              <el-dropdown-item command="scan">扫描结果</el-dropdown-item>
              <el-dropdown-item command="baseline">基线检查</el-dropdown-item>
              <el-dropdown-item command="reports">报告列表</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <el-button
          type="primary"
          :icon="RefreshRight"
          @click="
            loadReports();
            loadReportStats();
          "
          >刷新</el-button
        >
      </div>
    </div>

    <el-row :gutter="20" style="margin-bottom: 20px">
      <el-col :span="6">
        <el-card shadow="hover" style="background: rgba(26, 26, 46, 0.6); border-color: #333">
          <div style="text-align: center">
            <div style="font-size: 32px; color: #00d4ff; font-weight: bold">{{ reportStats.total || 0 }}</div>
            <div style="font-size: 14px; color: #999; margin-top: 5px">总报告数</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" style="background: rgba(26, 26, 46, 0.6); border-color: #333">
          <div style="text-align: center">
            <div style="font-size: 32px; color: #e74c3c; font-weight: bold">{{ reportStats.djpp || 0 }}</div>
            <div style="font-size: 14px; color: #999; margin-top: 5px">等保测评报告</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" style="background: rgba(26, 26, 46, 0.6); border-color: #333">
          <div style="text-align: center">
            <div style="font-size: 32px; color: #27ae60; font-weight: bold">{{ reportStats.virus || 0 }}</div>
            <div style="font-size: 14px; color: #999; margin-top: 5px">病毒查杀报告</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" style="background: rgba(26, 26, 46, 0.6); border-color: #333">
          <div style="text-align: center">
            <div style="font-size: 32px; color: #f39c12; font-weight: bold">{{ reportStats.baseline || 0 }}</div>
            <div style="font-size: 14px; color: #999; margin-top: 5px">基线检查报告</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-tabs v-model="activeTab" style="margin-bottom: 20px">
      <el-tab-pane label="全部报告" name="all">
        <el-table
          v-loading="loading"
          :data="reports"
          stripe
          style="width: 100%"
          :header-cell-style="{ background: '#1a1a3e', color: '#00d4ff' }"
          :row-style="{ background: 'rgba(26,26,46,0.6)' }"
        >
          <el-table-column prop="id" label="ID" width="80" />
          <el-table-column prop="title" label="报告标题" min-width="250" />
          <el-table-column prop="typeLabel" label="类型" width="120">
            <template #default="{ row }">
              <el-tag
                :type="
                  row.type === 'djpp'
                    ? 'danger'
                    : row.type === 'virus'
                      ? 'success'
                      : row.type === 'baseline'
                        ? 'warning'
                        : 'info'
                "
                size="small"
                >{{ row.typeLabel }}</el-tag
              >
            </template>
          </el-table-column>
          <el-table-column prop="generatedBy" label="生成者" width="120" />
          <el-table-column prop="generatedAt" label="生成时间" width="180" />
          <el-table-column label="操作" width="300" fixed="right">
            <template #default="{ row }">
              <el-button type="primary" link size="small" @click="viewReport(row)">查看</el-button>
              <el-button type="success" link size="small" @click="downloadMarkdownReport(row)">下载MD</el-button>
              <el-button type="warning" link size="small" :loading="generatingPDF" @click="generateAndDownloadDOCX(row)"
                >下载DOCX</el-button
              >
              <el-button type="danger" link size="small" @click="deleteReport(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="等保测评报告" name="djpp">
        <el-table
          v-loading="loading"
          :data="reports.filter((r) => r.type === 'djpp')"
          stripe
          style="width: 100%"
          :header-cell-style="{ background: '#1a1a3e', color: '#00d4ff' }"
          :row-style="{ background: 'rgba(26,26,46,0.6)' }"
        >
          <el-table-column prop="id" label="ID" width="80" />
          <el-table-column prop="title" label="报告标题" min-width="250" />
          <el-table-column prop="generatedBy" label="生成者" width="120" />
          <el-table-column prop="generatedAt" label="生成时间" width="180" />
          <el-table-column label="操作" width="300" fixed="right">
            <template #default="{ row }">
              <el-button type="primary" link size="small" @click="viewReport(row)">查看</el-button>
              <el-button type="success" link size="small" @click="downloadMarkdownReport(row)">下载MD</el-button>
              <el-button type="warning" link size="small" :loading="generatingPDF" @click="generateAndDownloadDOCX(row)"
                >下载DOCX</el-button
              >
              <el-button type="danger" link size="small" @click="deleteReport(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="病毒查杀报告" name="virus">
        <el-table
          v-loading="loading"
          :data="reports.filter((r) => r.type === 'virus')"
          stripe
          style="width: 100%"
          :header-cell-style="{ background: '#1a1a3e', color: '#00d4ff' }"
          :row-style="{ background: 'rgba(26,26,46,0.6)' }"
        >
          <el-table-column prop="id" label="ID" width="80" />
          <el-table-column prop="title" label="报告标题" min-width="250" />
          <el-table-column prop="generatedBy" label="生成者" width="120" />
          <el-table-column prop="generatedAt" label="生成时间" width="180" />
          <el-table-column label="操作" width="300" fixed="right">
            <template #default="{ row }">
              <el-button type="primary" link size="small" @click="viewReport(row)">查看</el-button>
              <el-button type="success" link size="small" @click="downloadMarkdownReport(row)">下载MD</el-button>
              <el-button type="warning" link size="small" :loading="generatingPDF" @click="generateAndDownloadDOCX(row)"
                >下载DOCX</el-button
              >
              <el-button type="danger" link size="small" @click="deleteReport(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="基线检查报告" name="baseline">
        <el-table
          v-loading="loading"
          :data="reports.filter((r) => r.type === 'baseline')"
          stripe
          style="width: 100%"
          :header-cell-style="{ background: '#1a1a3e', color: '#00d4ff' }"
          :row-style="{ background: 'rgba(26,26,46,0.6)' }"
        >
          <el-table-column prop="id" label="ID" width="80" />
          <el-table-column prop="title" label="报告标题" min-width="250" />
          <el-table-column prop="generatedBy" label="生成者" width="120" />
          <el-table-column prop="generatedAt" label="生成时间" width="180" />
          <el-table-column label="操作" width="300" fixed="right">
            <template #default="{ row }">
              <el-button type="primary" link size="small" @click="viewReport(row)">查看</el-button>
              <el-button type="success" link size="small" @click="downloadMarkdownReport(row)">下载MD</el-button>
              <el-button type="warning" link size="small" :loading="generatingPDF" @click="generateAndDownloadDOCX(row)"
                >下载DOCX</el-button
              >
              <el-button type="danger" link size="small" @click="deleteReport(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>

    <el-drawer
      v-model="showDetail"
      :title="reportDetail?.title || '报告详情'"
      size="60%"
      :style="{ background: '#1a1a2e' }"
    >
      <div v-if="reportDetail" style="color: #e0e0e0; line-height: 1.8">
        <p><strong>类型：</strong>{{ reportDetail.typeLabel }}</p>
        <p><strong>生成者：</strong>{{ reportDetail.generatedBy }}</p>
        <p><strong>时间：</strong>{{ reportDetail.generatedAt }}</p>
        <el-divider />
        <div style="white-space: pre-wrap; max-height: 60vh; overflow-y: auto">
          {{ reportDetail.content || reportDetail.stats ? JSON.stringify(reportDetail.stats) : '暂无内容' }}
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { RefreshRight, Download } from '@element-plus/icons-vue';
import { useUserStore } from '@/stores/user';
import { legacyApi } from '@/api';

// 与旧版 index.html 保持一致，用于拼接 DOCX 下载地址
const API_BASE = 'http://localhost:3000/api';

const loading = ref(true);
const reports = ref<Array<Record<string, any>>>([]);
const reportDetail = ref<Record<string, any> | null>(null);
const showDetail = ref(false);
const activeTab = ref('all');
const reportStats = ref<Record<string, any>>({ total: 0, djpp: 0, virus: 0, baseline: 0, scan: 0 });
const generatingPDF = ref(false);

const userStore = useUserStore();
const CSV_TYPES: Record<string, string> = {
  alerts: '告警',
  scan: '扫描',
  baseline: '基线',
  reports: '报告'
};

/** 批量导出 CSV（带鉴权头的流式下载） */
async function downloadCsv(type: string) {
  try {
    const resp = await fetch(`${API_BASE}/reports/export/csv?type=${type}`, {
      headers: { Authorization: `Bearer ${userStore.token}` }
    });
    if (!resp.ok) {
      ElMessage.error('CSV 导出失败');
      return;
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${type}_export_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    ElMessage.success(`${CSV_TYPES[type] || type}数据已导出`);
  } catch (e) {
    ElMessage.error('CSV 导出失败: ' + (e as Error).message);
  }
}

async function loadReportStats() {
  try {
    const res = await legacyApi.get('/reports/stats');
    if (res && res.code === 0) {
      reportStats.value = res.data as Record<string, any>;
    }
  } catch (e) {
    console.error('获取报告统计失败:', e);
  }
}

async function loadReports() {
  loading.value = true;
  try {
    let url = '/reports/list?page=1&pageSize=100';
    if (activeTab.value !== 'all') {
      url += `&type=${activeTab.value}`;
    }
    const res = await legacyApi.get(url);
    if (res && res.code === 0) {
      const data = res.data as any;
      reports.value = ((data && data.reports) || []).map((r: any) => ({
        id: r.id,
        reportId: r.reportId,
        title: r.title || '未命名报告',
        type: r.type,
        typeLabel: r.typeLabel || r.type,
        content: r.content || (typeof r.content === 'string' ? r.content : ''),
        generatedBy: r.generatedBy || '-',
        generatedAt: r.generatedAt ? new Date(r.generatedAt).toLocaleString('zh-CN') : '-',
        stats: r.stats || null,
        hasPDF: r.hasPDF || false,
        pdfUrl: r.pdfUrl || null
      }));
    }
  } catch (e) {
    console.error('获取报告列表失败:', e);
    ElMessage.error('获取报告列表失败');
    reports.value = [];
  }
  loading.value = false;
}

function viewReport(report: Record<string, any>) {
  reportDetail.value = report;
  showDetail.value = true;
}

function downloadMarkdownReport(report: Record<string, any>) {
  const content = report.content || '无内容';
  const blob = new Blob(
    [`# ${report.title}\n\n生成时间: ${report.generatedAt}\n生成者: ${report.generatedBy}\n\n${content}`],
    { type: 'text/markdown;charset=utf-8' }
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = report.title + '.md';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  ElMessage.success('Markdown报告已下载');
}

async function generateAndDownloadDOCX(report: Record<string, any>) {
  try {
    generatingPDF.value = true;
    ElMessage.info('正在生成DOCX报告，请稍候...');

    const res = await legacyApi.post(`/reports/${report.id}/generate-docx`, {});
    if (res && res.code === 0) {
      const data = res.data as any;
      const docxUrl = data.downloadUrl;
      const fullUrl = `${API_BASE}${docxUrl}`;

      window.open(fullUrl, '_blank');
      ElMessage.success('DOCX报告已下载');
      report.hasDOCX = true;
    } else {
      ElMessage.error(res.message || 'DOCX生成失败');
    }
  } catch (e: any) {
    console.error('DOCX报告生成失败:', e);
    ElMessage.error('DOCX报告生成失败: ' + (e.message || '网络错误'));
  } finally {
    generatingPDF.value = false;
  }
}

async function deleteReport(report: Record<string, any>) {
  try {
    await ElMessageBox.confirm('确定要删除此报告吗？', '确认删除', { type: 'warning' });
    const res = await legacyApi.delete(`/reports/${report.id}`);
    if (res && res.code === 0) {
      ElMessage.success('报告已删除');
      loadReports();
      loadReportStats();
    } else {
      ElMessage.error(res.message || '删除失败');
    }
  } catch (e: any) {
    if (e !== 'cancel') {
      console.error('删除报告失败:', e);
    }
  }
}

watch(activeTab, () => {
  loadReports();
});

onMounted(() => {
  loadReports();
  loadReportStats();
});
</script>
