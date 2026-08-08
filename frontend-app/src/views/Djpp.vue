<template>
  <div v-loading="loading">
    <div class="page-header">
      <div>
        <div class="page-title">等级保护测评</div>
        <div class="page-desc">按照等级保护一二三四五级测评流程进行各项安全测试</div>
      </div>
    </div>

    <el-tabs v-model="activeTab" style="margin-bottom: 20px">
      <el-tab-pane label="测评级别" name="levels">
        <div class="chart-card">
          <div style="margin-bottom: 20px">
            <h3 style="color: #00d4ff; margin-bottom: 16px">选择测评级别</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px">
              <div
                v-for="level in levels"
                :key="level.id"
                class="stat-card"
                :class="{ 'glow-border': selectedLevel === level.id }"
                style="cursor: pointer"
                @click="selectedLevel = level.id"
              >
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px">
                  <span class="stat-value" :class="selectedLevel === level.id ? 'cyan' : 'white'"
                    >第{{ level.level }}级</span
                  >
                  <el-tag :type="selectedLevel === level.id ? 'primary' : 'info'" size="small">{{ level.name }}</el-tag>
                </div>
                <div class="stat-label">{{ level.description }}</div>
                <div style="font-size: 12px; color: rgba(255, 255, 255, 0.4); margin-top: 8px; line-height: 1.5">
                  {{ level.description }}
                </div>
              </div>
            </div>
          </div>

          <el-divider content-position="left"><span style="color: #00d4ff">开始测评任务</span></el-divider>
          <el-form :model="taskForm" label-width="100px" style="max-width: 600px">
            <el-form-item label="测评级别">
              <el-select v-model="taskForm.level">
                <el-option v-for="level in levels" :key="level.id" :label="level.name" :value="level.level" />
              </el-select>
            </el-form-item>
            <el-form-item label="任务名称" required>
              <el-input v-model="taskForm.name" placeholder="请输入测评任务名称" />
            </el-form-item>
            <el-form-item label="任务描述">
              <el-input v-model="taskForm.description" type="textarea" :rows="3" placeholder="请输入任务描述" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="creatingTask" @click="startTask">
                <el-icon><VideoPlay /></el-icon> 启动测评
              </el-button>
            </el-form-item>
          </el-form>
        </div>
      </el-tab-pane>

      <el-tab-pane label="任务管理" name="tasks">
        <div class="chart-card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px">
            <h3 style="color: #00d4ff">测评任务列表</h3>
            <el-button type="primary" size="small" :icon="RefreshRight" @click="loadTasks">刷新</el-button>
          </div>
          <el-table
            :data="tasks"
            stripe
            style="width: 100%"
            :header-cell-style="{ background: '#1a1a3e', color: '#00d4ff' }"
            :row-style="{ background: 'rgba(26,26,46,0.6)' }"
          >
            <el-table-column prop="id" label="任务ID" width="150" />
            <el-table-column prop="name" label="任务名称" min-width="200" />
            <el-table-column prop="level" label="测评级别" width="100">
              <template #default="{ row }"
                ><el-tag type="primary" size="small">第{{ row.level }}级</el-tag></template
              >
            </el-table-column>
            <el-table-column prop="status" label="状态" width="100">
              <template #default="{ row }"
                ><el-tag :type="row.statusType" size="small">{{ row.statusText }}</el-tag></template
              >
            </el-table-column>
            <el-table-column prop="progress" label="进度" width="120">
              <template #default="{ row }">
                <el-progress :percentage="row.progress" :show-text="false" :stroke-width="8" />
              </template>
            </el-table-column>
            <el-table-column prop="created_by_name" label="创建人" width="100" />
            <el-table-column prop="created_at" label="创建时间" width="180" />
            <el-table-column label="操作" width="280" fixed="right">
              <template #default="{ row }">
                <el-button type="primary" link size="small" @click="viewTask(row.id)">查看</el-button>
                <el-button
                  v-if="row.status === 'completed'"
                  type="success"
                  link
                  size="small"
                  :loading="generatingReportId === row.id"
                  @click="generateReport(row.id)"
                  >生成报告</el-button
                >
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <el-tab-pane label="报告管理" name="reports">
        <div class="chart-card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px">
            <h3 style="color: #00d4ff">等保报告列表</h3>
            <el-button type="primary" size="small" :icon="RefreshRight" @click="loadReports">刷新</el-button>
          </div>
          <el-table
            :data="reports"
            stripe
            style="width: 100%"
            :header-cell-style="{ background: '#1a1a3e', color: '#00d4ff' }"
            :row-style="{ background: 'rgba(26,26,46,0.6)' }"
          >
            <el-table-column prop="title" label="报告名称" min-width="200" />
            <el-table-column prop="created_by_name" label="生成人" width="120" />
            <el-table-column prop="created_at" label="生成时间" width="180" />
            <el-table-column label="操作" width="220" fixed="right">
              <template #default="{ row }">
                <el-button type="primary" link size="small" @click="viewReport(row)">查看</el-button>
                <el-button type="success" link size="small" @click="downloadReportTxt(row)">下载</el-button>
                <el-button type="danger" link size="small" @click="deleteReport(row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>
    </el-tabs>

    <el-drawer
      v-model="showTaskDetail"
      :title="taskDetail?.task?.name || '任务详情'"
      size="70%"
      :style="{ background: '#1a1a2e' }"
    >
      <div v-if="taskDetail">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="任务ID">{{ taskDetail.task.id }}</el-descriptions-item>
          <el-descriptions-item label="测评级别">第{{ taskDetail.task.level }}级</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag
              :type="
                taskDetail.task.status === 'completed'
                  ? 'success'
                  : taskDetail.task.status === 'running'
                    ? 'primary'
                    : 'warning'
              "
            >
              {{
                taskDetail.task.status === 'completed'
                  ? '已完成'
                  : taskDetail.task.status === 'running'
                    ? '执行中'
                    : '待执行'
              }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="进度">{{ taskDetail.task.progress }}%</el-descriptions-item>
          <el-descriptions-item label="创建时间">{{ taskDetail.task.created_at }}</el-descriptions-item>
          <el-descriptions-item label="完成时间">{{ taskDetail.task.completed_at || '-' }}</el-descriptions-item>
        </el-descriptions>

        <el-divider style="margin: 20px 0" />

        <div style="display: flex; gap: 16px; margin-bottom: 16px">
          <div class="stat-card cyan" style="flex: 1">
            <div class="stat-label">总检查项</div>
            <div class="stat-value cyan">{{ taskDetail.stats.total }}</div>
          </div>
          <div class="stat-card green" style="flex: 1">
            <div class="stat-label">通过</div>
            <div class="stat-value green">{{ taskDetail.stats.pass }}</div>
          </div>
          <div class="stat-card orange" style="flex: 1">
            <div class="stat-label">失败</div>
            <div class="stat-value orange">{{ taskDetail.stats.fail }}</div>
          </div>
          <div class="stat-card purple" style="flex: 1">
            <div class="stat-label">合规率</div>
            <div class="stat-value purple">{{ taskDetail.stats.complianceRate }}%</div>
          </div>
        </div>

        <el-table
          :data="taskDetail.results"
          stripe
          style="width: 100%"
          :header-cell-style="{ background: '#1a1a3e', color: '#00d4ff' }"
          :row-style="{ background: 'rgba(26,26,46,0.6)' }"
        >
          <el-table-column prop="category_name" label="安全类别" width="120" />
          <el-table-column prop="check_code" label="检查项编码" width="100" />
          <el-table-column prop="check_name" label="检查项名称" min-width="200" />
          <el-table-column prop="status" label="状态" width="80">
            <template #default="{ row }"
              ><el-tag
                :type="row.status === 'pass' ? 'success' : row.status === 'fail' ? 'danger' : 'warning'"
                size="small"
                >{{ row.status === 'pass' ? '通过' : row.status === 'fail' ? '失败' : '警告' }}</el-tag
              ></template
            >
          </el-table-column>
          <el-table-column prop="severity" label="严重级别" width="100">
            <template #default="{ row }"
              ><el-tag
                :type="row.severity === 'critical' ? 'danger' : row.severity === 'high' ? 'warning' : 'info'"
                size="small"
                >{{
                  row.severity === 'critical'
                    ? '严重'
                    : row.severity === 'high'
                      ? '高'
                      : row.severity === 'medium'
                        ? '中'
                        : '低'
                }}</el-tag
              ></template
            >
          </el-table-column>
          <el-table-column prop="comment" label="备注" min-width="200" />
        </el-table>
      </div>
    </el-drawer>

    <el-drawer
      v-model="showReportDetail"
      :title="(currentReport?.taskName || currentReport?.title || '等保测评报告') + ' - 等保测评报告'"
      size="80%"
      :style="{ background: '#1a1a2e' }"
    >
      <div v-if="currentReport">
        <div style="display: flex; gap: 16px; margin-bottom: 20px">
          <el-button type="info" @click="downloadReportMD(currentReport)">
            <el-icon><Download /></el-icon> 下载MD报告
          </el-button>
          <el-button type="warning" @click="downloadReportDOCX">
            <el-icon><Document /></el-icon> 下载DOCX报告
          </el-button>
        </div>
        <div style="white-space: pre-wrap; color: #e0e0e0; line-height: 1.8; font-size: 14px">
          {{ currentReport.aiAnalysis || currentReport.content }}
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { VideoPlay, RefreshRight, Download, Document } from '@element-plus/icons-vue';
import { legacyApi } from '@/api';

const loading = ref(true);
const levels = ref<Array<Record<string, any>>>([]);
const tasks = ref<Array<Record<string, any>>>([]);
const reports = ref<Array<Record<string, any>>>([]);
const selectedLevel = ref<number>(3);
const taskDetail = ref<Record<string, any> | null>(null);
const showTaskDetail = ref(false);
const showReportDetail = ref(false);
const currentReport = ref<Record<string, any> | null>(null);
const creatingTask = ref(false);
const activeTab = ref('levels');
const generatingReportId = ref<number | null>(null);

const taskForm = reactive({
  level: 3,
  name: '',
  description: ''
});

async function loadLevels() {
  try {
    const res = await legacyApi.get<Array<Record<string, any>>>('/djpp/levels');
    if (res && res.code === 0) {
      levels.value = res.data;
    }
  } catch (e) {
    levels.value = [
      { id: 1, level: 1, name: '第一级', description: '自主保护级' },
      { id: 2, level: 2, name: '第二级', description: '指导保护级' },
      { id: 3, level: 3, name: '第三级', description: '监督保护级' },
      { id: 4, level: 4, name: '第四级', description: '强制保护级' },
      { id: 5, level: 5, name: '第五级', description: '专控保护级' }
    ];
  }
}

async function loadTasks() {
  loading.value = true;
  try {
    const res = await legacyApi.get<{ tasks: Array<Record<string, any>> }>('/djpp/tasks?page=1&pageSize=50');
    if (res && res.code === 0) {
      tasks.value = (res.data.tasks || []).map((t) => ({
        ...t,
        statusText:
          t.status === 'pending'
            ? '待执行'
            : t.status === 'running'
              ? '执行中'
              : t.status === 'completed'
                ? '已完成'
                : '失败',
        statusType:
          t.status === 'pending'
            ? 'warning'
            : t.status === 'running'
              ? 'primary'
              : t.status === 'completed'
                ? 'success'
                : 'danger'
      }));
    }
  } catch (e) {
    tasks.value = [];
  }
  loading.value = false;
}

async function startTask() {
  if (!taskForm.name) {
    ElMessage.warning('请输入任务名称');
    return;
  }
  creatingTask.value = true;
  try {
    const res = await legacyApi.post('/djpp/tasks', {
      level: taskForm.level,
      name: taskForm.name,
      description: taskForm.description
    });
    if (res && res.code === 0) {
      ElMessage.success('测评任务已启动');
      taskForm.name = '';
      taskForm.description = '';
      loadTasks();
    }
  } catch (e) {
    ElMessage.error('任务创建失败');
  }
  creatingTask.value = false;
}

async function viewTask(taskId: number) {
  try {
    const res = await legacyApi.get<Record<string, any>>('/djpp/tasks/' + taskId);
    if (res && res.code === 0) {
      taskDetail.value = res.data;
      showTaskDetail.value = true;
    }
  } catch (e) {
    ElMessage.error('获取任务详情失败');
  }
}

async function generateReport(taskId: number) {
  if (generatingReportId.value) {
    ElMessage.warning('报告正在生成中，请稍候...');
    return;
  }
  generatingReportId.value = taskId;
  ElMessage.info('正在调用AI生成测评报告，预计需要30-60秒，请耐心等待...');
  try {
    const res = await legacyApi.post<Record<string, any>>('/djpp/tasks/' + taskId + '/report', {});
    if (res && res.code === 0 && res.data) {
      currentReport.value = res.data;
      showReportDetail.value = true;
      ElMessage.success('报告生成成功');
      loadTasks();
    } else {
      ElMessage.error('报告生成失败: ' + (res.message || '未知错误'));
    }
  } catch (e: any) {
    console.error('报告生成异常:', e);
    const errMsg = e.response?.data?.message || e.message || '网络连接失败';
    ElMessage.error('报告生成失败: ' + errMsg);
  } finally {
    generatingReportId.value = null;
  }
}

function downloadReportMD(report: Record<string, any>) {
  const content = report.aiAnalysis || report.content || '无内容';
  const blob = new Blob([`# ${report.taskName} - 等级保护${report.level}级测评报告\n\n${content}`], {
    type: 'text/markdown;charset=utf-8'
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `等保${report.level}级测评报告_${report.taskId}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  ElMessage.success('报告已下载');
}

function downloadReportTxt(report: Record<string, any>) {
  const content = report?.content
    ? typeof report.content === 'string'
      ? report.content
      : JSON.stringify(report.content)
    : JSON.stringify(report);
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${report?.title || '等保报告'}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function downloadReportDOCX() {
  if (!currentReport.value?.reportId) {
    ElMessage.warning('报告ID不存在，无法下载DOCX');
    return;
  }
  try {
    ElMessage.info('正在生成DOCX报告，请稍候...');
    const res = await legacyApi.post<{ downloadUrl?: string; message?: string }>(
      `/reports/${currentReport.value.reportId}/generate-docx`,
      {}
    );
    if (res && res.code === 0 && res.data && res.data.downloadUrl) {
      const docxUrl = '/api' + res.data.downloadUrl;
      window.open(docxUrl, '_blank');
      ElMessage.success('DOCX报告已开始下载');
    } else {
      ElMessage.error('DOCX生成失败: ' + (res.data?.message || '未知错误'));
    }
  } catch (e: any) {
    console.error('DOCX下载失败:', e);
    ElMessage.error('DOCX下载失败: ' + (e.response?.data?.message || e.message));
  }
}

async function loadReports() {
  try {
    const res = await legacyApi.get<{ reports: Array<Record<string, any>> }>('/djpp/reports');
    if (res && res.code === 0) {
      reports.value = res.data.reports || [];
    }
  } catch (err) {
    console.error('加载报告列表失败:', err);
  }
}

function viewReport(row: Record<string, any>) {
  currentReport.value = row;
  showReportDetail.value = true;
}

async function deleteReport(reportId: number) {
  try {
    await ElMessageBox.confirm('确定要删除此报告吗？', '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    });
  } catch {
    return;
  }
  try {
    const res = await legacyApi.delete('/djpp/reports/' + reportId);
    if (res && res.code === 0) {
      ElMessage.success('删除成功');
      loadReports();
    }
  } catch (e: any) {
    console.error('删除报告失败:', e);
    ElMessage.error('删除失败');
  }
}

onMounted(() => {
  loadLevels();
  loadTasks();
  loadReports();
});
</script>
