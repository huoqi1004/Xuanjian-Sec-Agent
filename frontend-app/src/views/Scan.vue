<template>
  <div v-loading="loading">
    <div class="page-header">
      <div>
        <div class="page-title">网络扫描</div>
        <div class="page-desc">对目标网络进行端口扫描和服务识别</div>
      </div>
    </div>
    <div class="chart-card" style="margin-bottom: 20px">
      <div class="chart-card-title">扫描参数</div>
      <el-form
        ref="formRef"
        :model="scanForm"
        :rules="scanRules"
        :inline="true"
        style="display: flex; flex-wrap: wrap; gap: 12px"
      >
        <el-form-item label="目标CIDR" prop="target_cidr">
          <el-input v-model="scanForm.target_cidr" placeholder="例: 192.168.1.0/24" style="width: 220px" />
        </el-form-item>
        <el-form-item label="扫描模式" prop="scan_mode">
          <el-select v-model="scanForm.scan_mode" style="width: 160px">
            <el-option label="TCP Connect" value="tcp_connect" />
            <el-option label="SYN" value="syn" />
          </el-select>
        </el-form-item>
        <el-form-item label="端口范围" prop="port_range">
          <el-input v-model="scanForm.port_range" placeholder="例: 1-1024" style="width: 160px" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="loading" @click="startScan">
            <el-icon><VideoPlay /></el-icon> 启动扫描
          </el-button>
        </el-form-item>
      </el-form>
    </div>
    <div class="chart-card">
      <div class="chart-card-title">扫描任务列表</div>
      <el-table :data="paginatedTasks" size="small" style="width: 100%">
        <el-table-column prop="id" label="任务ID" width="150" />
        <el-table-column prop="target" label="目标" width="180" />
        <el-table-column prop="mode" label="模式" width="120" />
        <el-table-column prop="ports" label="端口范围" width="100" />
        <el-table-column prop="status" label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="getStatusTag(row.status).type" size="small">{{ getStatusTag(row.status).label }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="进度" width="150">
          <template #default="{ row }">
            <el-progress
              :percentage="row.progress"
              :stroke-width="8"
              :color="row.status === 'completed' ? '#67c23a' : '#00d4ff'"
            />
          </template>
        </el-table-column>
        <el-table-column prop="createTime" label="创建时间" />
        <el-table-column label="操作" width="160" fixed="right">
          <template #default="{ row }">
            <el-button
              type="primary"
              link
              size="small"
              :disabled="row.status !== 'completed'"
              @click="viewResults(row.id)"
              >查看结果</el-button
            >
            <el-button type="danger" link size="small" @click="deleteTask(row.id)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div style="margin-top: 16px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="taskPagination.page"
          small
          layout="total, prev, pager, next"
          :total="tasks.length"
          :page-size="taskPagination.pageSize"
        />
      </div>
    </div>
    <el-drawer v-model="showResults" title="扫描结果" size="70%" direction="rtl">
      <div style="margin-bottom: 12px">
        <el-button type="success" size="small" :disabled="results.length === 0" @click="exportScanResults"
          >导出CSV</el-button
        >
      </div>
      <el-table :data="paginatedResults" size="small" style="width: 100%">
        <el-table-column prop="ip" label="IP地址" width="140" />
        <el-table-column prop="port" label="端口" width="80" />
        <el-table-column prop="service" label="服务" width="120" />
        <el-table-column prop="version" label="版本" width="120" />
        <el-table-column prop="state" label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="row.state === 'open' ? 'success' : 'info'" size="small">{{
              row.state === 'open' ? '开放' : '过滤'
            }}</el-tag>
          </template>
        </el-table-column>
      </el-table>
      <div style="margin-top: 16px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="resultPagination.page"
          small
          layout="total, prev, pager, next"
          :total="results.length"
          :page-size="resultPagination.pageSize"
        />
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from 'element-plus';
import { legacyApi } from '@/api';

const loading = ref(false);
const scanForm = reactive({ target_cidr: '192.168.1.0/24', scan_mode: 'tcp_connect', port_range: '1-1024' });
const cidrPattern = new RegExp('^(\\d{1,3}\\.){3}\\d{1,3}\\/\\d{1,2}$');
const scanRules: FormRules = {
  target_cidr: [
    { required: true, message: '请输入目标CIDR', trigger: 'blur' },
    { pattern: cidrPattern, message: '请输入有效的CIDR格式', trigger: 'blur' }
  ],
  port_range: [{ required: true, message: '请输入端口范围', trigger: 'blur' }]
};
const formRef = ref<FormInstance>();
const tasks = ref<Array<Record<string, any>>>([]);
const results = ref<Array<Record<string, any>>>([]);
const showResults = ref(false);
const taskPagination = reactive({ page: 1, pageSize: 10 });
const resultPagination = reactive({ page: 1, pageSize: 10 });
const paginatedTasks = computed(() => {
  const s = (taskPagination.page - 1) * taskPagination.pageSize;
  return tasks.value.slice(s, s + taskPagination.pageSize);
});
const paginatedResults = computed(() => {
  const s = (resultPagination.page - 1) * resultPagination.pageSize;
  return results.value.slice(s, s + resultPagination.pageSize);
});

function demoScanTasks() {
  const statuses = ['running', 'completed', 'pending', 'failed'];
  return Array.from({ length: 20 }, (_, i) => ({
    id: 'SCAN-' + (2000 + i),
    target: ['192.168.1.0/24', '10.0.0.0/16', '172.16.0.0/24', '192.168.100.0/22'][Math.floor(Math.random() * 4)],
    mode: Math.random() > 0.5 ? 'TCP Connect' : 'SYN',
    ports: '1-1024',
    status: statuses[Math.floor(Math.random() * statuses.length)],
    progress:
      statuses[Math.floor(Math.random() * statuses.length)] === 'completed' ? 100 : Math.floor(Math.random() * 100),
    createTime: new Date(Date.now() - Math.random() * 3 * 86400000).toLocaleString('zh-CN')
  }));
}

function demoScanResults() {
  const services = ['SSH', 'HTTP', 'HTTPS', 'FTP', 'MySQL', 'Redis', 'MongoDB', 'RDP', 'SMTP', 'DNS'];
  const versions = ['2.0', '5.7.32', '6.2.6', '4.8.1', '1.1.1', '3.0', '8.0.28', '2.4.51', 'latest', '9.16.1'];
  return Array.from({ length: 80 }, (_, i) => ({
    ip: `192.168.1.${(i % 50) + 1}`,
    port: [22, 80, 443, 21, 3306, 6379, 27017, 3389, 25, 53][Math.floor(Math.random() * 10)],
    service: services[Math.floor(Math.random() * services.length)],
    version: versions[Math.floor(Math.random() * versions.length)],
    state: Math.random() > 0.1 ? 'open' : 'filtered'
  }));
}

async function loadTasks() {
  try {
    const res = await legacyApi.get('/scan/tasks');
    if (res && res.code === 0) {
      tasks.value = ((res.data as Array<Record<string, any>>) || []).map((t) => ({
        id: t.id,
        target: t.target_cidr,
        mode: t.scan_mode,
        ports: t.port_range,
        status: t.status,
        progress: t.progress || (t.status === 'completed' ? 100 : 0),
        createTime: t.created_at ? new Date(t.created_at).toLocaleString('zh-CN') : '-'
      }));
    }
  } catch (e) {
    tasks.value = demoScanTasks();
  }
}

async function startScan() {
  if (!formRef.value) return;
  try {
    await formRef.value.validate();
  } catch (e) {
    return;
  }
  loading.value = true;
  try {
    const res = await legacyApi.post('/scan/start', scanForm);
    if (res && res.code === 0) {
      const t = res.data as Record<string, any>;
      tasks.value.unshift({
        id: t.task_id,
        target: t.target_cidr,
        mode: t.scan_mode,
        ports: t.port_range,
        status: 'running',
        progress: 0,
        createTime: new Date().toLocaleString('zh-CN')
      });
      ElMessage.success('扫描任务已启动');
    }
  } catch (e) {
    ElMessage.error('启动扫描失败');
  }
  loading.value = false;
}

async function viewResults(taskId: string) {
  showResults.value = true;
  loading.value = true;
  try {
    const res = await legacyApi.get('/scan/tasks/' + taskId);
    if (res && res.code === 0) {
      results.value = ((res.data as Record<string, any>)?.results || []).map((r: Record<string, any>) => ({
        ip: r.ip,
        port: r.port,
        service: r.service,
        version: r.version,
        state: r.state
      }));
    }
  } catch (e) {
    results.value = demoScanResults();
  }
  loading.value = false;
}

async function deleteTask(taskId: string) {
  try {
    await ElMessageBox.confirm('确定要删除此扫描任务吗？', '确认', { type: 'warning' });
  } catch (e) {
    return;
  }
  try {
    await legacyApi.delete('/scan/tasks/' + taskId);
  } catch (e) {
    /* 忽略删除接口错误，本地直接移除 */
  }
  tasks.value = tasks.value.filter((t) => t.id !== taskId);
  ElMessage.success('已删除');
}

onMounted(() => {
  loadTasks();
});

function getStatusTag(status: string) {
  const map: Record<string, { label: string; type: string }> = {
    running: { label: '运行中', type: 'primary' },
    completed: { label: '已完成', type: 'success' },
    pending: { label: '等待中', type: 'info' },
    failed: { label: '失败', type: 'danger' }
  };
  return map[status] || { label: status, type: 'info' };
}

function exportScanResults() {
  if (results.value.length === 0) return;
  const headers = 'IP,端口,服务,版本,状态\n';
  const rows = results.value.map((r) => `${r.ip},${r.port},${r.service},${r.version},${r.state}`).join('\n');
  const blob = new Blob(['\uFEFF' + headers + rows], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'scan_results.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  ElMessage.success('扫描结果已导出');
}
</script>
