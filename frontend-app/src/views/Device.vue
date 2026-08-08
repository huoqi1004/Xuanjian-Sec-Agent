<template>
  <div v-loading="loading">
    <div class="page-header">
      <div>
        <div class="page-title">边缘设备管理</div>
        <div class="page-desc">管理和监控所有接入的安全边缘设备</div>
      </div>
    </div>
    <div class="chart-card">
      <div class="chart-card-title">设备列表</div>
      <el-table :data="paginatedDevices" size="small" style="width: 100%">
        <el-table-column prop="id" label="设备ID" width="110" />
        <el-table-column prop="hostname" label="主机名" width="120" />
        <el-table-column prop="ip" label="IP地址" width="130" />
        <el-table-column prop="type" label="类型" width="120" />
        <el-table-column label="状态" width="90">
          <template #default="{ row }"
            ><div class="device-status">
              <span class="dot" :class="row.online ? 'online' : 'offline'"></span
              ><span>{{ row.online ? '在线' : '离线' }}</span>
            </div></template
          >
        </el-table-column>
        <el-table-column prop="agentVersion" label="Agent版本" width="100" />
        <el-table-column prop="lastHeartbeat" label="最后心跳" width="160" />
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }"
            ><el-button type="primary" link size="small" @click="viewDetail(row)">详情</el-button
            ><el-button type="warning" link size="small" :disabled="!row.online" @click="openCommand(row)"
              >指令</el-button
            ></template
          >
        </el-table-column>
      </el-table>
      <div style="margin-top: 16px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="pagination.page"
          small
          layout="total, prev, pager, next"
          :total="devices.length"
          :page-size="pagination.pageSize"
        />
      </div>
    </div>
    <el-drawer v-model="showDetail" title="设备详情" size="65%" direction="rtl" destroy-on-close>
      <template v-if="selectedDevice">
        <el-descriptions :column="2" border size="small" style="margin-bottom: 20px">
          <el-descriptions-item label="设备ID">{{ selectedDevice.id }}</el-descriptions-item>
          <el-descriptions-item label="主机名">{{ selectedDevice.hostname }}</el-descriptions-item>
          <el-descriptions-item label="IP地址">{{ selectedDevice.ip }}</el-descriptions-item>
          <el-descriptions-item label="类型">{{ selectedDevice.type }}</el-descriptions-item>
          <el-descriptions-item label="状态"
            ><div class="device-status">
              <span class="dot" :class="selectedDevice.online ? 'online' : 'offline'"></span
              >{{ selectedDevice.online ? '在线' : '离线' }}
            </div></el-descriptions-item
          >
          <el-descriptions-item label="Agent版本">{{ selectedDevice.agentVersion }}</el-descriptions-item>
        </el-descriptions>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px">
          <div class="chart-card" style="margin-bottom: 0">
            <div class="chart-card-title">CPU使用率</div>
            <div id="device-cpu-chart" style="width: 100%; height: 200px"></div>
          </div>
          <div class="chart-card" style="margin-bottom: 0">
            <div class="chart-card-title">内存使用率</div>
            <div id="device-mem-chart" style="width: 100%; height: 200px"></div>
          </div>
        </div>
        <div class="chart-card">
          <div class="chart-card-title">网络流量 (Mbps)</div>
          <div id="device-net-chart" style="width: 100%; height: 200px"></div>
        </div>
        <div class="chart-card" style="margin-top: 20px">
          <div class="chart-card-title">指令执行历史</div>
          <el-table :data="commandHistory" size="small" style="width: 100%"
            ><el-table-column prop="id" label="指令ID" width="110" /><el-table-column
              prop="type"
              label="类型"
              width="120" /><el-table-column prop="status" label="状态" width="80"
              ><template #default="{ row }"
                ><el-tag :type="row.status === 'success' ? 'success' : 'danger'" size="small">{{
                  row.status === 'success' ? '成功' : '失败'
                }}</el-tag></template
              ></el-table-column
            ><el-table-column prop="time" label="时间"
          /></el-table>
        </div>
      </template>
    </el-drawer>
    <el-dialog v-model="showCommand" title="下发指令" width="500px" destroy-on-close>
      <el-form :model="commandForm" label-width="100px">
        <el-form-item label="目标设备"
          ><el-input :model-value="selectedDevice?.hostname + ' (' + selectedDevice?.ip + ')'" disabled
        /></el-form-item>
        <el-form-item label="指令类型" required
          ><el-select v-model="commandForm.type" style="width: 100%"
            ><el-option label="重启设备" value="reboot" /><el-option label="配置更新" value="config_update" /><el-option
              label="服务重启"
              value="service_restart" /><el-option label="防火墙规则" value="firewall_rule" /></el-select
        ></el-form-item>
        <el-form-item label="参数"
          ><el-input v-model="commandForm.params" type="textarea" :rows="3" placeholder="请输入指令参数"
        /></el-form-item>
      </el-form>
      <template #footer
        ><el-button @click="showCommand = false">取消</el-button
        ><el-button type="primary" @click="sendCommand">下发</el-button></template
      >
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, nextTick } from 'vue';
import { ElMessage } from 'element-plus';
import { legacyApi } from '@/api';
import * as echarts from 'echarts';

const loading = ref(false);
const devices = ref<Array<Record<string, any>>>([]);
const pagination = reactive({ page: 1, pageSize: 10 });
const showDetail = ref(false);
const showCommand = ref(false);
const selectedDevice = ref<Record<string, any> | null>(null);
const commandForm = reactive({ type: '', params: '' });
const commandHistory = ref<Array<Record<string, any>>>([]);
let perfCharts: echarts.ECharts[] = [];
const paginatedDevices = computed(() => {
  const s = (pagination.page - 1) * pagination.pageSize;
  return devices.value.slice(s, s + pagination.pageSize);
});

function demoDevices() {
  const types = ['Linux服务器', 'Windows服务器', '网络设备', '安全设备', '数据库服务器', 'Web服务器'];
  return Array.from({ length: 25 }, (_, i) => ({
    id: 'DEV-' + (5000 + i),
    ip: `10.0.${Math.floor(i / 10)}.${(i % 10) + 1}`,
    hostname: `node-${String(i + 1).padStart(3, '0')}`,
    type: types[Math.floor(Math.random() * types.length)],
    online: Math.random() > 0.2,
    lastHeartbeat: new Date(Date.now() - Math.random() * 600000).toLocaleString('zh-CN'),
    agentVersion: `2.${Math.floor(Math.random() * 5)}.${Math.floor(Math.random() * 10)}`,
    cpu: Math.floor(Math.random() * 80) + 10,
    memory: Math.floor(Math.random() * 70) + 20,
    networkIn: Math.floor(Math.random() * 500) + 10,
    networkOut: Math.floor(Math.random() * 200) + 5
  }));
}

async function loadDevices() {
  try {
    const res = await legacyApi.get('/device/list');
    if (res && res.code === 0) {
      devices.value = ((res.data as any[]) || []).map((d) => {
        const metrics = typeof d.metrics === 'string' ? JSON.parse(d.metrics) : d.metrics || {};
        return {
          id: d.device_id,
          hostname: d.device_id,
          ip: d.ip,
          type: d.device_type,
          online: !!d.online_status,
          agentVersion: d.agent_version || '-',
          lastHeartbeat: d.last_heartbeat ? new Date(d.last_heartbeat).toLocaleString('zh-CN') : '-',
          cpu: metrics.cpu || 30,
          memory: metrics.memory || 45,
          networkIn: metrics.network_in || 50,
          networkOut: metrics.network_out || 20
        };
      });
    }
  } catch (e) {
    devices.value = demoDevices();
  }
}

onMounted(() => {
  loadDevices();
});

async function viewDetail(device: Record<string, any>) {
  selectedDevice.value = device;
  showDetail.value = true;
  try {
    const res = await legacyApi.get('/device/' + device.id + '/commands');
    if (res && res.code === 0) {
      commandHistory.value = ((res.data as any[]) || []).map((c) => ({
        id: 'CMD-' + c.id,
        type: c.command,
        status: c.status,
        time: c.created_at ? new Date(c.created_at).toLocaleString('zh-CN') : '-'
      }));
    }
  } catch (e) {
    commandHistory.value = Array.from({ length: 10 }, (_, i) => ({
      id: 'CMD-' + (9000 + i),
      type: ['重启', '配置更新', '服务重启', '防火墙规则'][Math.floor(Math.random() * 4)],
      status: Math.random() > 0.1 ? 'success' : 'failed',
      time: new Date(Date.now() - Math.random() * 7 * 86400000).toLocaleString('zh-CN')
    }));
  }
  nextTick(() => {
    initPerfCharts();
  });
}

function openCommand(device: Record<string, any>) {
  selectedDevice.value = device;
  commandForm.type = '';
  commandForm.params = '';
  showCommand.value = true;
}

async function sendCommand() {
  if (!commandForm.type) {
    ElMessage.warning('请选择指令类型');
    return;
  }
  if (!selectedDevice.value) {
    ElMessage.warning('请先选择设备');
    return;
  }
  const deviceId = selectedDevice.value.id;
  loading.value = true;
  try {
    const res = await legacyApi.post('/device/' + deviceId + '/command', {
      command: commandForm.type,
      params: commandForm.params ? JSON.parse(commandForm.params) : {}
    });
    if (res && res.code === 0) {
      ElMessage.success('指令已下发');
    }
  } catch (e) {
    ElMessage.error('指令下发失败');
  }
  showCommand.value = false;
  loading.value = false;
}

function initPerfCharts() {
  if (!selectedDevice.value) return;
  const device = selectedDevice.value;
  perfCharts.forEach((c) => c.dispose());
  perfCharts = [];
  const cpuEl = document.getElementById('device-cpu-chart');
  const memEl = document.getElementById('device-mem-chart');
  const netEl = document.getElementById('device-net-chart');
  if (!cpuEl || !memEl || !netEl) return;
  const timeLabels: string[] = [];
  for (let i = 59; i >= 0; i--) {
    const d = new Date(Date.now() - i * 60000);
    timeLabels.push(d.getHours() + ':' + String(d.getMinutes()).padStart(2, '0'));
  }
  const genData = (base: number, range: number) =>
    Array.from({ length: 60 }, () => Math.max(0, Math.min(100, base + Math.random() * range - range / 2)));
  const baseOpt = (color: string, data: number[]) => ({
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#16213e',
      borderColor: 'rgba(0,212,255,0.2)',
      textStyle: { color: '#c0c0c0' }
    },
    grid: { left: '3%', right: '4%', bottom: '3%', top: '15%', containLabel: true },
    xAxis: {
      type: 'category',
      data: timeLabels,
      axisLine: { lineStyle: { color: 'rgba(0,212,255,0.2)' } },
      axisLabel: { color: '#909399', interval: 14 }
    },
    yAxis: {
      type: 'value',
      max: 100,
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(0,212,255,0.06)' } },
      axisLabel: { color: '#909399' }
    },
    series: [{ type: 'line', smooth: true, data, lineStyle: { color, width: 2 }, itemStyle: { color } }]
  });

  const cpuChart = echarts.init(cpuEl);
  cpuChart.setOption(baseOpt('#00d4ff', genData(device.cpu, 20)));
  perfCharts.push(cpuChart);
  const memChart = echarts.init(memEl);
  memChart.setOption(baseOpt('#7c3aed', genData(device.memory, 15)));
  perfCharts.push(memChart);
  const netChart = echarts.init(netEl);
  netChart.setOption({
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#16213e',
      borderColor: 'rgba(0,212,255,0.2)',
      textStyle: { color: '#c0c0c0' }
    },
    legend: { data: ['入站', '出站'], top: '5%', textStyle: { color: '#c0c0c0' }, itemWidth: 16, itemHeight: 3 },
    grid: { left: '3%', right: '4%', bottom: '3%', top: '20%', containLabel: true },
    xAxis: {
      type: 'category',
      data: timeLabels,
      axisLine: { lineStyle: { color: 'rgba(0,212,255,0.2)' } },
      axisLabel: { color: '#909399', interval: 14 }
    },
    yAxis: {
      type: 'value',
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(0,212,255,0.06)' } },
      axisLabel: { color: '#909399' }
    },
    series: [
      {
        name: '入站',
        type: 'line',
        smooth: true,
        data: genData(device.networkIn, 100),
        lineStyle: { color: '#00d4ff', width: 2 },
        itemStyle: { color: '#00d4ff' }
      },
      {
        name: '出站',
        type: 'line',
        smooth: true,
        data: genData(device.networkOut, 50),
        lineStyle: { color: '#7c3aed', width: 2 },
        itemStyle: { color: '#7c3aed' }
      }
    ]
  });
  perfCharts.push(netChart);
}
</script>
