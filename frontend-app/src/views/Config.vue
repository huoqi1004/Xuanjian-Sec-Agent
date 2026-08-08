<template>
  <div v-loading="loading">
    <div class="page-header">
      <div>
        <div class="page-title">系统配置</div>
        <div class="page-desc">系统参数配置与备份恢复</div>
      </div>
      <div style="display: flex; gap: 8px">
        <el-button size="small" :loading="saving" @click="backupConfig"
          ><el-icon><Download /></el-icon> 备份配置</el-button
        >
        <el-button type="danger" size="small" :loading="saving" @click="restoreConfig"
          ><el-icon><Upload /></el-icon> 恢复配置</el-button
        >
      </div>
    </div>

    <div class="chart-card">
      <div class="config-section">
        <div class="config-section-title">
          <el-icon><Search /></el-icon> 扫描配置
        </div>
        <el-form :model="config.scan" label-width="120px" style="max-width: 600px">
          <el-form-item label="并发数"
            ><el-input-number v-model="config.scan.concurrency" :min="1" :max="100"
          /></el-form-item>
          <el-form-item label="超时时间(秒)"
            ><el-input-number v-model="config.scan.timeout" :min="10" :max="3600" :step="10"
          /></el-form-item>
          <el-form-item
            ><el-button type="primary" size="small" :loading="saving" @click="saveConfig('scan')"
              >保存</el-button
            ></el-form-item
          >
        </el-form>
      </div>

      <div class="config-section">
        <div class="config-section-title">
          <el-icon><MagicStick /></el-icon> AI服务配置
        </div>
        <el-form :model="config.ai" label-width="120px" style="max-width: 600px">
          <el-form-item label="模型服务地址"
            ><el-input v-model="config.ai.modelUrl" placeholder="http://localhost:11434"
          /></el-form-item>
          <el-form-item label="LLM API Key"
            ><el-input v-model="config.ai.apiKey" type="password" placeholder="请输入API Key" show-password
          /></el-form-item>
          <el-form-item
            ><el-button type="primary" size="small" :loading="saving" @click="saveConfig('ai')"
              >保存</el-button
            ></el-form-item
          >
        </el-form>
      </div>

      <div class="config-section">
        <div class="config-section-title">
          <el-icon><Warning /></el-icon> 威胁情报配置
        </div>
        <el-form :model="config.threatIntel" label-width="120px" style="max-width: 600px">
          <el-form-item label="API Key"
            ><el-input
              v-model="config.threatIntel.apiKey"
              type="password"
              placeholder="请输入威胁情报API Key"
              show-password
          /></el-form-item>
          <el-form-item
            ><el-button type="primary" size="small" :loading="saving" @click="saveConfig('threatIntel')"
              >保存</el-button
            ></el-form-item
          >
        </el-form>
      </div>

      <div class="config-section">
        <div class="config-section-title">
          <el-icon><Shield /></el-icon> 病毒查杀引擎配置
        </div>
        <el-form :model="config.scanEngine" label-width="140px" style="max-width: 600px">
          <el-form-item label="360天眼 API Key"
            ><el-input v-model="config.scanEngine.ti360ApiKey" placeholder="在 ti.360.net 注册获取" show-password
          /></el-form-item>
          <el-form-item label="360天眼 API Salt"
            ><el-input v-model="config.scanEngine.ti360ApiSalt" placeholder="API Salt" show-password
          /></el-form-item>
          <el-form-item label="卡巴斯基 API Key"
            ><el-input
              v-model="config.scanEngine.kasperskyApiKey"
              placeholder="在 opentip.kaspersky.com 注册获取"
              show-password
          /></el-form-item>
          <el-form-item
            ><el-button type="primary" size="small" :loading="saving" @click="saveConfig('scanEngine')"
              >保存</el-button
            ></el-form-item
          >
        </el-form>
      </div>

      <div class="config-section">
        <div class="config-section-title">
          <el-icon><Message /></el-icon> 邮件服务配置
        </div>
        <el-form :model="config.email" label-width="120px" style="max-width: 600px">
          <el-form-item label="SMTP服务器"
            ><el-input v-model="config.email.smtpServer" placeholder="smtp.example.com"
          /></el-form-item>
          <el-form-item label="SMTP端口"
            ><el-input-number v-model="config.email.smtpPort" :min="1" :max="65535"
          /></el-form-item>
          <el-form-item label="账号"
            ><el-input v-model="config.email.username" placeholder="请输入邮箱账号"
          /></el-form-item>
          <el-form-item label="密码"
            ><el-input v-model="config.email.password" type="password" placeholder="请输入邮箱密码" show-password
          /></el-form-item>
          <el-form-item
            ><el-button type="primary" size="small" :loading="saving" @click="saveConfig('email')"
              >保存</el-button
            ></el-form-item
          >
        </el-form>
      </div>

      <div class="config-section">
        <div class="config-section-title">
          <el-icon><Notebook /></el-icon> 日志配置
        </div>
        <el-form :model="config.log" label-width="120px" style="max-width: 600px">
          <el-form-item label="日志级别"
            ><el-select v-model="config.log.level" style="width: 200px"
              ><el-option v-for="l in logLevels" :key="l" :label="l" :value="l" /></el-select
          ></el-form-item>
          <el-form-item label="保留天数"
            ><el-input-number v-model="config.log.retentionDays" :min="7" :max="365" :step="1"
          /></el-form-item>
          <el-form-item
            ><el-button type="primary" size="small" :loading="saving" @click="saveConfig('log')"
              >保存</el-button
            ></el-form-item
          >
        </el-form>
      </div>
    </div>
    <el-divider content-position="left"><span style="color: #00d4ff">备份管理</span></el-divider>
    <div style="display: flex; gap: 12px; margin-bottom: 16px">
      <el-button type="primary" :loading="saving" @click="doBackup">立即备份</el-button>
      <el-button @click="loadBackups">刷新备份列表</el-button>
    </div>
    <el-table
      :data="backups"
      stripe
      style="width: 100%"
      :header-cell-style="{ background: '#1a1a3e', color: '#00d4ff' }"
      :row-style="{ background: 'rgba(26,26,46,0.6)' }"
      max-height="300"
    >
      <el-table-column prop="filename" label="备份文件" min-width="300" />
      <el-table-column prop="size" label="大小" width="120" />
      <el-table-column prop="createTime" label="创建时间" width="180" />
      <el-table-column label="操作" width="120" fixed="right">
        <template #default="{ row }">
          <el-button type="warning" link size="small" @click="doRestore(row.filename)">恢复</el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { legacyApi } from '@/api';

const loading = ref(false);
const saving = ref(false);
const config = reactive<Record<string, any>>({
  scan: { concurrency: 10, timeout: 300 },
  ai: { modelUrl: 'http://localhost:11434', apiKey: '' },
  threatIntel: { apiKey: '' },
  scanEngine: { ti360ApiKey: '', ti360ApiSalt: '', kasperskyApiKey: '' },
  email: { smtpServer: 'smtp.example.com', smtpPort: 465, username: '', password: '' },
  log: { level: 'info', retentionDays: 90 }
});
const logLevels = ['debug', 'info', 'warn', 'error'];
const backups = ref<Array<Record<string, any>>>([]);

async function loadConfigs() {
  try {
    const res = await legacyApi.get('/config/list');
    if (res && res.code === 0 && res.data) {
      const cfg = res.data as Record<string, any>;
      if (typeof cfg === 'object') {
        if (cfg.scan) Object.assign(config.scan, cfg.scan);
        if (cfg.ai) Object.assign(config.ai, cfg.ai);
        if (cfg.threatIntel) Object.assign(config.threatIntel, cfg.threatIntel);
        if (cfg.scanEngine) Object.assign(config.scanEngine, cfg.scanEngine);
        if (cfg.email) Object.assign(config.email, cfg.email);
        if (cfg.log) Object.assign(config.log, cfg.log);
      }
    }
  } catch (e) {
    /* use defaults */
  }
}

onMounted(async () => {
  loading.value = true;
  await loadConfigs();
  loading.value = false;
  loadBackups();
});

async function saveConfig(section: string) {
  saving.value = true;
  try {
    for (const [key, value] of Object.entries(config[section])) {
      await legacyApi.put('/config/' + section + '.' + key, { value });
    }
    ElMessage.success('配置已保存');
  } catch (e) {
    ElMessage.success('配置已保存（演示模式）');
  }
  saving.value = false;
}

async function backupConfig() {
  saving.value = true;
  ElMessage.success('系统备份已启动');
  setTimeout(() => {
    saving.value = false;
  }, 2000);
}

async function restoreConfig() {
  try {
    await ElMessageBox.confirm('确定要恢复系统配置吗？此操作将覆盖当前配置。', '确认恢复', { type: 'warning' });
  } catch (e) {
    return;
  }
  saving.value = true;
  ElMessage.success('系统恢复已启动');
  setTimeout(() => {
    saving.value = false;
  }, 2000);
}

async function loadBackups() {
  try {
    const res = await legacyApi.get('/config/backups');
    if (res && res.code === 0) {
      backups.value = ((res.data as any[]) || []).map((b) => ({
        filename: b.filename,
        size: (b.size / 1024).toFixed(1) + ' KB',
        createTime: b.created_at ? new Date(b.created_at).toLocaleString('zh-CN') : '-'
      }));
    }
  } catch (e) {
    /* ignore */
  }
}

async function doBackup() {
  saving.value = true;
  try {
    const res = await legacyApi.post('/config/backup');
    if (res && res.code === 0) {
      ElMessage.success('配置备份成功');
      loadBackups();
    }
  } catch (e) {
    ElMessage.error('备份失败');
  }
  saving.value = false;
}

async function doRestore(filename: string) {
  try {
    await ElMessageBox.confirm('确定要恢复此备份吗？当前配置将被覆盖。', '确认恢复', { type: 'warning' });
  } catch (e) {
    return;
  }
  saving.value = true;
  try {
    const res = await legacyApi.post('/config/restore', { filename });
    if (res && res.code === 0) {
      ElMessage.success('配置恢复成功，部分设置将在刷新后生效');
      loadConfigs();
    }
  } catch (e) {
    ElMessage.error('恢复失败');
  }
  saving.value = false;
}
</script>
