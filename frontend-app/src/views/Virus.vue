<template>
  <div v-loading="loading">
    <div class="page-header">
      <div>
        <div class="page-title">病毒查杀 - 多引擎协同检测</div>
        <div class="page-desc">本地哈希 + 360天眼 + 卡巴斯基 + AI恶意检测 + AI投毒检测</div>
      </div>
    </div>
    <div class="chart-card" style="margin-bottom: 20px">
      <div class="chart-card-title">文件上传检测</div>
      <el-upload
        v-model:file-list="fileList"
        drag
        :auto-upload="false"
        :limit="1"
        accept=".exe,.dll,.bat,.msi,.sys,.pdf,.doc,.xls,.zip,.rar,.py,.sh"
      >
        <div class="upload-icon">
          <el-icon :size="48"><UploadFilled /></el-icon>
        </div>
        <div class="upload-text">将文件拖到此处，或点击上传</div>
        <div class="upload-hint">支持所有文件类型，多引擎并行扫描</div>
      </el-upload>
      <div style="margin-top: 16px">
        <el-button type="primary" :loading="uploading" :disabled="fileList.length === 0" @click="handleUpload">
          <el-icon><Microscope /></el-icon> 开始多引擎扫描
        </el-button>
      </div>
    </div>

    <!-- 多引擎扫描进度 -->
    <div v-if="detecting || detectResult" class="chart-card" style="margin-bottom: 20px">
      <div class="chart-card-title">扫描引擎状态</div>
      <div
        style="display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; margin-top: 12px"
      >
        <div
          v-for="(eng, idx) in engineProgress"
          :key="idx"
          :style="{
            background: 'rgba(26,26,46,0.8)',
            border:
              '1px solid ' +
              (eng.status === 'done' && eng.verdict === 'malicious'
                ? '#f56c6c'
                : eng.status === 'done'
                  ? '#67c23a'
                  : eng.status === 'scanning'
                    ? '#e6a23c'
                    : '#444'),
            borderRadius: '8px',
            padding: '12px'
          }"
        >
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px">
            <el-icon :size="20"><component :is="eng.icon" /></el-icon>
            <span style="color: #e0e0e0; font-weight: bold">{{ eng.name }}</span>
            <span v-if="eng.status === 'scanning'" style="color: #e6a23c"
              ><el-icon class="is-loading"><Loading /></el-icon
            ></span>
            <span v-else-if="eng.status === 'done'" style="color: #67c23a">&#10004;</span>
            <span v-else-if="eng.status === 'skipped'" style="color: #909399">&#9197;</span>
            <span v-else-if="eng.status === 'error'" style="color: #f56c6c">&#10008;</span>
            <span v-else style="color: #666">&#9675;</span>
          </div>
          <div v-if="eng.verdict && eng.status === 'done'" style="font-size: 12px">
            <span
              :style="{
                color:
                  eng.verdict === 'malicious' || eng.verdict === 'poisoned'
                    ? '#f56c6c'
                    : eng.verdict === 'suspicious'
                      ? '#e6a23c'
                      : '#67c23a'
              }"
            >
              {{
                eng.verdict === 'malicious'
                  ? '恶意'
                  : eng.verdict === 'suspicious'
                    ? '疑似'
                    : eng.verdict === 'poisoned'
                      ? '投毒'
                      : eng.verdict === 'clean'
                        ? '安全'
                        : '未知'
              }}
            </span>
            <span v-if="eng.confidence" style="color: #aaa; margin-left: 4px"
              >({{ (eng.confidence * 100).toFixed(0) }}%)</span
            >
          </div>
          <div v-if="eng.time" style="color: #888; font-size: 11px">{{ eng.time }}</div>
          <div
            v-if="eng.detail && eng.status !== 'scanning'"
            style="color: #aaa; font-size: 11px; margin-top: 4px; word-break: break-all"
          >
            {{ eng.detail }}
          </div>
        </div>
      </div>
    </div>

    <!-- AI决策结果 -->
    <div v-if="detectResult && !detecting" style="margin-bottom: 20px">
      <div
        :style="{
          background: 'rgba(26,26,46,0.8)',
          border:
            '2px solid ' +
            (detectResult.verdict === 'malicious'
              ? '#f56c6c'
              : detectResult.verdict === 'suspicious'
                ? '#e6a23c'
                : '#67c23a'),
          borderRadius: '12px',
          padding: '20px'
        }"
      >
        <div style="display: flex; align-items: center; gap: 16px; margin-bottom: 16px">
          <span :style="{ fontSize: '48px' }">{{
            detectResult.verdict === 'malicious'
              ? '&#128308;'
              : detectResult.verdict === 'suspicious'
                ? '&#128993;'
                : '&#128994;'
          }}</span>
          <div>
            <div
              style="font-size: 20px; font-weight: bold"
              :style="{
                color:
                  detectResult.verdict === 'malicious'
                    ? '#f56c6c'
                    : detectResult.verdict === 'suspicious'
                      ? '#e6a23c'
                      : '#67c23a'
              }"
            >
              {{
                detectResult.verdict === 'malicious'
                  ? '检测到恶意文件'
                  : detectResult.verdict === 'suspicious'
                    ? '检测到疑似威胁'
                    : '文件安全'
              }}
            </div>
            <div style="color: #aaa; font-size: 13px">
              置信度: {{ (detectResult.confidence * 100).toFixed(1) }}% | 主要引擎: {{ detectResult.primaryEngine }} |
              耗时: {{ detectResult.totalTime }}s
            </div>
          </div>
        </div>
        <div style="color: #e0e0e0; font-size: 13px; line-height: 1.8">
          <strong>处置建议:</strong> {{ detectResult.recommendation }}
        </div>
        <div style="margin-top: 12px; display: flex; gap: 8px">
          <el-button type="primary" size="small" @click="viewReport(detectResult.scanId)">查看详细报告</el-button>
          <el-button type="success" size="small" :disabled="!reportContent" @click="downloadReport">下载报告</el-button>
        </div>
      </div>
    </div>

    <!-- 报告对话框 -->
    <el-dialog v-model="showReportDialog" title="查杀报告" width="70%" top="5vh">
      <div style="max-height: 70vh; overflow-y: auto">
        <pre style="color: #e0e0e0; white-space: pre-wrap; font-family: monospace; font-size: 13px; line-height: 1.8">{{
          reportContent
        }}</pre>
      </div>
      <template #footer>
        <el-button @click="showReportDialog = false">关闭</el-button>
        <el-button type="success" @click="downloadReport">下载Markdown</el-button>
      </template>
    </el-dialog>

    <!-- 历史记录 -->
    <div class="chart-card" style="margin-top: 20px">
      <div class="chart-card-title">扫描历史记录</div>
      <el-table :data="paginatedRecords" size="small" style="width: 100%">
        <el-table-column prop="filename" label="文件名" min-width="150" />
        <el-table-column prop="hash" label="MD5" width="120">
          <template #default="{ row }"
            ><span style="font-size: 11px; font-family: monospace">{{ row.hash?.substring(0, 12) }}...</span></template
          >
        </el-table-column>
        <el-table-column prop="verdict" label="判定" width="80">
          <template #default="{ row }">
            <el-tag
              :type="row.verdict === 'malicious' ? 'danger' : row.verdict === 'suspicious' ? 'warning' : 'success'"
              size="small"
            >
              {{ row.verdict === 'malicious' ? '恶意' : row.verdict === 'suspicious' ? '疑似' : '安全' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="source" label="主要引擎" width="120" />
        <el-table-column prop="confidence" label="置信度" width="80" />
        <el-table-column prop="time" label="时间" width="160" />
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-button v-if="row.scanId" type="primary" link size="small" @click="viewReport(row.scanId)"
              >报告</el-button
            >
          </template>
        </el-table-column>
      </el-table>
      <div style="margin-top: 16px; display: flex; justify-content: flex-end">
        <el-pagination
          v-model:current-page="pagination.page"
          small
          layout="total, prev, pager, next"
          :total="records.length"
          :page-size="pagination.pageSize"
        />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { ElMessage, type UploadUserFile } from 'element-plus';
import { legacyApi } from '@/api';
import http from '@/api/http';

const loading = ref(false);
const uploading = ref(false);
const detecting = ref(false);
const detectResult = ref<Record<string, any> | null>(null);
const records = ref<Array<Record<string, any>>>([]);
const pagination = reactive({ page: 1, pageSize: 10 });
const fileList = ref<UploadUserFile[]>([]);
const showReportDialog = ref(false);
const reportContent = ref('');
const engineProgress = reactive([
  { name: '本地哈希库', icon: 'Database', status: 'pending', verdict: '', confidence: 0, detail: '', time: '' },
  { name: '360天眼', icon: 'Shield', status: 'pending', verdict: '', confidence: 0, detail: '', time: '' },
  { name: '卡巴斯基', icon: 'Lock', status: 'pending', verdict: '', confidence: 0, detail: '', time: '' },
  { name: 'AI恶意检测', icon: 'Cpu', status: 'pending', verdict: '', confidence: 0, detail: '', time: '' },
  { name: 'AI投毒检测', icon: 'Warning', status: 'pending', verdict: '', confidence: 0, detail: '', time: '' }
]);
const paginatedRecords = computed(() => {
  const s = (pagination.page - 1) * pagination.pageSize;
  return records.value.slice(s, s + pagination.pageSize);
});

function demoVirusRecords() {
  const conclusions = ['malicious', 'benign', 'suspicious'];
  const sources = ['哈希匹配', 'VirusTotal', 'AI模型分析'];
  const filenames = [
    'update_v2.exe',
    'report.pdf.exe',
    'tool_setup.msi',
    'config.xml',
    'backup.zip',
    'patch.bat',
    'service.dll',
    'driver.sys'
  ];
  return Array.from({ length: 30 }, (_, i) => ({
    id: 'VIR-' + (3000 + i),
    filename: filenames[Math.floor(Math.random() * filenames.length)],
    filesize: Math.floor(Math.random() * 50000) + 100,
    hash: Array.from({ length: 32 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join(''),
    conclusion: conclusions[Math.floor(Math.random() * conclusions.length)],
    source: sources[Math.floor(Math.random() * sources.length)],
    confidence: (60 + Math.random() * 40).toFixed(1),
    time: new Date(Date.now() - Math.random() * 30 * 86400000).toLocaleString('zh-CN')
  }));
}

async function loadRecords() {
  try {
    const res = await legacyApi.get('/virus/records');
    if (res && res.code === 0) {
      records.value = ((res.data as Array<Record<string, any>>) || []).map((r) => ({
        id: 'VIR-' + r.id,
        filename: r.file_name,
        filesize: r.file_size || 0,
        hash: r.file_hash_md5 || '',
        conclusion: r.detection_result || 'benign',
        source: r.detection_source || '未知',
        confidence: r.model_score ? (r.model_score * 100).toFixed(1) : '-',
        time: r.created_at ? new Date(r.created_at).toLocaleString('zh-CN') : '-'
      }));
    }
  } catch (e) {
    records.value = demoVirusRecords();
  }
}

onMounted(() => {
  loadRecords();
});

async function handleUpload() {
  const raw = fileList.value[0]?.raw;
  if (!raw) {
    ElMessage.warning('请先选择文件');
    return;
  }
  uploading.value = true;
  detecting.value = true;
  detectResult.value = null;

  // 重置引擎进度
  engineProgress.forEach((e) => {
    e.status = 'scanning';
  });

  try {
    const formData = new FormData();
    formData.append('file', raw);

    const resp = await http.post('/virus/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });

    const res = resp.data;
    if (res && res.code === 0) {
      const d = res.data;

      // 更新引擎结果
      if (d.engines) {
        const engineMap: Record<string, number> = {
          local_hash: 0,
          '360_ti': 1,
          kaspersky: 2,
          ai_malware: 3,
          ai_poisoning: 4
        };
        for (const [key, result] of Object.entries(d.engines)) {
          const r = result as Record<string, any>;
          const idx = engineMap[key];
          if (idx !== undefined) {
            engineProgress[idx].status =
              r.status === 'completed' ? 'done' : r.status === 'skipped' ? 'skipped' : 'error';
            engineProgress[idx].verdict = r.verdict;
            engineProgress[idx].confidence = r.confidence;
            engineProgress[idx].detail = r.detail || '';
            engineProgress[idx].time = (r.responseTime / 1000).toFixed(1) + 's';
          }
        }
      }

      // 最终结果
      detectResult.value = {
        filename: d.fileName,
        filesize: d.fileSize,
        hash: d.hashes?.sha256 || d.hashes?.md5 || '',
        verdict: d.decision?.verdict || 'clean',
        confidence: d.decision?.confidence || 0,
        primaryEngine: d.decision?.primaryEngine || '',
        recommendation: d.decision?.recommendation || '',
        scanId: d.scanId,
        totalTime: d.totalTime || 0,
        report: d.report
      };

      // 添加到历史记录
      records.value.unshift({
        id: 'VIR-' + d.recordId,
        filename: d.fileName,
        filesize: d.fileSize || 0,
        hash: d.hashes?.md5 || '',
        verdict: detectResult.value.verdict,
        source: d.decision?.primaryEngine || '多引擎',
        confidence: (detectResult.value.confidence * 100).toFixed(1),
        time: new Date().toLocaleString('zh-CN'),
        scanId: d.scanId
      });
    }
  } catch (e: any) {
    engineProgress.forEach((ep) => {
      ep.status = 'error';
      ep.detail = '调用失败';
    });
    ElMessage.error('扫描失败: ' + (e.response?.data?.message || e.message));
  }
  detecting.value = false;
  uploading.value = false;
}

async function viewReport(scanId: string) {
  if (!scanId) {
    ElMessage.warning('无报告ID');
    return;
  }
  try {
    const res = await legacyApi.get('/virus/report/' + scanId);
    if (res && res.code === 0 && res.data) {
      const data = res.data as Record<string, any>;
      reportContent.value = data.report?.aiSummary || data.report?.title || '无报告内容';
      showReportDialog.value = true;
    }
  } catch (e) {
    ElMessage.error('获取报告失败');
  }
}

function downloadReport() {
  if (!reportContent.value) return;
  const blob = new Blob([reportContent.value], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = (detectResult.value?.filename || 'scan_report') + '_查杀报告.md';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  ElMessage.success('报告已下载');
}
</script>
