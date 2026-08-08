<template>
  <div class="playbook-page">
    <!-- 顶部操作栏 -->
    <div class="toolbar">
      <div>
        <el-button type="primary" :icon="Refresh" @click="loadList">刷新</el-button>
        <el-button v-if="isAdmin" :icon="Plus" @click="openCreate">新建剧本</el-button>
        <el-button v-if="isAdmin" :icon="Files" @click="seedTemplates">导入模板</el-button>
      </div>
      <div v-if="pendingApprovals.length > 0" class="pending-tip">
        <el-badge :value="pendingApprovals.length" type="danger">
          <el-button size="small" @click="openApprovals">待审批</el-button>
        </el-badge>
      </div>
    </div>

    <!-- 剧本列表 -->
    <el-card shadow="never" class="table-card">
      <el-table v-loading="loading" :data="list" stripe>
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="name" label="名称" min-width="160" show-overflow-tooltip />
        <el-table-column prop="trigger" label="触发" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="triggerTag(row.trigger)">{{ row.trigger }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="描述" min-width="220" show-overflow-tooltip />
        <el-table-column label="步骤数" width="90" align="center">
          <template #default="{ row }">{{ row.steps?.length || 0 }}</template>
        </el-table-column>
        <el-table-column label="启用" width="90" align="center">
          <template #default="{ row }">
            <el-switch :model-value="row.enabled === 1" :disabled="!isAdmin" @change="(v: boolean) => toggle(row, v)" />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="300" fixed="right">
          <template #default="{ row }">
            <el-button size="small" type="primary" plain @click="openDetail(row)">详情</el-button>
            <el-button size="small" type="success" plain @click="openExecute(row)">执行</el-button>
            <template v-if="isAdmin">
              <el-button size="small" plain @click="openEdit(row)">编辑</el-button>
              <el-popconfirm title="确认删除该剧本？" @confirm="remove(row)">
                <template #reference>
                  <el-button size="small" type="danger" plain>删除</el-button>
                </template>
              </el-popconfirm>
            </template>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 创建/编辑对话框 -->
    <el-dialog v-model="editVisible" :title="editing ? '编辑剧本' : '新建剧本'" width="680px">
      <el-form :model="form" label-width="90px">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="剧本名称" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" type="textarea" :rows="2" placeholder="剧本用途说明" />
        </el-form-item>
        <el-form-item label="触发">
          <el-select v-model="form.trigger" placeholder="触发方式">
            <el-option label="手动触发" value="manual" />
            <el-option label="暴力破解" value="brute_force" />
            <el-option label="情报命中" value="intel_match" />
            <el-option label="勒索告警" value="ransomware" />
          </el-select>
        </el-form-item>
        <el-form-item label="步骤 JSON">
          <el-input v-model="stepsJson" type="textarea" :rows="10" :placeholder="stepPlaceholder" />
          <div class="form-tip">{{ stepTip }}</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </template>
    </el-dialog>

    <!-- 详情抽屉 -->
    <el-drawer v-model="detailVisible" :title="detail?.name" size="560px">
      <el-descriptions :column="1" border>
        <el-descriptions-item label="描述">{{ detail?.description || '-' }}</el-descriptions-item>
        <el-descriptions-item label="触发">{{ detail?.trigger }}</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="detail?.enabled === 1 ? 'success' : 'info'">{{
            detail?.enabled === 1 ? '已启用' : '已停用'
          }}</el-tag>
        </el-descriptions-item>
      </el-descriptions>
      <h4>执行步骤</h4>
      <el-timeline v-if="detail?.steps?.length">
        <el-timeline-item v-for="(s, i) in detail.steps" :key="i" :type="stepType(s.type)" :hollow="true">
          <div class="step-item">
            <el-tag size="small" :type="stepType(s.type)">{{ stepLabel(s) }}</el-tag>
            <span class="step-name">{{ s.name || stepDesc(s) }}</span>
          </div>
        </el-timeline-item>
      </el-timeline>
      <el-empty v-else description="暂无步骤" :image-size="60" />
    </el-drawer>

    <!-- 执行对话框 -->
    <el-dialog v-model="execVisible" :title="`执行剧本：${execTarget?.name || ''}`" width="600px">
      <el-form label-width="90px">
        <el-form-item label="事件 JSON">
          <el-input
            v-model="eventJson"
            type="textarea"
            :rows="8"
            placeholder='{"ip":"185.220.101.34","severity":"high","confidence":0.9,"fail_count":8}'
          />
          <div class="form-tip">事件字段供 condition 判断与动作参数「字段名」引用。</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="execVisible = false">取消</el-button>
        <el-button type="primary" :loading="executing" @click="doExecute">执行</el-button>
      </template>
    </el-dialog>

    <!-- 执行结果 -->
    <el-dialog v-model="resultVisible" title="执行结果" width="640px">
      <el-alert
        v-if="runResult"
        :type="
          runResult.status === 'completed' ? 'success' : runResult.status === 'awaiting_approval' ? 'warning' : 'error'
        "
        :title="`状态：${runResult.status || 'unknown'}`"
        :description="runResult.success ? `运行ID: ${runResult.run_id}` : runResult.error"
        :closable="false"
        show-icon
        style="margin-bottom: 12px"
      />
      <el-table v-if="runResult?.results?.length" :data="runResult.results" size="small" border max-height="380">
        <el-table-column label="步骤" width="120">
          <template #default="{ row }">{{ row.name || row.type }}</template>
        </el-table-column>
        <el-table-column label="类型" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="stepType(row.type)">{{ row.type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="结果" min-width="200">
          <template #default="{ row }">
            <span v-if="row.type === 'condition'">{{ row.ok ? '✅ 满足' : '⛔ 不满足' }}</span>
            <span v-else-if="row.success === false" class="err-text">{{ row.error || '失败' }}</span>
            <span v-else-if="row.status === 'pending'">等待人工审批（{{ row.approval_id }}）</span>
            <span v-else>{{ row.detail || row.message || '成功' }}</span>
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>

    <!-- 待审批列表 -->
    <el-dialog v-model="approvalVisible" title="待人工审批" width="620px">
      <el-table :data="pendingApprovals" size="small" border>
        <el-table-column prop="id" label="审批ID" width="130" />
        <el-table-column prop="title" label="事项" min-width="200" />
        <el-table-column prop="playbookId" label="剧本ID" width="80" />
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button size="small" type="success" @click="handleApproval(row, 'approve')">批准</el-button>
            <el-button size="small" type="danger" @click="handleApproval(row, 'reject')">拒绝</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-if="pendingApprovals.length === 0" description="暂无待审批事项" :image-size="60" />
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { ElMessage } from 'element-plus';
import { Refresh, Plus, Files } from '@element-plus/icons-vue';
import { playbookApi } from '@/api';
import { useUserStore } from '@/stores/user';
import type { Playbook, PlaybookStep, PlaybookRunResult } from '@/types';

const userStore = useUserStore();
const isAdmin = computed(() => userStore.user?.role_id === 1);

const list = ref<Playbook[]>([]);
const loading = ref(false);
const pendingApprovals = ref<Array<{ id: string; title: string; playbookId: number; status: string }>>([]);

const editVisible = ref(false);
const editing = ref<Playbook | null>(null);
const form = ref({ name: '', description: '', trigger: 'manual' });
const stepsJson = ref('[]');
const saving = ref(false);
// 占位提示（{{x}} 语法在模板中需经变量绑定，避免被解析为插值表达式）
const stepPlaceholder =
  '[{"type":"condition","fact":"fail_count","operator":"gt","value":5}, {"type":"action","action":"firewall_block","params":{"ip":"{{ip}}","duration":1800}}]';
const stepTip =
  '步骤类型：condition 条件 / action 动作(firewall_block,account_lock,raise_alert,notify,webhook,log_only) / approval 人工审批 / notification 通知 / wait 等待。动作参数支持 {{字段}} 引用执行事件字段。';

const detailVisible = ref(false);
const detail = ref<Playbook | null>(null);

const execVisible = ref(false);
const execTarget = ref<Playbook | null>(null);
const eventJson = ref('{}');
const executing = ref(false);

const resultVisible = ref(false);
const runResult = ref<PlaybookRunResult | null>(null);

const approvalVisible = ref(false);

async function loadList() {
  loading.value = true;
  try {
    const data = await playbookApi.list({ page: 1, pageSize: 100 });
    list.value = data.list ?? [];
  } catch (e) {
    ElMessage.error('加载剧本列表失败');
  } finally {
    loading.value = false;
  }
}

async function loadApprovals() {
  try {
    pendingApprovals.value = await playbookApi.pendingApprovals();
  } catch (e) {
    pendingApprovals.value = [];
  }
}

function triggerTag(trigger: string) {
  if (trigger === 'brute_force') return 'danger';
  if (trigger === 'intel_match') return 'warning';
  if (trigger === 'ransomware') return 'danger';
  return 'info';
}

function stepLabel(s: PlaybookStep) {
  const labels: Record<string, string> = {
    condition: '条件',
    action: '动作',
    approval: '审批',
    notification: '通知',
    wait: '等待'
  };
  return labels[s.type] || s.type;
}

function stepDesc(s: PlaybookStep) {
  if (s.type === 'condition') return `${s.fact} ${s.operator} ${JSON.stringify(s.value)}`;
  if (s.type === 'action') return `${s.action} ${JSON.stringify(s.params || {})}`;
  if (s.type === 'notification') return `通知（${s.channel || 'all'}）`;
  return '';
}

function stepType(type: string): 'primary' | 'success' | 'warning' | 'info' {
  if (type === 'action') return 'primary';
  if (type === 'approval') return 'warning';
  if (type === 'notification') return 'success';
  if (type === 'condition') return 'info';
  return 'info';
}

function openCreate() {
  editing.value = null;
  form.value = { name: '', description: '', trigger: 'manual' };
  stepsJson.value = JSON.stringify(
    [
      { type: 'condition', name: '条件示例', fact: 'severity', operator: 'eq', value: 'high' },
      { type: 'action', name: '封禁IP', action: 'firewall_block', params: { ip: '{{ip}}', duration: 3600 } }
    ],
    null,
    2
  );
  editVisible.value = true;
}

function openEdit(row: Playbook) {
  editing.value = row;
  form.value = { name: row.name, description: row.description || '', trigger: row.trigger || 'manual' };
  stepsJson.value = JSON.stringify(row.steps || [], null, 2);
  editVisible.value = true;
}

async function save() {
  if (!form.value.name) {
    ElMessage.warning('请输入剧本名称');
    return;
  }
  let steps: PlaybookStep[];
  try {
    steps = JSON.parse(stepsJson.value);
  } catch (e) {
    ElMessage.error('步骤 JSON 格式错误');
    return;
  }
  saving.value = true;
  try {
    if (editing.value) {
      await playbookApi.update(editing.value.id, { ...form.value, steps });
      ElMessage.success('剧本已更新');
    } else {
      await playbookApi.create({ ...form.value, steps });
      ElMessage.success('剧本创建成功');
    }
    editVisible.value = false;
    loadList();
  } catch (e) {
    ElMessage.error('保存失败');
  } finally {
    saving.value = false;
  }
}

async function toggle(row: Playbook, enabled: boolean) {
  try {
    await playbookApi.update(row.id, { enabled: enabled ? 1 : 0 });
    row.enabled = enabled ? 1 : 0;
    ElMessage.success(enabled ? '已启用' : '已停用');
  } catch (e) {
    ElMessage.error('操作失败');
  }
}

async function remove(row: Playbook) {
  try {
    await playbookApi.remove(row.id);
    ElMessage.success('剧本已删除');
    loadList();
  } catch (e) {
    ElMessage.error('删除失败');
  }
}

async function seedTemplates() {
  try {
    const r = await playbookApi.seedTemplates();
    ElMessage.success(`模板导入完成（新增 ${r.seeded} 个）`);
    loadList();
  } catch (e) {
    ElMessage.error('模板导入失败');
  }
}

async function openDetail(row: Playbook) {
  detail.value = row;
  detailVisible.value = true;
}

function openExecute(row: Playbook) {
  execTarget.value = row;
  eventJson.value = JSON.stringify({ ip: '185.220.101.34', severity: 'high', confidence: 0.9, fail_count: 8 }, null, 2);
  execVisible.value = true;
}

async function doExecute() {
  let event: Record<string, unknown>;
  try {
    event = JSON.parse(eventJson.value);
  } catch (e) {
    ElMessage.error('事件 JSON 格式错误');
    return;
  }
  executing.value = true;
  try {
    const r = await playbookApi.execute(execTarget.value!.id, event);
    runResult.value = r;
    execVisible.value = false;
    resultVisible.value = true;
    loadApprovals();
    loadList();
  } catch (e) {
    ElMessage.error('执行失败');
  } finally {
    executing.value = false;
  }
}

function openApprovals() {
  approvalVisible.value = true;
  loadApprovals();
}

async function handleApproval(row: { id: string }, decision: 'approve' | 'reject') {
  try {
    await playbookApi.confirmApproval(row.id, decision);
    ElMessage.success(decision === 'approve' ? '已批准' : '已拒绝');
    loadApprovals();
  } catch (e) {
    ElMessage.error('处理失败');
  }
}

onMounted(() => {
  loadList();
  loadApprovals();
});
</script>

<style scoped>
.playbook-page {
  padding: 4px;
}
.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}
.table-card {
  border-radius: 8px;
}
.form-tip {
  font-size: 12px;
  color: #909399;
  margin-top: 6px;
  line-height: 1.6;
}
.step-item {
  display: flex;
  align-items: center;
  gap: 8px;
}
.step-name {
  color: #606266;
}
.err-text {
  color: #f56c6c;
}
</style>
