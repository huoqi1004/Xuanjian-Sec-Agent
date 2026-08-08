<template>
  <div v-loading="loading">
    <div class="page-header">
      <div>
        <div class="page-title">自动化防御</div>
        <div class="page-desc">安全策略管理与自动化响应</div>
      </div>
      <el-button type="primary" size="small" @click="openCreateDialog"
        ><el-icon><Plus /></el-icon> 创建策略</el-button
      >
    </div>
    <div class="chart-card">
      <el-tabs v-model="activeTab">
        <el-tab-pane label="策略列表" name="policies">
          <el-table :data="paginatedPolicies" size="small" style="width: 100%">
            <el-table-column prop="id" label="ID" width="110" />
            <el-table-column prop="name" label="策略名称" min-width="140" />
            <el-table-column prop="condition" label="触发条件" min-width="200" show-overflow-tooltip />
            <el-table-column prop="action" label="执行动作" width="130" />
            <el-table-column prop="status" label="状态" width="90">
              <template #default="{ row }"
                ><el-tag :type="getStatusTag(row.status).type" size="small">{{
                  getStatusTag(row.status).label
                }}</el-tag></template
              >
            </el-table-column>
            <el-table-column label="冷却时间" width="90"
              ><template #default="{ row }">{{ row.cooldown }}s</template></el-table-column
            >
            <el-table-column label="无人值守" width="80">
              <template #default="{ row }"
                ><el-tag :type="row.unattended ? 'success' : 'info'" size="small">{{
                  row.unattended ? '是' : '否'
                }}</el-tag></template
              >
            </el-table-column>
            <el-table-column label="操作" width="220" fixed="right">
              <template #default="{ row }">
                <el-switch
                  v-if="row.status !== 'pending_approval'"
                  v-model="row.status"
                  active-value="active"
                  inactive-value="inactive"
                  style="margin-right: 8px"
                  @change="togglePolicy(row)"
                />
                <el-button
                  v-if="row.status === 'pending_approval'"
                  type="success"
                  link
                  size="small"
                  @click="approvePolicy(row.id, true)"
                  >通过</el-button
                >
                <el-button
                  v-if="row.status === 'pending_approval'"
                  type="danger"
                  link
                  size="small"
                  @click="approvePolicy(row.id, false)"
                  >驳回</el-button
                >
                <el-button type="danger" link size="small" @click="deletePolicy(row.id)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
          <div style="margin-top: 16px; display: flex; justify-content: flex-end">
            <el-pagination
              v-model:current-page="policyPagination.page"
              small
              layout="total, prev, pager, next"
              :total="policies.length"
              :page-size="policyPagination.pageSize"
            />
          </div>
        </el-tab-pane>
        <el-tab-pane name="approvals">
          <template #label
            ><span
              >待审批
              <el-badge :value="pendingApprovals.length" :hidden="pendingApprovals.length === 0" type="warning" /></span
          ></template>
          <el-table v-if="pendingApprovals.length > 0" :data="pendingApprovals" size="small" style="width: 100%">
            <el-table-column prop="name" label="策略名称" min-width="140" />
            <el-table-column prop="condition" label="触发条件" min-width="180" show-overflow-tooltip />
            <el-table-column prop="action" label="执行动作" width="130" />
            <el-table-column prop="requesterName" label="申请人" width="100" />
            <el-table-column prop="requestDate" label="申请时间" width="160" />
            <el-table-column label="操作" width="150" fixed="right">
              <template #default="{ row }">
                <el-button type="success" size="small" @click="handleApproval(row.approvalId, true)">通过</el-button>
                <el-button type="danger" size="small" @click="handleApproval(row.approvalId, false)">驳回</el-button>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-else description="暂无待审批策略" />
        </el-tab-pane>
        <el-tab-pane label="动作日志" name="logs">
          <el-table :data="paginatedLogs" size="small" style="width: 100%">
            <el-table-column prop="id" label="日志ID" width="110" />
            <el-table-column prop="policyName" label="策略名称" width="130" />
            <el-table-column prop="action" label="执行动作" width="100" />
            <el-table-column prop="target" label="目标" width="150" />
            <el-table-column prop="result" label="结果" width="80">
              <template #default="{ row }"
                ><el-tag :type="getResultTag(row.result).type" size="small">{{
                  getResultTag(row.result).label
                }}</el-tag></template
              >
            </el-table-column>
            <el-table-column prop="time" label="时间" />
          </el-table>
          <div style="margin-top: 16px; display: flex; justify-content: flex-end">
            <el-pagination
              v-model:current-page="logPagination.page"
              small
              layout="total, prev, pager, next"
              :total="actionLogs.length"
              :page-size="logPagination.pageSize"
            />
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>
    <el-dialog v-model="showCreateDialog" title="创建防御策略" width="600px" destroy-on-close>
      <el-form :model="newPolicy" label-width="100px">
        <el-form-item label="策略名称" required
          ><el-input v-model="newPolicy.name" placeholder="请输入策略名称"
        /></el-form-item>
        <el-form-item label="条件类型"
          ><el-select v-model="newPolicy.conditionType" style="width: 100%"
            ><el-option label="阈值触发" value="threshold" /><el-option label="规则匹配" value="rule" /><el-option
              label="异常检测"
              value="anomaly" /><el-option label="威胁情报" value="threat_intel" /></el-select
        ></el-form-item>
        <el-form-item label="条件参数"
          ><el-input v-model="newPolicy.conditionValue" placeholder="例: 5分钟内>10次失败"
        /></el-form-item>
        <el-form-item label="动作类型"
          ><el-select v-model="newPolicy.actionType" style="width: 100%"
            ><el-option label="封禁IP" value="block_ip" /><el-option label="隔离主机" value="isolate_host" /><el-option
              label="阻断连接"
              value="block_connection" /><el-option label="发送告警" value="alert" /><el-option
              label="记录日志"
              value="log" /></el-select
        ></el-form-item>
        <el-form-item label="动作参数"
          ><el-input v-model="newPolicy.actionParam" placeholder="例: 封禁时长24h"
        /></el-form-item>
        <el-form-item label="冷却时间"
          ><el-input-number v-model="newPolicy.cooldown" :min="60" :max="86400" :step="60" />
          <span style="margin-left: 8px; color: rgba(255, 255, 255, 0.4)">秒</span></el-form-item
        >
        <el-form-item label="无人值守"
          ><el-switch v-model="newPolicy.unattended" /><span
            style="margin-left: 8px; color: rgba(255, 255, 255, 0.4); font-size: 12px"
            >开启后策略将自动执行无需审批</span
          ></el-form-item
        >
      </el-form>
      <template #footer
        ><el-button @click="showCreateDialog = false">取消</el-button
        ><el-button type="primary" @click="createPolicy">创建</el-button></template
      >
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { legacyApi } from '@/api';

const loading = ref(false);
const policies = ref<Array<Record<string, any>>>([]);
const actionLogs = ref<Array<Record<string, any>>>([]);
const pendingApprovals = ref<Array<Record<string, any>>>([]);
const showCreateDialog = ref(false);
const activeTab = ref('policies');
const policyPagination = reactive({ page: 1, pageSize: 10 });
const logPagination = reactive({ page: 1, pageSize: 10 });
const newPolicy = reactive({
  name: '',
  conditionType: 'threshold',
  conditionValue: '',
  actionType: 'block_ip',
  actionParam: '',
  cooldown: 300,
  unattended: false
});
const paginatedPolicies = computed(() => {
  const s = (policyPagination.page - 1) * policyPagination.pageSize;
  return policies.value.slice(s, s + policyPagination.pageSize);
});
const paginatedLogs = computed(() => {
  const s = (logPagination.page - 1) * logPagination.pageSize;
  return actionLogs.value.slice(s, s + logPagination.pageSize);
});

function demoDefensePolicies() {
  const conditions = [
    '检测到暴力破解(5分钟内>10次)',
    '检测到DDoS攻击',
    '检测到恶意文件上传',
    '检测到SQL注入',
    '检测到异常端口扫描',
    '检测到未授权访问尝试'
  ];
  const actions = ['自动封禁IP(24h)', '发送告警通知', '隔离受感染主机', '阻断连接', '记录日志'];
  const statuses = ['active', 'inactive', 'pending_approval'];
  return Array.from({ length: 15 }, (_, i) => ({
    id: 'POL-' + (4000 + i),
    name: [
      '暴力破解防护',
      'DDoS防护',
      '恶意文件拦截',
      'SQL注入防护',
      '端口扫描检测',
      '未授权访问拦截',
      '异常流量监控',
      '恶意IP黑名单',
      '弱密码检测',
      '提权行为监控',
      '反弹Shell检测',
      'Webshell检测',
      '异常DNS检测',
      '横向移动检测',
      '数据泄露防护'
    ][i],
    condition: conditions[Math.floor(Math.random() * conditions.length)],
    action: actions[Math.floor(Math.random() * actions.length)],
    status: statuses[Math.floor(Math.random() * statuses.length)],
    cooldown: [300, 600, 900, 1800, 3600][Math.floor(Math.random() * 5)],
    unattended: Math.random() > 0.5,
    createTime: new Date(Date.now() - Math.random() * 60 * 86400000).toLocaleString('zh-CN')
  }));
}

function demoActionLogs() {
  const actions = ['封禁IP', '隔离主机', '阻断连接', '发送告警', '更新规则'];
  return Array.from({ length: 40 }, (_, i) => ({
    id: 'LOG-' + (6000 + i),
    policyName: ['暴力破解防护', 'DDoS防护', '恶意文件拦截', 'SQL注入防护'][Math.floor(Math.random() * 4)],
    action: actions[Math.floor(Math.random() * actions.length)],
    target: `192.168.${Math.floor(Math.random() * 5)}.${Math.floor(Math.random() * 255)}`,
    result: Math.random() > 0.1 ? 'success' : 'failed',
    time: new Date(Date.now() - Math.random() * 7 * 86400000).toLocaleString('zh-CN'),
    detail: '策略自动触发执行'
  }));
}

async function loadData() {
  try {
    const [polRes, logRes, approvalRes] = await Promise.all([
      legacyApi.get('/defense/policies'),
      legacyApi.get('/defense/action-logs'),
      legacyApi.get('/defense/pending-approvals')
    ]);
    if (polRes && polRes.code === 0) {
      policies.value = ((polRes.data as any[]) || []).map((p) => ({
        id: p.id,
        name: p.name,
        condition: Array.isArray(p.conditions)
          ? p.conditions.map((c: any) => c.field || c.fact).join(', ')
          : p.description || '-',
        action: Array.isArray(p.actions) ? p.actions.map((a: any) => a.type).join(', ') : '-',
        status: p.approval_status === 'pending' ? 'pending_approval' : p.enabled ? 'active' : 'inactive',
        cooldown: p.cooldown,
        unattended: !!p.unattended,
        createTime: p.created_at ? new Date(p.created_at).toLocaleString('zh-CN') : '-'
      }));
    }
    if (logRes && logRes.code === 0) {
      actionLogs.value = ((logRes.data as any[]) || []).map((l) => ({
        id: 'LOG-' + l.id,
        policyName: '策略#' + (l.policy_id || '-'),
        action: l.action_type || '-',
        target: l.action_detail || '-',
        result: l.result || 'success',
        time: l.executed_at ? new Date(l.executed_at).toLocaleString('zh-CN') : '-'
      }));
    }
    if (approvalRes && approvalRes.code === 0) {
      pendingApprovals.value = ((approvalRes.data as any[]) || []).map((a) => ({
        approvalId: a.approval_id,
        policyId: a.id,
        name: a.name,
        condition: Array.isArray(a.conditions)
          ? a.conditions.map((c: any) => c.field || c.fact).join(', ')
          : a.description || '-',
        action: Array.isArray(a.actions) ? a.actions.map((a2: any) => a2.type).join(', ') : '-',
        requesterName: a.requester_name || '未知',
        requestDate: a.request_date ? new Date(a.request_date).toLocaleString('zh-CN') : '-'
      }));
    }
  } catch (e) {
    policies.value = demoDefensePolicies();
    actionLogs.value = demoActionLogs();
  }
}

onMounted(() => {
  loadData();
});

function openCreateDialog() {
  Object.assign(newPolicy, {
    name: '',
    conditionType: 'threshold',
    conditionValue: '',
    actionType: 'block_ip',
    actionParam: '',
    cooldown: 300,
    unattended: false
  });
  showCreateDialog.value = true;
}

async function createPolicy() {
  if (!newPolicy.name) {
    ElMessage.warning('请输入策略名称');
    return;
  }
  loading.value = true;
  try {
    const payload = {
      name: newPolicy.name,
      description: newPolicy.conditionType + ': ' + newPolicy.conditionValue,
      conditions: [{ field: newPolicy.conditionType, operator: 'equals', value: newPolicy.conditionValue }],
      actions: [{ type: newPolicy.actionType, params: { detail: newPolicy.actionParam } }],
      cooldown: newPolicy.cooldown,
      unattended: newPolicy.unattended
    };
    const res = await legacyApi.post('/defense/policies', payload);
    if (res && res.code === 0) {
      policies.value.unshift({
        id: (res.data as any).id,
        name: newPolicy.name,
        condition: newPolicy.conditionType + ': ' + newPolicy.conditionValue,
        action: newPolicy.actionType,
        status: 'active',
        cooldown: newPolicy.cooldown,
        unattended: newPolicy.unattended,
        createTime: new Date().toLocaleString('zh-CN')
      });
      showCreateDialog.value = false;
      ElMessage.success('策略创建成功');
    }
  } catch (e) {
    ElMessage.error('创建失败');
  }
  loading.value = false;
}

async function togglePolicy(policy: Record<string, any>) {
  const newEnabled = policy.status === 'active';
  try {
    await legacyApi.put('/defense/policies/' + policy.id, { enabled: newEnabled });
  } catch (e) {
    /* ignore */
  }
  policy.status = newEnabled ? 'active' : 'inactive';
  ElMessage.success('策略已' + (newEnabled ? '启用' : '禁用'));
}

async function deletePolicy(id: string) {
  try {
    await ElMessageBox.confirm('确定要删除此策略吗？', '确认', { type: 'warning' });
  } catch (e) {
    return;
  }
  try {
    await legacyApi.delete('/defense/policies/' + id);
  } catch (e) {
    /* ignore */
  }
  policies.value = policies.value.filter((p) => p.id !== id);
  ElMessage.success('已删除');
}

async function approvePolicy(id: string, approved: boolean) {
  try {
    await legacyApi.post('/defense/approvals/' + id, {
      status: approved ? 'approved' : 'rejected',
      risk_assessment: approved ? '审批通过' : '审批驳回'
    });
  } catch (e) {
    /* ignore */
  }
  const policy = policies.value.find((p) => p.id === id);
  if (policy) policy.status = approved ? 'active' : 'inactive';
  ElMessage.success(approved ? '已审批通过' : '已驳回');
}

async function handleApproval(approvalId: string, approved: boolean) {
  try {
    await legacyApi.post('/defense/approvals/' + approvalId, {
      status: approved ? 'approved' : 'rejected',
      risk_assessment: approved ? '审批通过' : '审批驳回'
    });
    pendingApprovals.value = pendingApprovals.value.filter((a) => a.approvalId !== approvalId);
    ElMessage.success(approved ? '策略已审批通过' : '策略已驳回');
    loadData();
  } catch (e) {
    ElMessage.error('审批操作失败');
  }
}

function getStatusTag(status: string) {
  const map: Record<string, { label: string; type: string }> = {
    active: { label: '已启用', type: 'success' },
    inactive: { label: '已禁用', type: 'info' },
    pending_approval: { label: '待审批', type: 'warning' }
  };
  return map[status] || { label: status, type: 'info' };
}

function getResultTag(result: string) {
  return result === 'success' ? { label: '成功', type: 'success' } : { label: '失败', type: 'danger' };
}
</script>
