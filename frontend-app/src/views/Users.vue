<template>
  <div v-loading="loading">
    <div class="page-header">
      <div>
        <div class="page-title">用户管理</div>
        <div class="page-desc">系统用户管理与操作审计</div>
      </div>
      <el-button type="primary" size="small" @click="openAdd"
        ><el-icon><Plus /></el-icon> 添加用户</el-button
      >
    </div>
    <div class="chart-card">
      <el-tabs v-model="activeTab">
        <el-tab-pane label="用户列表" name="users">
          <el-table :data="paginatedUsers" size="small" style="width: 100%">
            <el-table-column prop="id" label="ID" width="60" />
            <el-table-column prop="username" label="用户名" width="120" />
            <el-table-column prop="role" label="角色" width="90">
              <template #default="{ row }"
                ><el-tag :type="getRoleTag(row.role).type" size="small">{{
                  getRoleTag(row.role).label
                }}</el-tag></template
              >
            </el-table-column>
            <el-table-column prop="department" label="部门" width="130" />
            <el-table-column prop="status" label="状态" width="80">
              <template #default="{ row }"
                ><el-tag :type="row.status === 'active' ? 'success' : 'danger'" size="small">{{
                  row.status === 'active' ? '正常' : '禁用'
                }}</el-tag></template
              >
            </el-table-column>
            <el-table-column prop="createTime" label="创建时间" width="160" />
            <el-table-column prop="lastLogin" label="最后登录" width="160" />
            <el-table-column label="操作" width="180" fixed="right">
              <template #default="{ row }"
                ><el-button type="primary" link size="small" @click="openEdit(row)">编辑</el-button
                ><el-button
                  :type="row.status === 'active' ? 'warning' : 'success'"
                  link
                  size="small"
                  @click="toggleUserStatus(row)"
                  >{{ row.status === 'active' ? '禁用' : '启用' }}</el-button
                ></template
              >
            </el-table-column>
          </el-table>
          <div style="margin-top: 16px; display: flex; justify-content: flex-end">
            <el-pagination
              v-model:current-page="pagination.page"
              small
              layout="total, prev, pager, next"
              :total="users.length"
              :page-size="pagination.pageSize"
            />
          </div>
        </el-tab-pane>
        <el-tab-pane label="审计日志" name="audit">
          <div style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap">
            <el-input
              v-model="auditFilter.username"
              placeholder="用户名"
              clearable
              style="width: 150px"
              @clear="loadData"
              @keyup.enter="loadData"
            />
            <el-select
              v-model="auditFilter.operation_type"
              placeholder="操作类型"
              clearable
              style="width: 150px"
              @change="loadData"
            >
              <el-option label="登录" value="login" />
              <el-option label="扫描" value="scan" />
              <el-option label="基线检查" value="baseline_check" />
              <el-option label="病毒检测" value="virus_scan" />
              <el-option label="策略操作" value="policy" />
              <el-option label="配置变更" value="config" />
              <el-option label="密码修改" value="password_change" />
            </el-select>
            <el-date-picker
              v-model="auditFilter.dateRange"
              type="daterange"
              range-separator="至"
              start-placeholder="开始日期"
              end-placeholder="结束日期"
              style="width: 280px"
              value-format="YYYY-MM-DD"
              @change="loadData"
            />
            <el-button type="primary" @click="loadData">查询</el-button>
            <el-button @click="resetAuditFilter">重置</el-button>
            <el-button type="success" size="small" @click="exportAuditLogs">导出CSV</el-button>
          </div>
          <el-table :data="paginatedAudit" size="small" style="width: 100%">
            <el-table-column prop="id" label="日志ID" width="110" />
            <el-table-column prop="user" label="操作用户" width="100" />
            <el-table-column prop="action" label="操作类型" width="100" />
            <el-table-column prop="target" label="操作对象" min-width="150" />
            <el-table-column prop="ip" label="来源IP" width="130" />
            <el-table-column prop="result" label="结果" width="80">
              <template #default="{ row }"
                ><el-tag :type="row.result === 'success' ? 'success' : 'danger'" size="small">{{
                  row.result === 'success' ? '成功' : '失败'
                }}</el-tag></template
              >
            </el-table-column>
            <el-table-column prop="time" label="时间" />
          </el-table>
          <div style="margin-top: 16px; display: flex; justify-content: flex-end">
            <el-pagination
              v-model:current-page="auditPagination.page"
              small
              layout="total, prev, pager, next"
              :total="auditLogs.length"
              :page-size="auditPagination.pageSize"
            />
          </div>
        </el-tab-pane>
      </el-tabs>
    </div>
    <el-dialog v-model="showAddDialog" title="添加用户" width="500px" destroy-on-close>
      <el-form :model="addUser" label-width="80px">
        <el-form-item label="用户名" required
          ><el-input v-model="addUser.username" placeholder="请输入用户名"
        /></el-form-item>
        <el-form-item label="密码" required
          ><el-input v-model="addUser.password" type="password" placeholder="请输入密码" show-password
        /></el-form-item>
        <el-form-item label="角色"
          ><el-select v-model="addUser.role" style="width: 100%"
            ><el-option label="操作员" value="user" /><el-option label="观察员" value="viewer" /><el-option
              label="管理员"
              value="admin" /></el-select
        ></el-form-item>
        <el-form-item label="部门"><el-input v-model="addUser.department" placeholder="请输入部门" /></el-form-item>
      </el-form>
      <template #footer
        ><el-button @click="showAddDialog = false">取消</el-button
        ><el-button type="primary" @click="submitAdd">添加</el-button></template
      >
    </el-dialog>
    <el-dialog v-model="showEditDialog" title="编辑用户" width="500px" destroy-on-close>
      <el-form :model="editUser" label-width="80px">
        <el-form-item label="用户名"><el-input v-model="editUser.username" /></el-form-item>
        <el-form-item label="角色"
          ><el-select v-model="editUser.role" style="width: 100%"
            ><el-option label="管理员" value="admin" /><el-option label="操作员" value="user" /><el-option
              label="观察员"
              value="viewer" /></el-select
        ></el-form-item>
        <el-form-item label="部门"><el-input v-model="editUser.department" /></el-form-item>
      </el-form>
      <template #footer
        ><el-button @click="showEditDialog = false">取消</el-button
        ><el-button type="primary" @click="submitEdit">保存</el-button></template
      >
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue';
import { ElMessage } from 'element-plus';
import { legacyApi } from '@/api';

const loading = ref(false);
const users = ref<Array<Record<string, any>>>([]);
const auditLogs = ref<Array<Record<string, any>>>([]);
const pagination = reactive({ page: 1, pageSize: 10 });
const auditPagination = reactive({ page: 1, pageSize: 10 });
const showAddDialog = ref(false);
const showEditDialog = ref(false);
const activeTab = ref('users');
const editUser = reactive({ id: null as number | null, username: '', role: 'user', department: '', status: 'active' });
const addUser = reactive({ username: '', password: '', role: 'user', department: '' });
const auditFilter = reactive({ username: '', operation_type: '', dateRange: null as string[] | null });
const paginatedUsers = computed(() => {
  const s = (pagination.page - 1) * pagination.pageSize;
  return users.value.slice(s, s + pagination.pageSize);
});
const paginatedAudit = computed(() => {
  const s = (auditPagination.page - 1) * auditPagination.pageSize;
  return auditLogs.value.slice(s, s + auditPagination.pageSize);
});

function demoUsers() {
  const roles = ['admin', 'user', 'viewer'];
  const departments = ['安全运营中心', '网络运维部', '系统管理部', '安全研发部', '合规审计部'];
  return Array.from({ length: 15 }, (_, i) => ({
    id: i + 1,
    username: [
      'admin',
      'zhangsan',
      'lisi',
      'wangwu',
      'zhaoliu',
      'sunqi',
      'zhouba',
      'wujiu',
      'zhengshi',
      'chenyi',
      'lianger',
      'huangsan',
      'qiansi',
      'wuwu',
      'liuliu'
    ][i],
    role: i === 0 ? 'admin' : roles[Math.floor(Math.random() * roles.length)],
    department: departments[Math.floor(Math.random() * departments.length)],
    status: Math.random() > 0.1 ? 'active' : 'disabled',
    createTime: new Date(Date.now() - Math.random() * 365 * 86400000).toLocaleString('zh-CN'),
    lastLogin: new Date(Date.now() - Math.random() * 7 * 86400000).toLocaleString('zh-CN')
  }));
}

function demoAuditLogs() {
  const actions = ['用户登录', '创建策略', '修改配置', '删除设备', '导出报告', '审批策略', '修改用户', '启动扫描'];
  return Array.from({ length: 50 }, (_, i) => ({
    id: 'AUD-' + (7000 + i),
    user: ['admin', 'zhangsan', 'lisi', 'wangwu'][Math.floor(Math.random() * 4)],
    action: actions[Math.floor(Math.random() * actions.length)],
    target: ['策略POL-4001', '用户lisi', '扫描任务SCAN-2001', '系统配置', '设备DEV-5001'][
      Math.floor(Math.random() * 5)
    ],
    ip: `10.0.${Math.floor(Math.random() * 5)}.${Math.floor(Math.random() * 255)}`,
    time: new Date(Date.now() - Math.random() * 30 * 86400000).toLocaleString('zh-CN'),
    result: Math.random() > 0.05 ? 'success' : 'failed'
  }));
}

function resetAuditFilter() {
  auditFilter.username = '';
  auditFilter.operation_type = '';
  auditFilter.dateRange = null;
  loadData();
}

async function loadData() {
  try {
    const [userRes, auditRes] = await Promise.all([
      legacyApi.get('/user/list'),
      (async () => {
        let auditUrl = '/user/audit-logs?page=1&pageSize=50';
        if (auditFilter.username) auditUrl += '&username=' + encodeURIComponent(auditFilter.username);
        if (auditFilter.operation_type) auditUrl += '&operation_type=' + encodeURIComponent(auditFilter.operation_type);
        if (auditFilter.dateRange && auditFilter.dateRange.length === 2) {
          auditUrl += '&start_date=' + auditFilter.dateRange[0] + '&end_date=' + auditFilter.dateRange[1];
        }
        return legacyApi.get(auditUrl);
      })()
    ]);
    if (userRes && userRes.code === 0) {
      users.value = ((userRes.data as any[]) || []).map((u) => ({
        id: u.id,
        username: u.username,
        role: u.role_name || u.role_id,
        department: u.department || '-',
        status: u.status ? 'active' : 'disabled',
        createTime: u.created_at ? new Date(u.created_at).toLocaleString('zh-CN') : '-',
        lastLogin: '-'
      }));
    }
    if (auditRes && auditRes.code === 0) {
      auditLogs.value = ((auditRes.data as any[]) || []).map((l) => ({
        id: 'AUD-' + l.id,
        user: l.username || '-',
        action: l.operation_type || '-',
        target: l.operation_target || '-',
        ip: l.client_ip || '-',
        result: l.result || 'success',
        time: l.created_at ? new Date(l.created_at).toLocaleString('zh-CN') : '-'
      }));
    }
  } catch (e) {
    users.value = demoUsers();
    auditLogs.value = demoAuditLogs();
  }
}

onMounted(() => {
  loadData();
});

function openAdd() {
  Object.assign(addUser, { username: '', password: '', role: 'user', department: '' });
  showAddDialog.value = true;
}
function openEdit(user: Record<string, any>) {
  Object.assign(editUser, {
    id: user.id,
    username: user.username,
    role: user.role,
    department: user.department,
    status: user.status
  });
  showEditDialog.value = true;
}

async function submitAdd() {
  if (!addUser.username || !addUser.password) {
    ElMessage.warning('请填写必填项');
    return;
  }
  try {
    const res = await legacyApi.post('/auth/register', addUser);
    if (res && res.code === 0) {
      users.value.push({
        id: users.value.length + 1,
        username: addUser.username,
        role: addUser.role,
        department: addUser.department,
        status: 'active',
        createTime: new Date().toLocaleString('zh-CN'),
        lastLogin: '-'
      });
      showAddDialog.value = false;
      ElMessage.success('用户已添加');
    } else {
      ElMessage.error(res.message || '添加失败');
    }
  } catch (e) {
    ElMessage.error('添加失败');
  }
}

async function submitEdit() {
  try {
    const roleIdMap: Record<string, number> = { admin: 1, user: 2, viewer: 3 };
    const res = await legacyApi.put('/user/' + editUser.id, {
      username: editUser.username,
      role_id: roleIdMap[editUser.role] || 2,
      department: editUser.department
    });
    if (res && res.code === 0) {
      const user = users.value.find((u) => u.id === editUser.id);
      if (user) {
        user.username = editUser.username;
        user.role = editUser.role;
        user.department = editUser.department;
      }
      showEditDialog.value = false;
      ElMessage.success('用户信息已更新');
    }
  } catch (e) {
    ElMessage.error('更新失败');
  }
}

async function toggleUserStatus(user: Record<string, any>) {
  const newStatus = user.status === 'active' ? 0 : 1;
  try {
    await legacyApi.put('/user/' + user.id, { status: newStatus });
    user.status = newStatus ? 'active' : 'disabled';
    ElMessage.success('用户已' + (newStatus ? '启用' : '禁用'));
  } catch (e) {
    ElMessage.error('操作失败');
  }
}

function getRoleTag(role: string) {
  const map: Record<string, { label: string; type: string }> = {
    admin: { label: '管理员', type: 'danger' },
    user: { label: '操作员', type: 'primary' },
    viewer: { label: '观察员', type: 'info' }
  };
  return map[role] || { label: role, type: 'info' };
}

function exportAuditLogs() {
  if (auditLogs.value.length === 0) return;
  const headers = '用户,操作类型,操作目标,IP,结果,时间\n';
  const rows = auditLogs.value.map((l) => `${l.user},${l.action},${l.target},${l.ip},${l.result},${l.time}`).join('\n');
  const blob = new Blob(['\uFEFF' + headers + rows], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'audit_logs.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  ElMessage.success('审计日志已导出');
}
</script>
