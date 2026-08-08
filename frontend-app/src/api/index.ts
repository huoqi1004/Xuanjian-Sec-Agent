import { request, requestData } from './http';
import type {
  UserInfo,
  LoginResult,
  PageResult,
  ScanTask,
  ScanResult,
  AlertRecord,
  VirusRecord,
  ThreatIntel,
  AutoPolicy,
  EdgeDevice,
  DjppTask,
  DjppResult,
  Report,
  Playbook,
  PlaybookRunResult
} from '@/types';

// ============ 认证 ============
export const authApi = {
  login: (username: string, password: string) =>
    requestData<LoginResult>({ method: 'POST', url: '/auth/login', data: { username, password } }),
  profile: () => requestData<UserInfo>({ method: 'GET', url: '/auth/profile' }),
  register: (data: { username: string; password: string; role_id?: number; department?: string }) =>
    requestData<{ id: number }>({ method: 'POST', url: '/auth/register', data }),
  changePassword: (old_password: string, new_password: string) =>
    requestData<null>({ method: 'PUT', url: '/auth/password', data: { old_password, new_password } })
};

// ============ 网络扫描 ============
export const scanApi = {
  tasks: () => requestData<ScanTask[]>({ method: 'GET', url: '/scan/tasks' }),
  start: (data: { target_cidr: string; scan_mode?: string; port_range?: string }) =>
    requestData<{ task_id: string }>({ method: 'POST', url: '/scan/start', data }),
  detail: (taskId: string) =>
    requestData<{ task: ScanTask; results: ScanResult[] }>({ method: 'GET', url: `/scan/tasks/${taskId}` }),
  remove: (taskId: string) => requestData<null>({ method: 'DELETE', url: `/scan/tasks/${taskId}` })
};

// ============ 基线排查 ============
export const baselineApi = {
  policies: () =>
    requestData<Array<{ id: number; name: string; description?: string; standard?: string }>>({
      method: 'GET',
      url: '/baseline/policies'
    }),
  check: (policy_id: number) =>
    requestData<{ task_id: string }>({
      method: 'POST',
      url: '/baseline/check',
      data: { policy_id, host: 'localhost' }
    }),
  results: (taskId: string) =>
    requestData<{
      task_id: string;
      policy_name?: string;
      checks: Array<Record<string, unknown>>;
      stats?: Record<string, unknown>;
    }>({ method: 'GET', url: `/baseline/results/${taskId}` })
};

// ============ 病毒查杀 ============
export const virusApi = {
  records: () => requestData<VirusRecord[]>({ method: 'GET', url: '/virus/records' }),
  scanHistory: (page = 1, pageSize = 20) =>
    requestData<PageResult<VirusRecord>>({ method: 'GET', url: '/virus/scan-history', params: { page, pageSize } }),
  report: (scanId: string) => requestData<Record<string, unknown>>({ method: 'GET', url: `/virus/report/${scanId}` }),
  hashList: (params: { page?: number; pageSize?: number; search?: string }) =>
    requestData<PageResult<VirusRecord>>({ method: 'GET', url: '/virus/hash-list', params }),
  analyzeHash: (hash: string, hashType = 'md5') =>
    requestData<unknown[]>({ method: 'POST', url: '/virus/analyze-hash', data: { hash, hashType } }),
  exportReport: (scanId: string, format = 'markdown') =>
    requestData<{ report: string }>({ method: 'POST', url: '/virus/export-report', data: { scanId, format } })
};

// ============ 态势感知 ============
export const situationalApi = {
  dashboard: () => requestData<Record<string, unknown>>({ method: 'GET', url: '/situational/dashboard' }),
  alerts: (params?: { page?: number; pageSize?: number; severity?: string; status?: string }) =>
    requestData<{ list: AlertRecord[]; total: number }>({ method: 'GET', url: '/situational/alerts', params }),
  threatIntel: () => requestData<ThreatIntel[]>({ method: 'GET', url: '/situational/threat-intel' }),
  updateAlertStatus: (id: number, status: string) =>
    requestData<null>({ method: 'PUT', url: `/situational/alerts/${id}`, data: { status } }),
  generateReport: (type: string, title: string) =>
    requestData<{ report_id?: number }>({ method: 'POST', url: '/situational/report', data: { type, title } })
};

// ============ 自动化防御 ============
export const defenseApi = {
  policies: () => requestData<AutoPolicy[]>({ method: 'GET', url: '/defense/policies' }),
  actionLogs: () => requestData<Array<Record<string, unknown>>>({ method: 'GET', url: '/defense/action-logs' }),
  pendingApprovals: () =>
    requestData<Array<Record<string, unknown>>>({ method: 'GET', url: '/defense/pending-approvals' }),
  create: (data: Partial<AutoPolicy> & { created_by: number }) =>
    requestData<{ id: number }>({ method: 'POST', url: '/defense/policies', data }),
  toggle: (id: number, enabled: boolean) =>
    requestData<null>({ method: 'PUT', url: `/defense/policies/${id}`, data: { enabled } }),
  remove: (id: number) => requestData<null>({ method: 'DELETE', url: `/defense/policies/${id}` }),
  approve: (id: number, status: string, risk_assessment: string) =>
    requestData<null>({ method: 'POST', url: `/defense/approvals/${id}`, data: { status, risk_assessment } })
};

// ============ 边缘设备 ============
export const deviceApi = {
  list: () => requestData<EdgeDevice[]>({ method: 'GET', url: '/device/list' }),
  commands: (deviceId: string) =>
    requestData<Array<Record<string, unknown>>>({ method: 'GET', url: `/device/${deviceId}/commands` }),
  sendCommand: (deviceId: string, command: string, params: Record<string, unknown>) =>
    requestData<{ command_id: number }>({
      method: 'POST',
      url: `/device/${deviceId}/command`,
      data: { command, params }
    })
};

// ============ 用户管理 ============
export const userApi = {
  list: () => requestData<Array<UserInfo & { role_name?: string }>>({ method: 'GET', url: '/user/list' }),
  update: (id: number, data: { username?: string; role_id?: number; department?: string; status?: number }) =>
    requestData<null>({ method: 'PUT', url: `/user/${id}`, data }),
  remove: (id: number) => requestData<null>({ method: 'DELETE', url: `/user/${id}` })
};

// ============ 系统配置 ============
export const configApi = {
  list: () => requestData<Record<string, Record<string, string>>>({ method: 'GET', url: '/config/list' }),
  update: (key: string, value: string) => requestData<null>({ method: 'PUT', url: `/config/${key}`, data: { value } }),
  backups: () => requestData<Array<Record<string, unknown>>>({ method: 'GET', url: '/config/backups' }),
  backup: () => requestData<{ filename: string }>({ method: 'POST', url: '/config/backup' }),
  restore: (filename: string) => requestData<null>({ method: 'POST', url: '/config/restore', data: { filename } })
};

// ============ 等保测评 ============
export const djppApi = {
  levels: () =>
    requestData<Array<{ id: number; level: number; name: string; description?: string }>>({
      method: 'GET',
      url: '/djpp/levels'
    }),
  tasks: () => requestData<DjppTask[]>({ method: 'GET', url: '/djpp/tasks?page=1&pageSize=50' }),
  create: (data: { level: number; name: string; description?: string }) =>
    requestData<{ task_id: string }>({ method: 'POST', url: '/djpp/tasks', data }),
  detail: (taskId: string) =>
    requestData<{ task: DjppTask; results: DjppResult[] }>({ method: 'GET', url: `/djpp/tasks/${taskId}` }),
  report: (taskId: string) =>
    requestData<{ report?: string }>({ method: 'POST', url: `/djpp/tasks/${taskId}/report`, timeout: 120000 })
};

// ============ 报告管理 ============
export const reportsApi = {
  stats: () => requestData<Record<string, unknown>>({ method: 'GET', url: '/reports/stats' }),
  list: () => requestData<Report[]>({ method: 'GET', url: '/reports/list' }),
  overview: () =>
    requestData<{
      risk_ranking: Array<{ asset: string; total: number; critical: number; high: number; unresolved: number }>;
      compliance: { total_tasks: number; total_checks: number; compliance_rate: number };
      summary: Record<string, number>;
    }>({ method: 'GET', url: '/reports/overview' })
};

// ============ SOAR 剧本 ============
export const playbookApi = {
  list: (params?: { page?: number; pageSize?: number; enabled?: number | string }) =>
    requestData<PageResult<Playbook>>({ method: 'GET', url: '/playbook/list', params }),
  detail: (id: number) => requestData<Playbook>({ method: 'GET', url: `/playbook/${id}` }),
  create: (data: { name: string; description?: string; trigger?: string; steps: Playbook['steps'] }) =>
    requestData<{ id: number }>({ method: 'POST', url: '/playbook/create', data }),
  update: (id: number, data: Partial<Playbook>) => requestData<null>({ method: 'PUT', url: `/playbook/${id}`, data }),
  remove: (id: number) => requestData<null>({ method: 'DELETE', url: `/playbook/${id}` }),
  execute: (id: number, event: Record<string, unknown>) =>
    requestData<PlaybookRunResult>({ method: 'POST', url: `/playbook/${id}/execute`, data: { event } }),
  pendingApprovals: () =>
    requestData<Array<{ id: string; title: string; playbookId: number; status: string }>>({
      method: 'GET',
      url: '/playbook/approvals/pending'
    }),
  confirmApproval: (id: string, decision: 'approve' | 'reject') =>
    requestData<unknown>({ method: 'POST', url: `/playbook/approvals/${id}`, data: { decision } }),
  seedTemplates: () => requestData<{ seeded: number }>({ method: 'POST', url: '/playbook/templates/seed' })
};

// 兼容旧接口：整体响应体（含 code/message/data）
export const legacyApi = {
  get: <T = unknown>(url: string) => request<T>({ method: 'GET', url }),
  post: <T = unknown>(url: string, data?: unknown) => request<T>({ method: 'POST', url, data }),
  put: <T = unknown>(url: string, data?: unknown) => request<T>({ method: 'PUT', url, data }),
  delete: <T = unknown>(url: string) => request<T>({ method: 'DELETE', url })
};
