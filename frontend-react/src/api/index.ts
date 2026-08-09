import { requestData } from './http';

export const authApi = {
  login: (username: string, password: string) =>
    requestData<{ token: string; user?: unknown }>({ method: 'POST', url: '/auth/login', data: { username, password } }),
  profile: () => requestData<unknown>({ method: 'GET', url: '/auth/profile' }),
  register: (data: { username: string; password: string; role_id?: number; department?: string }) =>
    requestData<unknown>({ method: 'POST', url: '/auth/register', data }),
  changePassword: (old_password: string, new_password: string) =>
    requestData<null>({ method: 'PUT', url: '/auth/password', data: { old_password, new_password } })
};

export const agentApi = {
  run: (task: string) => requestData<unknown>({ method: 'POST', url: '/ai/agent/run', data: { task } }),
  confirm: (confirmation_id: string, decision: string) =>
    requestData<unknown>({ method: 'POST', url: '/ai/agent/confirm', data: { confirmation_id, decision } }),
  pending: () => requestData<unknown[]>({ method: 'GET', url: '/ai/agent/pending' }),
  tools: () => requestData<unknown[]>({ method: 'GET', url: '/ai/agent/tools' }),
  plan: (task: string) => requestData<unknown>({ method: 'GET', url: '/ai/agent/plan', params: { task } })
};

// ============ 态势感知 ============
export interface AlertRecord {
  id: number;
  related_asset?: string;
  alert_type?: string;
  severity?: string;
  confidence?: number;
  description?: string;
  status?: string;
  created_at?: string;
}

export interface ThreatIntelRecord {
  id: number;
  ioc_type: string;
  ioc_value: string;
  source?: string;
  confidence?: number;
  description?: string;
  updated_at?: string;
}

export interface DashboardData {
  security_score?: number;
  alerts?: {
    total?: number;
    new_count?: number;
    acknowledged_count?: number;
    resolved_count?: number;
    false_positive_count?: number;
    critical_count?: number;
    high_count?: number;
    medium_count?: number;
    low_count?: number;
  };
  threat_intel?: { total?: number; ip_count?: number; domain_count?: number; hash_count?: number; cve_count?: number; avg_confidence?: number };
  scans?: { total_tasks?: number; running_tasks?: number; completed_tasks?: number; failed_tasks?: number; open_ports?: number };
  defense?: { total_policies?: number; enabled_policies?: number; unattended_policies?: number };
  devices?: { total_devices?: number; online_devices?: number; offline_devices?: number };
  virus_detection?: { total_scans?: number; malicious_count?: number; suspicious_count?: number; poisoned_count?: number; clean_count?: number };
  baseline?: { compliance_rate?: number };
  risk_distribution?: Array<{ name: string; value: number }>;
  threat_trend?: Array<{ date: string; count: number }>;
  vuln_distribution?: Array<{ name: string; value: number }>;
  recent_alerts?: AlertRecord[];
  recent_threat_intel?: ThreatIntelRecord[];
}

export interface ReportItem {
  id: number;
  reportId: number;
  title: string;
  type: string;
  typeLabel: string;
  generatedBy: string;
  generatedAt: string;
  hasMD: boolean;
  hasDOCX: boolean;
}

export const situationalApi = {
  dashboard: () => requestData<DashboardData>({ method: 'GET', url: '/situational/dashboard' }),
  alerts: (params?: { page?: number; pageSize?: number; severity?: string; status?: string }) =>
    requestData<AlertRecord[]>({ method: 'GET', url: '/situational/alerts', params }),
  threatIntel: () => requestData<ThreatIntelRecord[]>({ method: 'GET', url: '/situational/threat-intel' }),
  updateAlertStatus: (id: number, status: string) =>
    requestData<null>({ method: 'PUT', url: `/situational/alerts/${id}`, data: { status } }),
  generateReport: (type: string, title: string) =>
    requestData<{ id: number }>({ method: 'POST', url: '/situational/report', data: { type, title } })
};

// ============ 报告管理 ============
export const reportsApi = {
  list: () => requestData<{ reports: ReportItem[]; total: number }>({ method: 'GET', url: '/reports/list' }),
  detail: (id: number) => requestData<Record<string, unknown>>({ method: 'GET', url: `/reports/${id}` }),
  remove: (id: number) => requestData<null>({ method: 'DELETE', url: `/reports/${id}` }),
  overview: () =>
    requestData<{
      risk_ranking: Array<{ asset: string; total: number; critical: number; high: number; unresolved: number }>;
      compliance: { total_tasks: number; total_checks: number; compliance_rate: number };
      summary: Record<string, number>;
    }>({ method: 'GET', url: '/reports/overview' })
};

// ============ 网络扫描 ============
export interface ScanTask {
  id: string;
  target_cidr: string;
  scan_mode?: string;
  port_range?: string;
  status: string;
  progress?: number;
  created_at?: string;
  completed_at?: string;
}

export interface ScanResult {
  task_id: string;
  ip: string;
  port: number;
  service?: string;
  version?: string;
  banner?: string;
  state?: string;
}

export const scanApi = {
  tasks: (params?: { page?: number; pageSize?: number; status?: string }) =>
    requestData<{ list: ScanTask[]; total: number; page: number; pageSize: number }>({
      method: 'GET',
      url: '/scan/tasks',
      params
    }),
  start: (data: { target_cidr: string; scan_mode?: string; port_range?: string }) =>
    requestData<{ task_id: string; target_cidr?: string; scan_mode?: string; port_range?: string; status?: string }>({
      method: 'POST',
      url: '/scan/start',
      data
    }),
  detail: (taskId: string) =>
    requestData<
      ScanTask & {
        results: ScanResult[];
        stats?: { total_hosts?: number; open_ports?: number; services?: Record<string, number> };
      }
    >({ method: 'GET', url: `/scan/tasks/${taskId}` }),
  remove: (taskId: string) => requestData<null>({ method: 'DELETE', url: `/scan/tasks/${taskId}` })
};

// ============ 基线排查 ============
export interface BaselinePolicy {
  id: number;
  name: string;
  description?: string;
  standard?: string;
  checks?: Array<Record<string, unknown>>;
}

export interface BaselineCheckResult {
  task_id?: string;
  host_id?: string;
  check_id?: string;
  check_name: string;
  expected_value?: string;
  actual_value?: string;
  status?: string;
  severity?: string;
  remediation?: string;
}

export interface BaselineResultsData {
  results: BaselineCheckResult[];
  stats?: { total?: number; pass?: number; fail?: number; warn?: number; compliance_rate?: number | string };
  bySeverity?: Record<string, BaselineCheckResult[]>;
}

export const baselineApi = {
  policies: () => requestData<BaselinePolicy[]>({ method: 'GET', url: '/baseline/policies' }),
  check: (policy_id: number, host = 'localhost') =>
    requestData<{ task_id: string; policy_id: number; policy_name?: string; host_id?: string; check_count?: number; status?: string }>({
      method: 'POST',
      url: '/baseline/check',
      data: { policy_id, host }
    }),
  results: (taskId: string) =>
    requestData<BaselineResultsData>({ method: 'GET', url: `/baseline/results/${taskId}` })
};

// ============ 病毒查杀 ============
export interface VirusRecord {
  id?: number;
  file_name?: string;
  file_hash_md5?: string;
  file_hash_sha256?: string;
  file_size?: number;
  detection_result?: string;
  detection_source?: string;
  model_score?: number;
  uploaded_by?: number;
  created_at?: string;
}

export interface VirusHash {
  id?: number;
  hash_value?: string;
  hash_type?: string;
  threat_name?: string;
  virus_name?: string;
  severity?: string;
  threat_level?: string;
  source?: string;
  description?: string;
  created_at?: string;
}

export interface VirusEngineResult {
  engine?: string;
  status?: string;
  verdict?: string;
  confidence?: number;
  detail?: string;
  responseTime?: number;
  [key: string]: unknown;
}

/** POST /virus/upload 返回的扫描结果 */
export interface VirusScanData {
  scanId?: string;
  recordId?: number | null;
  fileName?: string;
  fileSize?: number;
  hashes?: { md5?: string; sha1?: string; sha256?: string };
  engines?: Record<string, VirusEngineResult>;
  decision?: {
    verdict?: string;
    confidence?: number;
    recommendation?: string;
    primaryEngine?: string;
    maliciousScore?: number;
    suspiciousScore?: number;
  };
  report?: { title?: string; aiSummary?: string; [key: string]: unknown };
  totalTime?: number;
}

/** GET /virus/report/:scanId 返回的扫描报告 */
export interface VirusScanReport {
  scanId?: string;
  file?: string | { originalname?: string; size?: number };
  hashes?: Record<string, string>;
  engineResults?: Array<Record<string, unknown>>;
  decision?: Record<string, unknown>;
  report?: { title?: string; aiSummary?: string; [key: string]: unknown };
  scannedAt?: string;
}

export const virusApi = {
  /** 上传文件进行多引擎查杀（FormData + multipart） */
  upload: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return requestData<VirusScanData>({
      method: 'POST',
      url: '/virus/upload',
      data: formData,
      headers: { 'Content-Type': 'multipart/form-data' }
    });
  },
  /** 兼容旧版：直接返回记录数组（后端无 /records 时走 scan-history 的兜底逻辑） */
  records: () => requestData<VirusRecord[]>({ method: 'GET', url: '/virus/records' }),
  /** 扫描历史（分页） */
  scanHistory: (page = 1, pageSize = 20) =>
    requestData<{ list: VirusRecord[]; total: number; page: number; pageSize: number }>({
      method: 'GET',
      url: '/virus/scan-history',
      params: { page, pageSize }
    }),
  /** 扫描报告详情 */
  report: (scanId: string) =>
    requestData<VirusScanReport>({ method: 'GET', url: `/virus/report/${scanId}` }),
  /** 病毒哈希列表（分页/搜索） */
  hashList: (params: { page?: number; pageSize?: number; search?: string }) =>
    requestData<{ list: VirusHash[]; total: number; page: number; pageSize: number }>({
      method: 'GET',
      url: '/virus/hash-list',
      params
    }),
  /** 哈希分析（多源威胁情报查询） */
  analyzeHash: (hash: string, hashType = 'md5') =>
    requestData<VirusHash[]>({ method: 'POST', url: '/virus/analyze-hash', data: { hash, hashType } }),
  /** 导出 AI 查杀报告 */
  exportReport: (scanId: string, format = 'markdown') =>
    requestData<{ report: string; format: string; scanId: string; fileName?: string }>({
      method: 'POST',
      url: '/virus/export-report',
      data: { scanId, format }
    })
};

// ============ 等保测评 ============
export interface DjppLevel {
  id: number;
  level: number;
  name: string;
  description?: string;
  created_at?: string;
}

export interface DjppCategory {
  id: number;
  level_id: number;
  category_code: string;
  category_name: string;
  description?: string;
}

export interface DjppCheck {
  id: number;
  category_id: number;
  check_code: string;
  check_name: string;
  description?: string;
  check_command?: string;
  expected_value?: string;
  severity?: string;
  requirement_type?: string;
  category_name?: string;
  level_id?: number;
}

export interface DjppTask {
  id: string;
  level: number;
  name: string;
  description?: string;
  status: string;
  progress?: number;
  started_at?: string;
  completed_at?: string;
  created_by?: number;
  created_by_name?: string;
  created_at?: string;
}

export interface DjppResult {
  id?: number;
  task_id?: string;
  check_id?: number;
  check_code?: string;
  check_name: string;
  category_name?: string;
  actual_value?: string;
  status?: string;
  evidence?: string;
  comment?: string;
  severity?: string;
}

export interface DjppTaskDetail {
  task: DjppTask;
  results: DjppResult[];
  stats: {
    total?: number;
    pass?: number;
    fail?: number;
    warning?: number;
    complianceRate?: number | string;
  };
}

export interface DjppReport {
  id: string;
  title: string;
  type?: string;
  content?: string;
  generated_by?: number;
  generated_by_name?: string;
  created_at?: string;
}

/** POST /djpp/tasks/:id/report 返回的测评报告内容 */
export interface DjppReportData {
  reportId?: string;
  taskId?: string;
  level?: number;
  taskName?: string;
  generatedAt?: string;
  stats?: DjppTaskDetail['stats'];
  aiAnalysis?: string;
  content?: string;
  details?: Array<Record<string, unknown>>;
}

export const djppApi = {
  /** 测评等级列表 */
  levels: () => requestData<DjppLevel[]>({ method: 'GET', url: '/djpp/levels' }),
  /** 指定等级的安全类别 */
  categories: (level: number) =>
    requestData<DjppCategory[]>({ method: 'GET', url: `/djpp/levels/${level}/categories` }),
  /** 指定类别的检查项 */
  checks: (categoryId: number) =>
    requestData<DjppCheck[]>({ method: 'GET', url: `/djpp/categories/${categoryId}/checks` }),
  /** 指定等级的全部检查项 */
  levelChecks: (level: number) =>
    requestData<DjppCheck[]>({ method: 'GET', url: `/djpp/levels/${level}/checks` }),
  /** 测评任务列表 */
  tasks: (params?: { page?: number; pageSize?: number }) =>
    requestData<{ tasks: DjppTask[]; total: number; page: number; pageSize: number }>({
      method: 'GET',
      url: '/djpp/tasks',
      params
    }),
  /** 创建测评任务 */
  create: (data: { level: number; name: string; description?: string }) =>
    requestData<{ taskId: string; status: string }>({ method: 'POST', url: '/djpp/tasks', data }),
  /** 任务详情（含检查项结果与统计） */
  detail: (taskId: string) =>
    requestData<DjppTaskDetail>({ method: 'GET', url: `/djpp/tasks/${taskId}` }),
  /** 生成 AI 测评报告（耗时较长） */
  report: (taskId: string) =>
    requestData<DjppReportData>({ method: 'POST', url: `/djpp/tasks/${taskId}/report`, timeout: 120000 }),
  /** 等保报告列表 */
  reports: (params?: { page?: number; pageSize?: number }) =>
    requestData<{ reports: DjppReport[]; total: number; page: number; pageSize: number }>({
      method: 'GET',
      url: '/djpp/reports',
      params
    }),
  /** 删除等保报告 */
  deleteReport: (reportId: string) =>
    requestData<null>({ method: 'DELETE', url: `/djpp/reports/${reportId}` }),
  /** 生成并下载 DOCX 报告（通用报告服务） */
  generateDocx: (reportId: string) =>
    requestData<{ docxPath?: string; downloadUrl?: string }>({
      method: 'POST',
      url: `/reports/${reportId}/generate-docx`
    })
};
// ============ 自动化防御 ============
export interface AutoPolicy {
  id: number;
  name: string;
  description?: string;
  conditions: Array<Record<string, unknown>>;
  actions: Array<Record<string, unknown>>;
  cooldown: number;
  unattended?: number | boolean;
  enabled?: number | boolean;
  approval_status?: string;
  created_by?: number;
  created_at?: string;
}

export interface PolicyApproval {
  approval_id?: number;
  id?: number;
  policy_id?: number;
  name?: string;
  description?: string;
  conditions?: unknown;
  actions?: unknown;
  requester_id?: number;
  requester_name?: string;
  status?: string;
  risk_assessment?: string;
  request_date?: string;
  created_at?: string;
}

export interface ActionLog {
  id: number;
  policy_id?: number;
  policy_name?: string;
  action_type?: string;
  action_detail?: string;
  result?: string;
  executed_at?: string;
}

export interface PageResult<T> {
  list: T[];
  total: number;
  page: number;
  pageSize: number;
}

export interface PolicyPayload {
  name: string;
  description?: string;
  conditions: Array<Record<string, unknown>>;
  actions: Array<Record<string, unknown>>;
  cooldown?: number;
  unattended?: boolean;
  enabled?: boolean;
}

export const defenseApi = {
  /** 获取防御策略列表 */
  policies: () => requestData<AutoPolicy[]>({ method: 'GET', url: '/defense/policies' }),
  /** 创建防御策略 */
  create: (data: PolicyPayload) =>
    requestData<{ id: number; name: string; approval_status?: string }>({
      method: 'POST',
      url: '/defense/policies',
      data
    }),
  /** 更新策略（名称/条件/动作/冷却/启停等） */
  update: (id: number, data: Partial<PolicyPayload>) =>
    requestData<AutoPolicy | null>({ method: 'PUT', url: `/defense/policies/${id}`, data }),
  /** 启停策略 */
  toggle: (id: number, enabled: boolean) =>
    requestData<AutoPolicy | null>({ method: 'PUT', url: `/defense/policies/${id}`, data: { enabled } }),
  /** 删除策略 */
  remove: (id: number) => requestData<null>({ method: 'DELETE', url: `/defense/policies/${id}` }),
  /** 待审批列表 */
  pendingApprovals: () => requestData<PolicyApproval[]>({ method: 'GET', url: '/defense/pending-approvals' }),
  /** 审批策略 */
  approve: (approvalId: number, status: 'approved' | 'rejected', risk_assessment?: string) =>
    requestData<PolicyApproval | null>({
      method: 'POST',
      url: `/defense/approvals/${approvalId}`,
      data: { status, risk_assessment }
    }),
  /** 动作日志（分页） */
  actionLogs: (params?: { page?: number; pageSize?: number; policy_id?: number }) =>
    requestData<PageResult<ActionLog>>({ method: 'GET', url: '/defense/action-logs', params })
};

// ============ AI 安全助手 ============
export interface ChatMessage {
  role: string;
  content: string;
  is_report?: boolean;
}

export interface ChatReply {
  content: string;
  is_report: boolean;
  conversation_id: string;
}

export interface ChatHistory {
  conversation_id: string;
  messages: ChatMessage[];
}

export const aiApi = {
  /** 发送消息进行 AI 对话 */
  chat: (message: string, conversation_id = 'default') =>
    requestData<ChatReply>({ method: 'POST', url: '/ai/chat', data: { message, conversation_id } }),
  /** 获取指定会话的历史消息 */
  history: (conversation_id: string) =>
    requestData<ChatHistory>({ method: 'GET', url: `/ai/history/${conversation_id}` }),
  /** 清除指定会话历史 */
  clearHistory: (conversation_id: string) =>
    requestData<null>({ method: 'DELETE', url: `/ai/history/${conversation_id}` })
};

// ============ 边缘设备 ============
export interface EdgeDevice {
  id?: number;
  device_id: string;
  token?: string;
  ip?: string;
  device_type?: string;
  online_status?: number;
  last_heartbeat?: string;
  metrics?: Record<string, unknown>;
  agent_version?: string;
  registered_at?: string;
}

export interface DeviceCommand {
  id: number;
  device_id: string;
  command: string;
  params?: string | Record<string, unknown>;
  status?: string;
  result?: string | Record<string, unknown> | null;
  created_at?: string;
  executed_at?: string;
}

export const deviceApi = {
  /** 设备列表（分页/在线状态过滤） */
  list: (params?: { page?: number; pageSize?: number; online_status?: number | string }) =>
    requestData<PageResult<EdgeDevice>>({ method: 'GET', url: '/device/list', params }),
  /** 注册新设备 */
  register: (data: { device_id: string; device_type?: string; ip?: string }) =>
    requestData<{ device_id: string; token?: string; ip?: string; device_type?: string; message?: string }>({
      method: 'POST',
      url: '/device/register',
      data
    }),
  /** 设备状态详情 */
  status: (deviceId: string) =>
    requestData<EdgeDevice & { is_online?: boolean; heartbeat_age?: number | null }>({
      method: 'GET',
      url: `/device/${deviceId}/status`
    }),
  /** 下发指令（指令须在服务端白名单内） */
  sendCommand: (deviceId: string, command: string, params: Record<string, unknown>) =>
    requestData<{ command_id: number; device_id: string; command: string; status: string }>({
      method: 'POST',
      url: `/device/${deviceId}/command`,
      data: { command, params }
    }),
  /** 指令历史（分页） */
  commands: (deviceId: string, params?: { page?: number; pageSize?: number }) =>
    requestData<PageResult<DeviceCommand>>({ method: 'GET', url: `/device/${deviceId}/commands`, params }),
  /** 注销设备（管理员） */
  unregister: (deviceId: string) =>
    requestData<null>({ method: 'POST', url: `/device/${deviceId}/unregister` })
};

// ============ 用户管理 ============
export interface UserRecord {
  id: number;
  username: string;
  role_id: number;
  role_name?: string;
  department?: string;
  org_id?: number;
  org_name?: string;
  status?: number;
  created_at?: string;
  updated_at?: string;
}

export interface Org {
  id: number;
  name: string;
  description?: string;
  created_at?: string;
}

export interface AuditLog {
  id: number;
  username?: string;
  operation_type?: string;
  operation_target?: string;
  client_ip?: string;
  result?: string;
  created_at?: string;
}

export const userApi = {
  /** 用户列表（按组织过滤，admin 可传 org_id 跨组织查看） */
  list: (params?: { page?: number; pageSize?: number; keyword?: string; org_id?: number | string }) =>
    requestData<PageResult<UserRecord> & { org_id?: number }>({ method: 'GET', url: '/user/list', params }),
  /** 新建用户（管理员） */
  create: (data: { username: string; password: string; role_id?: number; department?: string; org_id?: number }) =>
    requestData<{ id: number }>({ method: 'POST', url: '/auth/register', data }),
  /** 更新用户（角色/部门/状态） */
  update: (id: number, data: { role_id?: number; department?: string; status?: number; username?: string }) =>
    requestData<null>({ method: 'PUT', url: `/user/${id}`, data }),
  /** 删除用户（管理员） */
  remove: (id: number) => requestData<null>({ method: 'DELETE', url: `/user/${id}` }),
  /** 组织列表（管理员） */
  orgs: () => requestData<Org[]>({ method: 'GET', url: '/user/orgs' }),
  /** 创建组织（管理员） */
  createOrg: (data: { name: string; description?: string }) =>
    requestData<{ id: number; name: string }>({ method: 'POST', url: '/user/orgs', data }),
  /** 审计日志 */
  auditLogs: (params?: {
    page?: number;
    pageSize?: number;
    username?: string;
    operation_type?: string;
    start_date?: string;
    end_date?: string;
  }) => requestData<AuditLog[]>({ method: 'GET', url: '/user/audit-logs', params })
};

// ============ SOAR 剧本 ============
export interface PlaybookStep {
  type?: string;
  name?: string;
  fact?: string;
  operator?: string;
  value?: unknown;
  action?: string;
  params?: Record<string, unknown>;
  channel?: string;
  message?: string;
  title?: string;
  seconds?: number;
}

export interface Playbook {
  id: number;
  name: string;
  description?: string;
  trigger?: string;
  steps: PlaybookStep[];
  enabled?: number | boolean;
  created_by?: number;
  created_at?: string;
  updated_at?: string;
}

export interface PlaybookStepResult {
  step?: number;
  type?: string;
  name?: string;
  ok?: boolean;
  success?: boolean;
  error?: string;
  status?: string;
  approval_id?: string;
  detail?: string;
  message?: string;
}

export interface PlaybookRunResult {
  success?: boolean;
  run_id?: string;
  playbook_id?: number;
  playbook_name?: string;
  status?: string;
  error?: string;
  results?: PlaybookStepResult[];
}

export interface PlaybookApproval {
  id: string;
  playbookId: number;
  stepIndex?: number;
  title: string;
  status: string;
  userId?: number;
  createdAt?: string;
}

export const playbookApi = {
  /** 剧本列表（分页/启用过滤） */
  list: (params?: { page?: number; pageSize?: number; enabled?: number | string }) =>
    requestData<PageResult<Playbook>>({ method: 'GET', url: '/playbook/list', params }),
  /** 剧本详情 */
  detail: (id: number) => requestData<Playbook>({ method: 'GET', url: `/playbook/${id}` }),
  /** 创建剧本（管理员） */
  create: (data: { name: string; description?: string; trigger?: string; steps: PlaybookStep[]; enabled?: boolean }) =>
    requestData<{ id: number; name: string; trigger: string }>({ method: 'POST', url: '/playbook/create', data }),
  /** 更新剧本（管理员） */
  update: (id: number, data: Partial<Playbook>) => requestData<null>({ method: 'PUT', url: `/playbook/${id}`, data }),
  /** 删除剧本（管理员） */
  remove: (id: number) => requestData<null>({ method: 'DELETE', url: `/playbook/${id}` }),
  /** 执行剧本（body 携带触发事件） */
  execute: (id: number, event: Record<string, unknown>) =>
    requestData<PlaybookRunResult>({ method: 'POST', url: `/playbook/${id}/execute`, data: { event } }),
  /** 待人工审批列表 */
  pendingApprovals: () => requestData<PlaybookApproval[]>({ method: 'GET', url: '/playbook/approvals/pending' }),
  /** 审批处理（approve/reject） */
  confirmApproval: (id: string, decision: 'approve' | 'reject') =>
    requestData<{ approval_id: string; status: string; title: string }>({
      method: 'POST',
      url: `/playbook/approvals/${id}`,
      data: { decision }
    }),
  /** 导入剧本模板（管理员） */
  seedTemplates: () => requestData<{ seeded: number }>({ method: 'POST', url: '/playbook/templates/seed' })
};

// ============ 系统配置 ============
export interface ConfigItem {
  id: number;
  key: string;
  value: string;
  description?: string;
  version?: number;
  updated_by?: number;
  updated_at?: string;
}

export interface ConfigBackupItem {
  filename: string;
  size: number;
  created_at?: string;
}

export const configApi = {
  /** 系统配置列表（sys_config 全量） */
  list: () => requestData<ConfigItem[]>({ method: 'GET', url: '/config/list' }),
  /** 更新配置值（管理员） */
  update: (key: string, value: string) => requestData<null>({ method: 'PUT', url: `/config/${key}`, data: { value } }),
  /** 备份文件列表（管理员） */
  backups: () => requestData<ConfigBackupItem[]>({ method: 'GET', url: '/config/backups' }),
  /** 立即备份（管理员） */
  backup: () => requestData<{ filename: string; size: number }>({ method: 'POST', url: '/config/backup' }),
  /** 恢复备份（管理员） */
  restore: (filename: string) =>
    requestData<{ restored_at?: string }>({ method: 'POST', url: '/config/restore', data: { filename } })
};
