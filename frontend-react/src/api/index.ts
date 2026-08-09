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

// 以下模块桩：C5-C10 逐个填充
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const virusApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const djppApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const defenseApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const deviceApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const userApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const playbookApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const configApi = {} as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const aiApi = {} as any;
