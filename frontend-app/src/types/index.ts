/** 通用 API 响应结构 */
export interface ApiResponse<T = unknown> {
  code: number;
  message: string;
  data: T;
}

/** 用户信息 */
export interface UserInfo {
  id: number;
  username: string;
  role_id: number;
  role_name?: string;
  department?: string;
  status?: number;
  permissions?: string;
  created_at?: string;
}

/** 登录响应 */
export interface LoginResult {
  token: string;
  user: UserInfo;
}

/** 分页参数 */
export interface PageQuery {
  page?: number;
  pageSize?: number;
}

/** 分页结果 */
export interface PageResult<T> {
  list: T[];
  total: number;
  page: number;
  pageSize: number;
}

/** 扫描任务 */
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

/** 扫描结果 */
export interface ScanResult {
  id: number;
  task_id: string;
  ip: string;
  port: number;
  service?: string;
  version?: string;
  banner?: string;
  state?: string;
}

/** 告警记录 */
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

/** 病毒扫描记录 */
export interface VirusRecord {
  id: number;
  file_name: string;
  file_hash_md5?: string;
  file_hash_sha256?: string;
  file_size?: number;
  detection_result?: string;
  detection_source?: string;
  model_score?: number;
  created_at?: string;
}

/** 威胁情报 */
export interface ThreatIntel {
  id: number;
  ioc_type: string;
  ioc_value: string;
  source?: string;
  confidence?: number;
  description?: string;
  updated_at?: string;
}

/** 防御策略 */
export interface AutoPolicy {
  id: number;
  name: string;
  description?: string;
  conditions?: Array<Record<string, unknown>>;
  actions?: Array<Record<string, unknown>>;
  cooldown?: number;
  unattended?: boolean;
  enabled?: boolean;
  approval_status?: string;
  created_at?: string;
}

/** 边缘设备 */
export interface EdgeDevice {
  id: number;
  device_id: string;
  ip?: string;
  device_type?: string;
  online_status?: number;
  last_heartbeat?: string;
  metrics?: Record<string, unknown>;
  agent_version?: string;
}

/** 等保测评任务 */
export interface DjppTask {
  id: string;
  level: number;
  name: string;
  description?: string;
  status: string;
  progress?: number;
  created_at?: string;
}

/** 等保测评结果 */
export interface DjppResult {
  id: number;
  task_id: string;
  check_code?: string;
  check_name?: string;
  category_name?: string;
  actual_value?: string;
  status: string;
  severity?: string;
  comment?: string;
}

/** 报告 */
export interface Report {
  id: number;
  title: string;
  type: string;
  content?: string;
  has_docx?: number;
  created_at?: string;
}

/** SOAR 剧本步骤 */
export interface PlaybookStep {
  type: 'condition' | 'action' | 'approval' | 'notification' | 'wait';
  name?: string;
  fact?: string;
  operator?: string;
  value?: unknown;
  action?: string;
  params?: Record<string, unknown>;
  channel?: string;
  message?: string;
  seconds?: number;
  title?: string;
}

/** SOAR 剧本 */
export interface Playbook {
  id: number;
  name: string;
  description?: string;
  trigger?: string;
  steps: PlaybookStep[];
  enabled?: number;
  created_by?: number;
  created_at?: string;
}

/** SOAR 剧本执行结果 */
export interface PlaybookRunResult {
  success: boolean;
  run_id?: string;
  playbook_id?: number;
  status?: string;
  results?: Array<Record<string, unknown>>;
  error?: string;
}

/** WebSocket 推送消息 */
export interface WsMessage {
  type: string;
  data: Record<string, unknown>;
  timestamp: string;
}
