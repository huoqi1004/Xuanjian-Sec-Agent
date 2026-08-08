-- SQLITE Schema（由 scripts/n06/generate-schema.js 自动生成，请勿手改）
-- 生成时间: 2026-08-08T23:11:06.351Z
-- 共 29 张表

CREATE TABLE IF NOT EXISTS action_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  policy_id INTEGER,
  action_type TEXT,
  action_detail TEXT,
  result TEXT DEFAULT 'success',
  executed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (policy_id) REFERENCES auto_policies(id)
);

CREATE TABLE IF NOT EXISTS agent_memories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  memory_key TEXT NOT NULL,
  memory_value TEXT,
  memory_type TEXT DEFAULT 'conclusion',
  importance INTEGER DEFAULT 1,
  source_task_id TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alert_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  related_asset TEXT,
  alert_type TEXT NOT NULL,
  severity TEXT DEFAULT 'medium',
  confidence REAL,
  description TEXT,
  status TEXT DEFAULT 'new',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  resolved_at DATETIME
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  username TEXT,
  operation_type TEXT,
  operation_target TEXT,
  operation_detail TEXT,
  result TEXT DEFAULT 'success',
  client_ip TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS auto_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  conditions TEXT DEFAULT '[]',
  actions TEXT DEFAULT '[]',
  cooldown INTEGER DEFAULT 300,
  unattended BOOLEAN DEFAULT false,
  enabled BOOLEAN DEFAULT true,
  approval_status TEXT DEFAULT 'approved',
  created_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS baseline_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  description TEXT,
  standard TEXT DEFAULT 'CIS',
  checks TEXT DEFAULT '[]',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS baseline_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  host_id TEXT,
  check_id TEXT NOT NULL,
  check_name TEXT,
  expected_value TEXT,
  actual_value TEXT,
  status TEXT DEFAULT 'fail',
  severity TEXT DEFAULT 'medium',
  remediation TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chat_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id TEXT NOT NULL,
  role TEXT NOT NULL,
  content TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS device_commands (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  command TEXT NOT NULL,
  params TEXT DEFAULT '{}',
  status TEXT DEFAULT 'pending',
  result TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  executed_at DATETIME,
  FOREIGN KEY (device_id) REFERENCES edge_devices(device_id)
);

CREATE TABLE IF NOT EXISTS djpp_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  level_id INTEGER NOT NULL,
  category_code TEXT NOT NULL,
  category_name TEXT NOT NULL,
  description TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (level_id) REFERENCES djpp_levels(id)
);

CREATE TABLE IF NOT EXISTS djpp_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category_id INTEGER NOT NULL,
  check_code TEXT NOT NULL,
  check_name TEXT NOT NULL,
  description TEXT,
  check_command TEXT,
  expected_value TEXT,
  severity TEXT DEFAULT 'medium',
  requirement_type TEXT DEFAULT 'main',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (category_id) REFERENCES djpp_categories(id)
);

CREATE TABLE IF NOT EXISTS djpp_levels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  level INTEGER NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS djpp_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  check_id INTEGER NOT NULL,
  check_code TEXT,
  check_name TEXT,
  category_name TEXT,
  actual_value TEXT,
  status TEXT DEFAULT 'fail',
  evidence TEXT,
  comment TEXT,
  severity TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (task_id) REFERENCES djpp_tasks(id),
  FOREIGN KEY (check_id) REFERENCES djpp_checks(id)
);

CREATE TABLE IF NOT EXISTS djpp_tasks (
  id TEXT PRIMARY KEY,
  level INTEGER NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  status TEXT DEFAULT 'pending',
  progress INTEGER DEFAULT 0,
  started_at DATETIME,
  completed_at DATETIME,
  created_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS edge_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT UNIQUE NOT NULL,
  token TEXT NOT NULL,
  ip TEXT,
  device_type TEXT DEFAULT 'gateway',
  online_status INTEGER DEFAULT 0,
  last_heartbeat DATETIME,
  metrics TEXT DEFAULT '{}',
  agent_version TEXT DEFAULT '',
  registered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS organizations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  description TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS playbooks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  trigger TEXT DEFAULT 'manual',
  steps TEXT DEFAULT '[]',
  enabled INTEGER DEFAULT 1,
  created_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policy_approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  policy_id INTEGER NOT NULL,
  requester_id INTEGER,
  approver_id INTEGER,
  status TEXT DEFAULT 'pending',
  risk_assessment TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  reviewed_at DATETIME,
  FOREIGN KEY (policy_id) REFERENCES auto_policies(id),
  FOREIGN KEY (requester_id) REFERENCES users(id),
  FOREIGN KEY (approver_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  type TEXT DEFAULT 'weekly',
  content TEXT,
  has_docx INTEGER DEFAULT 0,
  generated_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (generated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS role_permissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role_id INTEGER NOT NULL,
  resource TEXT NOT NULL,
  actions TEXT DEFAULT '[]',
  FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  description TEXT,
  permissions TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS scan_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  service TEXT DEFAULT '',
  version TEXT DEFAULT '',
  banner TEXT DEFAULT '',
  state TEXT DEFAULT 'open',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (task_id) REFERENCES scan_tasks(id)
);

CREATE TABLE IF NOT EXISTS scan_tasks (
  id TEXT PRIMARY KEY,
  target_cidr TEXT NOT NULL,
  scan_mode TEXT DEFAULT 'tcp_connect',
  port_range TEXT DEFAULT '1-1024',
  status TEXT DEFAULT 'pending',
  progress INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME,
  result_path TEXT,
  created_by INTEGER,
  FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS schema_migrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sys_config (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  value TEXT,
  description TEXT,
  version INTEGER DEFAULT 1,
  updated_by INTEGER,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (updated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS threat_intel (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ioc_type TEXT NOT NULL,
  ioc_value TEXT NOT NULL,
  source TEXT,
  confidence REAL DEFAULT 0.5,
  description TEXT,
  intel_status TEXT DEFAULT 'active',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role_id INTEGER NOT NULL,
  department TEXT DEFAULT '',
  status INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS virus_hashes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hash_value TEXT UNIQUE NOT NULL,
  hash_type TEXT DEFAULT 'md5',
  threat_name TEXT,
  severity TEXT DEFAULT 'high',
  source TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS virus_scan_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_name TEXT NOT NULL,
  file_hash_md5 TEXT,
  file_hash_sha256 TEXT,
  file_size INTEGER,
  detection_result TEXT DEFAULT 'clean',
  detection_source TEXT,
  model_score REAL,
  uploaded_by INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (uploaded_by) REFERENCES users(id)
);

-- 索引

CREATE INDEX IF NOT EXISTS idx_scan_results_task ON scan_results (task_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_ip ON scan_results (ip);
CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs (created_at);
CREATE INDEX IF NOT EXISTS idx_alert_records_severity ON alert_records (severity, status);
CREATE INDEX IF NOT EXISTS idx_alert_records_status ON alert_records (status);
CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intel (ioc_type);
CREATE INDEX IF NOT EXISTS idx_virus_records_time ON virus_scan_records (created_at);
CREATE INDEX IF NOT EXISTS idx_baseline_results_task ON baseline_results (task_id);
CREATE INDEX IF NOT EXISTS idx_device_commands_device ON device_commands (device_id);
CREATE INDEX IF NOT EXISTS idx_action_logs_policy ON action_logs (policy_id);
CREATE INDEX IF NOT EXISTS idx_agent_memories_user ON agent_memories (user_id);
