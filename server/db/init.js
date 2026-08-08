const { getDb } = require('./database');
const bcrypt = require('bcryptjs');
const logger = require('../utils/logger');

async function initDatabase() {
  const db = await getDb();

  db.exec(`
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
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      permissions TEXT DEFAULT '[]'
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS role_permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role_id INTEGER NOT NULL,
      resource TEXT NOT NULL,
      actions TEXT DEFAULT '[]',
      FOREIGN KEY (role_id) REFERENCES roles(id)
    );
  `);

  db.exec(`
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
  `);

  db.exec(`
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
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS baseline_policies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      standard TEXT DEFAULT 'CIS',
      checks TEXT DEFAULT '[]',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  db.exec(`
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
  `);

  db.exec(`
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
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS virus_hashes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hash_value TEXT UNIQUE NOT NULL,
      hash_type TEXT DEFAULT 'md5',
      threat_name TEXT,
      severity TEXT DEFAULT 'high',
      source TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  db.exec(`
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
  `);

  db.exec(`
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
  `);

  db.exec(`
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
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS action_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      policy_id INTEGER,
      action_type TEXT,
      action_detail TEXT,
      result TEXT DEFAULT 'success',
      executed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (policy_id) REFERENCES auto_policies(id)
    );
  `);

  db.exec(`
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
  `);

  db.exec(`
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
  `);

  db.exec(`
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
  `);

  db.exec(`
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
  `);

  db.exec(`
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
  `);

  db.exec(`
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
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS djpp_levels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      level INTEGER NOT NULL UNIQUE,
      name TEXT NOT NULL,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS djpp_categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      level_id INTEGER NOT NULL,
      category_code TEXT NOT NULL,
      category_name TEXT NOT NULL,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (level_id) REFERENCES djpp_levels(id)
    );
  `);

  db.exec(`
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
  `);

  db.exec(`
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
  `);

  db.exec(`
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
  `);

  logger.info('数据库表结构创建完成');

  const indexes = [
    'CREATE INDEX IF NOT EXISTS idx_scan_results_task ON scan_results(task_id)',
    'CREATE INDEX IF NOT EXISTS idx_scan_results_ip ON scan_results(ip)',
    'CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(created_at)',
    'CREATE INDEX IF NOT EXISTS idx_alert_records_severity ON alert_records(severity, status)',
    'CREATE INDEX IF NOT EXISTS idx_alert_records_status ON alert_records(status)',
    'CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intel(ioc_type)',
    'CREATE INDEX IF NOT EXISTS idx_virus_records_time ON virus_scan_records(created_at)',
    'CREATE INDEX IF NOT EXISTS idx_baseline_results_task ON baseline_results(task_id)',
    'CREATE INDEX IF NOT EXISTS idx_device_commands_device ON device_commands(device_id)',
    'CREATE INDEX IF NOT EXISTS idx_action_logs_policy ON action_logs(policy_id)',
  ];

  indexes.forEach(sql => {
    try { db.exec(sql); } catch(e) { }
  });

  await insertDefaultData(db);
}

async function insertDefaultData(db) {
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (userCount.count > 0) {
    logger.info('数据库已包含初始数据，跳过默认数据插入');
    return;
  }

  const insertRole = db.prepare('INSERT OR IGNORE INTO roles (id, name, description, permissions) VALUES (?, ?, ?, ?)');
  insertRole.run(1, 'admin', '系统管理员', JSON.stringify(['*']));
  insertRole.run(2, 'auditor', '审计员', JSON.stringify(['scan', 'view', 'report']));
  insertRole.run(3, 'viewer', '普通用户', JSON.stringify(['view']));

  const insertPerm = db.prepare('INSERT OR IGNORE INTO role_permissions (role_id, resource, actions) VALUES (?, ?, ?)');

  const adminResources = [
    ['/api/auth', '["GET","POST","PUT"]'],
    ['/api/scan', '["GET","POST","DELETE"]'],
    ['/api/baseline', '["GET","POST"]'],
    ['/api/virus', '["GET","POST"]'],
    ['/api/situational', '["GET","POST","PUT"]'],
    ['/api/defense', '["GET","POST","PUT","DELETE"]'],
    ['/api/device', '["GET","POST"]'],
    ['/api/user', '["GET","PUT","DELETE"]'],
    ['/api/config', '["GET","POST","PUT"]']
  ];
  adminResources.forEach(([resource, actions]) => {
    insertPerm.run(1, resource, actions);
  });

  const auditorResources = [
    ['/api/auth', '["GET"]'],
    ['/api/scan', '["GET","POST"]'],
    ['/api/baseline', '["GET","POST"]'],
    ['/api/virus', '["GET"]'],
    ['/api/situational', '["GET","POST"]'],
    ['/api/defense', '["GET"]'],
    ['/api/device', '["GET"]'],
    ['/api/user', '["GET"]'],
    ['/api/playbook', '["GET","POST"]']
  ];
  auditorResources.forEach(([resource, actions]) => {
    insertPerm.run(2, resource, actions);
  });

  const viewerResources = [
    ['/api/auth', '["GET"]'],
    ['/api/scan', '["GET"]'],
    ['/api/baseline', '["GET"]'],
    ['/api/virus', '["GET"]'],
    ['/api/situational', '["GET"]'],
    ['/api/defense', '["GET"]'],
    ['/api/device', '["GET"]'],
    ['/api/playbook', '["GET"]']
  ];
  viewerResources.forEach(([resource, actions]) => {
    insertPerm.run(3, resource, actions);
  });

  const passwordHash = bcrypt.hashSync('admin123', parseInt(process.env.BCRYPT_ROUNDS) || 10);
  const insertUser = db.prepare('INSERT INTO users (username, password_hash, role_id, department) VALUES (?, ?, ?, ?)');
  insertUser.run('admin', passwordHash, 1, '安全运维部');

  const insertConfig = db.prepare('INSERT OR IGNORE INTO sys_config (key, value, description) VALUES (?, ?, ?)');
  insertConfig.run('scan_max_concurrency', '100', '扫描最大并发数');
  insertConfig.run('scan_timeout', '5000', '扫描超时时间(ms)');
  insertConfig.run('device_heartbeat_timeout', '60', '设备心跳超时时间(秒)');
  insertConfig.run('threat_intel_interval', '30', '威胁情报采集间隔(分钟)');
  insertConfig.run('ai_service_url', 'http://localhost:5000', 'AI微服务地址');
  insertConfig.run('virustotal_api_key', '', 'VirusTotal API Key');
  insertConfig.run('ti360_api_key', '', '360天眼API Key');
  insertConfig.run('ti360_api_salt', '', '360天眼API Salt');
  insertConfig.run('kaspersky_api_key', '', '卡巴斯基OpenTIP API Key');
  insertConfig.run('llm_api_key', '', 'LLM API Key');
  insertConfig.run('llm_api_base', 'https://api.openai.com/v1', 'LLM API基础地址');
  insertConfig.run('llm_model', 'gpt-4', 'LLM模型名称');
  insertConfig.run('defense_cooldown', '300', '防御策略冷却时间(秒)');
  insertConfig.run('max_upload_size', '104857600', '最大上传文件大小(字节)');
  insertConfig.run('log_retention_days', '90', '日志保留天数');
  insertConfig.run('smtp_host', '', 'SMTP服务器地址');
  insertConfig.run('smtp_port', '587', 'SMTP端口');
  insertConfig.run('smtp_user', '', 'SMTP用户名');
  insertConfig.run('smtp_pass', '', 'SMTP密码');
  insertConfig.run('notify_email', '', '告警通知接收邮箱');
  insertConfig.run('webhook_url', '', 'Webhook通知URL');

  const insertBaseline = db.prepare('INSERT OR IGNORE INTO baseline_policies (name, description, standard, checks) VALUES (?, ?, ?, ?)');

  const cisDebianChecks = JSON.stringify([
    { id: 'CIS-1.1.1', name: '确保/tmp挂载使用noexec选项', check_command: "mount | grep ' /tmp ' | grep -o 'noexec' || echo 'not_found'", expected_value: 'noexec', operator: 'contains', severity: 'medium', remediation: '编辑/etc/fstab，在/tmp挂载选项中添加noexec' },
    { id: 'CIS-1.4.1', name: '确保系统SSH服务已安装', check_command: "dpkg -l openssh-server 2>/dev/null | grep '^ii' && echo 'installed' || echo 'not_installed'", expected_value: 'installed', operator: 'equals', severity: 'low', remediation: '执行 apt install openssh-server' },
    { id: 'CIS-2.2.1', name: '确保时间同步服务已启用', check_command: "systemctl is-active systemd-timesyncd 2>/dev/null || systemctl is-active chronyd 2>/dev/null || systemctl is-active ntpd 2>/dev/null || echo 'inactive'", expected_value: 'active', operator: 'equals', severity: 'medium', remediation: '执行 apt install systemd-timesyncd && systemctl enable --now systemd-timesyncd' },
    { id: 'CIS-3.1.1', name: '确保IP转发已禁用', check_command: "sysctl net.ipv4.ip_forward 2>/dev/null | awk '{print $3}'", expected_value: '0', operator: 'equals', severity: 'high', remediation: '在/etc/sysctl.conf中设置 net.ipv4.ip_forward=0，然后执行 sysctl -p' },
    { id: 'CIS-3.2.1', name: '确保源路由已禁用', check_command: "sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null | awk '{print $3}'", expected_value: '0', operator: 'equals', severity: 'medium', remediation: '在/etc/sysctl.conf中设置 net.ipv4.conf.all.accept_source_route=0' },
    { id: 'CIS-4.1.1', name: '确保审计服务已安装', check_command: "dpkg -l auditd audispd-plugins 2>/dev/null | grep '^ii' | wc -l", expected_value: '1', operator: 'gte', severity: 'medium', remediation: '执行 apt install auditd audispd-plugins' },
    { id: 'CIS-4.2.1', name: '确保审计日志存储已配置', check_command: "grep -c '^log_file' /etc/audit/auditd.conf 2>/dev/null || echo '0'", expected_value: '1', operator: 'equals', severity: 'medium', remediation: '编辑/etc/audit/auditd.conf，设置log_file参数' },
    { id: 'CIS-5.2.1', name: '确保SSH协议版本为2', check_command: "sshd -T 2>/dev/null | grep -o 'protocol [0-9]' | awk '{print $2}' || grep '^Protocol' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo '2'", expected_value: '2', operator: 'equals', severity: 'high', remediation: '在/etc/ssh/sshd_config中设置 Protocol 2' },
    { id: 'CIS-5.2.2', name: '确保SSH禁止root远程登录', check_command: "sshd -T 2>/dev/null | grep 'permitrootlogin' | awk '{print $2}' || grep '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo 'yes'", expected_value: 'no', operator: 'equals', severity: 'high', remediation: '在/etc/ssh/sshd_config中设置 PermitRootLogin no' },
    { id: 'CIS-5.3.1', name: '确保密码最小长度为14', check_command: "grep '^minlen' /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' || grep '^pam_unix.so' /etc/pam.d/common-password 2>/dev/null | grep -o 'minlen=[0-9]*' | cut -d= -f2 || echo '0'", expected_value: '14', operator: 'equals', severity: 'medium', remediation: '在/etc/security/pwquality.conf中设置 minlen=14' },
    { id: 'CIS-6.1.1', name: '确保文件系统完整性检查已启用', check_command: "dpkg -l aide 2>/dev/null | grep -c '^ii'", expected_value: '2', operator: 'equals', severity: 'medium', remediation: '执行 apt install aide && 配置定时检查任务' },
    { id: 'CIS-6.2.1', name: '确保系统已配置自动安全更新', check_command: "dpkg -l unattended-upgrades 2>/dev/null | grep -c '^ii'", expected_value: '1', operator: 'equals', severity: 'medium', remediation: '执行 apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades' }
  ]);

  insertBaseline.run('CIS Debian Linux Benchmark', 'CIS Debian Linux 基线安全检查策略', 'CIS', cisDebianChecks);

  const cisWindowsChecks = JSON.stringify([
    { id: 'CIS-WIN-1.1.1', name: '确保密码最小长度至少为14个字符', check_command: 'net accounts | findstr "最小密码长度"', expected_value: '14', operator: 'regex', severity: 'high', remediation: '在本地安全策略中设置密码最小长度 = 14' },
    { id: 'CIS-WIN-1.1.2', name: '确保密码最长使用期限不超过365天', check_command: 'net accounts | findstr "密码最长使用期限"', expected_value: '365', operator: 'range', severity: 'medium', remediation: '在本地安全策略中设置密码最长使用期限不超过365天' },
    { id: 'CIS-WIN-1.2.1', name: '确保账户锁定阈值为5次或更少', check_command: 'net accounts | findstr "锁定阈值"', expected_value: '5', operator: 'range', severity: 'high', remediation: '在本地安全策略中设置账户锁定阈值为5次或更少' },
    { id: 'CIS-WIN-2.1.1', name: '确保Windows防火墙已启用', check_command: 'netsh advfirewall show allprofiles state | findstr "已启用"', expected_value: '已启用', operator: 'contains', severity: 'high', remediation: '启用Windows防火墙' },
    { id: 'CIS-WIN-2.2.1', name: '确保远程桌面已禁用', check_command: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections', expected_value: '0x1', operator: 'contains', severity: 'high', remediation: '禁用远程桌面' },
    { id: 'CIS-WIN-2.2.2', name: '确保WinRM服务未运行', check_command: 'powershell -Command "Get-Service WinRM | Select-Object -ExpandProperty Status"', expected_value: 'Stopped', operator: 'equals', severity: 'medium', remediation: '停止并禁用WinRM服务' },
    { id: 'CIS-WIN-2.3.1', name: '确保SMBv1已禁用', check_command: 'powershell -Command "Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol"', expected_value: 'False', operator: 'equals', severity: 'high', remediation: '禁用SMBv1' },
    { id: 'CIS-WIN-9.1.1', name: '确保Windows事件日志已启用', check_command: 'wevtutil get-log Application | findstr "enabled"', expected_value: 'true', operator: 'contains', severity: 'medium', remediation: '启用Windows事件日志' },
    { id: 'CIS-WIN-9.2.1', name: '确保审计登录事件已启用', check_command: 'auditpol /get /subcategory:"Logon"', expected_value: '成功和失败', operator: 'contains', severity: 'high', remediation: '启用登录审计' },
    { id: 'CIS-WIN-17.1.1', name: '确保安装了最新的安全补丁', check_command: 'systeminfo | findstr /B /C:"OS 名称" /C:"OS 版本"', expected_value: '10.0.19045', operator: 'contains', severity: 'high', remediation: '运行Windows Update并安装所有可用安全补丁' }
  ]);

  insertBaseline.run('CIS Windows Benchmark', 'CIS Microsoft Windows 基线安全检查策略', 'CIS', cisWindowsChecks);

  const djppChecks = JSON.stringify([
    { id: 'DJPP-8.1.1', name: '身份鉴别-密码复杂度', check_command: "grep '^minclass' /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' || echo '0'", expected_value: '3', operator: 'equals', severity: 'high', remediation: '在/etc/security/pwquality.conf中设置 minclass=3' },
    { id: 'DJPP-8.1.2', name: '身份鉴别-登录失败处理', check_command: "grep '^pam_faillock.so\\|^auth.*pam_faillock' /etc/pam.d/common-auth 2>/dev/null | wc -l || echo '0'", expected_value: '1', operator: 'not_equals', severity: 'high', remediation: '配置pam_faillock模块' },
    { id: 'DJPP-8.1.3', name: '访问控制-权限管理', check_command: "awk -F: '$3 == 0 {print $1}' /etc/passwd | grep -v '^root$' | wc -l", expected_value: '0', operator: 'equals', severity: 'high', remediation: '确保只有root用户的UID为0' },
    { id: 'DJPP-8.1.4', name: '安全审计-审计策略', check_command: "systemctl is-active auditd 2>/dev/null || echo 'inactive'", expected_value: 'active', operator: 'equals', severity: 'high', remediation: '安装并启用auditd' },
    { id: 'DJPP-8.1.5', name: '入侵防范-恶意代码防范', check_command: "(dpkg -l clamav 2>/dev/null | grep -c '^ii') + (systemctl is-active clamav-freshclam 2>/dev/null | grep -c 'active') | bc 2>/dev/null || echo '0'", expected_value: '2', operator: 'equals', severity: 'high', remediation: '安装并启用ClamAV' },
    { id: 'DJPP-8.1.6', name: '入侵防范-入侵检测', check_command: "(dpkg -l fail2ban 2>/dev/null | grep -c '^ii') + (systemctl is-active fail2ban 2>/dev/null | grep -c 'active') | bc 2>/dev/null || echo '0'", expected_value: '2', operator: 'equals', severity: 'medium', remediation: '安装并启用fail2ban' },
    { id: 'DJPP-8.1.7', name: '可信验证-可信启动', check_command: "ls /sys/firmware/efi 2>/dev/null && echo 'uefi' || echo 'bios'", expected_value: 'uefi', operator: 'equals', severity: 'medium', remediation: '启用UEFI Secure Boot' },
    { id: 'DJPP-8.1.8', name: '数据完整性-传输加密', check_command: "openssl version 2>/dev/null | awk '{print $2}' | grep -oE '^[0-9]+\\.[0-9]+' || echo '0.0'", expected_value: '1.1', operator: 'regex', severity: 'high', remediation: '确保OpenSSL版本支持TLS 1.2+' }
  ]);

  insertBaseline.run('等保2.0 安全基线', '信息安全等级保护2.0标准基线检查策略', '等保2.0', djppChecks);

  const insertHash = db.prepare('INSERT OR IGNORE INTO virus_hashes (hash_value, hash_type, threat_name, severity, source) VALUES (?, ?, ?, ?, ?)');
  const sampleHashes = [
    ['44d88612fea8a8f36de82e1278abb02f', 'md5', 'EICAR-Test-File', 'low', 'EICAR'],
    ['275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'sha256', 'EICAR-Test-File', 'low', 'EICAR'],
    ['5d41402abc4b2a76b9719d911017c592', 'md5', 'Trojan.Win32.Generic', 'high', 'VirusTotal'],
    ['a3f2b8c9d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0', 'sha256', 'Ransomware.CryptoLocker', 'critical', 'VirusTotal'],
    ['e99a18c428cb38d5f260853678922e03', 'md5', 'Backdoor.Win32.Meterpreter', 'critical', 'Malwarebytes'],
    ['098f6bcd4621d373cade4e832627b4f6', 'md5', 'Trojan.Downloader.Agent', 'high', 'Kaspersky'],
    ['d41d8cd98f00b204e9800998ecf8427e', 'md5', 'Adware.PUP.Toolbar', 'medium', 'Symantec'],
    ['c4ca4238a0b923820dcc509a6f75849b', 'md5', 'Ransomware.Wannacry', 'critical', 'CISA'],
    ['8f14e45fceea167a5a36dedd4bea2543', 'md5', 'Spyware.Keylogger.Gen', 'high', 'Bitdefender'],
    ['e2fc714c4727ee9395f324cd2e7f331f', 'md5', 'Rootkit.Agent.Hidden', 'critical', 'ESET'],
    ['25f9e794323b453885f5181f1b624d0b', 'md5', 'Trojan.Win32.Zeus', 'critical', 'VirusTotal'],
    ['356a192b7913b04c54574d18c28d46e6', 'md5', 'Ransomware.Locky', 'critical', 'Malwarebytes'],
    ['da4b9237bacccdf19c0760cab7aec4a8', 'md5', 'Worm.Email.Bagle', 'high', 'Kaspersky'],
    ['77de68daecd823babbb58edb1c8e14d7', 'md5', 'Trojan.Banker.SpyEye', 'critical', 'Symantec'],
    ['1b6453892473a467d07372d45eb05abc', 'md5', 'Adware.Browser.Hijacker', 'medium', 'Bitdefender'],
    ['ac3478d69a3c81fa62e60f5c3696165a', 'md5', 'Ransomware.CryptoWall', 'critical', 'ESET'],
    ['32d1c57b374576028874bc02e68dc205', 'md5', 'Backdoor.Android.Spy', 'high', 'VirusTotal'],
    ['e4da3b7fbbce2345d7772b0674a318d5', 'md5', 'Trojan.Mac.OSX.Generic', 'high', 'Malwarebytes'],
    ['6b86b273ff34fce19d6b804eff5a3f57', 'md5', 'Worm.SQL.Slammer', 'critical', 'CISA'],
    ['d4735e3a265e16eee03f59718b9b5d03', 'md5', 'Trojan.Password.Stealer', 'high', 'Kaspersky']
  ];
  sampleHashes.forEach(([hash, type, name, severity, source]) => {
    insertHash.run(hash, type, name, severity, source);
  });

  const insertScanRecord = db.prepare('INSERT INTO virus_scan_records (file_name, file_hash_md5, file_hash_sha256, file_size, detection_result, detection_source, model_score, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
  const scanRecords = [
    ['suspicious_file.exe', '5d41402abc4b2a76b9719d911017c592', 'a3f2b8c9d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0', 153600, 'malicious', 'Hash-Match', 0.95, 1],
    ['clean_doc.docx', 'd41d8cd98f00b204e9800998ecf8427e', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 12288, 'clean', 'AI-Analysis', 0.02, 1],
    ['installer.exe', 'e99a18c428cb38d5f260853678922e03', 'f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea8a95f7b76b7fd4', 524288, 'malicious', 'Hash-Match', 0.98, 1],
    ['data_backup.zip', 'c4ca4238a0b923820dcc509a6f75849b', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 1048576, 'malicious', 'AI-Analysis', 0.91, 1],
    ['system_update.dll', '8f14e45fceea167a5a36dedd4bea2543', '4a0a19218e082a343a1b17e5333409af9d98f0f4a9f4460f9f98505d7031a5c6', 65536, 'malicious', 'Hash-Match', 0.89, 1],
    ['presentation.pptx', 'e2fc714c4727ee9395f324cd2e7f331f', 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c', 45056, 'clean', 'AI-Analysis', 0.05, 1],
    ['test_file.txt', '44d88612fea8a8f36de82e1278abb02f', '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 68, 'suspicious', 'EICAR-Test', 0.10, 1],
    ['invoice.pdf', '098f6bcd4621d373cade4e832627b4f6', 'a10a81b4b8a5d5b6f7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a1', 73728, 'malicious', 'AI-Analysis', 0.85, 1],
    ['image.png', 'da4b9237bacccdf19c0760cab7aec4a8', 'c5e478d59288c841aa530db6845c4c8d96299773bcbea9045d8c1e55d926fb78', 262144, 'clean', 'AI-Analysis', 0.03, 1],
    ['setup.msi', '25f9e794323b453885f5181f1b624d0b', 'd6a3c7e2f8e8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4', 10485760, 'malicious', 'Hash-Match', 0.97, 1],
    ['readme.txt', '356a192b7913b04c54574d18c28d46e6', '7b8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8', 1024, 'clean', 'AI-Analysis', 0.01, 1],
    ['archive.rar', 'ac3478d69a3c81fa62e60f5c3696165a', '8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9', 2097152, 'malicious', 'AI-Analysis', 0.93, 1],
    ['video.mp4', '32d1c57b374576028874bc02e68dc205', '9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e', 5242880, 'clean', 'AI-Analysis', 0.04, 1],
    ['config.xml', 'e4da3b7fbbce2345d7772b0674a318d5', '0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f', 4096, 'clean', 'AI-Analysis', 0.02, 1],
    ['script.ps1', '6b86b273ff34fce19d6b804eff5a3f57', '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1', 8192, 'malicious', 'AI-Analysis', 0.88, 1],
    ['driver.sys', 'd4735e3a265e16eee03f59718b9b5d03', '2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2', 131072, 'malicious', 'Hash-Match', 0.94, 1],
    ['document.xlsx', '77de68daecd823babbb58edb1c8e14d7', '3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3', 32768, 'clean', 'AI-Analysis', 0.06, 1],
    ['program.exe', '1b6453892473a467d07372d45eb05abc', '4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4', 262144, 'suspicious', 'AI-Analysis', 0.45, 1]
  ];
  scanRecords.forEach(([name, md5, sha256, size, result, source, score, user]) => {
    insertScanRecord.run(name, md5, sha256, size, result, source, score, user);
  });

  const insertIntel = db.prepare('INSERT OR IGNORE INTO threat_intel (ioc_type, ioc_value, source, confidence, description) VALUES (?, ?, ?, ?, ?)');
  const sampleIntel = [
    ['ip', '185.220.101.34', 'OTX', 0.95, '已知恶意IP - Tor出口节点'],
    ['ip', '45.33.32.156', 'VirusTotal', 0.88, '已知恶意IP - 关联僵尸网络C2通信'],
    ['ip', '103.224.182.250', 'CISA KEV', 0.92, '已知恶意IP - 关联钓鱼攻击'],
    ['ip', '192.168.1.100', '本地扫描', 0.6, '内网异常通信'],
    ['domain', 'malware-distribution.example.com', 'OTX', 0.95, '恶意软件分发域名'],
    ['domain', 'phishing-login.example.com', 'VirusTotal', 0.9, '钓鱼登录页面域名'],
    ['domain', 'c2-server.example.com', 'CISA KEV', 0.98, 'C2控制服务器域名'],
    ['hash', '44d88612fea8a8f36de82e1278abb02f', 'VirusTotal', 1.0, 'EICAR测试文件'],
    ['hash', 'e99a18c428cb38d5f260853678922e03', 'VirusTotal', 0.95, '已知后门程序'],
    ['cve', 'CVE-2024-0001', 'NVD', 0.9, '远程代码执行漏洞 - CVSS 9.8'],
    ['cve', 'CVE-2024-0002', 'NVD', 0.85, '权限提升漏洞 - CVSS 8.1'],
    ['cve', 'CVE-2024-0003', 'NVD', 0.8, '信息泄露漏洞 - CVSS 7.5'],
    ['ip', '10.0.0.50', '本地检测', 0.7, '内网异常流量'],
    ['ip', '172.16.0.100', '本地检测', 0.65, '内网异常端口扫描行为'],
    ['domain', 'update-service.example.com', 'OTX', 0.75, '疑似恶意更新服务域名']
  ];
  sampleIntel.forEach(([type, value, source, confidence, desc]) => {
    insertIntel.run(type, value, source, confidence, desc);
  });

  const insertPolicy = db.prepare('INSERT OR IGNORE INTO auto_policies (name, description, conditions, actions, cooldown, unattended, enabled, approval_status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');

  insertPolicy.run('恶意IP自动封禁', '当检测到与已知恶意IP通信时自动封禁', JSON.stringify([{ fact: 'threat_intel_match', operator: 'equal', value: true }, { fact: 'confidence', operator: 'greaterThan', value: 0.85 }]), JSON.stringify([{ type: 'block_ip', params: { duration: 3600 } }, { type: 'alert', params: { level: 'high' } }]), 300, 0, 1, 'approved', 1);
  insertPolicy.run('暴力破解自动防御', '当检测到SSH暴力破解行为时自动防御', JSON.stringify([{ fact: 'event_type', operator: 'equal', value: 'brute_force' }, { fact: 'fail_count', operator: 'greaterThan', value: 5 }]), JSON.stringify([{ type: 'block_ip', params: { duration: 1800 } }, { type: 'alert', params: { level: 'medium' } }, { type: 'account_lock', params: { duration: 900 } }]), 600, 1, 1, 'approved', 1);
  insertPolicy.run('异常流量告警', '当检测到异常网络流量时发送告警', JSON.stringify([{ fact: 'traffic_anomaly', operator: 'equal', value: true }, { fact: 'traffic_multiplier', operator: 'greaterThan', value: 3 }]), JSON.stringify([{ type: 'alert', params: { level: 'high' } }, { type: 'traffic_limit', params: { max_bandwidth: '10Mbps' } }]), 300, 0, 1, 'approved', 1);

  const insertAlert = db.prepare('INSERT OR IGNORE INTO alert_records (related_asset, alert_type, severity, confidence, description, status) VALUES (?, ?, ?, ?, ?, ?)');
  insertAlert.run('192.168.1.100', '恶意通信', 'high', 0.92, '检测到与已知恶意IP 185.220.101.34的通信', 'new');
  insertAlert.run('10.0.0.50', '异常流量', 'medium', 0.75, '内网主机10.0.0.50产生异常出站流量', 'new');
  insertAlert.run('web-server-01', '暴力破解', 'high', 0.88, 'SSH服务检测到暴力破解尝试', 'acknowledged');
  insertAlert.run('db-server-01', '漏洞利用', 'critical', 0.95, '检测到CVE-2024-0001漏洞利用尝试', 'new');
  insertAlert.run('172.16.0.100', '横向移动', 'high', 0.82, '检测到内网横向移动行为', 'new');

  const insertDjppLevel = db.prepare('INSERT OR IGNORE INTO djpp_levels (level, name, description) VALUES (?, ?, ?)');
  insertDjppLevel.run(1, '第一级', '自主保护级：信息系统的安全保护能力达到国家标准的第一级，信息系统运营、使用单位应当按照国家有关管理规范和技术标准保护信息系统');
  insertDjppLevel.run(2, '第二级', '指导保护级：信息系统的安全保护能力达到国家标准的第二级，信息系统运营、使用单位应当按照国家有关管理规范和技术标准保护信息系统，由信息安全主管部门进行指导');
  insertDjppLevel.run(3, '第三级', '监督保护级：信息系统的安全保护能力达到国家标准的第三级，信息系统运营、使用单位应当按照国家有关管理规范和技术标准保护信息系统，由信息安全主管部门进行监督');
  insertDjppLevel.run(4, '第四级', '强制保护级：信息系统的安全保护能力达到国家标准的第四级，信息系统运营、使用单位应当按照国家有关管理规范和技术标准保护信息系统，由信息安全主管部门进行强制要求');
  insertDjppLevel.run(5, '第五级', '专控保护级：信息系统的安全保护能力达到国家标准的第五级，信息系统运营、使用单位应当按照国家有关管理规范和技术标准保护信息系统，由国家指定的专门部门、机构进行专门控制');

  const insertDjppCategory = db.prepare('INSERT OR IGNORE INTO djpp_categories (level_id, category_code, category_name, description) VALUES (?, ?, ?, ?)');
  const categories = [
    [2, 'S1', '身份鉴别', '验证用户身份的真实性，防止身份冒充'],
    [2, 'S2', '访问控制', '控制用户对资源的访问权限'],
    [2, 'S3', '安全审计', '记录和审计重要安全事件'],
    [2, 'S4', '数据完整性', '保证数据的完整性'],
    [2, 'S5', '数据保密性', '保护数据的保密性'],
    [2, 'S6', '可信验证', '对重要组件进行验证'],
    [3, 'S1', '身份鉴别', '验证用户身份的真实性'],
    [3, 'S2', '访问控制', '控制用户对资源的访问权限'],
    [3, 'S3', '安全审计', '记录和审计重要安全事件'],
    [3, 'S4', '数据完整性', '保证数据的完整性'],
    [3, 'S5', '数据保密性', '保护数据的保密性'],
    [3, 'S6', '可信验证', '对重要组件进行验证'],
    [3, 'S7', '入侵防范', '防范网络入侵行为'],
    [3, 'S8', '恶意代码防范', '防范恶意代码攻击'],
    [4, 'S1', '身份鉴别', '验证用户身份的真实性'],
    [4, 'S2', '访问控制', '控制用户对资源的访问权限'],
    [4, 'S3', '安全审计', '记录和审计重要安全事件'],
    [4, 'S4', '数据完整性', '保证数据的完整性'],
    [4, 'S5', '数据保密性', '保护数据的保密性'],
    [4, 'S6', '可信验证', '对重要组件进行验证'],
    [4, 'S7', '入侵防范', '防范网络入侵行为'],
    [4, 'S8', '恶意代码防范', '防范恶意代码攻击'],
    [4, 'S9', '数据备份恢复', '重要数据的备份和恢复']
  ];
  categories.forEach(([levelId, code, name, desc]) => {
    insertDjppCategory.run(levelId, code, name, desc);
  });

  const insertDjppCheck = db.prepare('INSERT OR IGNORE INTO djpp_checks (category_id, check_code, check_name, description, check_command, expected_value, severity, requirement_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
  const checks = [
    [1, 'S1-01', '身份标识唯一性', '确保用户身份标识唯一', "awk -F: '{print $1}' /etc/passwd | sort | uniq -d | wc -l", '0', 'high', 'main'],
    [1, 'S1-02', '密码复杂度要求', '配置密码复杂度', "grep '^minclass' /etc/security/pwquality.conf 2>/dev/null | wc -l", '1', 'high', 'main'],
    [1, 'S2-01', '最小权限原则', '确保权限配置', "awk -F: '$3 == 0 {print $1}' /etc/passwd | grep -v '^root$' | wc -l", '0', 'high', 'main'],
    [2, 'S1-01', '身份标识唯一性', '确保用户身份标识唯一', "awk -F: '{print $1}' /etc/passwd | sort | uniq -d | wc -l", '0', 'high', 'main'],
    [2, 'S1-02', '登录失败处理', '配置登录失败锁定', "grep '^pam_faillock.so' /etc/pam.d/common-auth 2>/dev/null | wc -l", '1', 'high', 'main'],
    [2, 'S2-01', '最小权限原则', '确保权限配置', "awk -F: '$3 == 0 {print $1}' /etc/passwd | grep -v '^root$' | wc -l", '0', 'high', 'main'],
    [2, 'S3-01', '审计服务运行', '审计服务已启用', "systemctl is-active auditd 2>/dev/null || echo 'inactive'", 'active', 'high', 'main'],
    [2, 'S4-01', '数据完整性保护', '完整性检查机制存在', "which sha256sum 2>/dev/null && echo 'exist' || echo 'missing'", 'exist', 'medium', 'main'],
    [2, 'S5-01', '传输加密', 'TLS配置', "openssl version 2>/dev/null | grep '1.1' || echo 'old'", '1.1', 'high', 'main'],
    [3, 'S1-01', '身份标识唯一性', '确保用户身份标识唯一', "awk -F: '{print $1}' /etc/passwd | sort | uniq -d | wc -l", '0', 'high', 'main'],
    [3, 'S1-02', '登录失败处理', '配置登录失败锁定', "grep '^pam_faillock.so' /etc/pam.d/common-auth 2>/dev/null | wc -l", '1', 'high', 'main'],
    [3, 'S2-01', '最小权限原则', '确保权限配置', "awk -F: '$3 == 0 {print $1}' /etc/passwd | grep -v '^root$' | wc -l", '0', 'high', 'main'],
    [3, 'S3-01', '审计服务运行', '审计服务已启用', "systemctl is-active auditd 2>/dev/null || echo 'inactive'", 'active', 'high', 'main'],
    [3, 'S4-01', '数据完整性保护', '完整性检查机制存在', "which sha256sum 2>/dev/null && echo 'exist' || echo 'missing'", 'exist', 'medium', 'main'],
    [3, 'S5-01', '传输加密', 'TLS配置', "openssl version 2>/dev/null | grep '1.1' || echo 'old'", '1.1', 'high', 'main'],
    [3, 'S7-01', '入侵检测', 'IDS/IPS运行', "dpkg -l fail2ban 2>/dev/null | grep -c '^ii'", '1', 'high', 'main'],
    [3, 'S8-01', '恶意代码防护', '防病毒软件运行', "dpkg -l clamav 2>/dev/null | grep -c '^ii'", '1', 'high', 'main'],
    [4, 'S1-01', '身份标识唯一性', '确保用户身份标识唯一', "awk -F: '{print $1}' /etc/passwd | sort | uniq -d | wc -l", '0', 'critical', 'main'],
    [4, 'S1-02', '登录失败处理', '配置登录失败锁定', "grep '^pam_faillock.so' /etc/pam.d/common-auth 2>/dev/null | wc -l", '1', 'critical', 'main'],
    [4, 'S2-01', '最小权限原则', '确保权限配置', "awk -F: '$3 == 0 {print $1}' /etc/passwd | grep -v '^root$' | wc -l", '0', 'critical', 'main'],
    [4, 'S3-01', '审计服务运行', '审计服务已启用', "systemctl is-active auditd 2>/dev/null || echo 'inactive'", 'active', 'critical', 'main'],
    [4, 'S4-01', '数据完整性保护', '完整性检查机制存在', "which sha256sum 2>/dev/null && echo 'exist' || echo 'missing'", 'exist', 'high', 'main'],
    [4, 'S5-01', '传输加密', 'TLS配置', "openssl version 2>/dev/null | grep '1.1' || echo 'old'", '1.1', 'high', 'main'],
    [4, 'S7-01', '入侵检测', 'IDS/IPS运行', "dpkg -l fail2ban 2>/dev/null | grep -c '^ii'", '1', 'critical', 'main'],
    [4, 'S8-01', '恶意代码防护', '防病毒软件运行', "dpkg -l clamav 2>/dev/null | grep -c '^ii'", '1', 'critical', 'main'],
    [4, 'S9-01', '数据备份', '备份策略配置', "ls /var/backups 2>/dev/null | wc -l", '1', 'high', 'main']
  ];
  checks.forEach(([catId, code, name, desc, cmd, expected, severity, reqType]) => {
    insertDjppCheck.run(catId, code, name, desc, cmd, expected, severity, reqType);
  });

  const insertDjppTask = db.prepare('INSERT OR IGNORE INTO djpp_tasks (id, level, name, description, status, progress, started_at, completed_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
  const djppTasks = [
    ['DJPP-TASK-001', 3, '2026年度等级保护第三级测评', '针对公司核心业务系统进行等级保护第三级测评', 'completed', 100, '2026-05-20 09:00:00', '2026-05-20 11:30:00', 1, '2026-05-20 08:50:00'],
    ['DJPP-TASK-002', 2, '办公系统等保二级测评', '对办公自动化系统进行等级保护第二级测评', 'completed', 100, '2026-05-18 14:00:00', '2026-05-18 16:00:00', 1, '2026-05-18 13:30:00'],
    ['DJPP-TASK-003', 4, '金融业务系统四级测评', '针对金融交易系统进行等级保护第四级测评', 'completed', 100, '2026-05-15 09:00:00', '2026-05-15 17:00:00', 1, '2026-05-15 08:30:00'],
    ['DJPP-TASK-004', 3, '门户网站等保三级测评', '对外门户网站等级保护第三级测评', 'completed', 100, '2026-05-10 10:00:00', '2026-05-10 12:30:00', 1, '2026-05-10 09:30:00'],
    ['DJPP-TASK-005', 2, '内部管理系统二级测评', '内部资源管理系统等级保护第二级测评', 'completed', 100, '2026-05-08 14:00:00', '2026-05-08 15:30:00', 1, '2026-05-08 13:45:00'],
    ['DJPP-TASK-006', 1, '测试系统一级测评', '开发测试环境等级保护第一级测评', 'completed', 100, '2026-05-05 15:00:00', '2026-05-05 15:30:00', 1, '2026-05-05 14:45:00']
  ];
  djppTasks.forEach(([id, level, name, desc, status, progress, started, completed, createdBy, createdAt]) => {
    insertDjppTask.run(id, level, name, desc, status, progress, started, completed, createdBy, createdAt);
  });

  const insertDjppResult = db.prepare('INSERT OR IGNORE INTO djpp_results (task_id, check_id, check_code, check_name, category_name, actual_value, status, evidence, comment, severity) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
  const djppResults = [
    ['DJPP-TASK-001', 13, 'S1-01', '身份标识唯一性', '身份鉴别', '0', 'pass', '执行命令检查用户唯一性，结果为0，表示无重复用户', '符合要求', 'high'],
    ['DJPP-TASK-001', 14, 'S1-02', '登录失败处理', '身份鉴别', '1', 'pass', 'pam_faillock模块已配置', '符合要求', 'high'],
    ['DJPP-TASK-001', 15, 'S2-01', '最小权限原则', '访问控制', '0', 'pass', '检查root用户，无异常UID=0用户', '符合要求', 'high'],
    ['DJPP-TASK-001', 16, 'S3-01', '审计服务运行', '安全审计', 'active', 'pass', 'auditd服务已启动并运行', '符合要求', 'high'],
    ['DJPP-TASK-001', 17, 'S4-01', '数据完整性保护', '数据完整性', 'exist', 'pass', 'sha256sum工具已安装', '符合要求', 'medium'],
    ['DJPP-TASK-001', 18, 'S5-01', '传输加密', '数据保密性', '1.1', 'pass', 'OpenSSL版本符合要求', '符合要求', 'high'],
    ['DJPP-TASK-001', 19, 'S7-01', '入侵检测', '入侵防范', '1', 'pass', 'fail2ban已安装', '符合要求', 'high'],
    ['DJPP-TASK-001', 20, 'S8-01', '恶意代码防护', '恶意代码防范', '0', 'fail', 'clamav未安装', '期望: 1, 实际: 0', 'high'],
    ['DJPP-TASK-002', 1, 'S1-01', '身份标识唯一性', '身份鉴别', '0', 'pass', '用户身份标识唯一', '符合要求', 'high'],
    ['DJPP-TASK-002', 2, 'S1-02', '密码复杂度要求', '身份鉴别', '1', 'pass', '密码复杂度已配置', '符合要求', 'high'],
    ['DJPP-TASK-002', 3, 'S2-01', '最小权限原则', '访问控制', '0', 'pass', '权限配置符合要求', '符合要求', 'high'],
    ['DJPP-TASK-002', 4, 'S1-01', '身份标识唯一性', '身份鉴别', '0', 'pass', '用户身份标识唯一', '符合要求', 'high'],
    ['DJPP-TASK-002', 5, 'S1-02', '登录失败处理', '身份鉴别', '0', 'fail', '未配置登录失败锁定', '期望: 1, 实际: 0', 'high'],
    ['DJPP-TASK-003', 21, 'S1-01', '身份标识唯一性', '身份鉴别', '0', 'pass', '用户身份标识唯一', '符合要求', 'critical'],
    ['DJPP-TASK-003', 22, 'S1-02', '登录失败处理', '身份鉴别', '1', 'pass', 'pam_faillock已配置', '符合要求', 'critical'],
    ['DJPP-TASK-003', 23, 'S2-01', '最小权限原则', '访问控制', '0', 'pass', '权限配置严格', '符合要求', 'critical'],
    ['DJPP-TASK-003', 24, 'S3-01', '审计服务运行', '安全审计', 'active', 'pass', 'auditd运行正常', '符合要求', 'critical'],
    ['DJPP-TASK-003', 25, 'S4-01', '数据完整性保护', '数据完整性', 'exist', 'pass', '完整性检查机制存在', '符合要求', 'high'],
    ['DJPP-TASK-003', 26, 'S5-01', '传输加密', '数据保密性', '1.1', 'pass', 'TLS配置符合要求', '符合要求', 'high'],
    ['DJPP-TASK-003', 27, 'S7-01', '入侵检测', '入侵防范', '1', 'pass', 'IDS运行正常', '符合要求', 'critical'],
    ['DJPP-TASK-003', 28, 'S8-01', '恶意代码防护', '恶意代码防范', '1', 'pass', '防病毒软件运行', '符合要求', 'critical'],
    ['DJPP-TASK-003', 29, 'S9-01', '数据备份', '数据备份恢复', '15', 'pass', '备份策略已配置', '符合要求', 'high']
  ];
  djppResults.forEach(([taskId, checkId, code, name, category, actual, status, evidence, comment, severity]) => {
    insertDjppResult.run(taskId, checkId, code, name, category, actual, status, evidence, comment, severity);
  });

  const insertReport = db.prepare('INSERT OR IGNORE INTO reports (id, title, type, content, generated_by, created_at) VALUES (?, ?, ?, ?, ?, ?)');
  const djppReportContent = {
    taskId: 'DJPP-TASK-001',
    level: 3,
    taskName: '2026年度等级保护第三级测评',
    generatedAt: '2026-05-20T11:30:00.000Z',
    stats: { total: 8, pass: 7, fail: 1, warning: 0, complianceRate: '87.5' },
    aiAnalysis: `# 等级保护第三级测评报告

## 测评概要
- 测评任务: 2026年度等级保护第三级测评
- 测评级别: 第三级（监督保护级）
- 开始时间: 2026-05-20 09:00:00
- 完成时间: 2026-05-20 11:30:00

## 测评结果汇总
| 项目 | 数量 | 占比 |
|------|------|------|
| 总检查项 | 8项 | 100% |
| 通过 | 7项 | 87.5% |
| 失败 | 1项 | 12.5% |
| 合规率 | 87.5% | |

## 详细测评分析

### 1. 身份鉴别（通过）
- S1-01 身份标识唯一性: ✅ 通过
- S1-02 登录失败处理: ✅ 通过

### 2. 访问控制（通过）
- S2-01 最小权限原则: ✅ 通过

### 3. 安全审计（通过）
- S3-01 审计服务运行: ✅ 通过

### 4. 数据完整性（通过）
- S4-01 数据完整性保护: ✅ 通过

### 5. 数据保密性（通过）
- S5-01 传输加密: ✅ 通过

### 6. 入侵防范（通过）
- S7-01 入侵检测: ✅ 通过

### 7. 恶意代码防范（失败）
- S8-01 恶意代码防护: ❌ 失败
  - 问题描述: clamav防病毒软件未安装
  - 严重级别: 高

## 风险评估
- 严重风险: 0项
- 高风险: 1项（恶意代码防护缺失）
- 中风险: 0项

## 整改建议
1. **立即整改（高风险）**
   - 安装并配置clamav防病毒软件
   - 执行命令: apt install clamav clamav-daemon
   - 配置定时病毒扫描任务

2. **建议改进**
   - 建立定期病毒库更新机制
   - 配置邮件告警通知

## 总体评价
本次等级保护第三级测评整体合规率为87.5%，大部分安全控制措施已有效实施。主要问题在于恶意代码防范能力不足，建议尽快完成整改。`,
    details: []
  };
  
  insertReport.run('REP-DJPP-001', '2026年度等级保护第三级测评报告', 'djpp', JSON.stringify(djppReportContent), 1, '2026-05-20 11:35:00');

  const djppReportContent2 = {
    taskId: 'DJPP-TASK-003',
    level: 4,
    taskName: '金融业务系统四级测评',
    generatedAt: '2026-05-15T17:00:00.000Z',
    stats: { total: 9, pass: 9, fail: 0, warning: 0, complianceRate: '100.0' },
    aiAnalysis: `# 等级保护第四级测评报告

## 测评概要
- 测评任务: 金融业务系统四级测评
- 测评级别: 第四级（强制保护级）
- 开始时间: 2026-05-15 09:00:00
- 完成时间: 2026-05-15 17:00:00

## 测评结果汇总
| 项目 | 数量 | 占比 |
|------|------|------|
| 总检查项 | 9项 | 100% |
| 通过 | 9项 | 100% |
| 失败 | 0项 | 0% |
| 合规率 | 100% | |

## 详细测评分析

### 身份鉴别
- S1-01 身份标识唯一性: ✅ 通过
- S1-02 登录失败处理: ✅ 通过

### 访问控制
- S2-01 最小权限原则: ✅ 通过

### 安全审计
- S3-01 审计服务运行: ✅ 通过

### 数据完整性
- S4-01 数据完整性保护: ✅ 通过

### 数据保密性
- S5-01 传输加密: ✅ 通过

### 入侵防范
- S7-01 入侵检测: ✅ 通过

### 恶意代码防范
- S8-01 恶意代码防护: ✅ 通过

### 数据备份恢复
- S9-01 数据备份: ✅ 通过

## 风险评估
- 严重风险: 0项
- 高风险: 0项
- 中风险: 0项

## 总体评价
本次等级保护第四级测评合规率为100%，所有安全控制措施均已有效实施。建议继续保持当前安全防护水平，定期进行安全巡检和评估。`,
    details: []
  };
  
  insertReport.run('REP-DJPP-002', '金融业务系统等级保护第四级测评报告', 'djpp', JSON.stringify(djppReportContent2), 1, '2026-05-15 17:05:00');

  logger.info('默认数据初始化完成');
}

module.exports = { initDatabase };