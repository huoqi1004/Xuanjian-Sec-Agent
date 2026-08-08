/*
检查执行器（命令白名单机制）
- 仅允许执行内置白名单中的检查命令（按 checkId 索引），不接受任意 shell 命令
- 支持 Linux / Windows 双平台命令
- 检查命令与平台"基线排查/等保测评"模块保持一致（CIS Debian/Windows、等保2.0）
*/

const { execSync } = require('child_process');

const isWindows = process.platform === 'win32';

/**
 * 内置检查项白名单
 * 结构: checkId -> { linux: 命令, windows: 命令, expected: 期望值, operator: 比较方式, name: 名称, severity: 级别 }
 * operator: equals / contains / regex / gte / range / not_equals
 */
const CHECK_WHITELIST = {
  // ---------- CIS Debian Linux ----------
  'CIS-1.1.1': { linux: "mount | grep ' /tmp ' | grep -o 'noexec' || echo 'not_found'", expected: 'noexec', operator: 'contains', name: '/tmp挂载使用noexec选项', severity: 'medium' },
  'CIS-1.4.1': { linux: "dpkg -l openssh-server 2>/dev/null | grep '^ii' && echo 'installed' || echo 'not_installed'", expected: 'installed', operator: 'equals', name: 'SSH服务已安装', severity: 'low' },
  'CIS-2.2.1': { linux: "systemctl is-active systemd-timesyncd 2>/dev/null || systemctl is-active chronyd 2>/dev/null || systemctl is-active ntpd 2>/dev/null || echo 'inactive'", expected: 'active', operator: 'equals', name: '时间同步服务已启用', severity: 'medium' },
  'CIS-3.1.1': { linux: "sysctl net.ipv4.ip_forward 2>/dev/null | awk '{print $3}'", expected: '0', operator: 'equals', name: 'IP转发已禁用', severity: 'high' },
  'CIS-3.2.1': { linux: "sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null | awk '{print $3}'", expected: '0', operator: 'equals', name: '源路由已禁用', severity: 'medium' },
  'CIS-4.1.1': { linux: "dpkg -l auditd audispd-plugins 2>/dev/null | grep '^ii' | wc -l", expected: '1', operator: 'gte', name: '审计服务已安装', severity: 'medium' },
  'CIS-5.2.1': { linux: "sshd -T 2>/dev/null | grep -o 'protocol [0-9]' | awk '{print $2}' || echo '2'", expected: '2', operator: 'equals', name: 'SSH协议版本为2', severity: 'high' },
  'CIS-5.2.2': { linux: "sshd -T 2>/dev/null | grep 'permitrootlogin' | awk '{print $2}' || echo 'yes'", expected: 'no', operator: 'equals', name: 'SSH禁止root远程登录', severity: 'high' },
  'CIS-6.2.1': { linux: "dpkg -l unattended-upgrades 2>/dev/null | grep -c '^ii'", expected: '1', operator: 'equals', name: '已配置自动安全更新', severity: 'medium' },

  // ---------- CIS Windows ----------
  'CIS-WIN-1.1.1': { windows: 'net accounts | findstr "最小密码长度"', expected: '14', operator: 'regex', name: '密码最小长度>=14', severity: 'high' },
  'CIS-WIN-2.1.1': { windows: 'netsh advfirewall show allprofiles state | findstr "已启用"', expected: '已启用', operator: 'contains', name: 'Windows防火墙已启用', severity: 'high' },
  'CIS-WIN-2.2.1': { windows: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections', expected: '0x1', operator: 'contains', name: '远程桌面已禁用', severity: 'high' },
  'CIS-WIN-2.3.1': { windows: 'powershell -Command "Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol"', expected: 'False', operator: 'equals', name: 'SMBv1已禁用', severity: 'high' },

  // ---------- 等保2.0 ----------
  'DJPP-8.1.1': { linux: "grep '^minclass' /etc/security/pwquality.conf 2>/dev/null | awk -F= '{print $2}' || echo '0'", expected: '3', operator: 'equals', name: '身份鉴别-密码复杂度', severity: 'high' },
  'DJPP-8.1.4': { linux: "systemctl is-active auditd 2>/dev/null || echo 'inactive'", expected: 'active', operator: 'equals', name: '安全审计-审计策略', severity: 'high' },
  'DJPP-8.1.5': { linux: "(dpkg -l clamav 2>/dev/null | grep -c '^ii') + (systemctl is-active clamav-freshclam 2>/dev/null | grep -c 'active') | bc 2>/dev/null || echo '0'", expected: '2', operator: 'equals', name: '入侵防范-恶意代码防范', severity: 'high' },
  'DJPP-8.1.6': { linux: "(dpkg -l fail2ban 2>/dev/null | grep -c '^ii') + (systemctl is-active fail2ban 2>/dev/null | grep -c 'active') | bc 2>/dev/null || echo '0'", expected: '2', operator: 'equals', name: '入侵防范-入侵检测', severity: 'medium' },
  'DJPP-8.1.7': { linux: "ls /sys/firmware/efi 2>/dev/null && echo 'uefi' || echo 'bios'", expected: 'uefi', operator: 'equals', name: '可信验证-可信启动', severity: 'medium' }
};

/** 命令执行失败时的占位输出 */
const EXEC_ERROR_MARK = '__EXEC_ERROR__';

/** Windows 命令输出为本地编码（GBK），需显式解码 */
function decodeWindowsOutput(buf) {
  try {
    return new TextDecoder('gbk').decode(buf).trim();
  } catch (e) {
    return buf.toString('utf-8').trim();
  }
}

function executeCommand(command) {
  try {
    if (isWindows) {
      const buf = execSync(command, { encoding: 'buffer', timeout: 10000, stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
      return decodeWindowsOutput(buf);
    }
    const out = execSync(command, { encoding: 'utf-8', timeout: 10000, stdio: ['ignore', 'pipe', 'ignore'] });
    return out.trim();
  } catch (e) {
    // 命令以非零退出码结束（如 grep 未命中），部分场景下输出仍有效
    const stdout = e.stdout || Buffer.alloc(0);
    const text = isWindows ? decodeWindowsOutput(stdout) : stdout.toString('utf-8').trim();
    return text || EXEC_ERROR_MARK;
  }
}

/** 比较实际值与期望值 */
function compare(actual, expected, operator) {
  const a = String(actual || '').trim().toLowerCase();
  const e = String(expected || '').trim().toLowerCase();
  switch (operator) {
    case 'equals': return a === e;
    case 'contains': return a.includes(e);
    case 'not_equals': return a !== e;
    case 'regex': return new RegExp(e, 'i').test(a);
    case 'gte': return (parseFloat(a) || 0) >= (parseFloat(e) || 0);
    case 'range': return (parseFloat(a) || 0) <= (parseFloat(e) || 0);
    default: return a === e;
  }
}

/**
 * 执行白名单检查项
 * @param {string} checkId - 白名单检查项ID（如 CIS-1.1.1、DJPP-8.1.4）
 * @returns {Object|null} 检查结果；checkId 不在白名单返回 null
 */
function executeCheck(checkId) {
  const entry = CHECK_WHITELIST[checkId];
  if (!entry) return null;

  const command = isWindows ? entry.windows : entry.linux;
  if (!command) {
    return { checkId, status: 'not_applicable', detail: '当前平台不支持该检查项', name: entry.name, severity: entry.severity };
  }

  const actual = executeCommand(command);
  if (actual === EXEC_ERROR_MARK) {
    return { checkId, status: 'error', detail: '命令执行失败或未找到目标', name: entry.name, severity: entry.severity };
  }

  const passed = compare(actual, entry.expected, entry.operator);
  return {
    checkId,
    status: passed ? 'pass' : 'fail',
    actual,
    expected: entry.expected,
    operator: entry.operator,
    name: entry.name,
    severity: entry.severity,
    detail: `期望: ${entry.expected} (${entry.operator}), 实际: ${actual}`
  };
}

/** 返回全部白名单检查项 ID 与名称（供服务端同步） */
function listChecks() {
  return Object.entries(CHECK_WHITELIST).map(([id, v]) => ({ id, name: v.name, severity: v.severity }));
}

module.exports = { executeCheck, listChecks, compare };
