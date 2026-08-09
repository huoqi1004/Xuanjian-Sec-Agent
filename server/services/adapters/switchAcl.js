/**
 * 玄鉴安全智能体 - 交换机 ACL 适配器（对应 ROADMAP N-23B）
 *
 * 通过 SSH 连接交换机（华为/H3C/思科），创建/删除 ACL 规则封禁/解封 IP。
 * - 命令模板按 vendor 可配（内置华为/H3C/思科默认，支持 params.template 覆盖）
 * - dry-run 模式：未配置凭据或 params.dry_run=true 时模拟执行并落审计，不真实连接
 * - 高危语义：本适配器为 SOAR 动作，人工审批由 Playbook approval 步骤负责，不重复审批
 * - 审计：写入 action_logs（action_type=switch_acl_block/switch_acl_unblock）
 *          与 audit_logs（operation_type=soar_adapter, operation_target=switch_acl:block/unblock）
 */

const { getDb } = require('../../db/database');
const { getCredential } = require('../../utils/credentialStore');
const logger = require('../../utils/logger');

const DEFAULT_TEMPLATES = {
  huawei: {
    block: [
      'system-view',
      'acl number 3999',
      'rule deny ip source {ip} 0',
      'quit',
      'quit',
      'save force'
    ],
    unblock: [
      'system-view',
      'acl number 3999',
      'undo rule deny ip source {ip} 0',
      'quit',
      'quit',
      'save force'
    ]
  },
  h3c: {
    block: ['system-view', 'acl advanced 3999', 'rule deny ip source {ip} 0', 'quit', 'save force'],
    unblock: ['system-view', 'acl advanced 3999', 'undo rule deny ip source {ip} 0', 'quit', 'save force']
  },
  cisco: {
    block: ['configure terminal', 'ip access-list extended BLOCK_SOAR', 'deny ip host {ip} any', 'end', 'write memory'],
    unblock: ['configure terminal', 'ip access-list extended BLOCK_SOAR', 'no deny ip host {ip} any', 'end', 'write memory']
  }
};

/**
 * 渲染命令：优先 templateOverride → DEFAULT_TEMPLATES[vendor] → 华为。
 * 将模板中的 {ip} 占位符替换为真实 IP。
 * vendor 未知（非空且不在内置模板中）时回退华为并 warn。
 */
function renderCommands(vendor, action, ip, templateOverride) {
  const key = vendor || 'huawei';
  let template = templateOverride || DEFAULT_TEMPLATES[key];
  if (!template) {
    logger.warn(`[switchAcl] 未知交换机厂商 ${vendor}，回退华为命令模板`);
    template = DEFAULT_TEMPLATES.huawei;
  }
  const lines = (template && template[action]) || [];
  return lines.map((line) => String(line).replace(/\{ip\}/g, ip));
}

/**
 * 落审计：action_logs + audit_logs
 */
function insertLogs(db, actionType, operationTarget, detail, result, policyId) {
  db.prepare('INSERT INTO action_logs (policy_id, action_type, action_detail, result) VALUES (?, ?, ?, ?)')
    .run(policyId || null, actionType, detail, result);
  db.prepare('INSERT INTO audit_logs (user_id, username, operation_type, operation_target, operation_detail, result) VALUES (?, ?, ?, ?, ?, ?)')
    .run(null, 'soar', 'soar_adapter', operationTarget, detail, result);
}

/**
 * 真实 SSH 执行：建立单一 shell 会话，按序写入命令（保持设备 CLI 上下文，如 system-view 状态），
 * 收集输出；连接/会话失败或超时则整体失败（抛错交由调用方落审计 result=failed）。
 */
function execSshCommands(conn, commands) {
  return new Promise((resolve, reject) => {
    const { Client } = require('ssh2');
    const client = new Client();
    let settled = false;
    let stdout = '';
    let stderr = '';

    const finish = (err, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      client.end();
      if (err) reject(err);
      else resolve(result);
    };
    const timer = setTimeout(() => finish(new Error('SSH 执行超时（30s）')), 30000);

    client.on('ready', () => {
      client.shell((err, stream) => {
        if (err) return finish(new Error(`打开 shell 失败: ${err.message}`));
        stream.on('close', () => finish(null, { stdout, stderr }));
        stream.on('error', (e) => finish(new Error(`shell 异常: ${e.message}`)));
        stream.stderr.on('data', (d) => { stderr += d.toString(); });
        stream.on('data', (d) => { stdout += d.toString(); });

        let idx = 0;
        const sendNext = () => {
          if (idx >= commands.length) {
            // 全部命令发送完毕，稍候设备落盘后关闭会话
            setTimeout(() => { try { stream.end(); } catch (e) {} }, 800);
            return;
          }
          const cmd = commands[idx++];
          stream.write(`${cmd}\n`);
          setTimeout(sendNext, 800);
        };
        sendNext();
      });
    });

    client.on('error', (e) => finish(new Error(`SSH 连接失败: ${e.message}`)));
    client.connect({
      host: conn.host,
      port: Number(conn.port) || 22,
      username: conn.username,
      password: conn.password,
      readyTimeout: 10000,
      // 网络设备多为自签密钥，业务上信任首次连接指纹；生产环境建议改用 knownHosts/指纹校验
      ...(conn.privateKey ? { privateKey: conn.privateKey } : {})
    });
  });
}

/**
 * 统一执行入口：解析凭据 → 渲染命令 → dry-run 判定 → 真实执行 → 落审计
 */
async function executeSwitchAcl(action, params) {
  const { ip } = params || {};
  if (!ip) return { success: false, error: '缺少 ip 参数' };

  const db = getDb();
  const actionType = `switch_acl_${action}`;
  const operationTarget = `switch_acl:${action}`;
  const actionLabel = action === 'block' ? '封禁' : '解封';

  // 1. 解析连接参数：params 显式值优先，其次凭据（provider='switch'）
  let credential = null;
  if (!params.host || !params.username) {
    try {
      credential = getCredential('switch', params.credential_name || 'default');
    } catch (err) {
      logger.warn(`[switchAcl] 读取交换机凭据失败: ${err.message}`);
    }
  }
  const host = params.host || (credential && credential.host);
  const port = params.port || (credential && credential.port) || 22;
  const username = params.username || (credential && credential.fields && credential.fields.username);
  const password = params.password || (credential && credential.fields && credential.fields.password);
  const vendor = params.vendor || (credential && credential.vendor) || 'huawei';

  // 2. 渲染命令（params.template 覆盖内置模板）
  const commands = renderCommands(vendor, action, ip, params.template);

  // 3. dry-run：显式 dry_run=true，或未取到完整连接凭据（host/username）
  const isDryRun = params.dry_run === true || !host || !username;

  if (isDryRun) {
    const detail = `[dry-run] 模拟${actionLabel} ${ip}`;
    logger.info(`[switchAcl][dry-run] 模拟${actionLabel} IP ${ip}（厂商 ${vendor}）命令: ${commands.join(' | ')}`);
    insertLogs(db, actionType, operationTarget, detail, 'dry_run', params.policy_id);
    return { success: true, detail, dry_run: true, commands };
  }

  // 4. 真实执行（SSH）
  try {
    const output = await execSshCommands({ host, port, username, password }, commands);
    const detail = `已${actionLabel} ${ip}（${vendor}）`;
    insertLogs(db, actionType, operationTarget, detail, 'success', params.policy_id);
    logger.info(`[switchAcl] ${detail}`);
    return { success: true, detail, commands, output };
  } catch (err) {
    const detail = `${actionLabel} ${ip} 失败: ${err.message}`;
    insertLogs(db, actionType, operationTarget, detail, 'failed', params.policy_id);
    logger.error(`[switchAcl] ${detail}`);
    return { success: false, detail, error: err.message, commands };
  }
}

/**
 * 封禁：创建/追加 ACL 规则拒绝指定 IP
 */
async function switchAclBlock(params) {
  return executeSwitchAcl('block', params);
}

/**
 * 解封：删除对应 ACL 规则
 */
async function switchAclUnblock(params) {
  return executeSwitchAcl('unblock', params);
}

module.exports = {
  switchAclBlock,
  switchAclUnblock,
  renderCommands,
  DEFAULT_TEMPLATES
};
