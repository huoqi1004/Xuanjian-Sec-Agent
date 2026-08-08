const { Engine } = require('json-rules-engine');
const { getDb } = require('../db/database');
const { generateId } = require('../utils/helpers');
const logger = require('../utils/logger');

// 策略引擎实例缓存
const engines = new Map();
// 冷却追踪
const cooldowns = new Map();

// WebSocket广播函数（由server.js设置）
let broadcastFn = null;
function setBroadcastFn(fn) { broadcastFn = fn; }

/**
 * 获取防御策略列表
 */
function getPolicies() {
  const db = getDb();
  const policies = db.prepare('SELECT * FROM auto_policies ORDER BY id DESC').all();

  return policies.map(policy => ({
    ...policy,
    conditions: JSON.parse(policy.conditions || '[]'),
    actions: JSON.parse(policy.actions || '[]')
  }));
}

/**
 * 创建防御策略
 */
function createPolicy(params) {
  const db = getDb();
  const { name, description, conditions, actions, cooldown, unattended, created_by } = params;

  // 解析动作列表，判断是否包含高危动作
  const parsedActions = typeof actions === 'string' ? JSON.parse(actions) : (actions || []);
  const highRiskActions = ['block_ip', 'account_lock'];
  const hasHighRiskAction = parsedActions.some(a => highRiskActions.includes(a.type));
  const needsApproval = hasHighRiskAction || unattended;

  const approvalStatus = needsApproval ? 'pending' : 'approved';

  const result = db.prepare(`
    INSERT INTO auto_policies (name, description, conditions, actions, cooldown, unattended, approval_status, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    name,
    description || '',
    conditions || '[]',
    actions || '[]',
    cooldown || 300,
    unattended ? 1 : 0,
    approvalStatus,
    created_by
  );

  // 如果需要审批，创建审批记录
  if (needsApproval) {
    db.prepare(`
      INSERT INTO policy_approvals (policy_id, requester_id, status, risk_assessment)
      VALUES (?, ?, 'pending', ?)
    `).run(
      result.lastInsertRowid,
      created_by || null,
      hasHighRiskAction ? '包含高危动作(' + parsedActions.filter(a => highRiskActions.includes(a.type)).map(a => a.type).join(', ') + ')' : '无人值守模式需审批'
    );
    logger.info(`策略 "${name}" 已创建，等待审批 (原因: ${hasHighRiskAction ? '高危动作' : '无人值守模式'})`);
  } else {
    // 构建规则引擎（仅已审批的策略才构建引擎）
    const parsedConditions = typeof conditions === 'string' ? JSON.parse(conditions) : (conditions || []);
    buildEngine(result.lastInsertRowid, parsedConditions);
  }

  return { id: result.lastInsertRowid, name, approval_status: approvalStatus };
}

/**
 * 更新策略
 */
function updatePolicy(id, updates) {
  const db = getDb();

  const existing = db.prepare('SELECT * FROM auto_policies WHERE id = ?').get(id);
  if (!existing) return null;

  const fields = [];
  const values = [];

  if (updates.name !== undefined) { fields.push('name = ?'); values.push(updates.name); }
  if (updates.description !== undefined) { fields.push('description = ?'); values.push(updates.description); }
  if (updates.conditions !== undefined) { fields.push('conditions = ?'); values.push(JSON.stringify(updates.conditions)); }
  if (updates.actions !== undefined) { fields.push('actions = ?'); values.push(JSON.stringify(updates.actions)); }
  if (updates.cooldown !== undefined) { fields.push('cooldown = ?'); values.push(updates.cooldown); }
  if (updates.unattended !== undefined) { fields.push('unattended = ?'); values.push(updates.unattended ? 1 : 0); }
  if (updates.enabled !== undefined) { fields.push('enabled = ?'); values.push(updates.enabled ? 1 : 0); }

  if (fields.length === 0) return existing;

  values.push(id);
  db.prepare(`UPDATE auto_policies SET ${fields.join(', ')} WHERE id = ?`).run(...values);

  // 重建引擎
  if (updates.conditions) {
    buildEngine(id, updates.conditions);
  }

  return db.prepare('SELECT * FROM auto_policies WHERE id = ?').get(id);
}

/**
 * 删除策略
 */
function deletePolicy(id) {
  const db = getDb();
  db.prepare('DELETE FROM auto_policies WHERE id = ?').run(id);
  engines.delete(id);
}

/**
 * 构建规则引擎
 */
function buildEngine(policyId, conditions) {
  const engine = new Engine();

  for (const condition of conditions) {
    const rule = {
      conditions: {
        all: [{
          fact: condition.fact,
          operator: condition.operator,
          value: condition.value
        }]
      },
      event: {
        type: `policy_${policyId}_triggered`,
        params: {
          policyId: policyId
        }
      }
    };
    engine.addRule(rule);
  }

  engines.set(policyId, engine);
}

/**
 * 评估策略
 */
async function evaluatePolicies(facts) {
  const db = getDb();
  const policies = db.prepare('SELECT * FROM auto_policies WHERE enabled = 1 AND approval_status = ?').all('approved');

  const triggeredPolicies = [];

  for (const policy of policies) {
    // 检查冷却
    if (isInCooldown(policy.id, policy.cooldown)) {
      continue;
    }

    // 获取或创建引擎
    if (!engines.has(policy.id)) {
      buildEngine(policy.id, JSON.parse(policy.conditions || '[]'));
    }

    const engine = engines.get(policy.id);

    try {
      // 监听事件（必须在 engine.run 之前注册）
      engine.on('success', (event) => {
        if (event.type === `policy_${policy.id}_triggered`) {
          triggeredPolicies.push(policy);
        }
      });

      await engine.run(facts);
    } catch (err) {
      logger.error(`策略 ${policy.id} 评估失败:`, err.message);
    }
  }

  // 执行触发的策略动作
  for (const policy of triggeredPolicies) {
    await executePolicyActions(policy, facts);
    setCooldown(policy.id, policy.cooldown);
  }

  return triggeredPolicies;
}

/**
 * 执行策略动作
 */
async function executePolicyActions(policy, facts) {
  const db = getDb();
  const actions = JSON.parse(policy.actions || '[]');

  for (const action of actions) {
    let result = 'success';
    let detail = '';

    try {
      switch (action.type) {
        case 'block_ip': {
            const targetIp = facts.target_ip || facts.ip || 'unknown';
            const duration = action.params?.duration || 3600;
            detail = `封禁IP: ${targetIp}，持续 ${duration} 秒`;
            try {
                const { execSync } = require('child_process');
                // 检查是否已有该规则
                const check = execSync(`iptables -C INPUT -s ${targetIp} -j DROP 2>&1 || echo "not_found"`, { encoding: 'utf-8' }).trim();
                if (check.includes('not_found')) {
                    execSync(`iptables -I INPUT -s ${targetIp} -j DROP`, { encoding: 'utf-8' });
                    logger.info(`[防御] iptables封禁成功: ${targetIp}`);
                    // 设置定时解封
                    setTimeout(() => {
                        try {
                            execSync(`iptables -D INPUT -s ${targetIp} -j DROP`, { encoding: 'utf-8' });
                            logger.info(`[防御] iptables自动解封: ${targetIp} (已过${duration}秒)`);
                        } catch(e) {}
                    }, duration * 1000);
                } else {
                    logger.info(`[防御] IP ${targetIp} 已在封禁列表中`);
                }
            } catch(e) {
                logger.warn(`[防御] iptables封禁失败(可能无权限): ${e.message.substring(0, 100)}`);
                detail += ` (执行失败: ${e.message.substring(0, 50)})`;
            }
            break;
        }

        case 'alert':
          detail = `发送${action.params?.level || 'medium'}级别告警`;
          // 创建告警记录
          const alertResult = db.prepare(`
            INSERT INTO alert_records (related_asset, alert_type, severity, confidence, description, status)
            VALUES (?, ?, ?, ?, ?, 'new')
          `).run(
            facts.target_ip || facts.related_asset || '',
            '自动防御',
            action.params?.level || 'medium',
            facts.confidence || 0.8,
            `策略"${policy.name}"触发: ${detail}`
          );

          // 通过WebSocket推送新告警通知
          if (broadcastFn) {
            try {
              broadcastFn('new_alert', {
                id: alertResult.lastInsertRowid,
                alert_type: '自动防御',
                severity: action.params?.level || 'medium',
                related_asset: facts.target_ip || facts.related_asset || '',
                description: `策略"${policy.name}"触发: ${detail}`,
                confidence: facts.confidence || 0.8,
                created_at: new Date().toISOString()
              });
            } catch (err) {
              logger.error('推送告警通知失败:', err.message);
            }
          }
          break;

        case 'account_lock': {
            const username = facts.username || action.params?.username || 'unknown';
            detail = `锁定用户账户: ${username}`;
            try {
                const { execSync } = require('child_process');
                execSync(`passwd -l ${username} 2>&1 || usermod -L ${username} 2>&1`, { encoding: 'utf-8' });
                logger.info(`[防御] 用户锁定成功: ${username}`);
            } catch(e) {
                logger.warn(`[防御] 用户锁定失败: ${e.message.substring(0, 100)}`);
                detail += ` (执行失败)`;
            }
            break;
        }

        case 'traffic_limit': {
            const targetIp = facts.target_ip || facts.ip || 'unknown';
            const rate = action.params?.rate || action.params?.max_bandwidth || '1mbit';
            detail = `限制流量: ${targetIp} -> ${rate}`;
            try {
                const { execSync } = require('child_process');
                execSync(`tc qdisc add dev eth0 root handle 1: htb default 10 2>/dev/null; tc class add dev eth0 parent 1: classid 1:1 htb rate ${rate} 2>/dev/null; tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip dst ${targetIp} flowid 1:1 2>/dev/null`, { encoding: 'utf-8', timeout: 5000 });
                logger.info(`[防御] 流量限制成功: ${targetIp} -> ${rate}`);
            } catch(e) {
                logger.warn(`[防御] 流量限制失败(可能无权限或tc未安装): ${e.message.substring(0, 100)}`);
                detail += ` (执行失败)`;
            }
            break;
        }

        case 'notify': {
            const message = action.params?.message || `防御策略触发: ${policy.name}`;
            const channel = action.params?.channel || 'email';
            detail = `发送通知(${channel}): ${message.substring(0, 50)}`;
            try {
                const notifyService = require('./notifyService');
                await notifyService.send({ channel, message, severity: policy.name, target: facts.target_ip || facts.related_asset });
                logger.info(`[防御] 通知发送成功: ${channel}`);
            } catch(e) {
                logger.warn(`[防御] 通知发送失败: ${e.message.substring(0, 100)}`);
                detail += ` (发送失败)`;
            }
            break;
        }

        default:
          detail = `未知动作类型: ${action.type}`;
          result = 'failed';
      }
    } catch (err) {
      result = 'failed';
      detail = err.message;
      logger.error(`执行策略动作失败:`, err.message);
    }

    // 记录动作日志
    db.prepare(`
      INSERT INTO action_logs (policy_id, action_type, action_detail, result)
      VALUES (?, ?, ?, ?)
    `).run(policy.id, action.type, detail, result);
  }
}

/**
 * 冷却检查
 */
function isInCooldown(policyId, cooldownSeconds) {
  const lastTrigger = cooldowns.get(policyId);
  if (!lastTrigger) return false;
  return (Date.now() - lastTrigger) < (cooldownSeconds * 1000);
}

/**
 * 设置冷却
 */
function setCooldown(policyId, cooldownSeconds) {
  cooldowns.set(policyId, Date.now());
}

/**
 * 获取动作日志
 */
function getActionLogs(page, pageSize, policy_id) {
  const db = getDb();
  const offset = (page - 1) * pageSize;

  let whereClause = '1=1';
  const params = [];

  if (policy_id) {
    whereClause += ' AND l.policy_id = ?';
    params.push(policy_id);
  }

  const total = db.prepare(`SELECT COUNT(*) as count FROM action_logs l WHERE ${whereClause}`).get(...params).count;
  const logs = db.prepare(`
    SELECT l.*, p.name as policy_name
    FROM action_logs l
    LEFT JOIN auto_policies p ON l.policy_id = p.id
    WHERE ${whereClause}
    ORDER BY l.executed_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, pageSize, offset);

  return { list: logs, total, page, pageSize };
}

/**
 * 审批策略
 */
function approvePolicy(approvalId, status, riskAssessment, approverId) {
  const db = getDb();

  const approval = db.prepare('SELECT * FROM policy_approvals WHERE id = ?').get(approvalId);
  if (!approval) return null;

  db.prepare(`
    UPDATE policy_approvals SET status = ?, risk_assessment = ?, approver_id = ?, reviewed_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(status, riskAssessment || '', approverId, approvalId);

  // 更新策略审批状态
  if (status === 'approved') {
    db.prepare('UPDATE auto_policies SET approval_status = ? WHERE id = ?').run('approved', approval.policy_id);
  } else {
    db.prepare('UPDATE auto_policies SET approval_status = ? WHERE id = ?').run('rejected', approval.policy_id);
  }

  return db.prepare('SELECT * FROM policy_approvals WHERE id = ?').get(approvalId);
}

/**
 * 初始化所有策略引擎
 */
function initEngines() {
  const db = getDb();
  const policies = db.prepare('SELECT * FROM auto_policies WHERE enabled = 1').all();

  for (const policy of policies) {
    try {
      buildEngine(policy.id, JSON.parse(policy.conditions || '[]'));
    } catch (err) {
      logger.error(`初始化策略引擎失败 [ID=${policy.id}]:`, err.message);
    }
  }

  logger.info(`已初始化 ${policies.length} 个防御策略引擎`);
}

module.exports = {
  getPolicies,
  createPolicy,
  updatePolicy,
  deletePolicy,
  evaluatePolicies,
  getActionLogs,
  approvePolicy,
  initEngines,
  setBroadcastFn
};
