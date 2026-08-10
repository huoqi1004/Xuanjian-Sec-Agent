/**
 * 迁移 008：病毒扫描自动处置策略（对应 N-17 病毒查杀模块）
 * 插入三条自动隔离/删除/告警策略，幂等可重复执行
 */
const logger = require('../../utils/logger');

module.exports = {
  name: '008_virus_scan_policies',
  up(db) {
    const insertPolicy = db.prepare(
      'INSERT OR IGNORE INTO auto_policies (name, description, conditions, actions, cooldown, unattended, enabled, approval_status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    );

    const policies = [
      {
        name: '恶意文件自动隔离',
        description: '病毒扫描检测到恶意文件时自动隔离至 quarantine 目录并发送高优告警',
        conditions: JSON.stringify([{ field: 'source', operator: '==', value: 'virus_scan' }]),
        actions: JSON.stringify([
          { type: 'quarantine_file', params: { quarantine_dir: './uploads/quarantine' } },
          { type: 'alert', params: { level: 'high' } },
          { type: 'notify', params: { channel: 'webhook', message: '发现恶意文件，已自动隔离至 quarantine 目录' } }
        ]),
        cooldown: 600,
        unattended: true,
        created_by: 1
      },
      {
        name: '严重威胁文件删除',
        description: '恶意程度为 critical 时直接删除文件，不隔离，避免残留风险',
        conditions: JSON.stringify([
          { field: 'source', operator: '==', value: 'virus_scan' },
          { field: 'threat_level', operator: '==', value: 'critical' }
        ]),
        actions: JSON.stringify([
          { type: 'delete_file' },
          { type: 'alert', params: { level: 'critical' } }
        ]),
        cooldown: 3600,
        unattended: true,
        created_by: 1
      },
      {
        name: '可疑文件人工审核',
        description: '中等风险文件仅记录告警，不自动处置，等待管理员人工审核',
        conditions: JSON.stringify([
          { field: 'source', operator: '==', value: 'virus_scan' },
          { field: 'verdict', operator: '==', value: 'suspicious' }
        ]),
        actions: JSON.stringify([
          { type: 'alert', params: { level: 'medium' } },
          { type: 'notify', params: { channel: 'email', message: '发现可疑文件，需人工审核确认' } }
        ]),
        cooldown: 300,
        unattended: false,
        created_by: 1
      }
    ];

    for (const p of policies) {
      const needsApproval = p.unattended;
      insertPolicy.run(
        p.name,
        p.description,
        p.conditions,
        p.actions,
        p.cooldown,
        p.unattended ? 1 : 0,
        1,
        needsApproval ? 'pending' : 'approved',
        p.created_by
      );
    }

    const count = db.prepare("SELECT COUNT(*) as cnt FROM auto_policies WHERE name IN ('恶意文件自动隔离','严重威胁文件删除','可疑文件人工审核')").get().cnt;
    logger.info(`[迁移:008] 病毒扫描处置策略已写入（共 ${count}/3 条）`);
  }
};
