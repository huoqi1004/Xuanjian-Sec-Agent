// 病毒扫描自动处置策略初始化脚本（可直接运行）
// 运行方式: node db/init-virus-policies.js
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });
const { getDb } = require('./database');

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
    unattended: true
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
    unattended: true
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
    unattended: false
  }
];

const db = getDb();
const insertPolicy = db.prepare(
  'INSERT OR IGNORE INTO auto_policies (name, description, conditions, actions, cooldown, unattended, enabled, approval_status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
);

let inserted = 0;
for (const p of policies) {
  const needsApproval = p.unattended;
  const result = insertPolicy.run(
    p.name,
    p.description,
    p.conditions,
    p.actions,
    p.cooldown,
    p.unattended ? 1 : 0,
    1,
    needsApproval ? 'pending' : 'approved',
    1
  );
  if (result.changes > 0) {
    console.log(`  ✅ 已插入: ${p.name} | 状态: ${needsApproval ? 'pending (需审批)' : 'approved'}`);
    inserted++;
  } else {
    console.log(`  ⏭  已存在: ${p.name}`);
  }
}

const all = db.prepare("SELECT name, approval_status, unattended FROM auto_policies WHERE name LIKE '%病毒%' OR name LIKE '%恶意文件%' OR name LIKE '%可疑文件%' OR name LIKE '%威胁%'").all();
console.log(`\n当前病毒处置策略（共 ${all.length} 条）:`);
for (const r of all) {
  console.log(`  - ${r.name} | status=${r.approval_status} | unattended=${r.unattended ? '是' : '否'}`);
}
console.log(`\n完成: 新增 ${inserted} 条，已存在 ${policies.length - inserted} 条`);
