/**
 * 玄鉴安全智能体 - 安全运营 Copilot（对应 ROADMAP 4.15）
 *
 * 能力：
 * 1. 告警智能研判 triageAlerts：聚合去重 → 根因推断（规则模板）→ 处置建议（RAG 增强）
 * 2. 主动巡检 runProactivePatrol：定时扫描目标端口 + 汇总告警/情报 → 生成巡检报告入库
 */

const { getDb } = require('../db/database');
const aiService = require('./aiService');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

/* ---------------- 告警智能研判 ---------------- */

/**
 * 聚合去重：按 related_asset 分组，合并同资产告警
 */
function groupAlerts(alerts) {
  const groups = new Map();
  for (const a of alerts) {
    const key = (a.related_asset || 'unknown').toLowerCase();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(a);
  }
  return [...groups.entries()].map(([asset, items]) => ({
    asset,
    count: items.length,
    severities: [...new Set(items.map((i) => i.severity))],
    types: [...new Set(items.map((i) => i.alert_type))],
    max_confidence: Math.max(...items.map((i) => Number(i.confidence) || 0)),
    alerts: items.slice(0, 10)
  }));
}

/**
 * 根因推断（规则模板，可解释）
 */
function inferRootCause(groups) {
  const findings = [];
  for (const g of groups) {
    const types = g.types;
    const isHigh = g.severities.includes('critical') || g.severities.includes('high');

    if (types.includes('intel_match') && isHigh) {
      findings.push({ asset: g.asset, inference: '命中已知威胁情报，疑似受控主机或与恶意基础设施通信', confidence: g.max_confidence });
    }
    if (types.includes('brute_force') && types.some((t) => /login|auth|account/i.test(t))) {
      findings.push({ asset: g.asset, inference: '疑似暴力破解成功后账号失陷', confidence: 0.85 });
    }
    if (types.some((t) => /lateral|move|横向|内网探测/i.test(t))) {
      findings.push({ asset: g.asset, inference: '检测到横向移动迹象，可能处于攻击链中段', confidence: 0.8 });
    }
    if (g.count >= 5 && isHigh) {
      findings.push({ asset: g.asset, inference: `短时间聚集 ${g.count} 条高危告警，疑似攻击行为集中爆发`, confidence: 0.75 });
    }
  }
  if (findings.length === 0 && groups.length > 0) {
    findings.push({ asset: groups[0].asset, inference: '未识别到明显攻击链特征，建议结合上下文持续观察', confidence: 0.3 });
  }
  return findings;
}

const RECOMMENDATION_TEMPLATES = [
  { key: '命中已知威胁情报', value: '将相关 IOC 加入黑名单；对受控主机隔离排查；检查 DNS 外联与异常连接。' },
  { key: '疑似暴力破解成功后账号失陷', value: '立即锁定相关账号并强制改密；排查登录源 IP；启用多因素认证。' },
  { key: '检测到横向移动迹象', value: '对相关主机进行隔离；审计凭据使用；检查 SMB/WMI/RDP 日志。' },
  { key: '短时间聚集', value: '按资产优先处置 critical 告警；开启临时封禁策略；升级监控粒度。' }
];

/**
 * 处置建议生成：规则模板 + RAG 知识库增强
 */
async function generateRecommendations(findings) {
  const recommendations = [];
  for (const f of findings) {
    let text = '对该资产执行基线检查与漏洞扫描；确认告警真实性后按风险级别处置。';
    for (const t of RECOMMENDATION_TEMPLATES) {
      if (f.inference.includes(t.key)) {
        text = t.value;
        break;
      }
    }
    // RAG 增强：检索知识库补充参考
    try {
      const hits = await aiService.searchKnowledge(f.inference, 2);
      if (hits.length > 0) {
        text += ` 参考知识：${hits.map((h) => h.title).join('；')}`;
      }
    } catch (e) {
      // 检索失败不影响建议
    }
    recommendations.push({ asset: f.asset, inference: f.inference, recommendation: text });
  }
  return recommendations;
}

/**
 * 告警智能研判主入口
 */
async function triageAlerts(limit = 50) {
  const db = getDb();
  const alerts = db.all('SELECT * FROM alert_records WHERE status = ? ORDER BY created_at DESC LIMIT ?', ['new', limit]);
  if (alerts.length === 0) {
    return { groups: [], findings: [], recommendations: [], source_count: 0 };
  }

  const groups = groupAlerts(alerts);
  const findings = inferRootCause(groups);
  const recommendations = await generateRecommendations(findings);

  metrics.inc('copilot_triages_total', {}, 1, 'Copilot 告警研判次数');
  logger.info(`[Copilot] 告警研判完成：${alerts.length} 条告警聚合为 ${groups.length} 组，识别 ${findings.length} 条根因推断`);
  return { groups, findings, recommendations, source_count: alerts.length };
}

/* ---------------- 主动巡检 ---------------- */

function getConfigValue(key, def) {
  const db = getDb();
  const row = db.prepare('SELECT * FROM sys_config WHERE key = ?').get(key);
  return row?.value || def;
}

/**
 * 主动巡检：扫描目标端口 + 汇总告警/情报 → 生成巡检报告入库
 */
async function runProactivePatrol(opts = {}) {
  const db = getDb();
  const target = opts.target || getConfigValue('patrol_target', '127.0.0.1');
  const ports = opts.ports || getConfigValue('patrol_ports', '22,80,443,3306,3389,6379');

  const scanService = require('./scanService');
  const task = await scanService.startScan({
    target_cidr: target,
    port_range: ports,
    scan_mode: 'tcp_connect',
    created_by: opts.userId || 1
  });

  // 轮询等待扫描完成（最长 30s）
  let detail = null;
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 500));
    detail = scanService.getTaskDetail(task.task_id);
    if (detail && (detail.status === 'completed' || detail.status === 'failed')) break;
  }

  const openPorts = detail?.results ? detail.results.filter((r) => r.state === 'open') : [];
  const newAlerts = db.all("SELECT * FROM alert_records WHERE status = 'new' ORDER BY created_at DESC LIMIT 10");
  const intelCount = db.prepare('SELECT COUNT(*) as count FROM threat_intel').get().count;

  const summary = {
    target,
    port_range: ports,
    scan_task_id: task.task_id,
    scan_status: detail?.status || 'timeout',
    open_ports: openPorts.map((r) => r.port),
    new_alerts: newAlerts.length,
    threat_intel_count: intelCount,
    generated_at: new Date().toISOString()
  };

  const report = {
    title: `主动巡检报告（${target}） ${new Date().toISOString().slice(0, 10)}`,
    content: JSON.stringify({ summary, open_ports: openPorts, alerts: newAlerts })
  };
  db.prepare('INSERT INTO reports (title, type, content, generated_by) VALUES (?, ?, ?, ?)')
    .run(report.title, 'patrol', report.content, opts.userId || 1);

  metrics.inc('copilot_patrols_total', {}, 1, 'Copilot 主动巡检次数');
  logger.info(`[Copilot] 主动巡检完成：目标=${target}，开放端口 ${openPorts.length} 个，新增告警 ${newAlerts.length} 条`);
  return { ...summary, report_title: report.title };
}

module.exports = { triageAlerts, runProactivePatrol, groupAlerts, inferRootCause };
