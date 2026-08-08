const { getDb } = require('../db/database');
const aiService = require('./aiService');
const logger = require('../utils/logger');

/**
 * 获取态势感知仪表盘数据
 */
async function getDashboard() {
  const db = getDb();

  // 告警统计
  const alertStats = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END) as new_count,
      SUM(CASE WHEN status = 'acknowledged' THEN 1 ELSE 0 END) as acknowledged_count,
      SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_count,
      SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) as false_positive_count,
      SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
      SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
      SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_count,
      SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low_count
    FROM alert_records
  `).get();

  // 威胁情报统计
  const intelStats = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN ioc_type = 'ip' THEN 1 ELSE 0 END) as ip_count,
      SUM(CASE WHEN ioc_type = 'domain' THEN 1 ELSE 0 END) as domain_count,
      SUM(CASE WHEN ioc_type = 'hash' THEN 1 ELSE 0 END) as hash_count,
      SUM(CASE WHEN ioc_type = 'cve' THEN 1 ELSE 0 END) as cve_count,
      AVG(confidence) as avg_confidence
    FROM threat_intel
  `).get();

  // 扫描任务统计
  const scanStats = db.prepare(`
    SELECT
      COUNT(*) as total_tasks,
      SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running_tasks,
      SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_tasks,
      SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_tasks
    FROM scan_tasks
  `).get();

  // 开放端口统计
  const portStats = db.prepare(`
    SELECT COUNT(*) as total_open_ports FROM scan_results WHERE state = 'open'
  `).get();

  // 最近告警
  const recentAlerts = db.prepare(`
    SELECT * FROM alert_records WHERE status = 'new'
    ORDER BY created_at DESC LIMIT 10
  `).all();

  // 最近威胁情报
  const recentIntel = db.prepare(`
    SELECT * FROM threat_intel ORDER BY updated_at DESC LIMIT 10
  `).all();

  // 防御策略统计
  const defenseStats = db.prepare(`
    SELECT
      COUNT(*) as total_policies,
      SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled_policies,
      SUM(CASE WHEN unattended = 1 THEN 1 ELSE 0 END) as unattended_policies
    FROM auto_policies
  `).get();

  // 设备统计
  const deviceStats = db.prepare(`
    SELECT
      COUNT(*) as total_devices,
      SUM(CASE WHEN online_status = 1 THEN 1 ELSE 0 END) as online_devices,
      SUM(CASE WHEN online_status = 0 THEN 1 ELSE 0 END) as offline_devices
    FROM edge_devices
  `).get();

  // 病毒检测统计
  const virusStats = db.prepare(`
    SELECT
      COUNT(*) as total_scans,
      SUM(CASE WHEN detection_result = 'malicious' THEN 1 ELSE 0 END) as malicious_count,
      SUM(CASE WHEN detection_result = 'suspicious' THEN 1 ELSE 0 END) as suspicious_count,
      SUM(CASE WHEN detection_result = 'poisoned' THEN 1 ELSE 0 END) as poisoned_count,
      SUM(CASE WHEN detection_result = 'clean' THEN 1 ELSE 0 END) as clean_count
    FROM virus_scan_records
  `).get();

  // 安全评分计算
  const securityScore = calculateSecurityScore(alertStats, intelStats, scanStats, virusStats);

  // 资产风险分布
  const riskDist = db.prepare(`
    SELECT
      CASE
        WHEN severity = 'critical' THEN '严重'
        WHEN severity = 'high' THEN '高危'
        WHEN severity = 'medium' THEN '中危'
        WHEN severity = 'low' THEN '低危'
        ELSE '信息'
      END as name,
      COUNT(*) as value
    FROM alert_records
    WHERE status != 'false_positive'
    GROUP BY severity
  `).all();

  // 威胁趋势（近7天）
  const threatTrend = [];
  for (let i = 6; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split('T')[0];
    const count = db.prepare("SELECT COUNT(*) as cnt FROM alert_records WHERE DATE(created_at) = ?").get(dateStr)?.cnt || 0;
    threatTrend.push({ date: `${date.getMonth()+1}/${date.getDate()}`, count });
  }

  // 漏洞等级分布（从基线检查结果统计）
  const vulnDist = db.prepare(`
    SELECT
      CASE
        WHEN severity = 'critical' THEN '严重'
        WHEN severity = 'high' THEN '高危'
        WHEN severity = 'medium' THEN '中危'
        WHEN severity = 'low' THEN '低危'
      END as name,
      COUNT(*) as value
    FROM baseline_results
    WHERE status = 'fail'
    GROUP BY severity
  `).all();

  return {
    security_score: securityScore,
    alerts: alertStats,
    threat_intel: intelStats,
    scans: { ...scanStats, open_ports: portStats.total_open_ports },
    defense: defenseStats,
    devices: deviceStats,
    virus_detection: virusStats,
    recent_alerts: recentAlerts,
    recent_threat_intel: recentIntel,
    risk_distribution: riskDist,
    threat_trend: threatTrend,
    vuln_distribution: vulnDist
  };
}

/**
 * 计算安全评分
 */
function calculateSecurityScore(alertStats, intelStats, scanStats, virusStats) {
  let score = 100;

  // 未处理告警扣分
  score -= (alertStats.new_count || 0) * 5;
  score -= (alertStats.critical_count || 0) * 3;

  // 威胁情报扣分
  score -= (intelStats.total || 0) * 0.5;

  // 病毒检测扣分
  score -= (virusStats.malicious_count || 0) * 2;
  score -= (virusStats.suspicious_count || 0) * 1;

  return Math.max(0, Math.min(100, Math.round(score)));
}

/**
 * 获取告警列表
 */
function getAlerts(page, pageSize, severity, status) {
  const db = getDb();
  const offset = (page - 1) * pageSize;

  let whereClause = '1=1';
  const params = [];

  if (severity) {
    whereClause += ' AND severity = ?';
    params.push(severity);
  }
  if (status) {
    whereClause += ' AND status = ?';
    params.push(status);
  }

  const total = db.prepare(`SELECT COUNT(*) as count FROM alert_records WHERE ${whereClause}`).get(...params).count;
  const alerts = db.prepare(`
    SELECT * FROM alert_records
    WHERE ${whereClause}
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, pageSize, offset);

  return { list: alerts, total, page, pageSize };
}

/**
 * 更新告警状态
 */
function updateAlertStatus(id, status) {
  const db = getDb();
  const resolvedAt = status === 'resolved' ? 'CURRENT_TIMESTAMP' : null;

  db.prepare(`
    UPDATE alert_records SET status = ?, resolved_at = ${resolvedAt || 'NULL'}
    WHERE id = ?
  `).run(status, id);
}

/**
 * 获取威胁情报
 */
function getThreatIntel(ioc_type, page, pageSize) {
  const db = getDb();
  const offset = (page - 1) * pageSize;

  let whereClause = '1=1';
  const params = [];

  if (ioc_type) {
    whereClause += ' AND ioc_type = ?';
    params.push(ioc_type);
  }

  const total = db.prepare(`SELECT COUNT(*) as count FROM threat_intel WHERE ${whereClause}`).get(...params).count;
  const intel = db.prepare(`
    SELECT * FROM threat_intel
    WHERE ${whereClause}
    ORDER BY updated_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, pageSize, offset);

  return { list: intel, total, page, pageSize };
}

/**
 * 生成安全报告
 */
async function generateReport(title, type, time_range, userId) {
  const db = getDb();
  const dashboard = await getDashboard();

  // 尝试调用AI服务生成报告
  let aiContent = '';
  try {
    aiContent = await aiService.generateSecurityReport(dashboard, type);
  } catch (err) {
    logger.warn('AI报告生成失败，使用默认模板:', err.message);
    aiContent = generateDefaultReport(dashboard, type);
  }

  // 保存报告到数据库
  const result = db.prepare(`
    INSERT INTO reports (title, type, content, generated_by)
    VALUES (?, ?, ?, ?)
  `).run(title || `${type}安全报告`, type || 'weekly', JSON.stringify({
    dashboard,
    content: aiContent,
    generated_at: new Date().toISOString()
  }), userId);

  return {
    id: result.lastInsertRowid,
    title: title || `${type}安全报告`,
    type: type || 'weekly',
    content: aiContent,
    dashboard_summary: dashboard
  };
}

/**
 * 生成默认报告
 */
function generateDefaultReport(dashboard, type) {
  return `# 安全评估报告

## 报告类型: ${type}
## 生成时间: ${new Date().toLocaleString()}

## 一、安全态势概览

安全评分: ${dashboard.security_score}/100

### 告警统计
- 总告警数: ${dashboard.alerts.total}
- 新告警: ${dashboard.alerts.new_count}
- 严重告警: ${dashboard.alerts.critical_count}
- 高危告警: ${dashboard.alerts.high_count}

### 威胁情报
- 总情报数: ${dashboard.threat_intel.total}
- 平均置信度: ${dashboard.threat_intel.avg_confidence ? (dashboard.threat_intel.avg_confidence * 100).toFixed(1) + '%' : 'N/A'}

### 扫描概况
- 总任务数: ${dashboard.scans.total_tasks}
- 开放端口: ${dashboard.scans.open_ports}

### 病毒检测
- 总扫描数: ${dashboard.virus_detection.total_scans}
- 恶意文件: ${dashboard.virus_detection.malicious_count}
- 可疑文件: ${dashboard.virus_detection.suspicious_count}

## 二、安全建议

1. 及时处理未确认的安全告警
2. 定期更新威胁情报库
3. 对高危漏洞进行优先修复
4. 加强网络边界安全防护
5. 定期进行安全基线检查`;
}

/**
 * 威胁情报来源可信度权重（用于置信度修正与展示）
 */
const SOURCE_TRUST = {
  'CISA-KEV': 0.95,
  'OTX': 0.8,
  'VirusTotal': 0.9,
  'LOCAL-SIM': 0.3,
  'LOCAL-DETECT': 0.6
};

/**
 * 情报去重更新：同一 (ioc_type, ioc_value) 已存在时，仅提升置信度并刷新时间
 * 注意：内存 shim 不支持多条件 WHERE，故先按 ioc_type 拉取再在内存中匹配
 */
function upsertIntel(db, type, value, source, confidence, description) {
  const candidates = db.prepare('SELECT * FROM threat_intel WHERE ioc_type = ?').all(type);
  const existing = candidates.find(r => r.ioc_value === value);

  if (existing) {
    const merged = Math.max(existing.confidence || 0, confidence || 0);
    db.prepare(
      'UPDATE threat_intel SET confidence = ?, source = ?, updated_at = CURRENT_TIMESTAMP, intel_status = ? WHERE id = ?'
    ).run(merged, source || existing.source, 'active', existing.id);
    return { changes: 0, merged: true };
  }

  const result = db.prepare(
    'INSERT INTO threat_intel (ioc_type, ioc_value, source, confidence, description, intel_status) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(type, value, source || 'UNKNOWN', confidence || 0.5, (description || '').substring(0, 200), 'active');
  return result;
}

/**
 * 情报联动防御：将高置信度恶意 IOC 转为"情报驱动"告警（供 SOC 处置/策略匹配）
 * 同一 IOC 已告警则跳过，避免重复刷屏
 */
function linkIntelToDefense() {
  const db = getDb();
  // 内存 shim 不支持 IN/>= 复杂 WHERE，全表拉取后过滤
  const allIntel = db.prepare('SELECT * FROM threat_intel').all();
  const high = allIntel.filter(ioc =>
    (ioc.confidence || 0) >= 0.8 && ['ip', 'domain', 'hash'].includes(ioc.ioc_type)
  );
  let linked = 0;

  const existingAlerts = db.prepare("SELECT * FROM alert_records WHERE alert_type = 'intel_match'").all();
  for (const ioc of high.slice(0, 20)) {
    const duplicated = existingAlerts.some(a => (a.description || '').includes(ioc.ioc_value));
    if (duplicated) continue;

    db.prepare(
      'INSERT INTO alert_records (related_asset, alert_type, severity, confidence, description, status) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(
      ioc.ioc_value,
      'intel_match',
      'high',
      ioc.confidence,
      `情报驱动告警: 检测到已知${ioc.ioc_type}威胁 ${ioc.ioc_value} (来源: ${ioc.source || '未知'})`,
      'new'
    );
    existingAlerts.push({ description: ioc.ioc_value });
    linked++;
  }

  if (linked > 0) logger.info(`[威胁情报] 生成 ${linked} 条情报关联告警`);
  return linked;
}

/**
 * 采集威胁情报 - 调用真实公共API
 */
async function collectThreatIntel() {
    const axios = require('axios');
    const db = getDb();
    let newCount = 0;

    // 1. 调用 AlienVault OTX API（免费，无需API Key）
    try {
        const otxResp = await axios.get('https://otx.alienvault.com/api/v1/pulses/subscribed', {
            params: { limit: 10 },
            timeout: 15000,
            headers: { 'User-Agent': 'XuanJian-SecurityAgent/1.0' }
        });

        if (otxResp.data && otxResp.data.results) {
            for (const pulse of otxResp.data.results.slice(0, 10)) {
                const indicators = pulse.indicators || [];
                for (const ind of indicators.slice(0, 3)) {
                    const iocType = mapOtxType(ind.type);
                    if (iocType && ind.indicator) {
                        try {
                            const confidence = Math.min(
                                (pulse.adversary ? 0.8 : 0.5) + (pulse.modified ? 0.1 : 0),
                                1.0
                            );
                            const result = upsertIntel(
                                db, iocType, ind.indicator, 'OTX', confidence,
                                (pulse.name || '').substring(0, 200)
                            );
                            if (result.changes > 0) newCount++;
                        } catch(e) { logger.warn(`[威胁情报] OTX单条入库失败: ${e.message}`); }
                    }
                }
            }
            logger.info(`[威胁情报] OTX采集完成，本次新增 ${newCount} 条`);
        }
    } catch(e) {
        logger.warn(`[威胁情报] OTX采集失败: ${e.message.substring(0, 100)}`);
    }

    // 2. 调用 CISA Known Exploited Vulnerabilities (KEV) Catalog（免费，无需API Key）
    try {
        const kevResp = await axios.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
            timeout: 15000,
            headers: { 'User-Agent': 'XuanJian-SecurityAgent/1.0' }
        });

        if (kevResp.data && kevResp.data.vulnerabilities) {
            let kevCount = 0;
            for (const vuln of kevResp.data.vulnerabilities.slice(0, 15)) {
                if (vuln.cveID) {
                    try {
                        const result = upsertIntel(
                            db, 'cve', vuln.cveID, 'CISA-KEV', 0.95,
                            `${vuln.product || ''} - ${vuln.shortDescription || ''}`.substring(0, 200)
                        );
                        if (result.changes > 0) { newCount++; kevCount++; }
                    } catch(e) {}
                }
            }
            logger.info(`[威胁情报] CISA KEV采集完成，新增 ${kevCount} 条`);
        }
    } catch(e) {
        logger.warn(`[威胁情报] CISA KEV采集失败: ${e.message.substring(0, 100)}`);
    }

    // 3. 补充：如果API都失败，生成少量模拟数据确保系统可用
    if (newCount === 0) {
        logger.info('[威胁情报] 外部API均不可用，使用本地模拟数据');
        const mockIntel = [
            { type: 'ip', value: `203.0.113.${Math.floor(Math.random() * 255)}`, source: 'LOCAL-SIM', confidence: 0.3, desc: '模拟威胁IP' },
            { type: 'domain', value: `malware-${Date.now()}.example.com`, source: 'LOCAL-SIM', confidence: 0.3, desc: '模拟恶意域名' },
        ];
        for (const item of mockIntel) {
            try {
                const result = upsertIntel(db, item.type, item.value, item.source, item.confidence, item.desc);
                if (result.changes > 0) newCount++;
            } catch(e) {}
        }
    }

    // 4. 情报联动：高置信度 IOC 生成关联告警
    try {
        const linked = linkIntelToDefense();
        if (linked > 0) logger.info(`[威胁情报] 情报联动生成 ${linked} 条告警`);
    } catch(e) {
        logger.warn(`[威胁情报] 情报联动失败: ${e.message}`);
    }

    return newCount;
}

/**
 * 映射OTX指标类型到内部类型
 */
function mapOtxType(otxType) {
    const map = {
        'IPv4': 'ip', 'IPv6': 'ip', 'domain': 'domain', 'hostname': 'domain',
        'URL': 'url', 'URI': 'url', 'FileHash-MD5': 'hash', 'FileHash-SHA256': 'hash',
        'FileHash-SHA1': 'hash', 'email': 'email', 'CVE': 'cve', 'CIDR': 'cidr'
    };
    return map[otxType] || null;
}

module.exports = {
  getDashboard,
  getAlerts,
  updateAlertStatus,
  getThreatIntel,
  generateReport,
  collectThreatIntel,
  linkIntelToDefense,
  SOURCE_TRUST
};
