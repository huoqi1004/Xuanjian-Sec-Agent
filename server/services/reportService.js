const { Document, Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow, TableCell, WidthType, BorderStyle, Packer } = require('docx');
const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

const REPORTS_DIR = path.resolve(__dirname, '../../data/reports');

if (!fs.existsSync(REPORTS_DIR)) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

function generateDJPPReportMD(reportData) {
  const { level, taskName, generatedAt, stats, aiAnalysis, details } = reportData;

  const levelNames = {
    1: '第一级(自主保护级)',
    2: '第二级(指导保护级)',
    3: '第三级(监督保护级)',
    4: '第四级(强制保护级)',
    5: '第五级(专控保护级)'
  };

  let md = '';
  md += `# 等级保护${levelNames[level] || level + '级'}测评报告\n\n`;
  md += `> ${taskName || '-'}\n`;
  md += `> 报告生成时间: ${new Date(generatedAt).toLocaleString('zh-CN')}\n\n`;
  md += `---\n\n`;

  md += `## 测评概要\n\n`;
  if (stats) {
    md += `| 指标 | 数值 |\n|------|------|\n`;
    md += `| 总检查项 | ${stats.total || 0} |\n`;
    md += `| 通过 | ${stats.pass || 0} |\n`;
    md += `| 失败 | ${stats.fail || 0} |\n`;
    md += `| 警告 | ${stats.warning || 0} |\n`;
    md += `| 合规率 | ${stats.complianceRate || '0.0'}% |\n\n`;
  }

  if (aiAnalysis) {
    md += `## AI分析报告\n\n${aiAnalysis}\n\n`;
  }

  if (details && details.length > 0) {
    md += `## 详细测评结果\n\n`;
    md += `| # | 类别 | 检查编号 | 检查项名称 | 状态 | 严重级别 | 实际值 | 检查结论 |\n|---|---|---|---|---|---|---|---|\n`;
    details.forEach((d, idx) => {
      const statusSymbol = d.status === 'pass' ? '✅通过' : d.status === 'fail' ? '❌失败' : '⚠️警告';
      md += `| ${idx + 1} | ${d.category || '-'} | ${d.checkCode || '-'} | ${d.checkName || '-'} | ${statusSymbol} | ${d.severity || '-'} | ${d.actual || '-'} | ${d.comment || '-'} |\n`;
    });
    md += `\n`;
  }

  md += `---\n\n`;
  md += `> 本报告由"玄鉴安全智能体 - 多引擎协同安全评估系统"自动生成\n`;
  md += `> 报告编号: ${reportData.reportId || '-'} | 本报告仅供内部参考使用\n`;

  return md;
}

function generateScanReportMD(reportData) {
  const { fileName, fileHash, scanTime, engines, decision, report } = reportData;

  let md = '';
  md += `# 病毒查杀报告\n\n`;
  md += `| 项目 | 内容 |\n|------|------|\n`;
  md += `| 文件名 | ${fileName || '-'} |\n`;
  md += `| 文件哈希 | ${fileHash || '-'} |\n`;
  md += `| 扫描时间 | ${scanTime || '-'} |\n`;
  md += `| 最终判定 | ${decision || '-'} |\n\n`;
  md += `---\n\n`;

  if (engines) {
    md += `## 引擎检测结果\n\n`;
    md += `| 引擎 | 结果 | 分数 | 详情 |\n|------|------|------|------|\n`;
    Object.entries(engines).forEach(([name, result]) => {
      const verdict = result.isMalicious ? '恶意' : result.isSuspicious ? '️可疑' : '✅安全';
      md += `| ${name} | ${verdict} | ${result.score || 'N/A'} | ${result.details || '-'} |\n`;
    });
    md += `\n`;
  }

  if (report) {
    md += `## AI分析报告\n\n${report}\n\n`;
  }

  md += `---\n\n`;
  md += `> 本报告由"玄鉴安全智能体 - 多引擎协同安全评估系统"自动生成\n`;

  return md;
}

function generateBaselineReportMD(reportData) {
  const { policyName, totalChecks, passed, failed, skipped, notApplicable, details, scanTime, complianceRate } = reportData;

  let md = '';
  md += `# 基线检查报告\n\n`;
  md += `> 策略: ${policyName || '-'}\n`;
  md += `> 检查时间: ${scanTime || new Date().toLocaleString('zh-CN')}\n\n`;
  md += `---\n\n`;

  md += `## 检查概况\n\n`;
  md += `| 指标 | 数值 |\n|------|------|\n`;
  md += `| 总检查项 | ${totalChecks || 0} |\n`;
  md += `| 通过 | ${passed || 0} |\n`;
  md += `| 失败 | ${failed || 0} |\n`;
  md += `| 跳过 | ${skipped || 0} |\n`;
  md += `| 不适用 | ${notApplicable || 0} |\n`;
  md += `| 合规率 | ${complianceRate || '0.0'}% |\n\n`;

  if (details && details.length > 0) {
    md += `## 检查详情\n\n`;
    md += `| # | 检查项 | 期望值 | 实际值 | 结果 | 严重级别 | 修复建议 |\n|---|---|---|---|---|---|---|\n`;
    details.forEach((d, idx) => {
      const resultSymbol = d.result === 'pass' ? '✅通过' : d.result === 'fail' ? '❌失败' : '⚠️跳过';
      md += `| ${idx + 1} | ${d.name || '-'} | ${d.expected || '-'} | ${d.actual || '-'} | ${resultSymbol} | ${d.severity || '-'} | ${d.remediation || '-'} |\n`;
    });
    md += `\n`;
  }

  md += `---\n\n`;
  md += `> 本报告由"玄鉴安全智能体 - 多引擎协同安全评估系统"自动生成\n`;

  return md;
}

function generateSituationalReportMD(reportData, reportType) {
  const { dashboard, content, generatedAt } = reportData;
  const typeLabel = reportType === 'weekly' ? '周' : '月';
  const alerts = dashboard?.alerts || {};
  const scans = dashboard?.scans || {};
  const threatIntel = dashboard?.threat_intel || {};
  const virusDetection = dashboard?.virus_detection || {};
  const devices = dashboard?.devices || {};

  let md = '';
  md += `# 安全态势${typeLabel}报\n\n`;
  md += `> 报告生成时间: ${new Date(generatedAt || Date.now()).toLocaleString('zh-CN')}\n\n`;
  md += `---\n\n`;

  md += `## 一、安全态势概览\n\n`;
  md += `### 告警统计\n\n`;
  md += `| 指标 | 数值 |\n|------|------|\n`;
  md += `| 总告警数 | ${alerts.total || 0} |\n`;
  md += `| 新告警 | ${alerts.new_count || 0} |\n`;
  md += `| 已确认 | ${alerts.acknowledged_count || 0} |\n`;
  md += `| 已解决 | ${alerts.resolved_count || 0} |\n`;
  md += `| 严重告警 | ${alerts.critical_count || 0} |\n`;
  md += `| 高危告警 | ${alerts.high_count || 0} |\n`;
  md += `| 中危告警 | ${alerts.medium_count || 0} |\n`;
  md += `| 低危告警 | ${alerts.low_count || 0} |\n\n`;

  md += `### 威胁情报\n\n`;
  md += `| 指标 | 数值 |\n|------|------|\n`;
  md += `| 总情报数 | ${threatIntel.total || 0} |\n`;
  md += `| IP情报 | ${threatIntel.ip_count || 0} |\n`;
  md += `| 域名情报 | ${threatIntel.domain_count || 0} |\n`;
  md += `| 哈希情报 | ${threatIntel.hash_count || 0} |\n`;
  md += `| 漏洞情报 | ${threatIntel.cve_count || 0} |\n`;
  md += `| 平均置信度 | ${threatIntel.avg_confidence ? (threatIntel.avg_confidence * 100).toFixed(1) + '%' : 'N/A'} |\n\n`;

  md += `### 扫描概况\n\n`;
  md += `| 指标 | 数值 |\n|------|------|\n`;
  md += `| 总任务数 | ${scans.total_tasks || 0} |\n`;
  md += `| 运行中 | ${scans.running_tasks || 0} |\n`;
  md += `| 已完成 | ${scans.completed_tasks || 0} |\n`;
  md += `| 开放端口 | ${scans.open_ports || 0} |\n\n`;

  md += `### 病毒检测\n\n`;
  md += `| 指标 | 数值 |\n|------|------|\n`;
  md += `| 总扫描数 | ${virusDetection.total_scans || 0} |\n`;
  md += `| 恶意文件 | ${virusDetection.malicious_count || 0} |\n`;
  md += `| 可疑文件 | ${virusDetection.suspicious_count || 0} |\n\n`;

  md += `### 设备状态\n\n`;
  md += `| 指标 | 数值 |\n|------|------|\n`;
  md += `| 在线设备 | ${devices.online_devices || 0} |\n`;
  md += `| 离线设备 | ${devices.offline_devices || 0} |\n\n`;

  md += `---\n\n`;

  md += `## 二、AI分析报告\n\n`;
  md += `${content || '暂无AI分析报告'}\n\n`;

  md += `---\n\n`;
  md += `> 本报告由"玄鉴安全智能体 - 多引擎协同安全评估系统"自动生成\n`;
  md += `> 本报告仅供内部参考使用\n`;

  return md;
}

async function generateSituationalReportDOCX(reportData, reportType) {
  try {
    const { dashboard, content, generatedAt } = reportData;
    const typeLabel = reportType === 'weekly' ? '周' : '月';
    const alerts = dashboard?.alerts || {};
    const scans = dashboard?.scans || {};
    const threatIntel = dashboard?.threat_intel || {};
    const virusDetection = dashboard?.virus_detection || {};
    const devices = dashboard?.devices || {};

    const children = [];

    children.push(new Paragraph({
      children: [new TextRun({ text: '安全态势' + typeLabel + '报', bold: true, size: 36 })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 200 }
    }));
    children.push(new Paragraph({
      children: [new TextRun({ text: `报告生成时间: ${new Date(generatedAt || Date.now()).toLocaleString('zh-CN')}`, size: 16, color: '999999' })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 400 }
    }));

    children.push(new Paragraph({
      children: [new TextRun({ text: '一、安全态势概览', bold: true, size: 24 })],
      heading: HeadingLevel.HEADING_2,
      spacing: { before: 300, after: 200 }
    }));

    children.push(new Paragraph({
      children: [new TextRun({ text: '告警统计', bold: true, size: 20 })],
      heading: HeadingLevel.HEADING_3,
      spacing: { before: 200, after: 100 }
    }));

    const alertRows = [
      new TableRow({ children: ['指标', '数值'].map(h => new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: h, bold: true })] })] })) }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('总告警数')] }), new TableCell({ children: [new Paragraph(String(alerts.total || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('新告警')] }), new TableCell({ children: [new Paragraph(String(alerts.new_count || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('已确认')] }), new TableCell({ children: [new Paragraph(String(alerts.acknowledged_count || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('已解决')] }), new TableCell({ children: [new Paragraph(String(alerts.resolved_count || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('严重告警')] }), new TableCell({ children: [new Paragraph(String(alerts.critical_count || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('高危告警')] }), new TableCell({ children: [new Paragraph(String(alerts.high_count || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('中危告警')] }), new TableCell({ children: [new Paragraph(String(alerts.medium_count || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('低危告警')] }), new TableCell({ children: [new Paragraph(String(alerts.low_count || 0))] })] })
    ];
    children.push(new Table({ width: { size: 50, type: WidthType.PERCENTAGE }, rows: alertRows }));

    children.push(new Paragraph({
      children: [new TextRun({ text: '威胁情报', bold: true, size: 20 })],
      heading: HeadingLevel.HEADING_3,
      spacing: { before: 300, after: 100 }
    }));

    const intelRows = [
      new TableRow({ children: ['指标', '数值'].map(h => new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: h, bold: true })] })] })) }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('总情报数')] }), new TableCell({ children: [new Paragraph(String(threatIntel.total || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('IP情报')] }), new TableCell({ children: [new Paragraph(String(threatIntel.ip_count || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('域名情报')] }), new TableCell({ children: [new Paragraph(String(threatIntel.domain_count || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('哈希情报')] }), new TableCell({ children: [new Paragraph(String(threatIntel.hash_count || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('漏洞情报')] }), new TableCell({ children: [new Paragraph(String(threatIntel.cve_count || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('平均置信度')] }), new TableCell({ children: [new Paragraph(threatIntel.avg_confidence ? (threatIntel.avg_confidence * 100).toFixed(1) + '%' : 'N/A')] })] })
    ];
    children.push(new Table({ width: { size: 50, type: WidthType.PERCENTAGE }, rows: intelRows }));

    children.push(new Paragraph({
      children: [new TextRun({ text: '扫描概况', bold: true, size: 20 })],
      heading: HeadingLevel.HEADING_3,
      spacing: { before: 300, after: 100 }
    }));

    const scanRows = [
      new TableRow({ children: ['指标', '数值'].map(h => new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: h, bold: true })] })] })) }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('总任务数')] }), new TableCell({ children: [new Paragraph(String(scans.total_tasks || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('运行中')] }), new TableCell({ children: [new Paragraph(String(scans.running_tasks || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('已完成')] }), new TableCell({ children: [new Paragraph(String(scans.completed_tasks || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('开放端口')] }), new TableCell({ children: [new Paragraph(String(scans.open_ports || 0))] })] })
    ];
    children.push(new Table({ width: { size: 50, type: WidthType.PERCENTAGE }, rows: scanRows }));

    children.push(new Paragraph({
      children: [new TextRun({ text: '病毒检测', bold: true, size: 20 })],
      heading: HeadingLevel.HEADING_3,
      spacing: { before: 300, after: 100 }
    }));

    const virusRows = [
      new TableRow({ children: ['指标', '数值'].map(h => new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: h, bold: true })] })] })) }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('总扫描数')] }), new TableCell({ children: [new Paragraph(String(virusDetection.total_scans || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('恶意文件')] }), new TableCell({ children: [new Paragraph(String(virusDetection.malicious_count || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('可疑文件')] }), new TableCell({ children: [new Paragraph(String(virusDetection.suspicious_count || 0))] })] })
    ];
    children.push(new Table({ width: { size: 50, type: WidthType.PERCENTAGE }, rows: virusRows }));

    children.push(new Paragraph({
      children: [new TextRun({ text: '设备状态', bold: true, size: 20 })],
      heading: HeadingLevel.HEADING_3,
      spacing: { before: 300, after: 100 }
    }));

    const deviceRows = [
      new TableRow({ children: ['指标', '数值'].map(h => new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: h, bold: true })] })] })) }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('在线设备')] }), new TableCell({ children: [new Paragraph(String(devices.online_devices || 0))] })] }),
      new TableRow({ children: [new TableCell({ children: [new Paragraph('离线设备')] }), new TableCell({ children: [new Paragraph(String(devices.offline_devices || 0))] })] })
    ];
    children.push(new Table({ width: { size: 50, type: WidthType.PERCENTAGE }, rows: deviceRows }));

    if (content) {
      children.push(new Paragraph({ pageBreakBefore: true }));
      children.push(new Paragraph({
        children: [new TextRun({ text: '二、AI分析报告', bold: true, size: 24 })],
        heading: HeadingLevel.HEADING_2,
        spacing: { before: 300, after: 200 }
      }));

      const lines = content.split('\n');
      lines.forEach(line => {
        if (line.trim()) {
          children.push(new Paragraph({
            children: [new TextRun({ text: line.replace(/[#*]/g, ''), size: 18 })],
            spacing: { after: 100 }
          }));
        } else {
          children.push(new Paragraph({ spacing: { after: 100 } }));
        }
      });
    }

    children.push(new Paragraph({ pageBreakBefore: true }));
    children.push(new Paragraph({
      children: [new TextRun({ text: '本报告由"玄鉴安全智能体 - 多引擎协同安全评估系统"自动生成', size: 14, color: '999999' })],
      alignment: AlignmentType.CENTER
    }));
    children.push(new Paragraph({
      children: [new TextRun({ text: '本报告仅供内部参考使用', size: 14, color: '999999' })],
      alignment: AlignmentType.CENTER
    }));

    const doc = new Document({ sections: [{ children }] });
    const buffer = await Packer.toBuffer(doc);

    const fileName = `situational_${reportType}_${Date.now()}.docx`;
    const docxPath = path.join(REPORTS_DIR, fileName);
    fs.writeFileSync(docxPath, buffer);
    logger.info(`态势感知DOCX报告已生成: ${docxPath}`);
    return docxPath;
  } catch (err) {
    logger.error('态势感知DOCX报告生成失败:', err);
    throw err;
  }
}

async function generateDJPPReportDOCX(reportData) {
  try {
    const { level, taskName, generatedAt, stats, aiAnalysis, details } = reportData;
    const levelNames = {
      1: '第一级(自主保护级)',
      2: '第二级(指导保护级)',
      3: '第三级(监督保护级)',
      4: '第四级(强制保护级)',
      5: '第五级(专控保护级)'
    };

    const children = [];

    children.push(new Paragraph({
      children: [new TextRun({ text: '等级保护测评报告', bold: true, size: 36 })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 200 }
    }));
    children.push(new Paragraph({
      children: [new TextRun({ text: levelNames[level] || `${level}级`, size: 24, color: '666666' })],
      alignment: AlignmentType.CENTER
    }));
    children.push(new Paragraph({
      children: [new TextRun({ text: taskName || '-', size: 20 })],
      alignment: AlignmentType.CENTER
    }));
    children.push(new Paragraph({
      children: [new TextRun({ text: `报告生成时间: ${new Date(generatedAt).toLocaleString('zh-CN')}`, size: 16, color: '999999' })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 400 }
    }));

    children.push(new Paragraph({
      children: [new TextRun({ text: '测评概要', bold: true, size: 24 })],
      heading: HeadingLevel.HEADING_2,
      spacing: { before: 300, after: 200 }
    }));

    if (stats) {
      const statsTable = new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          new TableRow({
            children: [
              new TableCell({ children: [new Paragraph('指标')], width: { size: 40, type: WidthType.PERCENTAGE } }),
              new TableCell({ children: [new Paragraph('数值')], width: { size: 60, type: WidthType.PERCENTAGE } })
            ]
          }),
          new TableRow({ children: [new TableCell({ children: [new Paragraph('总检查项')] }), new TableCell({ children: [new Paragraph(String(stats.total || 0))] })] }),
          new TableRow({ children: [new TableCell({ children: [new Paragraph('通过')] }), new TableCell({ children: [new Paragraph(String(stats.pass || 0))] })] }),
          new TableRow({ children: [new TableCell({ children: [new Paragraph('失败')] }), new TableCell({ children: [new Paragraph(String(stats.fail || 0))] })] }),
          new TableRow({ children: [new TableCell({ children: [new Paragraph('警告')] }), new TableCell({ children: [new Paragraph(String(stats.warning || 0))] })] }),
          new TableRow({ children: [new TableCell({ children: [new Paragraph('合规率')] }), new TableCell({ children: [new Paragraph(`${stats.complianceRate || '0.0'}%`)] })] })
        ]
      });
      children.push(statsTable);
    }

    if (aiAnalysis) {
      children.push(new Paragraph({
        children: [new TextRun({ text: 'AI分析报告', bold: true, size: 24 })],
        heading: HeadingLevel.HEADING_2,
        spacing: { before: 400, after: 200 }
      }));

      const lines = aiAnalysis.split('\n');
      lines.forEach(line => {
        if (line.trim()) {
          children.push(new Paragraph({
            children: [new TextRun({ text: line.replace(/[#*]/g, ''), size: 18 })],
            spacing: { after: 100 }
          }));
        } else {
          children.push(new Paragraph({ spacing: { after: 100 } }));
        }
      });
    }

    if (details && details.length > 0) {
      children.push(new Paragraph({ pageBreakBefore: true }));
      children.push(new Paragraph({
        children: [new TextRun({ text: '详细测评结果', bold: true, size: 24 })],
        heading: HeadingLevel.HEADING_2,
        spacing: { before: 300, after: 200 }
      }));

      const detailRows = [
        new TableRow({
          children: ['#', '类别', '检查编号', '检查项', '状态', '级别', '实际值', '结论'].map(h =>
            new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: h, bold: true })] })] })
          )
        })
      ];

      details.forEach((d, idx) => {
        const statusText = d.status === 'pass' ? '通过' : d.status === 'fail' ? '失败' : '警告';
        detailRows.push(new TableRow({
          children: [
            new TableCell({ children: [new Paragraph(String(idx + 1))] }),
            new TableCell({ children: [new Paragraph(d.category || '-')] }),
            new TableCell({ children: [new Paragraph(d.checkCode || '-')] }),
            new TableCell({ children: [new Paragraph(d.checkName || '-')] }),
            new TableCell({ children: [new Paragraph(statusText)] }),
            new TableCell({ children: [new Paragraph(d.severity || '-')] }),
            new TableCell({ children: [new Paragraph((d.actual || '-').substring(0, 30))] }),
            new TableCell({ children: [new Paragraph(d.comment || '-')] })
          ]
        }));
      });

      children.push(new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: detailRows
      }));
    }

    children.push(new Paragraph({ pageBreakBefore: true }));
    children.push(new Paragraph({
      children: [new TextRun({ text: '本报告由"玄鉴安全智能体 - 多引擎协同安全评估系统"自动生成', size: 14, color: '999999' })],
      alignment: AlignmentType.CENTER
    }));
    children.push(new Paragraph({
      children: [new TextRun({ text: `报告编号: ${reportData.reportId || '-'} | 本报告仅供内部参考使用`, size: 14, color: '999999' })],
      alignment: AlignmentType.CENTER
    }));

    const doc = new Document({ sections: [{ children }] });
    const buffer = await Packer.toBuffer(doc);

    const docxPath = path.join(REPORTS_DIR, `${reportData.reportId || 'report'}_${Date.now()}.docx`);
    fs.writeFileSync(docxPath, buffer);
    logger.info(`DOCX报告已生成: ${docxPath}`);
    return docxPath;
  } catch (err) {
    logger.error('DOCX生成失败:', err);
    throw err;
  }
}

async function generateScanReportDOCX(reportData) {
  try {
    const { fileName, fileHash, scanTime, engines, decision, report } = reportData;

    const children = [];

    children.push(new Paragraph({
      children: [new TextRun({ text: '病毒查杀报告', bold: true, size: 36 })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 400 }
    }));

    children.push(new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        new TableRow({ children: [new TableCell({ children: [new Paragraph('文件名')] }), new TableCell({ children: [new Paragraph(fileName || '-')] })] }),
        new TableRow({ children: [new TableCell({ children: [new Paragraph('文件哈希')] }), new TableCell({ children: [new Paragraph(fileHash || '-')] })] }),
        new TableRow({ children: [new TableCell({ children: [new Paragraph('扫描时间')] }), new TableCell({ children: [new Paragraph(scanTime || '-')] })] }),
        new TableRow({ children: [new TableCell({ children: [new Paragraph('最终判定')] }), new TableCell({ children: [new Paragraph(decision || '-')] })] })
      ]
    }));

    if (engines) {
      children.push(new Paragraph({
        children: [new TextRun({ text: '引擎检测结果', bold: true, size: 24 })],
        heading: HeadingLevel.HEADING_2,
        spacing: { before: 400, after: 200 }
      }));

      const engineRows = [
        new TableRow({
          children: ['引擎', '结果', '分数', '详情'].map(h =>
            new TableCell({ children: [new Paragraph({ children: [new TextRun({ text: h, bold: true })] })] })
          )
        })
      ];

      Object.entries(engines).forEach(([name, result]) => {
        const verdict = result.isMalicious ? '恶意' : result.isSuspicious ? '可疑' : '安全';
        engineRows.push(new TableRow({
          children: [
            new TableCell({ children: [new Paragraph(name)] }),
            new TableCell({ children: [new Paragraph(verdict)] }),
            new TableCell({ children: [new Paragraph(String(result.score || 'N/A'))] }),
            new TableCell({ children: [new Paragraph(result.details || '-')] })
          ]
        }));
      });

      children.push(new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows: engineRows }));
    }

    if (report) {
      children.push(new Paragraph({
        children: [new TextRun({ text: 'AI分析报告', bold: true, size: 24 })],
        heading: HeadingLevel.HEADING_2,
        spacing: { before: 400, after: 200 }
      }));
      report.split('\n').forEach(line => {
        if (line.trim()) {
          children.push(new Paragraph({ children: [new TextRun({ text: line.replace(/[#*]/g, ''), size: 18 })] }));
        }
      });
    }

    children.push(new Paragraph({
      children: [new TextRun({ text: '本报告由"玄鉴安全智能体 - 多引擎协同安全评估系统"自动生成', size: 14, color: '999999' })],
      alignment: AlignmentType.CENTER
    }));

    const doc = new Document({ sections: [{ children }] });
    const buffer = await Packer.toBuffer(doc);

    const docxPath = path.join(REPORTS_DIR, `scan_${fileHash || 'file'}_${Date.now()}.docx`);
    fs.writeFileSync(docxPath, buffer);
    logger.info(`DOCX查杀报告已生成: ${docxPath}`);
    return docxPath;
  } catch (err) {
    logger.error('DOCX生成失败:', err);
    throw err;
  }
}

function downloadFile(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error('文件不存在');
  }
  return fs.readFileSync(filePath);
}

module.exports = {
  generateDJPPReportMD,
  generateScanReportMD,
  generateBaselineReportMD,
  generateSituationalReportMD,
  generateDJPPReportDOCX,
  generateScanReportDOCX,
  generateSituationalReportDOCX,
  downloadFile,
  REPORTS_DIR
};