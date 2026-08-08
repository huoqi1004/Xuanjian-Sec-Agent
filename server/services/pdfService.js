const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

const REPORTS_DIR = path.resolve(__dirname, '../../data/reports');

if (!fs.existsSync(REPORTS_DIR)) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

function generateDJPPReportPDF(reportData) {
  return new Promise((resolve, reject) => {
    try {
      const pdfPath = path.join(REPORTS_DIR, `${reportData.reportId || 'report'}_${Date.now()}.pdf`);
      const doc = new PDFDocument({ margin: 50 });
      const stream = fs.createWriteStream(pdfPath);

      stream.on('finish', () => {
        logger.info(`PDF报告已生成: ${pdfPath}`);
        resolve(pdfPath);
      });

      stream.on('error', (err) => {
        logger.error('PDF保存失败:', err.message);
        reject(err);
      });

      doc.pipe(stream);

      const { level, taskName, generatedAt, stats, aiAnalysis, details } = reportData;
      
      const levelNames = {
        1: '第一级(自主保护级)',
        2: '第二级(指导保护级)', 
        3: '第三级(监督保护级)',
        4: '第四级(强制保护级)',
        5: '第五级(专控保护级)'
      };

      doc.fontSize(24).fillColor('#2c3e50').text('等级保护测评报告', { align: 'center' });
      doc.moveDown(0.5);
      doc.fontSize(14).fillColor('#666666').text(levelNames[level] || `${level}级`, { align: 'center' });
      doc.fontSize(12).fillColor('#333333').text(taskName || '-', { align: 'center' });
      doc.moveDown(0.3);
      doc.fontSize(10).fillColor('#999999').text(`报告生成时间: ${new Date(generatedAt).toLocaleString('zh-CN')}`, { align: 'center' });
      doc.moveDown(1);

      doc.fontSize(16).fillColor('#2980b9').text('测评概要');
      doc.moveDown(0.5);
      
      if (stats) {
        doc.fontSize(11).fillColor('#333333')
          .text(`总检查项: ${stats.total || 0}    通过: ${stats.pass || 0}    失败: ${stats.fail || 0}    警告: ${stats.warning || 0}    合规率: ${stats.complianceRate || '0.0'}%`);
      }
      doc.moveDown(1);

      if (aiAnalysis) {
        doc.fontSize(16).fillColor('#2980b9').text('AI分析报告');
        doc.moveDown(0.5);
        doc.fontSize(10).fillColor('#333333');
        
        const analysisLines = aiAnalysis.split('\n');
        analysisLines.forEach(line => {
          if (line.startsWith('# ')) {
            doc.fontSize(14).fillColor('#2c3e50').text(line.replace('# ', ''), { continued: false });
            doc.moveDown(0.3);
          } else if (line.startsWith('## ')) {
            doc.fontSize(12).fillColor('#2980b9').text(line.replace('## ', ''), { continued: false });
            doc.moveDown(0.2);
          } else if (line.startsWith('### ')) {
            doc.fontSize(11).fillColor('#34495e').text(line.replace('### ', ''), { continued: false });
            doc.moveDown(0.2);
          } else if (line.trim()) {
            doc.fontSize(10).fillColor('#333333').text(line, { continued: false });
            doc.moveDown(0.1);
          } else {
            doc.moveDown(0.3);
          }
        });
        doc.moveDown(1);
      }

      if (details && details.length > 0) {
        doc.addPage();
        doc.fontSize(16).fillColor('#2980b9').text('详细测评结果');
        doc.moveDown(0.5);

        details.forEach((d, idx) => {
          const statusSymbol = d.status === 'pass' ? '✅' : d.status === 'fail' ? '❌' : '⚠️';
          const statusText = d.status === 'pass' ? '通过' : d.status === 'fail' ? '失败' : '警告';
          
          doc.fontSize(11).fillColor('#333333')
            .text(`${idx + 1}. [${d.category || '-'}] ${d.checkCode || '-'} ${d.checkName || '-'}`);
          doc.fontSize(10).fillColor('#666666')
            .text(`   状态: ${statusSymbol} ${statusText}    严重级别: ${d.severity || '-'}`);
          doc.fontSize(10).fillColor('#666666')
            .text(`   实际值: ${d.actual || '-'}    结论: ${d.comment || '-'}`);
          doc.moveDown(0.3);

          if ((idx + 1) % 10 === 0 && idx < details.length - 1) {
            doc.addPage();
          }
        });
      }

      doc.addPage();
      doc.fontSize(10).fillColor('#999999').text('本报告由"玄鉴安全智能体 - 多引擎协同安全评估系统"自动生成', { align: 'center' });
      doc.text(`报告编号: ${reportData.reportId || '-'} | 本报告仅供内部参考使用`, { align: 'center' });

      doc.end();
    } catch (err) {
      logger.error('PDF生成异常:', err);
      reject(err);
    }
  });
}

function generateScanReportPDF(reportData) {
  return new Promise((resolve, reject) => {
    try {
      const pdfPath = path.join(REPORTS_DIR, `scan_${reportData.fileHash || 'file'}_${Date.now()}.pdf`);
      const doc = new PDFDocument({ margin: 50 });
      const stream = fs.createWriteStream(pdfPath);

      stream.on('finish', () => {
        logger.info(`PDF查杀报告已生成: ${pdfPath}`);
        resolve(pdfPath);
      });

      stream.on('error', (err) => {
        logger.error('PDF保存失败:', err.message);
        reject(err);
      });

      doc.pipe(stream);

      doc.fontSize(20).fillColor('#c0392b').text('病毒查杀报告');
      doc.moveDown(0.5);
      doc.fontSize(12).fillColor('#333333')
        .text(`文件名: ${reportData.fileName || '-'}`)
        .text(`文件哈希: ${reportData.fileHash || '-'}`)
        .text(`扫描时间: ${reportData.scanTime || '-'}`)
        .text(`最终判定: ${reportData.decision || '-'}`);
      doc.moveDown(1);

      if (reportData.report) {
        doc.fontSize(14).fillColor('#2980b9').text('AI分析报告');
        doc.moveDown(0.5);
        doc.fontSize(10).fillColor('#333333');
        
        const reportLines = reportData.report.split('\n');
        reportLines.forEach(line => {
          if (line.trim()) {
            doc.text(line.replace(/[#*]/g, ''), { continued: false });
            doc.moveDown(0.1);
          }
        });
      }

      doc.moveDown(2);
      doc.fontSize(10).fillColor('#999999').text('本报告由"玄鉴安全智能体 - 多引擎协同安全评估系统"自动生成', { align: 'center' });

      doc.end();
    } catch (err) {
      logger.error('PDF生成异常:', err);
      reject(err);
    }
  });
}

async function downloadPDF(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error('PDF文件不存在');
  }
  return fs.readFileSync(filePath);
}

module.exports = {
  generateDJPPReportPDF,
  generateScanReportPDF,
  downloadPDF,
  REPORTS_DIR
};