const fs = require('fs');
const path = require('path');
const { getDb } = require('../db/database');
const { calculateMD5, calculateSHA256, formatFileSize } = require('../utils/helpers');
const { config } = require('../config');
const aiService = require('./aiService');
const logger = require('../utils/logger');

/**
 * 扫描文件 - 多级检测串联
 */
async function scanFile(file, userId) {
  const db = getDb();
  const filePath = file.path;
  const fileName = file.originalname;
  const fileSize = file.size;

  // 1. 计算文件哈希
  let md5Hash, sha256Hash;
  try {
    md5Hash = await calculateMD5(filePath);
    sha256Hash = await calculateSHA256(filePath);
  } catch (err) {
    logger.error('计算文件哈希失败:', err.message);
    throw new Error('文件哈希计算失败');
  }

  // 2. 本地病毒库比对
  const localResult = checkLocalHash(db, md5Hash, sha256Hash);
  if (localResult) {
    // 本地库命中
    const record = saveRecord(db, {
      fileName, md5Hash, sha256Hash, fileSize, userId,
      result: 'malicious',
      source: 'local_hash',
      score: 1.0
    });
    return record;
  }

  // 3. VirusTotal API检测
  let vtResult = null;
  if (config.virusTotal.apiKey) {
    try {
      vtResult = await checkVirusTotal(md5Hash, sha256Hash);
    } catch (err) {
      logger.warn('VirusTotal检测失败:', err.message);
    }
  }

  if (vtResult && vtResult.malicious) {
    const record = saveRecord(db, {
      fileName, md5Hash, sha256Hash, fileSize, userId,
      result: 'malicious',
      source: 'virustotal',
      score: vtResult.score
    });
    return record;
  }

  // 4. AI模型检测
  let aiResult = null;
  try {
    aiResult = await aiService.detectMalware(filePath);
  } catch (err) {
    logger.warn('AI模型检测失败:', err.message);
  }

  if (aiResult && aiResult.is_malicious) {
    const record = saveRecord(db, {
      fileName, md5Hash, sha256Hash, fileSize, userId,
      result: 'malicious',
      source: 'ai_model',
      score: aiResult.score || 0.9
    });
    return record;
  }

  // 5. 投毒检测
  let poisonResult = null;
  try {
    poisonResult = await aiService.detectPoisoning(filePath);
  } catch (err) {
    logger.warn('投毒检测失败:', err.message);
  }

  if (poisonResult && poisonResult.is_poisoned) {
    const record = saveRecord(db, {
      fileName, md5Hash, sha256Hash, fileSize, userId,
      result: 'poisoned',
      source: 'ai_model',
      score: poisonResult.score || 0.8
    });
    return record;
  }

  // 综合判定
  let finalResult = 'clean';
  let finalScore = 0;
  let finalSource = 'multi_engine';

  if (vtResult && vtResult.suspicious) {
    finalResult = 'suspicious';
    finalScore = vtResult.score;
    finalSource = 'virustotal';
  } else if (aiResult && aiResult.score > 0.7) {
    finalResult = 'suspicious';
    finalScore = aiResult.score;
    finalSource = 'ai_model';
  }

  const record = saveRecord(db, {
    fileName, md5Hash, sha256Hash, fileSize, userId,
    result: finalResult,
    source: finalSource,
    score: finalScore
  });

  return record;
}

/**
 * 本地病毒库比对
 */
function checkLocalHash(db, md5Hash, sha256Hash) {
  // 检查MD5
  const md5Match = db.prepare('SELECT * FROM virus_hashes WHERE hash_value = ? AND hash_type = ?').get(md5Hash, 'md5');
  if (md5Match) {
    return { threat_name: md5Match.threat_name, severity: md5Match.severity };
  }

  // 检查SHA256
  const sha256Match = db.prepare('SELECT * FROM virus_hashes WHERE hash_value = ? AND hash_type = ?').get(sha256Hash, 'sha256');
  if (sha256Match) {
    return { threat_name: sha256Match.threat_name, severity: sha256Match.severity };
  }

  return null;
}

/**
 * VirusTotal API检测
 */
async function checkVirusTotal(md5Hash, sha256Hash) {
  if (!config.virusTotal.apiKey) return null;

  try {
    const axios = require('axios');
    const response = await axios.get(`https://www.virustotal.com/api/v3/files/${sha256Hash}`, {
      headers: { 'x-apikey': config.virusTotal.apiKey },
      timeout: 10000
    });

    const data = response.data;
    const stats = data.data?.attributes?.last_analysis_stats || {};

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0) || 1;

    return {
      malicious: malicious > 0,
      suspicious: suspicious > 0 || (malicious === 0 && malicious + suspicious > 2),
      score: (malicious + suspicious * 0.5) / total,
      stats,
      response: data
    };
  } catch (err) {
    if (err.response?.status === 404) {
      return { malicious: false, suspicious: false, score: 0, stats: {} };
    }
    throw err;
  }
}

/**
 * 保存检测记录
 */
function saveRecord(db, info) {
  const { fileName, md5Hash, sha256Hash, fileSize, userId, result, source, score } = info;

  const stmt = db.prepare(`
    INSERT INTO virus_scan_records (file_name, file_hash_md5, file_hash_sha256, file_size, detection_result, detection_source, model_score, uploaded_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const result2 = stmt.run(fileName, md5Hash, sha256Hash, fileSize, result, source, score);

  return {
    id: result2.lastInsertRowid,
    file_name: fileName,
    file_hash_md5: md5Hash,
    file_hash_sha256: sha256Hash,
    file_size: fileSize,
    file_size_text: formatFileSize(fileSize),
    detection_result: result,
    detection_source: source,
    model_score: score,
    result_text: getResultText(result)
  };
}

/**
 * 获取检测结果文本
 */
function getResultText(result) {
  const map = {
    clean: '安全',
    malicious: '恶意',
    suspicious: '可疑',
    poisoned: '投毒样本'
  };
  return map[result] || '未知';
}

/**
 * 获取检测历史
 */
function getRecords(page, pageSize, detection_result, tenant) {
  const db = getDb();
  const offset = (page - 1) * pageSize;

  // 内存 shim：全量 JOIN 后内存过滤（含组织隔离 N-02）
  const records = db.prepare(`
    SELECT r.*, u.username as uploaded_by_name
    FROM virus_scan_records r
    LEFT JOIN users u ON r.uploaded_by = u.id
  `).all();

  const { inOrg } = require('../utils/tenantHelpers');
  let filtered = inOrg(records, tenant, 'uploaded_by');
  if (detection_result) {
    filtered = filtered.filter((r) => r.detection_result === detection_result);
  }
  filtered.sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));

  return { list: filtered.slice(offset, offset + pageSize), total: filtered.length, page, pageSize };
}

/**
 * 获取检测详情（N-01：非管理员仅本人上传可访问）
 */
function getRecordDetail(id, tenant) {
  const db = getDb();
  const record = db.prepare(`
    SELECT r.*, u.username as uploaded_by_name
    FROM virus_scan_records r
    LEFT JOIN users u ON r.uploaded_by = u.id
    WHERE r.id = ?
  `).get(id);

  if (!record) return null;
  if (!require('../utils/tenantHelpers').isOwner(tenant, record, 'uploaded_by')) return null;

  // 查询本地库匹配信息
  const hashMatch = db.prepare('SELECT * FROM virus_hashes WHERE hash_value = ?').get(record.file_hash_md5)
    || db.prepare('SELECT * FROM virus_hashes WHERE hash_value = ?').get(record.file_hash_sha256);

  return {
    ...record,
    file_size_text: formatFileSize(record.file_size),
    result_text: getResultText(record.detection_result),
    local_match: hashMatch || null
  };
}

module.exports = {
  scanFile,
  getRecords,
  getRecordDetail
};
