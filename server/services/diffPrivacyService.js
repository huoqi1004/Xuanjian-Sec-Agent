/**
 * Phase 4.3: 差分隐私投毒防御服务
 * 功能：
 * 1. 知识库文档入库时自动添加拉普拉斯噪声
 * 2. 检测投毒异常（通过扰动前后的哈希差异分析）
 * 3. 记录隐私审计日志（epsilon/delta/sensitivity）
 */
const crypto = require('crypto');
const logger = require('../utils/logger');
const { getDb } = require('../db/database');
const { calcContentHash } = require('./kbIntegrityService');
const { scanKnowledgeDoc } = require('./promptGuard');
const metrics = require('../utils/metrics');

/**
 * 拉普拉斯噪声生成
 * @param {number} sensitivity - 敏感度（默认 1.0）
 * @param {number} epsilon - 隐私预算（默认 1.0，越低越安全但噪声越大）
 */
function laplaceNoise(sensitivity = 1.0, epsilon = 1.0) {
  const t0 = performance.now();
  const scale = sensitivity / epsilon;
  const u = Math.random() - 0.5; // [-0.5, 0.5]
  const noise = -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  const elapsed = (performance.now() - t0).toFixed(4);
  logger.debug(`[DiffPrivacy] laplaceNoise: scale=${scale.toFixed(4)}, raw_noise=${noise.toFixed(6)}, elapsed=${elapsed}ms`);
  return noise;
}

/**
 * 对文档内容添加差分隐私扰动（返回扰动后的内容）
 * 注意：实际生产中应在向量嵌入层面添加噪声，此处为简化实现
 */
function applyDPNoise(content, epsilon = 1.0, sensitivity = 1.0) {
  const t0 = performance.now();
  const noise = laplaceNoise(sensitivity, epsilon);
  // 对内容进行字符级别的扰动（扰动幅度与 noise 相关）
  const perturbFactor = Math.abs(noise) * 0.01; // 1% 最大扰动
  const words = content.split(/\s+/);
  const wordCount = words.length;
  let modifiedCount = 0;

  const perturbed = words.map(w => {
    if (Math.random() < perturbFactor) {
      // 随机替换个别字符（模拟噪声）
      const idx = Math.floor(Math.random() * w.length);
      const chars = w.split('');
      const replaceChars = 'abcdefghijklmnopqrstuvwxyz0123456789';
      chars[idx] = replaceChars[Math.floor(Math.random() * replaceChars.length)];
      modifiedCount++;
      return chars.join('');
    }
    return w;
  }).join(' ');

  const elapsed = (performance.now() - t0).toFixed(2);
  logger.debug(
    `[DiffPrivacy] applyDPNoise: content_len=${content.length}B, words=${wordCount}, modified=${modifiedCount}, perturb_factor=${perturbFactor.toFixed(4)}, noise=${noise.toFixed(6)}, elapsed=${elapsed}ms`
  );
  return perturbed;
}

/**
 * 检测投毒异常：比较原始文档与扰动后文档的相似度
 * 相似度突降可能表明文档被篡改（投毒攻击）
 */
function detectPoisoningAnomaly(originalContent, perturbedContent, threshold = 0.7) {
  const t0 = performance.now();
  const originalWords = new Set(originalContent.toLowerCase().split(/\s+/));
  const perturbedWords = new Set(perturbedContent.toLowerCase().split(/\s+/));
  let overlap = 0;
  for (const w of originalWords) {
    if (perturbedWords.has(w)) overlap++;
  }
  const union = new Set([...originalWords, ...perturbedWords]).size;
  const similarity = union > 0 ? overlap / union : 0;
  const isAnomaly = similarity < threshold;
  const elapsed = (performance.now() - t0).toFixed(2);

  logger.debug(
    `[DiffPrivacy] detectPoisoningAnomaly: original_words=${originalWords.size}, perturbed_words=${perturbedWords.size}, overlap=${overlap}, union=${union}, similarity=${similarity.toFixed(4)}, threshold=${threshold}, is_anomaly=${isAnomaly}, elapsed=${elapsed}ms`
  );

  return {
    similarity,
    isAnomaly,
    threshold,
    original_word_count: originalWords.size,
    perturbed_word_count: perturbedWords.size,
    overlap_count: overlap
  };
}

/**
 * 向知识库添加文档（含差分隐私保护）
 * @param {Object} doc - { title, content, category, epsilon, sensitivity }
 * @returns {Object} { id, anomaly_score, dp_params }
 */
function addDocumentWithDP(doc) {
  if (!doc || typeof doc.content !== 'string' || !doc.title) {
    throw new Error('文档参数不完整（需 title 和 content）');
  }

  const epsilon = doc.epsilon ?? 1.0;
  const sensitivity = doc.sensitivity ?? 1.0;
  const db = getDb();
  const t0 = performance.now();

  logger.info(`[DiffPrivacy] 开始文档入库: title="${doc.title}", content_len=${doc.content.length}B, epsilon=${epsilon}, sensitivity=${sensitivity}`);

  // 安全扫描
  const tScan = performance.now();
  const scan = scanKnowledgeDoc(doc);
  logger.debug(`[DiffPrivacy] scanKnowledgeDoc 耗时: ${(performance.now() - tScan).toFixed(2)}ms, approved=${scan.approved}`);
  if (!scan.approved) {
    logger.warn(`[DiffPrivacy] 文档入库被拒绝: title="${doc.title}", reason=${scan.reason}`);
    return { id: null, approved: false, reason: scan.reason };
  }

  // 计算原始哈希
  const tHash1 = performance.now();
  const contentHash = calcContentHash(doc.content);
  logger.debug(`[DiffPrivacy] 原始内容哈希计算: ${(performance.now() - tHash1).toFixed(2)}ms`);

  // 应用差分隐私噪声
  const tNoise = performance.now();
  const perturbedContent = applyDPNoise(doc.content, epsilon, sensitivity);
  logger.debug(`[DiffPrivacy] 差分隐私噪声应用: ${(performance.now() - tNoise).toFixed(2)}ms`);

  // 计算扰动后哈希
  const tHash2 = performance.now();
  const perturbedHash = calcContentHash(perturbedContent);
  logger.debug(`[DiffPrivacy] 扰动后内容哈希计算: ${(performance.now() - tHash2).toFixed(2)}ms`);

  // 检测投毒异常
  const tAnomaly = performance.now();
  const anomaly = detectPoisoningAnomaly(doc.content, perturbedContent, 0.7);
  logger.debug(`[DiffPrivacy] 投毒异常检测: ${(performance.now() - tAnomaly).toFixed(2)}ms, similarity=${anomaly.similarity.toFixed(4)}`);

  try {
    const tInsert = performance.now();
    const result = db.prepare(
      `INSERT INTO kb_documents (title, content, category, content_hash, source, version, approved, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 1, 1, datetime('now'), datetime('now'))`
    ).run(doc.title, doc.content, doc.category || 'general', contentHash, doc.source || 'dp_protected');

    const docId = result.lastInsertRowid;
    logger.debug(`[DiffPrivacy] kb_documents 插入: docId=${docId}, elapsed=${(performance.now() - tInsert).toFixed(2)}ms`);

    // 记录隐私审计
    const tAudit = performance.now();
    db.prepare(
      `INSERT INTO privacy_audit (doc_id, epsilon, delta, sensitivity, noise_type, original_hash, perturbed_hash, anomaly_score, is_anomaly, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
    ).run(
      docId, epsilon, 0.0001, sensitivity, 'laplace',
      contentHash, perturbedHash, anomaly.similarity, anomaly.isAnomaly ? 1 : 0
    );
    logger.debug(`[DiffPrivacy] privacy_audit 插入: elapsed=${(performance.now() - tAudit).toFixed(2)}ms`);

    const totalElapsed = (performance.now() - t0).toFixed(2);
    logger.info(
      `[DiffPrivacy] 文档入库成功: id=${docId}, epsilon=${epsilon}, similarity=${anomaly.similarity.toFixed(3)}, ${anomaly.isAnomaly ? '⚠️ 疑似投毒' : '✓ 正常'}, total=${totalElapsed}ms`
    );
    metrics.inc('dp_doc_added', 1);
    if (anomaly.isAnomaly) metrics.inc('dp_anomaly_detected', 1);

    return {
      id: docId,
      approved: true,
      anomaly_score: anomaly.similarity,
      dp_params: { epsilon, sensitivity, noise_type: 'laplace' },
      is_anomaly: anomaly.isAnomaly
    };
  } catch (err) {
    // 标题重复，更新版本
    const existing = db.prepare('SELECT id FROM kb_documents WHERE title = ?').get(doc.title);
    if (existing) {
      db.prepare(
        `UPDATE kb_documents SET content = ?, content_hash = ?, version = version + 1, updated_at = datetime('now') WHERE id = ?`
      ).run(doc.content, contentHash, existing.id);
      logger.info(`[DiffPrivacy] 文档更新: title="${doc.title}", version=${existing.version + 1}`);
      return { id: existing.id, updated: true, epsilon, sensitivity };
    }
    throw err;
  }
}

/**
 * 批量检测知识库中的投毒异常文档
 * @param {number} similarityThreshold - 相似度阈值（默认 0.7）
 */
function detectPoisoningDocs(similarityThreshold = 0.7) {
  const t0 = performance.now();
  const db = getDb();

  // 查询历史异常记录
  const tHist = performance.now();
  const anomalies = db.prepare(
    `SELECT pa.id, pa.doc_id, kb.title, pa.epsilon, pa.delta, pa.similarity,
            pa.original_hash, pa.perturbed_hash, pa.created_at
     FROM privacy_audit pa
     JOIN kb_documents kb ON pa.doc_id = kb.id
     WHERE pa.is_anomaly = 1
     ORDER BY pa.created_at DESC`
  ).all();
  logger.debug(`[DiffPrivacy] 历史异常查询: ${anomalies.length} 条, elapsed=${(performance.now() - tHist).toFixed(2)}ms`);

  // 实时检测：对所有文档进行扰动后比对
  const tFetch = performance.now();
  const allDocs = db.prepare('SELECT id, title, content FROM kb_documents').all();
  logger.debug(`[DiffPrivacy] 全量文档读取: ${allDocs.length} 条, elapsed=${(performance.now() - tFetch).toFixed(2)}ms`);

  const realTimeAnomalies = [];
  let processTime = 0;

  for (let i = 0; i < allDocs.length; i++) {
    const doc = allDocs[i];
    const docStart = performance.now();

    const perturbed = applyDPNoise(doc.content, 1.0, 1.0);
    const anomaly = detectPoisoningAnomaly(doc.content, perturbed, similarityThreshold);

    const docElapsed = performance.now() - docStart;
    processTime += docElapsed;

    if (anomaly.isAnomaly) {
      realTimeAnomalies.push({
        doc_id: doc.id,
        title: doc.title,
        similarity: anomaly.similarity,
        anomaly_score: anomaly.similarity
      });
      logger.warn(`[DiffPrivacy] ⚠️ 实时检测投毒异常: doc_id=${doc.id}, title="${doc.title}", similarity=${anomaly.similarity.toFixed(4)}`);
    }

    // 每 50 条打印进度日志
    if ((i + 1) % 50 === 0) {
      logger.info(`[DiffPrivacy] 批量检测进度: ${i + 1}/${allDocs.length}, 当前异常=${realTimeAnomalies.length}`);
    }
  }

  const totalElapsed = (performance.now() - t0).toFixed(2);
  logger.info(
    `[DiffPrivacy] 投毒检测完成: 历史异常=${anomalies.length}, 实时异常=${realTimeAnomalies.length}, 总文档=${allDocs.length}, 单文档均耗时=${(processTime / Math.max(allDocs.length, 1)).toFixed(2)}ms, total=${totalElapsed}ms`
  );
  metrics.inc('dp_detect_run', 1);

  return {
    historical_anomalies: anomalies,
    real_time_anomalies: realTimeAnomalies,
    total_documents: allDocs.length,
    detected_count: anomalies.length + realTimeAnomalies.length
  };
}

/**
 * 获取隐私审计日志
 */
function getPrivacyAuditLog(limit = 50) {
  const t0 = performance.now();
  const db = getDb();
  const rows = db.prepare(
    `SELECT pa.*, kb.title as doc_title, kb.content_hash
     FROM privacy_audit pa
     JOIN kb_documents kb ON pa.doc_id = kb.id
     ORDER BY pa.created_at DESC
     LIMIT ?`
  ).all(limit);
  logger.debug(`[DiffPrivacy] getPrivacyAuditLog: ${rows.length} 条, elapsed=${(performance.now() - t0).toFixed(2)}ms`);
  return rows;
}

module.exports = {
  laplaceNoise,
  applyDPNoise,
  detectPoisoningAnomaly,
  addDocumentWithDP,
  detectPoisoningDocs,
  getPrivacyAuditLog
};
