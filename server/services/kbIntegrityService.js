/**
 * 知识库完整性验证服务（KB Integrity Service）
 * 功能：
 * 1. 文档入库时自动计算 SHA-256 哈希
 * 2. 定时完整性校验，检测哈希不匹配的文档（防篡改）
 * 3. 提供手动触发校验接口
 */
const crypto = require('crypto');
const logger = require('../utils/logger');
const { getDb } = require('../db/database');
const { scanKnowledgeDoc } = require('./promptGuard');

/**
 * 计算文档内容的 SHA-256 哈希
 */
function calcContentHash(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * 向知识库添加文档（含安全扫描 + 哈希记录）
 * @param {Object} doc - { title, content, category?, source? }
 * @returns {Object} { id, approved, hash, warnings? }
 */
function addDocument(doc) {
  if (!doc || typeof doc.content !== 'string' || !doc.title) {
    throw new Error('文档参数不完整（需 title 和 content）');
  }

  const db = getDb();
  const contentHash = calcContentHash(doc.content);

  // 安全扫描
  const scan = scanKnowledgeDoc(doc);
  if (!scan.approved) {
    logger.warn(`[KB-Integrity] 文档入库被拒绝: title="${doc.title}", reason=${scan.reason}`);
    return { id: null, approved: false, hash: contentHash, reason: scan.reason };
  }

  try {
    const info = doc.category || 'general';
    const source = doc.source || 'manual';
    const result = db.prepare(
      `INSERT INTO kb_documents (title, content, category, content_hash, source, version, approved, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 1, 1, datetime('now'), datetime('now'))`
    ).run(doc.title, doc.content, info, contentHash, source);

    logger.info(`[KB-Integrity] 文档入库成功: id=${result.lastInsertRowid}, title="${doc.title}", hash=${contentHash.substring(0, 16)}...`);
    return { id: result.lastInsertRowid, approved: true, hash: contentHash, warnings: scan.warnings || [] };
  } catch (err) {
    // 标题重复，更新版本和哈希
    const existing = db.prepare('SELECT id, content_hash FROM kb_documents WHERE title = ?').get(doc.title);
    if (existing) {
      db.prepare(
        `UPDATE kb_documents SET content = ?, content_hash = ?, version = version + 1,
         approved = 1, updated_at = datetime('now') WHERE id = ?`
      ).run(doc.content, contentHash, existing.id);
      logger.info(`[KB-Integrity] 文档更新: title="${doc.title}", hash=${contentHash.substring(0, 16)}..., version=${existing.version + 1}`);
      return { id: existing.id, approved: true, hash: contentHash, updated: true };
    }
    throw err;
  }
}

/**
 * 验证所有文档的完整性，返回异常的文档列表
 * @returns {Array} [{ id, title, expected_hash, actual_hash, changed_at }]
 */
function verifyIntegrity() {
  const db = getDb();
  const docs = db.all('SELECT id, title, content_hash, updated_at FROM kb_documents');
  const anomalies = [];

  for (const doc of docs) {
    const row = db.prepare('SELECT content FROM kb_documents WHERE id = ?').get(doc.id);
    if (!row) continue;

    const actualHash = calcContentHash(row.content);
    if (actualHash !== doc.content_hash) {
      anomalies.push({
        id: doc.id,
        title: doc.title,
        expected_hash: doc.content_hash,
        actual_hash: actualHash,
        changed_at: doc.updated_at,
      });
      logger.error(
        `[KB-Integrity] 文档哈希不匹配，可能遭篡改！id=${doc.id}, title="${doc.title}"`
      );
    }
  }

  logger.info(
    `[KB-Integrity] 完整性校验完成: 总文档=${docs.length}, 异常=${anomalies.length}`
  );
  return anomalies;
}

/**
 * 获取所有文档列表（含哈希摘要）
 * @returns {Array} [{ id, title, category, content_hash, version, created_at }]
 */
function listDocuments() {
  const db = getDb();
  return db.all(
    'SELECT id, title, category, content_hash, version, approved, created_at FROM kb_documents ORDER BY id DESC'
  );
}

/**
 * 按分类统计文档数量
 */
function getCategoryStats() {
  const db = getDb();
  return db.all(
    'SELECT category, COUNT(*) as count, SUM(CASE WHEN approved=1 THEN 1 ELSE 0 END) as approved_count FROM kb_documents GROUP BY category'
  );
}

module.exports = { addDocument, verifyIntegrity, listDocuments, getCategoryStats, calcContentHash };
