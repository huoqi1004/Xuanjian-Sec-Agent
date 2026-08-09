const crypto = require('crypto');
const { getDb } = require('../db/database');
const logger = require('./logger');

const ENC_PREFIX = 'ENC:';
const MIN_SECRET_LENGTH = 16;
// 仅开发环境使用的内置默认密钥（生产环境禁止回退）
const DEV_DEFAULT_SECRET = 'xuanjian_adapter_dev_default_secret_2024';
const CONFIG_KEY_PREFIX = 'adapter_cred_';

/**
 * 派生 AES-256-GCM 密钥（32 字节）：
 * 优先 ADAPTER_SECRET（≥16 字符），回退 JWT_SECRET，再回退内置默认（仅开发环境 + console.warn；
 * 生产环境密钥缺失/过短直接抛错，杜绝弱密钥落盘）。
 */
function getSecretKey() {
  const isProduction = process.env.NODE_ENV === 'production';
  let secret = process.env.ADAPTER_SECRET || process.env.JWT_SECRET || '';
  if (typeof secret !== 'string' || secret.length < MIN_SECRET_LENGTH) {
    if (isProduction) {
      throw new Error('[credentialStore] 生产环境必须配置 ADAPTER_SECRET（或 ≥16 字符的 JWT_SECRET）作为凭据加密密钥');
    }
    console.warn('[credentialStore] ADAPTER_SECRET / JWT_SECRET 缺失或长度不足，开发环境回退内置默认密钥（严禁用于生产）');
    secret = DEV_DEFAULT_SECRET;
  }
  return crypto.createHash('sha256').update(secret).digest();
}

/**
 * 加密单个敏感字段，格式：ENC:<base64(iv)>:<base64(ciphertext)>:<base64(authTag)>
 */
function encryptField(plain, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${ENC_PREFIX}${iv.toString('base64')}:${enc.toString('base64')}:${tag.toString('base64')}`;
}

/**
 * 解密字段：仅处理 ENC: 前缀的密文，其余（明文/非字符串）原样返回。
 * 解密失败抛错交由调用方处理（密钥变更场景）。
 */
function decryptField(payload, key) {
  if (typeof payload !== 'string' || !payload.startsWith(ENC_PREFIX)) return payload;
  const parts = payload.slice(ENC_PREFIX.length).split(':');
  if (parts.length !== 3) return payload;
  const [ivB64, dataB64, tagB64] = parts;
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]).toString('utf8');
}

function configKey(provider, name) {
  return `${CONFIG_KEY_PREFIX}${provider}_${name}`;
}

/**
 * 保存/覆盖凭据：fields 中的字符串值逐字段加密后落库（不含明文）。
 * 已存在（key 唯一约束）则 UPDATE，否则 INSERT。
 */
function setCredential(provider, name, plainFields, meta = {}) {
  const key = getSecretKey();
  const db = getDb();
  const cfgKey = configKey(provider, name);

  const fields = {};
  Object.keys(plainFields || {}).forEach((k) => {
    const v = plainFields[k];
    fields[k] = typeof v === 'string' ? encryptField(v, key) : v;
  });

  const updatedAt = new Date().toISOString();
  const record = { provider, name, fields, ...(meta || {}), updatedAt, sealed: true };
  const value = JSON.stringify(record);
  const description = `SOAR 适配器凭据 - ${provider}/${name}`;

  const existing = db.prepare('SELECT id FROM sys_config WHERE key = ?').get(cfgKey);
  if (existing) {
    db.prepare('UPDATE sys_config SET value = ?, description = ?, updated_at = ? WHERE key = ?')
      .run(value, description, updatedAt, cfgKey);
  } else {
    db.prepare('INSERT INTO sys_config (key, value, description) VALUES (?, ?, ?)')
      .run(cfgKey, value, description);
  }
  return { ok: true, key: cfgKey };
}

/**
 * 读取并解密凭据：返回完整 fields（含明文敏感字段）+ meta（region/endpoint 等平铺顶层）。
 * 不存在返回 null；解析失败/解密失败（密钥变更）返回 null 并记录 warn，不抛崩。
 */
function getCredential(provider, name) {
  const key = getSecretKey();
  const db = getDb();
  const cfgKey = configKey(provider, name);

  const row = db.prepare('SELECT * FROM sys_config WHERE key = ?').get(cfgKey);
  if (!row) return null;

  let record;
  try {
    record = JSON.parse(row.value);
  } catch (err) {
    logger.warn(`[credentialStore] 凭据 ${cfgKey} 数据损坏，无法解析: ${err.message}`);
    return null;
  }

  const fields = {};
  for (const [k, v] of Object.entries(record.fields || {})) {
    try {
      fields[k] = decryptField(v, key);
    } catch (err) {
      logger.warn(`[credentialStore] 凭据 ${cfgKey} 字段 ${k} 解密失败（加密密钥可能已变更）`);
      return null;
    }
  }

  const result = { provider: record.provider || provider, name: record.name || name, fields };
  ['region', 'endpoint', 'host', 'port', 'sealed', 'updatedAt'].forEach((k) => {
    if (record[k] !== undefined) result[k] = record[k];
  });
  return result;
}

/**
 * 列出全部凭据：敏感字段值一律脱敏为 '***'，不含明文。
 */
function listCredentials() {
  const db = getDb();
  const rows = db.prepare(`SELECT * FROM sys_config WHERE key LIKE '${CONFIG_KEY_PREFIX}%'`).all();
  const items = [];
  rows.forEach((row) => {
    if (!String(row.key).startsWith(CONFIG_KEY_PREFIX)) return;
    let record;
    try {
      record = JSON.parse(row.value);
    } catch (err) {
      logger.warn(`[credentialStore] 凭据 ${row.key} 数据损坏，无法解析: ${err.message}`);
      return;
    }
    const fields = {};
    Object.keys(record.fields || {}).forEach((k) => { fields[k] = '***'; });
    const meta = {};
    Object.keys(record).forEach((k) => {
      if (!['provider', 'name', 'fields', 'sealed', 'updatedAt'].includes(k)) meta[k] = record[k];
    });
    items.push({
      provider: record.provider || '',
      name: record.name || '',
      fields,
      meta,
      updatedAt: record.updatedAt || ''
    });
  });
  return items;
}

/**
 * 删除凭据。
 */
function deleteCredential(provider, name) {
  const db = getDb();
  db.prepare('DELETE FROM sys_config WHERE key = ?').run(configKey(provider, name));
  return { ok: true };
}

module.exports = {
  setCredential,
  getCredential,
  listCredentials,
  deleteCredential,
  getSecretKey
};
