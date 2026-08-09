/**
 * 玄鉴安全智能体 - 云安全组适配器（对应 ROADMAP N-23C）
 *
 * 通过云厂商 OpenAPI 向安全组添加/删除出/入方向拒绝规则封禁/解封恶意 IP。
 * - 阿里云：RPC POP V1 签名（HMAC-SHA1 + RFC3986 percentEncode），自实现（不引入 pop-core 重依赖）
 * - 腾讯云：TC3-HMAC-SHA256 四步签名（CanonicalRequest → StringToSign → Signature → Authorization），自实现
 * - 凭据来自 credentialStore：aliyun 命名空间（accessKeyId/accessKeySecret），tencent（secretId/secretKey）
 * - dry-run 模式：params.dry_run=true 或无凭据/未指定安全组时模拟成功并落审计（result=dry_run），不真实调用
 * - 幂等/防误删：unblock 仅删除与本次 block 相同参数的规则，规则条件编码进 detail 留痕
 * - 审计：action_logs（action_type=cloud_sg_block/cloud_sg_unblock）+ audit_logs
 *          （operation_type=soar_adapter, operation_target=cloud_sg:block:<ip>）
 */

const crypto = require('crypto');
const { getDb } = require('../../db/database');
const { getCredential } = require('../../utils/credentialStore');
const logger = require('../../utils/logger');

const ALIYUN_ENDPOINT = 'https://ecs.aliyuncs.com/';
const ALIYUN_VERSION = '2014-05-26';
const TENCENT_VPC_VERSION = '2017-03-12';
const TENCENT_DEFAULT_SERVICE = 'vpc';

/** 腾讯云服务名按 action 映射（安全组策略均属 VPC 产品） */
const TENCENT_SERVICE_BY_ACTION = {
  CreateSecurityGroupPolicies: 'vpc',
  DeleteSecurityGroupPolicies: 'vpc'
};

/** 阿里云封禁/解封动作 */
const ALIYUN_ACTION = { block: 'AuthorizeSecurityGroup', unblock: 'RevokeSecurityGroup' };
/** 腾讯云封禁/解封动作 */
const TENCENT_ACTION = { block: 'CreateSecurityGroupPolicies', unblock: 'DeleteSecurityGroupPolicies' };

/**
 * RFC3986 percentEncode：保留 A-Za-z0-9-_.~，其余百分号编码。
 * encodeURIComponent 已满足该要求，此处再显式处理 !'()* 以对齐阿里云官方规范。
 */
function percentEncode(str) {
  return encodeURIComponent(String(str))
    .replace(/!/g, '%21')
    .replace(/'/g, '%27')
    .replace(/\(/g, '%28')
    .replace(/\)/g, '%29')
    .replace(/\*/g, '%2A');
}

/**
 * 阿里云 RPC（POP V1）签名：HMAC-SHA1(accessKeySecret, 规范化请求串)
 * 规范化请求串 = HTTPMethod&percentEncode("/")&percentEncode(CanonicalizedQueryString)
 * CanonicalizedQueryString = 全部参数（含公共参数）按参数名 ASCII 升序、key=value 各经 percentEncode 后以 & 连接
 * 返回含 Signature 的完整请求参数对象（可直接作为 axios 请求体/URL）。
 */
function signAliyunRpc(method, action, params, accessKeyId, accessKeySecret) {
  const baseParams = {
    ...(params || {}),
    Action: action,
    Version: ALIYUN_VERSION,
    AccessKeyId: accessKeyId,
    SignatureMethod: 'HMAC-SHA1',
    SignatureVersion: '1.0',
    SignatureNonce: crypto.randomUUID(),
    Timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    Format: 'JSON'
  };

  const sortedKeys = Object.keys(baseParams).sort();
  const canonicalizedQueryString = sortedKeys
    .map((k) => `${percentEncode(k)}=${percentEncode(baseParams[k])}`)
    .join('&');

  const stringToSign = `${String(method).toUpperCase()}&${percentEncode('/')}&${percentEncode(canonicalizedQueryString)}`;
  // 阿里云规范：HMAC key 为 AccessKeySecret 追加 &（ASCII 38）
  const signature = crypto.createHmac('sha1', `${String(accessKeySecret)}&`).update(stringToSign).digest('base64');

  return { ...baseParams, Signature: signature };
}

/**
 * 腾讯云 TC3-HMAC-SHA256 签名（官方标准算法）：
 * 1) CanonicalRequest（POST + / + 空查询串 + canonicalHeaders + signedHeaders + HashedRequestPayload）
 * 2) StringToSign（TC3-HMAC-SHA256 + Timestamp + CredentialScope + sha256(CanonicalRequest)）
 * 3) 派生密钥：SecretDate → SecretService → SecretSigning
 * 4) Authorization = TC3-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
 * 返回 { headers, url }；服务名按 action 映射（默认 vpc）。
 */
function signTencentTc3({ action, version, region, secretId, secretKey, payload }) {
  const service = TENCENT_SERVICE_BY_ACTION[action] || TENCENT_DEFAULT_SERVICE;
  const host = `${service}.tencentcloudapi.com`;
  const url = `https://${host}`;
  const timestamp = Math.floor(Date.now() / 1000);
  const date = new Date(timestamp * 1000).toISOString().slice(0, 10);

  const payloadStr = JSON.stringify(payload || {});
  const hashedPayload = crypto.createHash('sha256').update(payloadStr).digest('hex');

  const canonicalHeaders = 'content-type:application/json; charset=utf-8\n'
    + `host:${host}\n`
    + `x-tc-action:${action.toLowerCase()}\n`;
  const signedHeaders = 'content-type;host;x-tc-action';
  const canonicalRequest = ['POST', '/', '', canonicalHeaders, signedHeaders, hashedPayload].join('\n');

  const credentialScope = `${date}/${service}/tc3_request`;
  const stringToSign = ['TC3-HMAC-SHA256', String(timestamp), credentialScope,
    crypto.createHash('sha256').update(canonicalRequest).digest('hex')].join('\n');

  const secretDate = crypto.createHmac('sha256', `TC3${secretKey}`).update(date).digest();
  const secretService = crypto.createHmac('sha256', secretDate).update(service).digest();
  const secretSigning = crypto.createHmac('sha256', secretService).update('tc3_request').digest();
  const signature = crypto.createHmac('sha256', secretSigning).update(stringToSign).digest('hex');

  const headers = {
    Authorization: `TC3-HMAC-SHA256 Credential=${secretId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    'X-TC-Action': action,
    'X-TC-Version': version,
    'X-TC-Timestamp': String(timestamp),
    'Content-Type': 'application/json; charset=utf-8'
  };
  if (region) headers['X-TC-Region'] = region;

  return { headers, url };
}

/**
 * 构建阿里云封禁/解封请求：AuthorizeSecurityGroup / RevokeSecurityGroup
 * 规则：IpProtocol=all、PortRange=-1/-1、入方向 SourceCidrIp=<ip> / 出方向 DestCidrIp=<ip>
 * 返回 { method, url, params }（params 为签名后的完整请求参数）。
 */
function buildAliyunRequest({ action, ip, direction = 'ingress', securityGroupId, region, accessKeyId, accessKeySecret }) {
  const params = {
    RegionId: region,
    SecurityGroupId: securityGroupId,
    IpProtocol: 'all',
    PortRange: '-1/-1'
  };
  if (direction === 'egress') params.DestCidrIp = ip;
  else params.SourceCidrIp = ip;
  const signed = signAliyunRpc('POST', action, params, accessKeyId, accessKeySecret);
  return { method: 'POST', url: ALIYUN_ENDPOINT, params: signed };
}

/**
 * 构建腾讯云封禁/解封请求：CreateSecurityGroupPolicies / DeleteSecurityGroupPolicies
 * 规则：{ Protocol:'ALL', Port:'ALL', CidrBlock:'<ip>/32', Action:'DROP' }，按 direction 放入 Ingress/Egress
 * 返回 { headers, url, data }。
 */
function buildTencentRequest({ action, ip, direction = 'ingress', securityGroupId, region, version, secretId, secretKey, policyAction = 'DROP' }) {
  const rule = {
    PolicyIndex: 0,
    Protocol: 'ALL',
    Port: 'ALL',
    CidrBlock: `${ip}/32`,
    Action: policyAction,
    Description: 'xuanjian-soar'
  };
  const dirKey = direction === 'egress' ? 'Egress' : 'Ingress';
  const payload = {
    SecurityGroupId: securityGroupId,
    SecurityGroupPolicySet: { [dirKey]: [rule] }
  };
  const signed = signTencentTc3({
    action,
    version: version || TENCENT_VPC_VERSION,
    region,
    secretId,
    secretKey,
    payload
  });
  return { ...signed, data: payload };
}

/** 落审计：action_logs（业务动作）+ audit_logs（soar_adapter 审计），与 switchAcl 范式一致 */
function insertLogs(db, actionType, operationTarget, detail, result, policyId) {
  db.prepare('INSERT INTO action_logs (policy_id, action_type, action_detail, result) VALUES (?, ?, ?, ?)')
    .run(policyId || null, actionType, detail, result);
  db.prepare('INSERT INTO audit_logs (user_id, username, operation_type, operation_target, operation_detail, result) VALUES (?, ?, ?, ?, ?, ?)')
    .run(null, 'soar', 'soar_adapter', operationTarget, detail, result);
}

/**
 * 统一执行入口：解析参数 → 读凭据 → dry-run 判定 → 模拟/真实调用 → 双落审计
 */
async function executeCloudSg(action, params) {
  const { ip } = params || {};
  if (!ip) return { success: false, error: '缺少 ip 参数' };

  const provider = params.provider || 'aliyun';
  if (!['aliyun', 'tencent'].includes(provider)) {
    return { success: false, error: `不支持的云厂商: ${provider}（仅支持 aliyun/tencent）` };
  }

  const db = getDb();
  const actionType = `cloud_sg_${action}`;
  const operationTarget = `cloud_sg:${action}:${ip}`;
  const actionLabel = action === 'block' ? '封禁' : '解封';
  const apiAction = provider === 'aliyun' ? ALIYUN_ACTION[action] : TENCENT_ACTION[action];

  // 1. 读取凭据（provider 命名空间；params.credential_name 指定或 default）
  let credential = null;
  try {
    credential = getCredential(provider, params.credential_name || 'default');
  } catch (err) {
    logger.warn(`[cloudSg] 读取 ${provider} 凭据失败: ${err.message}`);
  }
  const fields = (credential && credential.fields) || {};
  const accessKeyId = params.access_key_id || fields.accessKeyId || fields.secretId;
  const accessKeySecret = params.access_key_secret || fields.accessKeySecret || fields.secretKey;
  const region = params.region || (credential && credential.region) || (provider === 'aliyun' ? 'cn-hangzhou' : 'ap-guangzhou');
  const securityGroupId = params.security_group_id || (credential && credential.securityGroupId);
  const direction = params.direction || 'ingress';

  // 2. 规则条件留痕（幂等/防误删：unblock 仅删与 block 相同参数的规则，条件编码进 detail）
  const ruleKey = provider === 'tencent'
    ? `${provider}:${securityGroupId || '?'}:${direction}:ALL:ALL:${ip}/32`
    : `${provider}:${securityGroupId || '?'}:${direction}:all:-1/-1:${ip}`;

  // 3. dry-run：显式 dry_run=true，或缺少凭据/安全组（无法真实调用）
  const isDryRun = params.dry_run === true || !credential || !securityGroupId || !accessKeyId || !accessKeySecret;

  // 构建请求（dry-run 时用占位凭据/占位安全组生成演示参数，不发送）
  let request;
  let built;
  if (provider === 'aliyun') {
    built = buildAliyunRequest({
      action: apiAction, ip, direction,
      securityGroupId: securityGroupId || 'sg-demo',
      region,
      accessKeyId: accessKeyId || 'demo-access-key-id',
      accessKeySecret: accessKeySecret || 'demo-access-key-secret'
    });
    request = built.params;
  } else {
    built = buildTencentRequest({
      action: apiAction, ip, direction,
      securityGroupId: securityGroupId || 'sg-demo',
      region,
      secretId: accessKeyId || 'demo-secret-id',
      secretKey: accessKeySecret || 'demo-secret-key'
    });
    request = { url: built.url, headers: built.headers, data: built.data };
  }

  if (isDryRun) {
    const detail = `[dry-run] 模拟在${provider}安全组(${securityGroupId || '未指定'})${direction === 'egress' ? '出' : '入'}方向${actionLabel} ${ip} [${ruleKey}]`;
    logger.info(`[cloudSg][dry-run] ${detail}`);
    insertLogs(db, actionType, operationTarget, detail, 'dry_run', params.policy_id);
    return { success: true, detail, dry_run: true, request, provider, action: apiAction };
  }

  // 4. 真实调用 OpenAPI（axios，timeout 10s）
  try {
    const axios = require('axios');
    let output;
    if (provider === 'aliyun') {
      const resp = await axios.post(ALIYUN_ENDPOINT, new URLSearchParams(request).toString(), { timeout: 10000 });
      output = resp.data || {};
      if (output.Code) throw new Error(`阿里云 API 错误 ${output.Code}: ${output.Message || ''}`);
    } else {
      const resp = await axios.post(request.url, request.data, { headers: request.headers, timeout: 10000 });
      output = resp.data || {};
      if (output.Response && output.Response.Error) {
        throw new Error(`腾讯云 API 错误 ${output.Response.Error.Code}: ${output.Response.Error.Message || ''}`);
      }
    }
    const detail = `已在${provider}安全组 ${securityGroupId} ${direction === 'egress' ? '出' : '入'}方向${actionLabel} ${ip} [${ruleKey}]`;
    insertLogs(db, actionType, operationTarget, detail, 'success', params.policy_id);
    logger.info(`[cloudSg] ${detail}`);
    return { success: true, detail, provider, action: apiAction, output };
  } catch (err) {
    const detail = `${actionLabel} ${ip} 失败: ${err.message} [${ruleKey}]`;
    insertLogs(db, actionType, operationTarget, detail, 'failed', params.policy_id);
    logger.error(`[cloudSg] ${detail}`);
    return { success: false, detail, provider, action: apiAction, error: err.message };
  }
}

/** 封禁：向云安全组添加拒绝规则 */
async function cloudSgBlock(params) {
  return executeCloudSg('block', params);
}

/** 解封：删除对应拒绝规则（同参数规则） */
async function cloudSgUnblock(params) {
  return executeCloudSg('unblock', params);
}

module.exports = {
  cloudSgBlock,
  cloudSgUnblock,
  buildAliyunRequest,
  buildTencentRequest,
  signAliyunRpc,
  signTencentTc3
};
