const { signAliyunRpc, signTencentTc3, cloudSgBlock, cloudSgUnblock } = require('../services/adapters/cloudSg');
const { runAction } = require('../services/adapters');
const { getDb } = require('../db/database');

describe('云安全组适配器（N-23C）', () => {
  test('阿里云 RPC 签名生成（含 Signature 参数）', () => {
    const req = signAliyunRpc('POST', 'AuthorizeSecurityGroup', { RegionId: 'cn-hangzhou', SecurityGroupId: 'sg-123' }, 'AKID', 'SK');
    expect(req.Signature).toBeTruthy();
    expect(req.Action).toBe('AuthorizeSecurityGroup');
    expect(req.AccessKeyId).toBe('AKID');
  });

  test('腾讯云 TC3 签名生成 Authorization 头', () => {
    const r = signTencentTc3({ action: 'CreateSecurityGroupPolicies', version: '2017-03-12', region: 'ap-guangzhou', secretId: 'SID', secretKey: 'SKEY', payload: {} });
    expect(r.headers.Authorization).toMatch(/^TC3-HMAC-SHA256 /);
    expect(r.headers['X-TC-Action']).toBe('CreateSecurityGroupPolicies');
  });

  test('dry-run 封禁 IP 落审计', async () => {
    const r = await cloudSgBlock({ ip: '1.2.3.4', provider: 'aliyun', region: 'cn-hangzhou', security_group_id: 'sg-1', dry_run: true });
    expect(r.success).toBe(true);
    expect(r.dry_run).toBe(true);
    const db = getDb();
    expect(db.prepare("SELECT * FROM action_logs WHERE action_type = 'cloud_sg_block'").all().length).toBeGreaterThan(0);
  });

  test('runAction 可调用 cloud_sg_block', async () => {
    const r = await runAction('cloud_sg_block', { ip: '5.6.7.8', provider: 'tencent', dry_run: true });
    expect(r.success).toBe(true);
  });

  test('unblock dry-run', async () => {
    const r = await cloudSgUnblock({ ip: '1.2.3.4', provider: 'aliyun', dry_run: true });
    expect(r.success).toBe(true);
  });
});
