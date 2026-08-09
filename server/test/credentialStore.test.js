const { setCredential, getCredential, listCredentials, deleteCredential } = require('../utils/credentialStore');
const { getDb } = require('../db/database');

describe('凭据加密存储（N-23A）', () => {
  beforeAll(() => { getDb(); });

  test('set/get 往返一致（敏感字段加密存储）', () => {
    const r = setCredential('aliyun', 'prod', { accessKeyId: 'AK_TEST', accessKeySecret: 'sk_secret' }, { region: 'cn-hangzhou' });
    expect(r.ok).toBe(true);
    const got = getCredential('aliyun', 'prod');
    expect(got.fields.accessKeyId).toBe('AK_TEST');
    expect(got.fields.accessKeySecret).toBe('sk_secret');
    expect(got.region).toBe('cn-hangzhou');
  });

  test('存储值中不含明文密钥（加密落库）', () => {
    const db = getDb();
    const row = db.prepare("SELECT * FROM sys_config WHERE key = 'adapter_cred_aliyun_prod'").get();
    expect(row).toBeTruthy();
    expect(row.value).not.toContain('sk_secret');
    expect(row.value).toContain('ENC:');
  });

  test('listCredentials 不暴露明文', () => {
    const items = listCredentials();
    const item = items.find((i) => i.provider === 'aliyun' && i.name === 'prod');
    expect(item).toBeTruthy();
    expect(item.fields.accessKeyId).toBe('***');
  });

  test('deleteCredential 删除', () => {
    expect(deleteCredential('aliyun', 'prod').ok).toBe(true);
    expect(getCredential('aliyun', 'prod')).toBeNull();
  });
});
