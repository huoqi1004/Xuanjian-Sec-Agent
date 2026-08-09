const request = require('supertest');
const { startServer } = require('../server');
const { resetForTest, closeDb } = require('../db/database');

describe('适配器凭据管理 API', () => {
  let app;
  let token;

  beforeAll(async () => {
    resetForTest();
    process.env.QUEUE_DRIVER = 'memory';
    app = await startServer({ listen: false });
    const login = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'admin123' });
    token = login.body.data.token;
  });

  afterAll(() => {
    closeDb();
  });

  beforeEach(async () => {
    // 清理测试凭据，保证用例间相互独立
    await request(app)
      .delete('/api/adapters/credentials')
      .set('Authorization', `Bearer ${token}`)
      .send({ provider: 'switch', name: 'test1' });
  });

  test('GET /api/adapters/credentials 返回凭据数组', async () => {
    const res = await request(app)
      .get('/api/adapters/credentials')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.code).toBe(0);
    expect(res.body.data).toBeInstanceOf(Array);
  });

  test('PUT /api/adapters/credentials 保存凭据并脱敏回显', async () => {
    const putRes = await request(app)
      .put('/api/adapters/credentials')
      .set('Authorization', `Bearer ${token}`)
      .send({
        provider: 'switch',
        name: 'test1',
        fields: { username: 'u', password: 'p' },
        meta: { host: '10.0.0.1' }
      });
    expect(putRes.status).toBe(200);
    expect(putRes.body.code).toBe(0);
    expect(putRes.body.data.key).toContain('adapter_cred_switch_test1');

    const listRes = await request(app)
      .get('/api/adapters/credentials')
      .set('Authorization', `Bearer ${token}`);
    const item = listRes.body.data.find((c) => c.provider === 'switch' && c.name === 'test1');
    expect(item).toBeTruthy();
    expect(item.fields.username).toBe('***');
    expect(item.meta.host).toBe('10.0.0.1');
  });

  test('DELETE /api/adapters/credentials 删除凭据', async () => {
    await request(app)
      .put('/api/adapters/credentials')
      .set('Authorization', `Bearer ${token}`)
      .send({ provider: 'switch', name: 'test1', fields: { username: 'u' } });

    const delRes = await request(app)
      .delete('/api/adapters/credentials')
      .set('Authorization', `Bearer ${token}`)
      .send({ provider: 'switch', name: 'test1' });
    expect(delRes.status).toBe(200);
    expect(delRes.body.code).toBe(0);
    expect(delRes.body.data.ok).toBe(true);

    const listRes = await request(app)
      .get('/api/adapters/credentials')
      .set('Authorization', `Bearer ${token}`);
    expect(listRes.body.data.find((c) => c.provider === 'switch' && c.name === 'test1')).toBeUndefined();
  });

  test('GET /api/adapters/list 返回适配器目录', async () => {
    const res = await request(app)
      .get('/api/adapters/list')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.code).toBe(0);
    expect(res.body.data).toBeInstanceOf(Array);
    const types = res.body.data.map((a) => a.type);
    expect(types).toContain('switch_acl_block');
    expect(types).toContain('cloud_sg_block');
    expect(types).toContain('siem_webhook');
    expect(types).toContain('firewall_block');
  });

  test('未认证访问 /api/adapters/list 返回 401', async () => {
    const res = await request(app).get('/api/adapters/list');
    expect(res.status).toBe(401);
  });

  test('非法 provider 保存凭据被拒绝', async () => {
    const res = await request(app)
      .put('/api/adapters/credentials')
      .set('Authorization', `Bearer ${token}`)
      .send({ provider: 'invalid', name: 'x', fields: { a: 'b' } });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe(1);
  });

  test('缺少 name 保存凭据被拒绝', async () => {
    const res = await request(app)
      .put('/api/adapters/credentials')
      .set('Authorization', `Bearer ${token}`)
      .send({ provider: 'switch', name: '  ', fields: { a: 'b' } });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe(1);
  });
});
