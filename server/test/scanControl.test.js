/**
 * N-04 扫描安全管控测试
 * - CIDR 白名单：白名单外目标创建任务被拒
 * - 大型任务审批：主机数超阈值挂起 pending_approval，审批后执行、拒绝则终止
 */
// 缩小审批阈值（须在 require config 之前设置）
process.env.SCAN_APPROVAL_HOST_THRESHOLD = '4';

const request = require('supertest');
const { startServer } = require('../server');
const { resetForTest, closeDb, getDb } = require('../db/database');

describe('N-04 扫描安全管控', () => {
  let app;
  let adminToken;

  beforeAll(async () => {
    resetForTest();
    process.env.QUEUE_DRIVER = 'memory';
    app = await startServer({ listen: false });

    const login = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'admin123' });
    adminToken = login.body.data.token;
  });

  afterAll(() => {
    closeDb();
  });

  test('白名单内目标（127.0.0.1）可创建任务', async () => {
    const res = await request(app)
      .post('/api/scan/start')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ target_cidr: '127.0.0.1', port_range: '9-9' });
    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('running');
  });

  test('白名单外目标（公网 IP）创建任务被拒', async () => {
    const res = await request(app)
      .post('/api/scan/start')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ target_cidr: '8.8.8.8', port_range: '80' });
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/不在允许的网段内/);

    // 混合网段也拒绝：192.168.1.5 不在 192.168.1.0/29 网段内
    const res2 = await request(app)
      .post('/api/scan/start')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ target_cidr: '192.168.1.0/30', port_range: '80' });
    expect(res2.status).toBe(200); // 192.168.0.0/16 在白名单内

    // 数据库不应出现公网任务记录
    const db = getDb();
    const denied = db.prepare("SELECT COUNT(*) as c FROM scan_tasks WHERE target_cidr = '8.8.8.8'").get().count;
    expect(denied).toBe(0);
  });

  test('大型扫描任务进入 pending_approval，审批后执行', async () => {
    // 192.168.1.0/29 展开 6 个主机 > 阈值 4 -> 需审批
    const create = await request(app)
      .post('/api/scan/start')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ target_cidr: '192.168.1.0/29', port_range: '80' });
    expect(create.status).toBe(200);
    expect(create.body.data.status).toBe('pending_approval');
    expect(create.body.data.needs_approval).toBe(true);
    const taskId = create.body.data.task_id;

    // 任务列表中出现 pending_approval
    const list = await request(app)
      .get('/api/scan/tasks')
      .set('Authorization', `Bearer ${adminToken}`);
    const pending = list.body.data.list.find((t) => t.id === taskId);
    expect(pending.status).toBe('pending_approval');

    // 审批通过 -> running
    const approve = await request(app)
      .post(`/api/scan/tasks/${taskId}/review`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ decision: 'approve' });
    expect(approve.status).toBe(200);
    expect(approve.body.data.status).toBe('running');

    // 重复审批报错
    const reapprove = await request(app)
      .post(`/api/scan/tasks/${taskId}/review`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ decision: 'approve' });
    expect(reapprove.body.code).toBe(1);
  });

  test('大型任务可被拒绝并终止', async () => {
    const create = await request(app)
      .post('/api/scan/start')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ target_cidr: '192.168.1.32/29', port_range: '80' });
    const taskId = create.body.data.task_id;
    expect(create.body.data.status).toBe('pending_approval');

    const reject = await request(app)
      .post(`/api/scan/tasks/${taskId}/review`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ decision: 'reject' });
    expect(reject.status).toBe(200);
    expect(reject.body.data.status).toBe('rejected');

    const detail = await request(app)
      .get(`/api/scan/tasks/${taskId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(detail.body.data.status).toBe('rejected');
  });

  test('非管理员不可审批扫描任务', async () => {
    // 注册普通审计员（org2）
    await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ username: 'scan_audit', password: 'Passw0rd!23', role_id: 2, org_id: 2 });
    const login = await request(app)
      .post('/api/auth/login')
      .send({ username: 'scan_audit', password: 'Passw0rd!23' });
    const userToken = login.body.data.token;

    const create = await request(app)
      .post('/api/scan/start')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ target_cidr: '192.168.2.0/29', port_range: '80' });
    const taskId = create.body.data.task_id;

    const res = await request(app)
      .post(`/api/scan/tasks/${taskId}/review`)
      .set('Authorization', `Bearer ${userToken}`)
      .send({ decision: 'approve' });
    expect(res.status).toBe(403);
  });
});
