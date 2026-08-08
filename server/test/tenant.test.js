/**
 * N-01/N-02 租户隔离与对象级 RBAC 测试
 * - 组织隔离：A 组织用户查询不到 B 组织数据
 * - 对象级：非管理员访问他人资源返回 403/不存在
 */
const request = require('supertest');
const { startServer } = require('../server');
const { resetForTest, closeDb, getDb } = require('../db/database');

describe('N-01/N-02 租户隔离与对象级权限', () => {
  let app;
  let adminToken;
  let auditorA; // 组织1 审计员
  let auditorB; // 组织2 审计员

  beforeAll(async () => {
    resetForTest();
    process.env.QUEUE_DRIVER = 'memory';
    app = await startServer({ listen: false });

    // 管理员登录
    const login = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'admin123' });
    adminToken = login.body.data.token;

    // 管理员注册：组织1 审计员 + 组织2 审计员
    const regA = await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ username: 'auditor_a', password: 'Passw0rd!23', role_id: 2, org_id: 1 });
    expect(regA.status).toBe(200);

    const regB = await request(app)
      .post('/api/auth/register')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ username: 'auditor_b', password: 'Passw0rd!23', role_id: 2, org_id: 2 });
    expect(regB.status).toBe(200);

    const loginA = await request(app)
      .post('/api/auth/login')
      .send({ username: 'auditor_a', password: 'Passw0rd!23' });
    auditorA = loginA.body.data.token;

    const loginB = await request(app)
      .post('/api/auth/login')
      .send({ username: 'auditor_b', password: 'Passw0rd!23' });
    auditorB = loginB.body.data.token;
  });

  afterAll(() => {
    closeDb();
  });

  test('组织 A 用户创建扫描任务，组织 B 用户不可见', async () => {
    // 用户 A 创建任务
    const create = await request(app)
      .post('/api/scan/start')
      .set('Authorization', `Bearer ${auditorA}`)
      .send({ target_cidr: '127.0.0.1', port_range: '9-9' });
    expect(create.status).toBe(200);
    const taskId = create.body.data.task_id;

    // 用户 A 可查看自己的任务
    const own = await request(app)
      .get(`/api/scan/tasks/${taskId}`)
      .set('Authorization', `Bearer ${auditorA}`);
    expect(own.status).toBe(200);
    expect(own.body.data.id).toBe(taskId);

    // 用户 B 查询列表：不包含 A 的任务
    const listB = await request(app)
      .get('/api/scan/tasks')
      .set('Authorization', `Bearer ${auditorB}`);
    expect(listB.status).toBe(200);
    const idsB = (listB.body.data.tasks || []).map((t) => t.id);
    expect(idsB).not.toContain(taskId);

    // 用户 B 访问 A 的任务详情：拒绝
    const detailB = await request(app)
      .get(`/api/scan/tasks/${taskId}`)
      .set('Authorization', `Bearer ${auditorB}`);
    expect(detailB.status).toBe(400);
    expect(detailB.body.message).toMatch(/无权访问/);

    // 用户 B 删除 A 的任务：拒绝
    const delB = await request(app)
      .delete(`/api/scan/tasks/${taskId}`)
      .set('Authorization', `Bearer ${auditorB}`);
    expect(delB.body.code).toBe(1);

    // 管理员可访问
    const adminView = await request(app)
      .get(`/api/scan/tasks/${taskId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(adminView.status).toBe(200);
  });

  test('用户 B 创建的任务，用户 A 列表同样隔离（双向验证）', async () => {
    const create = await request(app)
      .post('/api/scan/start')
      .set('Authorization', `Bearer ${auditorB}`)
      .send({ target_cidr: '127.0.0.1', port_range: '9-9' });
    expect(create.status).toBe(200);
    const taskId = create.body.data.task_id;

    const listA = await request(app)
      .get('/api/scan/tasks')
      .set('Authorization', `Bearer ${auditorA}`);
    const idsA = (listA.body.data.tasks || []).map((t) => t.id);
    expect(idsA).not.toContain(taskId);
  });

  test('等保任务列表按组织隔离', async () => {
    const db = getDb();
    // 直接插库构造等保任务（避免 startTask 执行真实系统检查命令）
    db.prepare(`
      INSERT INTO djpp_tasks (id, level, name, description, status, progress, created_by, started_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run('DJPP-ORG1-TEST', 2, 'A组织等保测评', 'org1', 'completed', 100, 2, '2026-07-01 09:00:00');

    const own = await request(app)
      .get('/api/djpp/tasks/DJPP-ORG1-TEST')
      .set('Authorization', `Bearer ${auditorA}`);
    expect(own.status).toBe(200);

    const listB = await request(app)
      .get('/api/djpp/tasks')
      .set('Authorization', `Bearer ${auditorB}`);
    const idsB = (listB.body.data.tasks || []).map((t) => t.id);
    expect(idsB).not.toContain('DJPP-ORG1-TEST');

    const detailB = await request(app)
      .get('/api/djpp/tasks/DJPP-ORG1-TEST')
      .set('Authorization', `Bearer ${auditorB}`);
    expect(detailB.status).toBe(404);
  });

  test('剧本列表按组织隔离，跨组织不可执行', async () => {
    // 管理员（组织1）创建剧本
    const create = await request(app)
      .post('/api/playbook/create')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: '隔离测试剧本',
        description: 'org1',
        trigger: 'manual',
        steps: [{ type: 'action', action: 'log_only', name: '记录', params: {} }]
      });
    expect(create.status).toBe(200);
    const pbId = create.body.data.id;

    // 组织1 审计员可看到并执行
    const listA = await request(app)
      .get('/api/playbook/list')
      .set('Authorization', `Bearer ${auditorA}`);
    expect(listA.body.data.list.some((p) => p.id === pbId)).toBe(true);

    // 组织2 审计员看不到，且不可执行
    const listB = await request(app)
      .get('/api/playbook/list')
      .set('Authorization', `Bearer ${auditorB}`);
    expect(listB.body.data.list.some((p) => p.id === pbId)).toBe(false);

    const execB = await request(app)
      .post(`/api/playbook/${pbId}/execute`)
      .set('Authorization', `Bearer ${auditorB}`)
      .send({ event: { ip: '1.2.3.4' } });
    expect(execB.body.code).toBe(1);
  });

  test('报告列表按组织隔离，删除他人报告被拒', async () => {
    const db = getDb();
    // 手动插入两条报告：org1（user=2）与 org2（user=3）
    // 注：内存 shim 的 INSERT 参数按位置映射到全部列，使用全参数形式
    const insert = db.prepare(
      "INSERT INTO reports (id, title, type, content, generated_by, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    );
    insert.run(900001, '组织1报告', 'djpp', '{}', 2, '2026-07-01 10:00:00');
    insert.run(900002, '组织2报告', 'djpp', '{}', 3, '2026-07-01 10:00:00');

    const listB = await request(app)
      .get('/api/reports/list')
      .set('Authorization', `Bearer ${auditorB}`);
    const titlesB = listB.body.data.reports.map((r) => r.title);
    expect(titlesB).not.toContain('组织1报告');
    expect(titlesB).toContain('组织2报告');

    // 用户 B 删除组织1的报告：拒绝
    const del = await request(app)
      .delete('/api/reports/900001')
      .set('Authorization', `Bearer ${auditorB}`);
    expect(del.status).toBe(403);
  });

  test('管理员跨组织可见全部数据', async () => {
    const list = await request(app)
      .get('/api/scan/tasks')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(list.status).toBe(200);

    const reports = await request(app)
      .get('/api/reports/list')
      .set('Authorization', `Bearer ${adminToken}`);
    const titles = reports.body.data.reports.map((r) => r.title);
    expect(titles).toContain('组织1报告');
    expect(titles).toContain('组织2报告');
  });
});
