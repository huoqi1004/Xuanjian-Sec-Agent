const request = require('supertest');
const { startServer } = require('../server');
const { resetForTest, closeDb } = require('../db/database');
const aiService = require('../services/aiService');

describe('API 集成冒烟测试', () => {
  let app;

  beforeAll(async () => {
    resetForTest();
    process.env.QUEUE_DRIVER = 'memory';
    app = await startServer({ listen: false });
  });

  afterAll(() => {
    closeDb();
  });

  test('GET /api/health 返回服务健康信息', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.code).toBe(0);
    expect(res.body.data.service).toBe('xuanjian-security-agent');
    expect(res.body.data.queue.driver).toBe('memory');
    expect(res.body.data.db.row_counts.users).toBeGreaterThan(0);
    // 链路追踪头
    expect(res.headers['x-request-id']).toBeTruthy();
  });

  test('GET /metrics 返回 Prometheus 文本格式', async () => {
    const res = await request(app).get('/metrics');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/plain');
    expect(res.text).toContain('nodejs_process_uptime_seconds');
    expect(res.text).toContain('http_requests_total');
  });

  test('POST /api/auth/login 登录成功返回 token', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'admin123' });
    expect(res.status).toBe(200);
    expect(res.body.code).toBe(0);
    expect(res.body.data.token).toBeTruthy();
  });

  test('错误口令登录被拒绝', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'wrongpass' });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe(1);
  });

  test('未认证访问受保护接口返回 401', async () => {
    const res = await request(app).get('/api/scan/tasks');
    expect(res.status).toBe(401);
  });

  test('创建扫描任务并查询（扫描临时监听端口）', async () => {
    // 登录获取 token
    const login = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'admin123' });
    const token = login.body.data.token;

    // 启动临时 TCP 服务器，提供可被扫描到的端口
    const net = require('net');
    const tempServer = net.createServer();
    await new Promise((resolve) => tempServer.listen(0, '127.0.0.1', resolve));
    const tempPort = tempServer.address().port;

    const create = await request(app)
      .post('/api/scan/start')
      .set('Authorization', `Bearer ${token}`)
      .send({ target_cidr: '127.0.0.1', port_range: `${tempPort}-${tempPort}` });
    expect(create.status).toBe(200);
    expect(create.body.data.status).toBe('running');
    expect(create.body.data.task_id).toBeTruthy();

    // 轮询等待任务完成
    let detail;
    for (let i = 0; i < 20; i++) {
      const res = await request(app)
        .get(`/api/scan/tasks/${create.body.data.task_id}`)
        .set('Authorization', `Bearer ${token}`);
      detail = res.body.data;
      if (detail && (detail.status === 'completed' || detail.status === 'failed')) break;
      await new Promise((r) => setTimeout(r, 300));
    }

    await new Promise((resolve) => tempServer.close(resolve));

    expect(detail.status).toBe('completed');
    expect(detail.stats.open_ports).toBeGreaterThanOrEqual(1);
    expect(detail.results.some((r) => r.port === tempPort)).toBe(true);
  }, 30000);

  test('未知接口返回 404', async () => {
    const res = await request(app).get('/api/not-exist');
    expect(res.status).toBe(404);
  });

  test('GET /api/ai/agent/tools 返回工具目录', async () => {
    // /api/ai/* 受 authMiddleware 保护，先登录获取 token
    const login = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'admin123' });
    const token = login.body.data.token;

    const res = await request(app)
      .get('/api/ai/agent/tools')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.code).toBe(0);
    expect(res.body.data).toBeInstanceOf(Array);
    const names = res.body.data.map((t) => t.name);
    expect(names).toContain('block_ip');
    expect(names).toContain('get_threat_intel');
  });

  test('GET /api/ai/agent/plan 返回计划预览（不入库不执行）', async () => {
    // 测试环境无外网：mock LLM 调用失败，路由应回退 buildFallbackPlan 并返回 code:0
    const spy = jest.spyOn(aiService, 'callDeepSeek').mockResolvedValue({ success: false, error: 'test: llm unavailable' });
    try {
      const login = await request(app)
        .post('/api/auth/login')
        .send({ username: 'admin', password: 'admin123' });
      const token = login.body.data.token;

      const res = await request(app)
        .get('/api/ai/agent/plan')
        .query({ task: '排查内网风险资产' })
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(res.body.code).toBe(0);
      expect(res.body.data).toBeTruthy();
      expect(Array.isArray(res.body.data.steps)).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });
});
