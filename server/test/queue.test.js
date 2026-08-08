const { MemoryQueue } = require('../services/queue');

describe('MemoryQueue 内存任务队列', () => {
  test('并发执行并触发完成事件', async () => {
    const q = new MemoryQueue({ concurrency: 2 });
    const results = [];
    const completed = [];
    q.process('task', async (job) => {
      await new Promise((r) => setTimeout(r, 10));
      results.push(job.data.v);
      return job.data.v * 2;
    });
    q.on('completed', (job) => completed.push(job.id));
    [1, 2, 3, 4].forEach((v) => q.add('task', { v }));

    // 轮询等待全部完成
    const deadline = Date.now() + 5000;
    while (q.stats().completed < 4 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 20));
    }

    expect(q.stats().completed).toBe(4);
    expect(q.stats().failed).toBe(0);
    expect(completed).toHaveLength(4);
    expect(results.sort()).toEqual([1, 2, 3, 4]);
  });

  test('失败后按 attempts 重试直至成功', async () => {
    const q = new MemoryQueue({ concurrency: 1 });
    let attempts = 0;
    q.process('task', async () => {
      attempts++;
      if (attempts < 3) throw new Error('模拟失败');
      return 'ok';
    });
    q.add('task', {}, { attempts: 3, backoff: 1 });

    await new Promise((resolve) => q.on('completed', resolve));
    expect(attempts).toBe(3);
    expect(q.stats().failed).toBe(0);
    expect(q.getJob([...q.jobs.keys()][0]).status).toBe('completed');
  });

  test('超过尝试次数后标记失败', async () => {
    const q = new MemoryQueue({ concurrency: 1 });
    q.process('task', async () => {
      throw new Error('始终失败');
    });
    q.add('task', {}, { attempts: 2, backoff: 1 });

    await new Promise((resolve) => q.on('failed', resolve));
    expect(q.stats().failed).toBe(1);
  });

  test('无处理器任务直接失败', () => {
    const q = new MemoryQueue();
    const failed = [];
    q.on('failed', (job) => failed.push(job));
    q.add('unknown', {});
    expect(failed).toHaveLength(1);
    expect(q.stats().failed).toBe(1);
    expect(q.stats().depth).toBe(0);
  });

  test('delay 延迟入队', async () => {
    const q = new MemoryQueue({ concurrency: 1 });
    const started = [];
    q.process('task', async (job) => { started.push(Date.now()); });
    const before = Date.now();
    q.add('task', {}, { delay: 50 });
    await new Promise((resolve) => q.on('completed', resolve));
    expect(Date.now() - before).toBeGreaterThanOrEqual(40);
    expect(started).toHaveLength(1);
  });
});
