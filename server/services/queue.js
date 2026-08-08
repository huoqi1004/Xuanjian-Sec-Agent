/**
 * 玄鉴安全智能体 - 统一任务队列抽象层
 *
 * 驱动选择（QUEUE_DRIVER）：
 * - memory（默认）：进程内队列，支持并发控制、失败重试（指数退避）、状态追踪。
 *   单实例/开发环境零依赖可用。
 * - bullmq：基于 Redis + BullMQ，跨实例共享队列（需安装 bullmq 并配置 REDIS_HOST/PORT）。
 *   若 Redis 不可达或依赖缺失，自动降级为 memory 并告警。
 *
 * 统一 API：
 *   queue.process(name, handler)         注册任务处理器
 *   queue.add(name, data, opts)          入队（opts: attempts/backoff/delay）
 *   queue.stats()                        队列统计 { driver, waiting, active, ... }
 *   queue.getJob(id)                     查询任务状态
 *   事件：completed / failed / completed:<name> / failed:<name> / added
 */

const { EventEmitter } = require('events');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

const queueConfig = {
  driver: (process.env.QUEUE_DRIVER || 'memory').toLowerCase(),
  concurrency: parseInt(process.env.QUEUE_CONCURRENCY) || 4,
  redisHost: process.env.REDIS_HOST || '127.0.0.1',
  redisPort: parseInt(process.env.REDIS_PORT) || 6379
};

/* ---------------- Memory 驱动 ---------------- */

class MemoryQueue extends EventEmitter {
  constructor(opts = {}) {
    super();
    this.driver = 'memory';
    this.concurrency = opts.concurrency || queueConfig.concurrency;
    this.handlers = new Map();
    this.jobs = new Map();
    this.waiting = [];
    this.active = new Map();
    this.completedCount = 0;
    this.failedCount = 0;
    this._jobSeq = 0;
  }

  process(name, handler) {
    if (typeof handler !== 'function') throw new Error('queue.process 需要处理器函数');
    this.handlers.set(name, handler);
  }

  add(name, data, opts = {}) {
    const id = `${name}_${Date.now()}_${++this._jobSeq}`;
    const job = {
      id,
      name,
      data,
      opts,
      status: opts.delay ? 'delayed' : 'waiting',
      attempts: 0,
      maxAttempts: opts.attempts || 1,
      createdAt: new Date().toISOString()
    };
    this.jobs.set(id, job);
    this.emit('added', job);

    if (opts.delay) {
      setTimeout(() => {
        if (job.status !== 'delayed') return;
        job.status = 'waiting';
        this.waiting.push(id);
        this._drain();
      }, opts.delay);
    } else {
      this.waiting.push(id);
    }
    this._drain();
    return job;
  }

  _drain() {
    while (this.waiting.length > 0 && this.active.size < this.concurrency) {
      const id = this.waiting.shift();
      const job = this.jobs.get(id);
      if (!job) continue;
      this._run(job);
    }
  }

  async _run(job) {
    const handler = this.handlers.get(job.name);
    this.active.set(job.id, job);
    job.status = 'active';
    job.startedAt = new Date().toISOString();
    metrics.incGauge('queue_active_jobs', { queue: job.name }, 1, '队列活跃任务数');

    if (!handler) {
      job.status = 'failed';
      job.error = `未注册任务处理器: ${job.name}`;
      this.active.delete(job.id);
      this.failedCount++;
      metrics.inc('queue_jobs_total', { queue: job.name, result: 'failed' }, 1, '队列任务总数');
      metrics.incGauge('queue_active_jobs', { queue: job.name }, -1, '队列活跃任务数');
      this.emit('failed', job);
      this.emit(`failed:${job.name}`, job);
      this._drain();
      return;
    }

    try {
      job.result = await handler(job);
      job.status = 'completed';
      job.completedAt = new Date().toISOString();
      this.active.delete(job.id);
      this.completedCount++;
      metrics.inc('queue_jobs_total', { queue: job.name, result: 'completed' }, 1, '队列任务总数');
      metrics.incGauge('queue_active_jobs', { queue: job.name }, -1, '队列活跃任务数');
      this.emit('completed', job);
      this.emit(`completed:${job.name}`, job);
      this._drain(); // 任务完成，调度下一个等待任务
    } catch (err) {
      job.attempts++;
      job.error = err.message || String(err);
      this.active.delete(job.id);
      metrics.incGauge('queue_active_jobs', { queue: job.name }, -1, '队列活跃任务数');

      if (job.attempts < job.maxAttempts) {
        const delay = (job.opts.backoff || 1000) * Math.pow(2, job.attempts - 1);
        job.status = 'delayed';
        logger.warn(`[队列] 任务 ${job.id} 第 ${job.attempts} 次执行失败，${delay}ms 后重试: ${job.error}`);
        setTimeout(() => {
          if (job.status !== 'delayed') return;
          job.status = 'waiting';
          this.waiting.push(job.id);
          this._drain();
        }, delay);
      } else {
        job.status = 'failed';
        job.completedAt = new Date().toISOString();
        this.failedCount++;
        metrics.inc('queue_jobs_total', { queue: job.name, result: 'failed' }, 1, '队列任务总数');
        logger.error(`[队列] 任务 ${job.id} 最终失败: ${job.error}`);
        this.emit('failed', job);
        this.emit(`failed:${job.name}`, job);
      }
      this._drain();
    }
  }

  stats() {
    const waiting = this.waiting.filter((id) => this.jobs.get(id)?.status === 'waiting').length;
    return {
      driver: this.driver,
      waiting,
      active: this.active.size,
      completed: this.completedCount,
      failed: this.failedCount,
      depth: waiting + this.active.size
    };
  }

  getJob(id) {
    return this.jobs.get(id);
  }
}

/* ---------------- BullMQ 驱动（Redis，可选） ---------------- */

function createBullMQQueue() {
  let Queue;
  let Worker;
  try {
    ({ Queue, Worker } = require('bullmq'));
  } catch (err) {
    logger.error(`[队列] bullmq 未安装，降级为 memory 驱动: ${err.message}`);
    return new MemoryQueue();
  }

  const connection = { host: queueConfig.redisHost, port: queueConfig.redisPort };
  const handlers = new Map();
  const queue = new Queue('xuanjian-jobs', { connection });
  const worker = new Worker(
    'xuanjian-jobs',
    async (bullJob) => {
      const handler = handlers.get(bullJob.name);
      if (!handler) throw new Error(`未注册任务处理器: ${bullJob.name}`);
      metrics.inc('queue_jobs_total', { queue: bullJob.name, result: 'processed' }, 1, '队列任务总数');
      return handler(bullJob);
    },
    { connection, concurrency: queueConfig.concurrency }
  );

  worker.on('completed', (job) => {
    logger.info(`[队列] BullMQ 任务完成: ${job.id}`);
  });
  worker.on('failed', (job, err) => {
    logger.error(`[队列] BullMQ 任务失败: ${job?.id} ${err?.message}`);
  });

  return {
    driver: 'bullmq',
    process: (name, handler) => handlers.set(name, handler),
    add: async (name, data, opts = {}) => {
      return queue.add(name, data, {
        attempts: opts.attempts || 1,
        backoff: opts.backoff ? { type: 'exponential', delay: opts.backoff } : undefined,
        delay: opts.delay || 0,
        removeOnComplete: true,
        removeOnFail: 100
      });
    },
    stats: async () => {
      const [waiting, active] = await Promise.all([
        queue.getWaitingCount(),
        queue.getActiveCount()
      ]);
      return { driver: 'bullmq', waiting, active, depth: waiting + active };
    },
    getJob: (id) => queue.getJob(id),
    close: async () => {
      await worker.close();
      await queue.close();
    }
  };
}

/* ---------------- 单例导出 ---------------- */

let queueInstance = null;

function getQueue() {
  if (!queueInstance) {
    if (queueConfig.driver === 'bullmq') {
      queueInstance = createBullMQQueue();
      logger.info(`[队列] 使用 BullMQ(Redis) 驱动 @ ${queueConfig.redisHost}:${queueConfig.redisPort}`);
    } else {
      queueInstance = new MemoryQueue();
      logger.info(`[队列] 使用 memory 驱动（QUEUE_DRIVER=memory，并发=${queueInstance.concurrency}）`);
    }
  }
  return queueInstance;
}

// 测试/重启时可重置
function resetQueue() {
  queueInstance = null;
}

module.exports = { getQueue, resetQueue, MemoryQueue, queueConfig };
