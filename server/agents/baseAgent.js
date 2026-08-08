/**
 * 玄鉴安全智能体 - 多 Agent 框架基类与上下文
 * 上下文（Context）是 Agent 间传递的共享工作区（黑板模式）：
 * 每个 Agent 读取前序产物，写入自己的产物，编排器负责调度顺序。
 */
const { randomUUID } = require('crypto');
const logger = require('../utils/logger');
const metrics = require('../utils/metrics');

/** 创建共享上下文 */
function createContext(task, opts = {}) {
  const store = new Map();
  const ctx = {
    runId: `agent_${Date.now().toString(36)}_${randomUUID().slice(0, 4)}`,
    task: String(task || ''),
    userId: opts.userId || null,
    startedAt: new Date().toISOString(),
    steps: [], // { agent, tool?, status, duration_ms, at }
    set(key, value) { store.set(key, value); },
    get(key) { return store.get(key); },
    has(key) { return store.has(key); },
    appendStep(record) { ctx.steps.push({ at: new Date().toISOString(), ...record }); }
  };
  return ctx;
}

/**
 * Agent 基类
 * 子类必须实现 run(ctx)：读取 ctx 输入，返回 { success, data?, message?, error? }
 */
class BaseAgent {
  constructor(name, capability) {
    this.name = name;          // 唯一标识，如 'planner'
    this.capability = capability; // 能力描述，供编排器路由
  }

  /** 统一执行入口：计时 + 指标 + 日志 + 步骤记录 */
  async execute(ctx) {
    const start = Date.now();
    const step = { agent: this.name, status: 'running' };
    ctx.appendStep(step);
    metrics.inc('agent_calls_total', { agent: this.name }, 1, 'Agent 调用次数');
    try {
      const result = await this.run(ctx);
      const ok = result && result.success !== false;
      step.status = ok ? 'done' : 'failed';
      step.duration_ms = Date.now() - start;
      if (ok) logger.info(`[Agent:${this.name}] 执行成功（${step.duration_ms}ms）`);
      else logger.warn(`[Agent:${this.name}] 执行失败: ${result && result.error}`);
      return { success: ok, agent: this.name, data: result.data, message: result.message, error: result.error };
    } catch (err) {
      step.status = 'failed';
      step.duration_ms = Date.now() - start;
      logger.error(`[Agent:${this.name}] 异常:`, err.message);
      return { success: false, agent: this.name, error: err.message };
    }
  }
}

module.exports = { createContext, BaseAgent };
