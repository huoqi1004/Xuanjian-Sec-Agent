/**
 * 威胁知识库同步服务
 * 通过 node-cron 定时调用，执行 Python 知识库构建脚本重建索引
 */
const { spawn } = require('child_process');
const path = require('path');
const logger = require('../utils/logger');

const KB_BUILD_SCRIPT = path.join(__dirname, '..', 'ai-service', 'scripts', 'build_threat_kb.py');
const PY_EXECUTABLE = process.env.PYTHON_BIN || 'python';

function syncKnowledgeIndex() {
  return new Promise((resolve) => {
    logger.info('[知识库同步] 开始重建索引...');
    const proc = spawn(PY_EXECUTABLE, [KB_BUILD_SCRIPT], {
      cwd: path.join(__dirname, '..'),
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60000,
    });

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (data) => { stdout += data.toString(); });
    proc.stderr.on('data', (data) => { stderr += data.toString(); });

    proc.on('close', (code) => {
      if (code === 0) {
        logger.info('[知识库同步] 索引重建成功');
        resolve({ success: true, output: stdout.trim() });
      } else {
        logger.error(`[知识库同步] 失败（exit=${code}）: ${stderr.substring(0, 200)}`);
        resolve({ success: false, error: stderr.trim() });
      }
    });

    proc.on('error', (err) => {
      logger.error('[知识库同步] 进程启动失败:', err.message);
      resolve({ success: false, error: err.message });
    });

    // 超时保护
    setTimeout(() => {
      proc.kill();
      logger.warn('[知识库同步] 超时（60s）');
      resolve({ success: false, error: 'timeout' });
    }, 65000);
  });
}

module.exports = { syncKnowledgeIndex };
