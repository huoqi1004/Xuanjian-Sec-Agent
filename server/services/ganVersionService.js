// -*- coding: utf-8 -*-
/**
 * GAN 模型版本管理服务（Node.js 端）
 *
 * 职责：
 * 1. 通过 aiService 调用 Python GAN 版本管理接口
 * 2. 提供同步的数据库写入（gan_model_versions / gan_scan_metrics）
 * 3. 监听 GAN 扫描结果，自动记录指标
 */

const { getDb } = require('../db/database');
const logger = require('../utils/logger');

class GANVersionService {
  constructor(aiService) {
    this.aiService = aiService;
  }

  /**
   * 注册 GAN 模型版本
   * @param {Object} params
   * @param {string} params.modelType - anomaly_gan | adversarial_gan
   * @param {string} params.version - 版本号
   * @param {string} params.filePath - 模型文件路径
   * @param {Object} params.trainingStats - 训练指标
   * @param {string} params.notes - 备注
   * @returns {Promise<Object>}
   */
  async registerModel(params) {
    try {
      const result = await this.aiService.callAiServiceJson(
        '/api/gan/model/register',
        params
      );
      if (result.code === 0) {
        logger.info(`[GAN版本] 模型注册成功: ${params.modelType} v${params.version}`);
      }
      return result;
    } catch (error) {
      logger.warn(`[GAN版本] 模型注册失败: ${error.message}`);
      return { code: 1, message: error.message, data: null };
    }
  }

  /**
   * 部署 GAN 模型版本
   * @param {string} modelType
   * @param {string} version
   * @returns {Promise<Object>}
   */
  async deployModel(modelType, version) {
    try {
      const result = await this.aiService.callAiServiceJson('/api/gan/model/deploy', {
        model_type: modelType,
        version,
      });
      if (result.code === 0) {
        logger.info(`[GAN版本] 模型部署成功: ${modelType} v${version}`);
      }
      return result;
    } catch (error) {
      logger.warn(`[GAN版本] 模型部署失败: ${error.message}`);
      return { code: 1, message: error.message, data: null };
    }
  }

  /**
   * 获取当前活动模型
   * @param {string} modelType
   * @returns {Promise<Object>}
   */
  async getActiveModel(modelType = 'anomaly_gan') {
    try {
      return await this.aiService.callAiServiceJson('/api/gan/model/active', {
        model_type: modelType,
      });
    } catch (error) {
      logger.warn(`[GAN版本] 获取活动模型失败: ${error.message}`);
      return { code: 1, message: error.message, data: null };
    }
  }

  /**
   * 列出所有模型版本
   * @param {string} modelType - 可选过滤
   * @param {string} status - 可选过滤
   * @returns {Promise<Object>}
   */
  async listModels(modelType, status) {
    try {
      const params = {};
      if (modelType) params.model_type = modelType;
      if (status) params.status = status;
      return await this.aiService.callAiServiceJson('/api/gan/model/list', params);
    } catch (error) {
      logger.warn(`[GAN版本] 列出模型失败: ${error.message}`);
      return { code: 1, message: error.message, data: [] };
    }
  }

  /**
   * 清理旧版本
   * @param {string} modelType
   * @param {number} keep
   * @returns {Promise<Object>}
   */
  async cleanupModels(modelType, keep = 5) {
    try {
      return await this.aiService.callAiServiceJson('/api/gan/model/cleanup', {
        model_type: modelType,
        keep,
      });
    } catch (error) {
      logger.warn(`[GAN版本] 清理模型失败: ${error.message}`);
      return { code: 1, message: error.message, data: null };
    }
  }

  /**
   * 获取模型监控摘要
   * @returns {Promise<Object>}
   */
  async getSummary() {
    try {
      return await this.aiService.callAiServiceJson('/api/gan/model/summary');
    } catch (error) {
      logger.warn(`[GAN版本] 获取摘要失败: ${error.message}`);
      return { code: 1, message: error.message, data: null };
    }
  }

  /**
   * 获取扫描指标摘要
   * @param {number} hours - 时间范围（小时）
   * @returns {Promise<Object>}
   */
  async getMetricsSummary(hours = 24) {
    try {
      return await this.aiService.callAiServiceJson(
        `/api/gan/metrics/summary?hours=${hours}`
      );
    } catch (error) {
      logger.warn(`[GAN指标] 获取摘要失败: ${error.message}`);
      return { code: 1, message: error.message, data: null };
    }
  }

  /**
   * 获取扫描趋势数据
   * @param {number} hours - 总时间范围
   * @param {number} intervalHours - 时间间隔
   * @returns {Promise<Object>}
   */
  async getMetricsTrend(hours = 24, intervalHours = 1) {
    try {
      return await this.aiService.callAiServiceJson(
        `/api/gan/metrics/trend?hours=${hours}&interval_hours=${intervalHours}`
      );
    } catch (error) {
      logger.warn(`[GAN指标] 获取趋势失败: ${error.message}`);
      return { code: 1, message: error.message, data: [] };
    }
  }

  /**
   * 本地记录 GAN 扫描指标（同步写入 SQLite）
   * 在 multiEngineScanService 扫描完成后调用
   */
  recordScanMetric(scanRecord) {
    try {
      const db = getDb();
      db.prepare(`
        INSERT INTO gan_scan_metrics
          (scan_id, file_path, file_hash_md5, file_size_bytes, model_version,
           recon_error, is_anomaly, anomaly_score, confidence, verdict,
           engine_verdict, engine_confidence, vote_merged, gan_boosted,
           gan_conflicted, response_time_ms, skipped, skip_reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        scanRecord.scanId || null,
        scanRecord.filePath || '',
        scanRecord.fileHashMd5 || null,
        scanRecord.fileSizeBytes || 0,
        scanRecord.modelVersion || 'unknown',
        scanRecord.reconError || 0,
        scanRecord.isAnomaly ? 1 : 0,
        scanRecord.anomalyScore || 0,
        scanRecord.confidence || 0,
        scanRecord.verdict || 'unknown',
        scanRecord.engineVerdict || null,
        scanRecord.engineConfidence || null,
        scanRecord.voteMerged ? 1 : 0,
        scanRecord.ganBoosted ? 1 : 0,
        scanRecord.ganConflicted ? 1 : 0,
        scanRecord.responseTimeMs || 0,
        scanRecord.skipped ? 1 : 0,
        scanRecord.skipReason || null,
      );
      logger.debug(`[GAN指标] 本地记录成功: ${scanRecord.filePath} | verdict=${scanRecord.verdict}`);
    } catch (error) {
      // 表不存在时静默跳过（首次启动可能表还未创建）
      logger.debug(`[GAN指标] 本地记录跳过（表可能未创建）: ${error.message}`);
    }
  }
}

module.exports = GANVersionService;
