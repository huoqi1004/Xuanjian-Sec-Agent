# -*- coding: utf-8 -*-
"""
GAN 监控指标收集器

收集每次 GAN 扫描的指标，并生成聚合统计报告。
指标包括：
  - 扫描次数 / 异常率 / 平均响应时间
  - 各版本模型的命中率对比
  - 每日趋势数据
"""

import json
import logging
import os
import sqlite3
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class GANMetricsCollector:
    """
    GAN 扫描指标收集器

    线程安全，支持批量写入和聚合查询。
    """

    def __init__(self, db_path: Optional[str] = None, retention_days: int = 30):
        """
        Args:
            db_path: SQLite 数据库路径
            retention_days: 数据保留天数（超过则自动清理）
        """
        self.retention_days = retention_days
        self._lock = threading.Lock()
        self._batch_buffer: List[Dict] = []
        self._batch_size = 50  # 每 50 条 flush 一次

        if db_path:
            self.db_path = db_path
            os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
            self._init_db()
        else:
            self.db_path = None
            logger.warning('未指定数据库路径，指标仅保存在内存中')

    def _init_db(self):
        """初始化数据库表"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS gan_scan_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        file_path TEXT NOT NULL,
                        file_hash_md5 TEXT,
                        file_size_bytes INTEGER DEFAULT 0,
                        model_version TEXT,
                        recon_error REAL DEFAULT 0,
                        is_anomaly INTEGER DEFAULT 0,
                        anomaly_score REAL DEFAULT 0,
                        confidence REAL DEFAULT 0,
                        verdict TEXT DEFAULT 'unknown',
                        engine_verdict TEXT,
                        engine_confidence REAL,
                        vote_merged INTEGER DEFAULT 0,
                        gan_boosted INTEGER DEFAULT 0,
                        gan_conflicted INTEGER DEFAULT 0,
                        response_time_ms INTEGER DEFAULT 0,
                        skipped INTEGER DEFAULT 0,
                        skip_reason TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_gsm_scan ON gan_scan_metrics(scan_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_gsm_hash ON gan_scan_metrics(file_hash_md5)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_gsm_verdict ON gan_scan_metrics(verdict)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_gsm_created ON gan_scan_metrics(created_at)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_gsm_anomaly ON gan_scan_metrics(is_anomaly)')
            logger.info('GAN 指标数据库已初始化: %s', self.db_path)
        except Exception as e:
            logger.error('指标数据库初始化失败: %s', e)
            self.db_path = None

    def record_scan(self, scan_id: Optional[int], file_path: str,
                    file_hash_md5: Optional[str], file_size_bytes: int,
                    model_version: str, recon_error: float,
                    is_anomaly: bool, anomaly_score: float,
                    confidence: float, verdict: str,
                    engine_verdict: Optional[str], engine_confidence: Optional[float],
                    vote_merged: bool, gan_boosted: bool, gan_conflicted: bool,
                    response_time_ms: int, skipped: bool = False,
                    skip_reason: Optional[str] = None) -> bool:
        """
        记录一次 GAN 扫描指标

        Args:
            scan_id: 扫描记录 ID（关联 virus_scan_records）
            file_path: 文件路径
            file_hash_md5: 文件 MD5
            file_size_bytes: 文件大小
            model_version: 使用的模型版本
            recon_error: 重构误差
            is_anomaly: 是否判定为异常
            anomaly_score: 异常分数
            confidence: 置信度
            verdict: 判定结果（clean/suspicious/malicious）
            engine_verdict: 规则引擎判定
            engine_confidence: 规则引擎置信度
            vote_merged: 是否经过投票融合
            gan_boosted: 是否被 GAN 提升
            gan_conflicted: 是否与规则冲突
            response_time_ms: 响应时间（毫秒）
            skipped: 是否被跳过
            skip_reason: 跳过原因

        Returns:
            是否成功记录
        """
        record = {
            'scan_id': scan_id,
            'file_path': file_path,
            'file_hash_md5': file_hash_md5,
            'file_size_bytes': file_size_bytes,
            'model_version': model_version,
            'recon_error': round(recon_error, 6),
            'is_anomaly': 1 if is_anomaly else 0,
            'anomaly_score': round(anomaly_score, 6),
            'confidence': round(confidence, 4),
            'verdict': verdict,
            'engine_verdict': engine_verdict,
            'engine_confidence': round(engine_confidence, 4) if engine_confidence else None,
            'vote_merged': 1 if vote_merged else 0,
            'gan_boosted': 1 if gan_boosted else 0,
            'gan_conflicted': 1 if gan_conflicted else 0,
            'response_time_ms': response_time_ms,
            'skipped': 1 if skipped else 0,
            'skip_reason': skip_reason,
        }

        with self._lock:
            self._batch_buffer.append(record)
            if len(self._batch_buffer) >= self._batch_size:
                self._flush_buffer()

        return True

    def flush(self):
        """强制刷新缓冲区"""
        with self._lock:
            self._flush_buffer()

    def _flush_buffer(self):
        """批量写入数据库"""
        if not self._batch_buffer:
            return

        records = self._batch_buffer[:]
        self._batch_buffer.clear()

        if not self.db_path:
            logger.debug('内存模式：跳过 %d 条指标记录', len(records))
            return

        try:
            conn = sqlite3.connect(self.db_path)
            conn.executemany('''
                INSERT INTO gan_scan_metrics
                (scan_id, file_path, file_hash_md5, file_size_bytes, model_version,
                 recon_error, is_anomaly, anomaly_score, confidence, verdict,
                 engine_verdict, engine_confidence, vote_merged, gan_boosted,
                 gan_conflicted, response_time_ms, skipped, skip_reason)
                VALUES (:scan_id, :file_path, :file_hash_md5, :file_size_bytes,
                        :model_version, :recon_error, :is_anomaly, :anomaly_score,
                        :confidence, :verdict, :engine_verdict, :engine_confidence,
                        :vote_merged, :gan_boosted, :gan_conflicted,
                        :response_time_ms, :skipped, :skip_reason)
            ''', records)
            conn.commit()
            conn.close()
            logger.debug('已写入 %d 条 GAN 扫描指标', len(records))
        except Exception as e:
            logger.error('指标写入失败: %s', e)

    def get_summary(self, hours: int = 24) -> Dict:
        """
        获取指定时间范围内的扫描指标摘要

        Args:
            hours: 时间范围（小时）

        Returns:
            指标摘要
        """
        since = (datetime.now() - timedelta(hours=hours)).isoformat()

        if not self.db_path:
            return self._get_memory_summary(hours)

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row

                # 总量统计
                total = conn.execute(
                    "SELECT COUNT(*) as cnt FROM gan_scan_metrics WHERE created_at >= ?",
                    (since,)
                ).fetchone()['cnt']

                # 异常统计
                anomalies = conn.execute(
                    "SELECT COUNT(*) as cnt FROM gan_scan_metrics WHERE is_anomaly = 1 AND created_at >= ?",
                    (since,)
                ).fetchone()['cnt']

                # 跳过统计
                skipped = conn.execute(
                    "SELECT COUNT(*) as cnt FROM gan_scan_metrics WHERE skipped = 1 AND created_at >= ?",
                    (since,)
                ).fetchone()['cnt']

                # 平均响应时间
                avg_rt = conn.execute(
                    "SELECT AVG(response_time_ms) as avg_ms FROM gan_scan_metrics WHERE created_at >= ?",
                    (since,)
                ).fetchone()['avg_ms'] or 0

                # 按 verdict 统计
                verdict_dist = conn.execute(
                    """SELECT verdict, COUNT(*) as cnt
                       FROM gan_scan_metrics
                       WHERE created_at >= ? AND skipped = 0
                       GROUP BY verdict""",
                    (since,)
                ).fetchall()

                # 按模型版本统计
                version_dist = conn.execute(
                    """SELECT model_version, COUNT(*) as cnt,
                              AVG(recon_error) as avg_recon,
                              AVG(response_time_ms) as avg_rt
                       FROM gan_scan_metrics
                       WHERE created_at >= ? AND skipped = 0
                       GROUP BY model_version
                       ORDER BY cnt DESC""",
                    (since,)
                ).fetchall()

                # GAN 投票融合统计
                vote_merged = conn.execute(
                    "SELECT COUNT(*) as cnt FROM gan_scan_metrics WHERE vote_merged = 1 AND created_at >= ?",
                    (since,)
                ).fetchone()['cnt']

                gan_boosted = conn.execute(
                    "SELECT COUNT(*) as cnt FROM gan_scan_metrics WHERE gan_boosted = 1 AND created_at >= ?",
                    (since,)
                ).fetchone()['cnt']

                gan_conflicted = conn.execute(
                    "SELECT COUNT(*) as cnt FROM gan_scan_metrics WHERE gan_conflicted = 1 AND created_at >= ?",
                    (since,)
                ).fetchone()['cnt']

            return {
                'period_hours': hours,
                'total_scans': total,
                'anomaly_count': anomalies,
                'anomaly_rate': round(anomalies / max(total - skipped, 1), 4),
                'skipped_count': skipped,
                'skipped_rate': round(skipped / max(total, 1), 4),
                'avg_response_time_ms': round(avg_rt, 2),
                'vote_merge_count': vote_merged,
                'gan_boosted_count': gan_boosted,
                'gan_conflicted_count': gan_conflicted,
                'verdict_distribution': {r['verdict']: r['cnt'] for r in verdict_dist},
                'version_distribution': [
                    {
                        'version': r['model_version'],
                        'count': r['cnt'],
                        'avg_recon_error': round(r['avg_recon'], 6) if r['avg_recon'] else 0,
                        'avg_response_time_ms': round(r['avg_rt'], 2) if r['avg_rt'] else 0,
                    }
                    for r in version_dist
                ],
                'generated_at': datetime.now().isoformat(),
            }
        except Exception as e:
            logger.error('指标查询失败: %s', e)
            return {'error': str(e), 'period_hours': hours}

    def get_trend(self, hours: int = 24, interval_hours: int = 1) -> List[Dict]:
        """
        获取扫描指标时间序列（用于趋势图）

        Args:
            hours: 总时间范围
            interval_hours: 时间间隔

        Returns:
            时间序列数据
        """
        since = (datetime.now() - timedelta(hours=hours)).isoformat()

        if not self.db_path:
            return []

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    """SELECT
                           datetime(created_at, 'localtime') as time_slot,
                           COUNT(*) as total,
                           SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                           AVG(response_time_ms) as avg_rt
                       FROM gan_scan_metrics
                       WHERE created_at >= ?
                       GROUP BY strftime('%Y-%m-%d %H:00', created_at)
                       ORDER BY time_slot""",
                    (since,)
                ).fetchall()

                return [
                    {
                        'time': r['time_slot'],
                        'total': r['total'],
                        'anomalies': r['anomalies'],
                        'avg_response_time_ms': round(r['avg_rt'], 2) if r['avg_rt'] else 0,
                    }
                    for r in rows
                ]
        except Exception as e:
            logger.error('趋势查询失败: %s', e)
            return []

    def _get_memory_summary(self, hours: int) -> Dict:
        """内存模式下的摘要（近似统计）"""
        return {
            'period_hours': hours,
            'total_scans': 0,
            'anomaly_count': 0,
            'anomaly_rate': 0,
            'skipped_count': 0,
            'avg_response_time_ms': 0,
            'note': '内存模式：数据库未配置，使用近似统计',
        }

    def cleanup_old_data(self):
        """清理过期数据"""
        if not self.db_path:
            return

        cutoff = (datetime.now() - timedelta(days=self.retention_days)).isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                result = conn.execute(
                    "DELETE FROM gan_scan_metrics WHERE created_at < ?",
                    (cutoff,)
                )
                deleted = result.rowcount
            logger.info('已清理 %d 条过期 GAN 指标数据（> %d 天）', deleted, self.retention_days)
        except Exception as e:
            logger.error('数据清理失败: %s', e)


# 全局单例
_metrics_collector: Optional[GANMetricsCollector] = None


def get_metrics_collector(db_path: Optional[str] = None) -> GANMetricsCollector:
    global _metrics_collector
    if _metrics_collector is None:
        db = db_path or os.path.join(os.path.dirname(__file__), '..', 'models', 'gan_metrics.db')
        _metrics_collector = GANMetricsCollector(db_path=db)
    return _metrics_collector
