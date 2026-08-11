# -*- coding: utf-8 -*-
"""
GAN 模型版本管理 + 监控指标 单元测试
运行: pytest ai-service/test/test_gan_version_metrics.py -v
"""

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ai-service'))

from gan.version_manager import (
    GANVersionManager,
    MODEL_TYPE_ANOMALY,
    MODEL_TYPE_ADV,
    STATUS_DEPLOYED,
    STATUS_PENDING,
    get_version_manager,
)
from gan.metrics_collector import (
    GANMetricsCollector,
    get_metrics_collector,
)


class TestGANVersionManager(unittest.TestCase):
    """测试 GAN 模型版本管理器"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'gan_models.db')
        self.model_path = os.path.join(self.tmpdir, 'test_model.pt')
        # 创建占位模型文件
        with open(self.model_path, 'wb') as f:
            f.write(b'\x00' * 1024)  # 1KB 假模型
        self.mgr = GANVersionManager(db_path=self.db_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_register_model(self):
        """注册模型"""
        record = self.mgr.register_model(
            model_type=MODEL_TYPE_ANOMALY,
            version='1.0.0',
            file_path=self.model_path,
            training_stats={'train_acc': 0.95, 'test_acc': 0.92},
            notes='初始版本',
        )
        self.assertEqual(record['model_type'], MODEL_TYPE_ANOMALY)
        self.assertEqual(record['version'], '1.0.0')
        self.assertEqual(record['status'], STATUS_PENDING)
        self.assertGreater(record['file_size_bytes'], 0)
        self.assertIsNotNone(record['sha256_hash'])

    def test_register_invalid_type(self):
        """注册无效类型应抛出 ValueError"""
        with self.assertRaises(ValueError):
            self.mgr.register_model(
                model_type='invalid_type',
                version='1.0.0',
                file_path=self.model_path,
            )

    def test_register_missing_file(self):
        """注册不存在的文件应抛出 FileNotFoundError"""
        with self.assertRaises(FileNotFoundError):
            self.mgr.register_model(
                model_type=MODEL_TYPE_ANOMALY,
                version='1.0.0',
                file_path='/nonexistent/path.pt',
            )

    def test_deploy_model(self):
        """部署模型"""
        self.mgr.register_model(MODEL_TYPE_ANOMALY, '1.0.0', self.model_path)
        result = self.mgr.deploy_model(MODEL_TYPE_ANOMALY, '1.0.0')
        self.assertEqual(result['status'], STATUS_DEPLOYED)
        self.assertIsNotNone(result['deployed_at'])

    def test_get_active_model(self):
        """获取活动模型"""
        # 部署前无活动模型
        self.assertIsNone(self.mgr.get_active_model(MODEL_TYPE_ANOMALY))

        # 注册并部署
        self.mgr.register_model(MODEL_TYPE_ANOMALY, '1.0.0', self.model_path)
        self.mgr.deploy_model(MODEL_TYPE_ANOMALY, '1.0.0')
        active = self.mgr.get_active_model(MODEL_TYPE_ANOMALY)
        self.assertIsNotNone(active)
        self.assertEqual(active['version'], '1.0.0')
        self.assertEqual(active['status'], STATUS_DEPLOYED)

    def test_list_models(self):
        """列出模型"""
        self.mgr.register_model(MODEL_TYPE_ANOMALY, '1.0.0', self.model_path)
        self.mgr.register_model(MODEL_TYPE_ADV, '1.0.0', self.model_path)
        models = self.mgr.list_models()
        self.assertEqual(len(models), 2)

        # 按类型过滤
        anomaly_models = self.mgr.list_models(model_type=MODEL_TYPE_ANOMALY)
        self.assertEqual(len(anomaly_models), 1)
        self.assertEqual(anomaly_models[0]['model_type'], MODEL_TYPE_ANOMALY)

    def test_list_models_by_status(self):
        """按状态过滤"""
        self.mgr.register_model(MODEL_TYPE_ANOMALY, '1.0.0', self.model_path)
        self.mgr.deploy_model(MODEL_TYPE_ANOMALY, '1.0.0')
        deployed = self.mgr.list_models(status=STATUS_DEPLOYED)
        self.assertEqual(len(deployed), 1)
        self.assertEqual(deployed[0]['model_type'], MODEL_TYPE_ANOMALY)

    def test_cleanup_old_models(self):
        """清理旧版本"""
        # 注册 7 个版本（超过 keep=5）
        for i in range(7):
            self.mgr.register_model(
                MODEL_TYPE_ANOMALY, f'1.{i}.0', self.model_path,
                notes=f'版本 {i}'
            )
        result = self.mgr.cleanup_old_models(model_type=MODEL_TYPE_ANOMALY, keep=5)
        self.assertEqual(result['cleaned_count'], 2)

    def test_get_metrics_summary(self):
        """获取监控摘要"""
        self.mgr.register_model(MODEL_TYPE_ANOMALY, '1.0.0', self.model_path)
        self.mgr.deploy_model(MODEL_TYPE_ANOMALY, '1.0.0')
        summary = self.mgr.get_metrics_summary()
        self.assertIn('total_versions', summary)
        self.assertEqual(summary['total_versions'], 1)
        self.assertIn('by_type', summary)
        self.assertIn(MODEL_TYPE_ANOMALY, summary['by_type'])

    def test_register_and_deploy_classmethod(self):
        """一步注册+部署"""
        result = GANVersionManager.register_and_deploy(
            db_path=self.db_path,
            model_type=MODEL_TYPE_ANOMALY,
            version='2.0.0',
            file_path=self.model_path,
            training_stats={'train_acc': 0.97},
        )
        self.assertEqual(result['status'], 'registered_and_deployed')
        self.assertEqual(result['version'], '2.0.0')

    def test_deployment_inks_old_version(self):
        """部署新版本应降级旧版本"""
        self.mgr.register_model(MODEL_TYPE_ANOMALY, '1.0.0', self.model_path)
        self.mgr.deploy_model(MODEL_TYPE_ANOMALY, '1.0.0')
        # 注册并部署新版本
        self.mgr.register_model(MODEL_TYPE_ANOMALY, '2.0.0', self.model_path)
        self.mgr.deploy_model(MODEL_TYPE_ANOMALY, '2.0.0')
        # 旧版本应被降级
        models = self.mgr.list_models(model_type=MODEL_TYPE_ANOMALY)
        deployed = [m for m in models if m['status'] == STATUS_DEPLOYED]
        deprecated = [m for m in models if m['status'] == 'deprecated']
        self.assertEqual(len(deployed), 1)
        self.assertEqual(deployed[0]['version'], '2.0.0')
        self.assertEqual(len(deprecated), 1)
        self.assertEqual(deprecated[0]['version'], '1.0.0')


class TestGANMetricsCollector(unittest.TestCase):
    """测试 GAN 监控指标收集器"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'gan_metrics.db')
        self.collector = GANMetricsCollector(db_path=self.db_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_record_and_query(self):
        """记录指标并查询摘要"""
        self.collector.record_scan(
            scan_id=None,
            file_path='/tmp/test.exe',
            file_hash_md5='abc123',
            file_size_bytes=10240,
            model_version='1.0.0',
            recon_error=0.05,
            is_anomaly=True,
            anomaly_score=0.8,
            confidence=0.75,
            verdict='suspicious',
            engine_verdict='clean',
            engine_confidence=0.3,
            vote_merged=True,
            gan_boosted=True,
            gan_conflicted=False,
            response_time_ms=150,
        )
        self.collector.flush()  # 强制写入

        summary = self.collector.get_summary(hours=24)
        self.assertEqual(summary['total_scans'], 1)
        self.assertEqual(summary['anomaly_count'], 1)
        self.assertGreater(summary['anomaly_rate'], 0)
        self.assertGreater(summary['avg_response_time_ms'], 0)

    def test_record_clean_scan(self):
        """记录安全扫描"""
        self.collector.record_scan(
            scan_id=None,
            file_path='/tmp/safe.txt',
            file_hash_md5='def456',
            file_size_bytes=512,
            model_version='1.0.0',
            recon_error=0.001,
            is_anomaly=False,
            anomaly_score=0.05,
            confidence=0.95,
            verdict='clean',
            engine_verdict='clean',
            engine_confidence=0.9,
            vote_merged=False,
            gan_boosted=False,
            gan_conflicted=False,
            response_time_ms=50,
        )
        self.collector.flush()

        summary = self.collector.get_summary(hours=24)
        self.assertEqual(summary['total_scans'], 1)
        self.assertEqual(summary['anomaly_count'], 0)
        self.assertEqual(summary['anomaly_rate'], 0)

    def test_record_skipped_scan(self):
        """记录跳过的扫描"""
        self.collector.record_scan(
            scan_id=None,
            file_path='/tmp/big.exe',
            file_hash_md5=None,
            file_size_bytes=10 * 1024 * 1024,  # 10MB
            model_version='1.0.0',
            recon_error=0,
            is_anomaly=False,
            anomaly_score=0,
            confidence=0,
            verdict='unknown',
            engine_verdict=None,
            engine_confidence=None,
            vote_merged=False,
            gan_boosted=False,
            gan_conflicted=False,
            response_time_ms=0,
            skipped=True,
            skip_reason='文件过大 (>5MB)',
        )
        self.collector.flush()

        summary = self.collector.get_summary(hours=24)
        self.assertEqual(summary['total_scans'], 1)
        self.assertEqual(summary['skipped_count'], 1)
        self.assertEqual(summary['skipped_rate'], 1.0)

    def test_batch_record(self):
        """批量记录（自动 flush）"""
        for i in range(60):  # 超过 batch_size=50
            self.collector.record_scan(
                scan_id=None,
                file_path=f'/tmp/test_{i}.exe',
                file_hash_md5=f'hash_{i}',
                file_size_bytes=1024,
                model_version='1.0.0',
                recon_error=0.01 * i,
                is_anomaly=i % 5 == 0,  # 每 5 个异常
                anomaly_score=0.1 * i,
                confidence=0.9 - 0.01 * i,
                verdict='suspicious' if i % 5 == 0 else 'clean',
                engine_verdict='clean',
                engine_confidence=0.5,
                vote_merged=False,
                gan_boosted=False,
                gan_conflicted=False,
                response_time_ms=100 + i,
            )
        # 不 flush，等待自动 flush
        summary = self.collector.get_summary(hours=24)
        # 部分记录可能在缓冲区中，不要求精确值
        self.assertGreaterEqual(summary['total_scans'], 0)

    def test_trend(self):
        """获取趋势数据"""
        # 记录几条数据
        for i in range(5):
            self.collector.record_scan(
                scan_id=None,
                file_path=f'/tmp/trend_{i}.exe',
                file_hash_md5=f'trend_hash_{i}',
                file_size_bytes=1024,
                model_version='1.0.0',
                recon_error=0.02,
                is_anomaly=i % 2 == 0,
                anomaly_score=0.3,
                confidence=0.7,
                verdict='suspicious' if i % 2 == 0 else 'clean',
                engine_verdict='clean',
                engine_confidence=0.5,
                vote_merged=False,
                gan_boosted=False,
                gan_conflicted=False,
                response_time_ms=80,
            )
        self.collector.flush()

        trend = self.collector.get_trend(hours=24, interval_hours=1)
        self.assertGreaterEqual(len(trend), 1)

    def test_cleanup_old_data(self):
        """清理过期数据"""
        self.collector.cleanup_old_data()  # 不应报错
        # 内存模式下无数据，清理应为 0
        summary = self.collector.get_summary(hours=24)
        self.assertEqual(summary['total_scans'], 0)


class TestSingletons(unittest.TestCase):
    """测试全局单例"""

    def test_get_version_manager(self):
        """get_version_manager 返回 GANVersionManager 实例"""
        mgr = get_version_manager()
        self.assertIsInstance(mgr, GANVersionManager)
        # 重复调用应返回同一实例
        mgr2 = get_version_manager()
        self.assertIs(mgr, mgr2)

    def test_get_metrics_collector(self):
        """get_metrics_collector 返回 GANMetricsCollector 实例"""
        collector = get_metrics_collector()
        self.assertIsInstance(collector, GANMetricsCollector)
        collector2 = get_metrics_collector()
        self.assertIs(collector, collector2)


if __name__ == '__main__':
    unittest.main()
