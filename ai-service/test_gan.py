# -*- coding: utf-8 -*-
"""
GAN 模块单元测试
覆盖：预处理器、模型前向、训练循环、检测器推理。
运行: pytest ai-service/test_gan.py -v
"""

import os
import sys
import tempfile
import unittest

import numpy as np
import torch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ai-service'))

from gan.preprocessor import FileFeaturePreprocessor
from gan.anomaly_gan import AnomalyGAN
from gan.adversarial_gan import AdversarialMalwareGAN
from gan.metrics import compute_metrics, find_optimal_threshold, format_report
from gan.detector import GANAnomalyDetector, GANAdversarialGenerator


class TestFileFeaturePreprocessor(unittest.TestCase):
    """测试文件特征预处理"""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_image_mode_normal_file(self):
        """图像模式：正常文件 → (1, 784) 张量"""
        path = os.path.join(self.tmp_dir, 'test.bin')
        with open(path, 'wb') as f:
            f.write(os.urandom(1024))

        prep = FileFeaturePreprocessor(mode='image')
        tensor = prep.transform(path)

        self.assertEqual(tensor.shape, (1, 784))
        self.assertEqual(tensor.dtype, torch.float32)
        self.assertTrue((tensor >= 0).all() and (tensor <= 1).all())

    def test_image_mode_small_file(self):
        """图像模式：小文件（< 784 字节）→ 尾部补零"""
        path = os.path.join(self.tmp_dir, 'small.bin')
        with open(path, 'wb') as f:
            f.write(b'\xAB' * 100)

        prep = FileFeaturePreprocessor(mode='image')
        tensor = prep.transform(path)

        self.assertEqual(tensor.shape, (1, 784))
        # 前 100 字节应为 0xAB/255 ≈ 0.69，其余为 0
        self.assertAlmostEqual(tensor[0, 0].item(), 0xAB / 255.0, places=4)
        self.assertAlmostEqual(tensor[0, 100].item(), 0.0, places=4)

    def test_stats_mode(self):
        """统计模式：14 维特征向量"""
        path = os.path.join(self.tmp_dir, 'test.bin')
        with open(path, 'wb') as f:
            f.write(os.urandom(512))

        prep = FileFeaturePreprocessor(mode='stats')
        tensor = prep.transform(path)

        self.assertEqual(tensor.shape, (1, 14))
        self.assertEqual(tensor.dtype, torch.float32)

    def test_missing_file(self):
        """不存在的文件 → 返回全零张量"""
        prep = FileFeaturePreprocessor(mode='image')
        tensor = prep.transform('/nonexistent/file.bin')
        self.assertEqual(tensor.shape, (1, 784))
        self.assertTrue((tensor == 0).all())

    def test_input_dim(self):
        self.assertEqual(FileFeaturePreprocessor(mode='image').input_dim, 784)
        self.assertEqual(FileFeaturePreprocessor(mode='stats').input_dim, 14)


class TestAnomalyGAN(unittest.TestCase):
    """测试 AnomalyGAN 模型"""

    def test_forward_shapes(self):
        """前向传播输出形状正确"""
        model = AnomalyGAN(input_dim=784, latent_dim=64)
        x = torch.randn(4, 784)
        x_recon, z, d_out = model(x)

        self.assertEqual(x_recon.shape, (4, 784))
        self.assertEqual(z.shape, (4, 64))
        self.assertEqual(d_out.shape, (4, 1))

    def test_reconstruct_error(self):
        """重构误差计算正确"""
        model = AnomalyGAN(input_dim=10, latent_dim=4)
        x = torch.rand(2, 10)
        err = model.reconstruct_error(x)
        self.assertEqual(err.shape, (2,))
        self.assertTrue((err >= 0).all())

    def test_anomaly_score(self):
        """异常分数计算正常"""
        model = AnomalyGAN(input_dim=10, latent_dim=4)
        x = torch.rand(2, 10)
        score = model.anomaly_score(x)
        self.assertEqual(score.shape, (2,))
        self.assertTrue((score >= 0).all())

    def test_save_load(self):
        """模型保存和加载"""
        model = AnomalyGAN(input_dim=784, latent_dim=64)
        tmp_path = os.path.join(tempfile.mkdtemp(), 'test.pt')
        model.save(tmp_path, epoch=5, metrics={'auc': 0.9})

        model2 = AnomalyGAN(input_dim=784, latent_dim=64)
        model2.load_from_state_dict(tmp_path)
        model2.eval()  # BatchNorm 需 eval 模式才能处理 batch=1
        # 验证加载后前向传播正常
        x = torch.randn(1, 784)
        x_recon, z, d_out = model2(x)
        self.assertEqual(x_recon.shape, (1, 784))

    def test_output_range(self):
        """Sigmoid 输出应在 [0, 1] 范围内"""
        model = AnomalyGAN(input_dim=784, latent_dim=64)
        x = torch.rand(2, 784)
        x_recon, _, d_out = model(x)
        self.assertTrue((x_recon >= 0).all() and (x_recon <= 1).all())
        self.assertTrue((d_out >= 0).all() and (d_out <= 1).all())


class TestAdversarialGAN(unittest.TestCase):
    """测试 AdversarialGAN 模型"""

    def test_forward_shapes(self):
        """前向传播输出形状正确"""
        model = AdversarialMalwareGAN(feature_dim=14, latent_dim=32)
        x_clean = torch.rand(4, 14)
        x_adv = model(x_clean)
        self.assertEqual(x_adv.shape, (4, 14))

    def test_generate_variants(self):
        """生成对抗变体"""
        model = AdversarialMalwareGAN(feature_dim=14, latent_dim=32)
        x_clean = torch.rand(2, 14)
        variants = model.generate_adversarial(x_clean, n_variants=3, eps=0.15)

        self.assertEqual(len(variants), 3)
        for v in variants:
            self.assertEqual(v.shape, (2, 14))
            # 扰动幅度不超过 eps
            diff = (v - x_clean).abs().max(dim=1).values
            self.assertTrue((diff <= 0.15 + 1e-6).all())

    def test_adversarial_loss(self):
        """对抗损失计算正常"""
        model = AdversarialMalwareGAN(feature_dim=14, latent_dim=32)
        x_clean = torch.rand(4, 14)
        z = torch.randn(4, 32)
        x_adv = model(x_clean, z)
        loss = model.adversarial_loss(x_adv, x_clean)
        self.assertIsInstance(loss.item(), float)
        self.assertGreaterEqual(loss.item(), 0)


class TestMetrics(unittest.TestCase):
    """测试评估指标"""

    def test_compute_metrics_perfect(self):
        """完美分类指标"""
        y_true = [0, 0, 1, 1]
        y_scores = [0.1, 0.2, 0.8, 0.9]
        metrics = compute_metrics(y_true, y_scores)
        self.assertEqual(metrics['auc_roc'], 1.0)
        self.assertEqual(metrics['f1'], 1.0)

    def test_compute_metrics_worst(self):
        """最差分类指标"""
        y_true = [0, 0, 1, 1]
        y_scores = [0.9, 0.8, 0.2, 0.1]  # 完全反向
        metrics = compute_metrics(y_true, y_scores)
        self.assertEqual(metrics['auc_roc'], 0.0)

    def test_find_optimal_threshold(self):
        """最优阈值搜索"""
        y_true = [0, 0, 1, 1]
        y_scores = [0.1, 0.2, 0.8, 0.9]
        t = find_optimal_threshold(y_true, y_scores)
        self.assertGreaterEqual(t, 0.0)
        self.assertLessEqual(t, 1.0)

    def test_format_report(self):
        """指标格式化"""
        metrics = {'auc_roc': 0.95, 'f1': 0.90, 'precision': 0.88,
                   'recall': 0.92, 'accuracy': 0.93, 'tn': 90, 'fp': 5,
                   'fn': 3, 'tp': 97}
        report = format_report(metrics)
        self.assertIn('0.95', report)
        self.assertIn('TN=90', report)


class TestGANAnomalyDetector(unittest.TestCase):
    """测试 GAN 推理检测器"""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        # 创建测试文件
        self.normal_file = os.path.join(self.tmp_dir, 'normal.bin')
        with open(self.normal_file, 'wb') as f:
            f.write(os.urandom(512))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_detector_without_model(self):
        """未加载模型时返回降级结果"""
        detector = GANAnomalyDetector()
        result = detector.detect(self.normal_file)
        self.assertEqual(result['is_anomaly'], False)
        self.assertIn('error', result)

    def test_detector_with_model(self):
        """加载模型后进行检测"""
        model = AnomalyGAN(input_dim=784, latent_dim=64)
        tmp_path = os.path.join(self.tmp_dir, 'gan.pt')
        model.save(tmp_path)

        detector = GANAnomalyDetector(model_path=tmp_path, anomaly_threshold=1.0)
        result = detector.detect(self.normal_file)
        self.assertIn('is_anomaly', result)
        self.assertIn('reconstruction_error', result)

    def test_get_status(self):
        """状态查询"""
        detector = GANAnomalyDetector()
        status = detector.get_status()
        self.assertIn('loaded', status)
        self.assertIn('anomaly_threshold', status)


class TestGANAdversarialGenerator(unittest.TestCase):
    """测试对抗样本生成器"""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.tmp_dir, 'test.bin')
        with open(self.test_file, 'wb') as f:
            f.write(os.urandom(256))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_generator_without_model(self):
        """未加载模型时返回错误"""
        gen = GANAdversarialGenerator()
        result = gen.generate(self.test_file)
        self.assertIn('error', result)

    def test_generate_variants(self):
        """生成对抗变体"""
        model = AdversarialMalwareGAN()
        tmp_path = os.path.join(self.tmp_dir, 'adv.pt')
        model.save(tmp_path)

        gen = GANAdversarialGenerator(model_path=tmp_path)
        result = gen.generate(self.test_file, n_variants=3)
        self.assertIn('variants', result)
        self.assertEqual(len(result['variants']), 3)


if __name__ == '__main__':
    unittest.main()
