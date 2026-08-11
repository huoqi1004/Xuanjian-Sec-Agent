# -*- coding: utf-8 -*-
"""
GAN 推理服务
提供 AnomalyGAN 和 AdversarialGAN 的在线检测接口。
"""

import logging
import os
from typing import Dict, List, Optional

import torch
import torch.nn.functional as F

from .anomaly_gan import AnomalyGAN, DEFAULT_INPUT_DIM, DEFAULT_LATENT_DIM
from .adversarial_gan import AdversarialMalwareGAN, DEFAULT_FEATURE_DIM
from .preprocessor import FileFeaturePreprocessor

logger = logging.getLogger(__name__)


class GANAnomalyDetector:
    """
    AnomalyGAN 推理服务
    对单个或多个文件进行异常检测，返回重构误差和异常判定。
    """

    def __init__(self, model_path: Optional[str] = None,
                 input_dim: int = DEFAULT_INPUT_DIM,
                 latent_dim: int = DEFAULT_LATENT_DIM,
                 device: str = 'cpu',
                 anomaly_threshold: float = 0.02):
        """
        Args:
            model_path:        训练好的模型路径（.pt）
            input_dim:         输入维度（784=图像模式，14=统计模式）
            latent_dim:        隐空间维度
            device:            'cpu' 或 'cuda'
            anomaly_threshold: 异常阈值（重构误差 > 此值 → 异常）
        """
        self.device = device
        self.anomaly_threshold = anomaly_threshold
        self.preprocessor = FileFeaturePreprocessor(mode='image', image_size=input_dim)
        self.model = AnomalyGAN(input_dim=input_dim, latent_dim=latent_dim).to(device)
        self.model_loaded = False
        self.model_version = 'unknown'

        if model_path and os.path.isfile(model_path):
            self.load(model_path)

    def load(self, model_path: str) -> bool:
        """加载模型，返回是否成功"""
        try:
            self.model.load_from_state_dict(model_path, device=self.device)
            self.model.eval()
            self.model_loaded = True
            logger.info("GAN 检测器已加载: %s (input_dim=%d, threshold=%.6f)",
                        model_path, self.preprocessor.input_dim, self.anomaly_threshold)
            return True
        except Exception as e:
            logger.error("GAN 模型加载失败: %s, error=%s", model_path, e)
            self.model_loaded = False
            return False

    def detect(self, file_path: str) -> Dict:
        """
        检测单个文件是否异常。

        Returns:
            {
                'is_anomaly': bool,
                'reconstruction_error': float,
                'anomaly_score': float,
                'confidence': float,
                'model_version': str,
                'error': str  (仅在异常时)
            }
        """
        if not self.model_loaded:
            return {
                'is_anomaly': False,
                'reconstruction_error': 0.0,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'model_version': self.model_version,
                'error': 'GAN 模型未加载，使用降级检测',
            }

        try:
            x = self.preprocessor.transform(file_path).to(self.device)
            with torch.no_grad():
                recon_err = self.model.reconstruct_error(x).item()
                score = self.model.anomaly_score(x).item()

            is_anomaly = recon_err > self.anomaly_threshold
            confidence = max(0.0, min(1.0, 1.0 - recon_err))

            return {
                'is_anomaly': bool(is_anomaly),
                'reconstruction_error': round(recon_err, 6),
                'anomaly_score': round(score, 6),
                'confidence': round(confidence, 4),
                'model_version': self.model_version,
            }
        except Exception as e:
            logger.error("GAN 检测失败: %s, error=%s", file_path, e)
            return {
                'is_anomaly': False,
                'reconstruction_error': 0.0,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'model_version': self.model_version,
                'error': str(e),
            }

    def detect_batch(self, file_paths: List[str]) -> List[Dict]:
        """
        批量检测多个文件（单次预处理 + 单次模型前向，性能优于逐个检测）。
        """
        if not self.model_loaded:
            return [{
                'is_anomaly': False,
                'reconstruction_error': 0.0,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'model_version': self.model_version,
                'error': 'GAN 模型未加载',
            } for _ in file_paths]

        # 批量预处理
        tensors = []
        for fp in file_paths:
            try:
                t = self.preprocessor.transform(fp).to(self.device)
                tensors.append(t)
            except Exception as e:
                logger.error("批量预处理失败: %s, error=%s", fp, e)
                tensors.append(torch.zeros(1, self.preprocessor.input_dim, device=self.device))

        if not tensors:
            return []

        # 堆叠为批次，单次前向传播
        batch = torch.cat(tensors, dim=0)  # (N, input_dim)
        with torch.no_grad():
            x_recon, _, d_out = self.model.forward(batch)
            recon_err = F.mse_loss(x_recon, batch, reduction='none').mean(dim=1)  # (N,)
            disc_anomaly = (1.0 - d_out.squeeze(-1))  # (N,)
            score = 0.7 * recon_err + 0.3 * disc_anomaly

        results = []
        for i, fp in enumerate(file_paths):
            r_err = recon_err[i].item()
            is_anomaly = r_err > self.anomaly_threshold
            confidence = max(0.0, min(1.0, 1.0 - r_err))
            results.append({
                'is_anomaly': bool(is_anomaly),
                'reconstruction_error': round(r_err, 6),
                'anomaly_score': round(score[i].item(), 6),
                'confidence': round(confidence, 4),
                'model_version': self.model_version,
            })
        return results

    def get_status(self) -> Dict:
        """返回检测器状态"""
        return {
            'loaded': self.model_loaded,
            'model_version': self.model_version,
            'input_dim': self.preprocessor.input_dim,
            'anomaly_threshold': self.anomaly_threshold,
            'device': self.device,
        }


class GANAdversarialGenerator:
    """
    AdversarialGAN 推理服务
    生成对抗性样本，用于红队测试和对抗训练。
    """

    def __init__(self, model_path: Optional[str] = None,
                 feature_dim: int = DEFAULT_FEATURE_DIM,
                 latent_dim: int = 32,
                 device: str = 'cpu'):
        self.device = device
        self.model = AdversarialMalwareGAN(
            feature_dim=feature_dim, latent_dim=latent_dim
        ).to(device)
        self.model_loaded = False

        if model_path and os.path.isfile(model_path):
            self.load(model_path)

    def load(self, model_path: str) -> bool:
        try:
            self.model.load_from_state_dict(model_path, device=self.device)
            self.model.eval()
            self.model_loaded = True
            logger.info("AdversarialGAN 已加载: %s", model_path)
            return True
        except Exception as e:
            logger.error("AdversarialGAN 加载失败: %s", e)
            return False

    def generate(self, file_path: str, n_variants: int = 5,
                 eps: float = 0.15) -> Dict:
        """
        为指定文件生成对抗变体。

        Args:
            file_path:   输入文件路径
            n_variants:  生成变体数量
            eps:         最大扰动幅度
        Returns:
            {
                'original_features': list,
                'variants': [list, ...],
                'n_variants': int,
                'eps': float,
            }
        """
        if not self.model_loaded:
            return {'error': 'AdversarialGAN 模型未加载'}

        preprocessor = FileFeaturePreprocessor(mode='stats')
        try:
            x_clean = preprocessor.transform(file_path).to(self.device)
            variants = self.model.generate_adversarial(x_clean, n_variants=n_variants, eps=eps)
            return {
                'original_features': x_clean.squeeze(0).cpu().tolist(),
                'variants': [v.squeeze(0).cpu().tolist() for v in variants],
                'n_variants': n_variants,
                'eps': eps,
            }
        except Exception as e:
            logger.error("对抗样本生成失败: %s", e)
            return {'error': str(e)}

    def get_status(self) -> Dict:
        return {
            'loaded': self.model_loaded,
            'feature_dim': self.model.feature_dim,
            'latent_dim': self.model.latent_dim,
            'device': self.device,
        }
