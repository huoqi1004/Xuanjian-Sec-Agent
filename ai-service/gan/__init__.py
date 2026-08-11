# -*- coding: utf-8 -*-
"""
GAN 模块入口
提供异常检测（AnomalyGAN）和对抗样本生成（AdversarialGAN）能力。
"""

from .preprocessor import FileFeaturePreprocessor
from .anomaly_gan import AnomalyGAN
from .adversarial_gan import AdversarialMalwareGAN
from .detector import GANAnomalyDetector

__all__ = [
    'FileFeaturePreprocessor',
    'AnomalyGAN',
    'AdversarialMalwareGAN',
    'GANAnomalyDetector',
]
