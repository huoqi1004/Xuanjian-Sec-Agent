# -*- coding: utf-8 -*-
"""
AdversarialMalwareGAN — 对抗样本生成器

在良性文件特征空间生成恶意变体，用于：
  1. 对抗训练：将生成样本加入训练集，增强 malware_detector 鲁棒性
  2. 红队测试：批量生成对抗性样本，测试现有检测器的覆盖盲区

架构：
  Generator: z(latent) + x_clean(feature) → x_adv(feature)
  Discriminator: x → real/fake

推理时：给定一个良性特征向量 x_clean，生成 n 个对抗变体
"""

import logging
from typing import List

import torch
import torch.nn as nn
import torch.nn.functional as F

logger = logging.getLogger(__name__)

DEFAULT_FEATURE_DIM = len(__import__('features', fromlist=['FEATURE_NAMES']).FEATURE_NAMES)
DEFAULT_LATENT_DIM = 32


class AdversarialMalwareGAN(nn.Module):
    """
    对抗样本生成 GAN（特征空间版）
    输入：良性特征向量 + 随机噪声 → 输出：对抗变体
    """

    def __init__(self, feature_dim: int = DEFAULT_FEATURE_DIM,
                 latent_dim: int = DEFAULT_LATENT_DIM):
        super().__init__()
        self.feature_dim = feature_dim
        self.latent_dim = latent_dim

        # ── Generator ────────────────────────────────────────────
        # 输入：良性特征 + 随机噪声
        self.generator = nn.Sequential(
            nn.Linear(latent_dim + feature_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(inplace=True),

            nn.Linear(128, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(inplace=True),

            nn.Linear(128, feature_dim),
            nn.Tanh(),   # 输出到 [-1, 1]，推理时 clamp 到合理范围
        )

        # ── Discriminator ────────────────────────────────────────
        self.discriminator = nn.Sequential(
            nn.Linear(feature_dim, 64),
            nn.LeakyReLU(0.2, inplace=True),

            nn.Linear(64, 32),
            nn.LeakyReLU(0.2, inplace=True),

            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def forward(self, x_clean: torch.Tensor, z: torch.Tensor = None) -> torch.Tensor:
        """
        Args:
            x_clean: 良性特征 (batch, feature_dim)
            z:       随机噪声 (batch, latent_dim)，默认为 None（自动生成）
        Returns:
            x_adv:   对抗变体 (batch, feature_dim)
        """
        if z is None:
            z = torch.randn(x_clean.shape[0], self.latent_dim, device=x_clean.device)
        x_adv = self.generator(torch.cat([x_clean, z], dim=-1))
        return x_adv

    def generate_adversarial(self, x_clean: torch.Tensor, n_variants: int = 5,
                             eps: float = 0.15) -> List[torch.Tensor]:
        """
        为每个良性样本生成 n 个对抗变体，扰动幅度不超过 eps。

        Args:
            x_clean:  良性特征 (batch, feature_dim) 或 (feature_dim,)
            n_variants: 每个样本生成多少个变体
            eps:       最大扰动幅度（相对特征范围）
        Returns:
            列表，每个元素为 (batch, feature_dim) 张量
        """
        if x_clean.dim() == 1:
            x_clean = x_clean.unsqueeze(0)

        variants = []
        for _ in range(n_variants):
            z = torch.randn(x_clean.shape[0], self.latent_dim, device=x_clean.device)
            x_adv = self(x_clean, z)
            # clamp 到 [x_clean - eps, x_clean + eps]
            x_adv = torch.clamp(x_adv, x_clean - eps, x_clean + eps)
            variants.append(x_adv)
        return variants

    def adversarial_loss(self, x_adv: torch.Tensor, x_clean: torch.Tensor,
                         lam_adv: float = 1.0, lam_dist: float = 0.1) -> torch.Tensor:
        """
        对抗损失 = 判别器损失 + 距离约束（防止变体偏离原始太远）
        """
        d_out = self.discriminator(x_adv)
        # 希望判别器认为 adversarial 是 real
        adv_loss = F.binary_cross_entropy(d_out, torch.ones_like(d_out))
        # 距离约束：变体不能离原始太远
        dist_loss = F.mse_loss(x_adv, x_clean)
        return adv_loss + lam_dist * dist_loss

    def load_from_state_dict(self, path: str, device: str = 'cpu'):
        state = torch.load(path, map_location=device)
        if isinstance(state, dict) and 'model_state_dict' in state:
            self.load_state_dict(state['model_state_dict'])
        else:
            self.load_state_dict(state)
        logger.info("AdversarialGAN 模型已加载: %s", path)

    def save(self, path: str, epoch: int = 0, metrics: dict = None):
        obj = {
            'model_state_dict': self.state_dict(),
            'feature_dim': self.feature_dim,
            'latent_dim': self.latent_dim,
            'epoch': epoch,
            'metrics': metrics or {},
            'trained_at': __import__('datetime').datetime.now().isoformat(),
        }
        torch.save(obj, path)
        logger.info("AdversarialGAN 模型已保存: %s (epoch=%d)", path, epoch)
