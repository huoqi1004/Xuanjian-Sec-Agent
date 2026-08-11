# -*- coding: utf-8 -*-
"""
AnomalyGAN — 基于重构误差的文件异常检测模型

架构：
  Encoder(input_dim) → Bottleneck(latent_dim) → Decoder(latent_dim) → Reconstructed
  Discriminator(Reconstructed) → Real/Fake score

训练目标：
  - 仅在良性样本上训练，学习正常文件分布
  - 推理时计算重构误差（MSE），误差越大 → 越异常
  - 辅助判别器提供额外异常分数（对重构结果打分）

使用方式：
  model = AnomalyGAN(input_dim=784, latent_dim=64)
  recon, z, d_out = model(x)
  recon_error = F.mse_loss(x, recon)
"""

import logging
from typing import Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F

logger = logging.getLogger(__name__)

DEFAULT_INPUT_DIM = 784   # 28×28 灰度图像模式
DEFAULT_LATENT_DIM = 64


class AnomalyGAN(nn.Module):
    """
    异常检测 GAN
    编码器-解码器学习良性文件分布，判别器辅助判断重构结果合理性。
    """

    def __init__(self, input_dim: int = DEFAULT_INPUT_DIM, latent_dim: int = DEFAULT_LATENT_DIM):
        super().__init__()
        self.input_dim = input_dim
        self.latent_dim = latent_dim

        # ── Encoder ──────────────────────────────────────────────
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(inplace=True),
            nn.Dropout(0.2),

            nn.Linear(512, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(inplace=True),
            nn.Dropout(0.2),

            nn.Linear(256, latent_dim),
            nn.Tanh(),
        )

        # ── Decoder ──────────────────────────────────────────────
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(inplace=True),

            nn.Linear(256, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(inplace=True),

            nn.Linear(512, input_dim),
            nn.Sigmoid(),   # 输入已归一化到 [0,1]
        )

        # ── Discriminator（PatchGAN 简化版：直接对重构向量打分）──
        self.discriminator = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.LeakyReLU(0.2, inplace=True),

            nn.Linear(256, 128),
            nn.LeakyReLU(0.2, inplace=True),

            nn.Linear(128, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Args:
            x: 输入张量 (batch, input_dim)，值域 [0, 1]
        Returns:
            x_recon: 重构输出 (batch, input_dim)
            z:       隐空间编码 (batch, latent_dim)
            d_out:   判别器输出 (batch, 1)，表示重构结果"真实性"
        """
        z = self.encoder(x)
        x_recon = self.decoder(z)
        d_out = self.discriminator(x_recon)
        return x_recon, z, d_out

    def reconstruct_error(self, x: torch.Tensor) -> torch.Tensor:
        """
        计算逐样本重构误差（MSE），用于异常评分。
        返回值：(batch,) 每个样本的重构误差标量。
        """
        x_recon, _, _ = self.forward(x)
        return F.mse_loss(x_recon, x, reduction='none').mean(dim=1)  # (batch,)

    def anomaly_score(self, x: torch.Tensor, recon_weight: float = 0.7,
                      disc_weight: float = 0.3) -> torch.Tensor:
        """
        综合异常分数 = recon_weight × 重构误差 + disc_weight × (1 - D输出)
        分数越高 → 越异常。复用 reconstruct_error 避免重复 forward。
        """
        x_recon, _, d_out = self.forward(x)
        # 复用 reconstruct_error 的重构误差计算，避免重复 forward
        recon_err = F.mse_loss(x_recon, x, reduction='none').mean(dim=1)  # (batch,)
        # D 输出越接近 0 → 重构越不像真实数据 → 越异常
        disc_anomaly = (1.0 - d_out.squeeze(-1))  # (batch,)

        score = recon_weight * recon_err + disc_weight * disc_anomaly
        return score

    def load_from_state_dict(self, path: str, device: str = 'cpu'):
        """加载训练好的模型状态"""
        state = torch.load(path, map_location=device)
        if isinstance(state, dict) and 'model_state_dict' in state:
            self.load_state_dict(state['model_state_dict'])
        else:
            self.load_state_dict(state)
        logger.info("AnomalyGAN 模型已加载: %s", path)

    def save(self, path: str, epoch: int = 0, metrics: dict = None):
        """保存模型（含元数据）"""
        obj = {
            'model_state_dict': self.state_dict(),
            'input_dim': self.input_dim,
            'latent_dim': self.latent_dim,
            'epoch': epoch,
            'metrics': metrics or {},
            'trained_at': __import__('datetime').datetime.now().isoformat(),
        }
        torch.save(obj, path)
        logger.info("AnomalyGAN 模型已保存: %s (epoch=%d)", path, epoch)
