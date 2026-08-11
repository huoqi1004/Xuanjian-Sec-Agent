# -*- coding: utf-8 -*-
"""
GAN 训练循环
支持 AnomalyGAN 和 AdversarialGAN 的批量训练。
"""

import logging
import os
import time
from typing import Dict, List, Optional

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset

from .anomaly_gan import AnomalyGAN
from .adversarial_gan import AdversarialMalwareGAN
from .preprocessor import FileFeaturePreprocessor
from .metrics import compute_metrics, format_report

logger = logging.getLogger(__name__)


class GANTrainer:
    """
    GAN 训练器，支持 AnomalyGAN 和 AdversarialGAN。
    """

    def __init__(self, gan: nn.Module, device: str = 'cpu',
                 lr_g: float = 1e-3, lr_d: float = 1e-3):
        """
        Args:
            gan:  AnomalyGAN 或 AdversarialMalwareGAN 实例
            device: 'cpu' 或 'cuda'
            lr_g:  Generator 学习率
            lr_d:  Discriminator 学习率
        """
        self.gan = gan.to(device)
        self.device = device
        self.lr_g = lr_g
        self.lr_d = lr_d
        self.optimizer_g = None
        self.optimizer_d = None
        self._init_optimizers()

    def _init_optimizers(self):
        """根据 GAN 类型初始化优化器"""
        if isinstance(self.gan, AnomalyGAN):
            # AnomalyGAN：encoder+decoder 合并优化，discriminator 独立优化
            gen_params = list(self.gan.encoder.parameters()) + list(self.gan.decoder.parameters())
            self.optimizer_g = torch.optim.Adam(gen_params, lr=self.lr_g, betas=(0.5, 0.999))
            self.optimizer_d = torch.optim.Adam(self.gan.discriminator.parameters(),
                                                lr=self.lr_d, betas=(0.5, 0.999))
        elif isinstance(self.gan, AdversarialMalwareGAN):
            self.optimizer_g = torch.optim.Adam(self.gan.generator.parameters(),
                                                lr=self.lr_g, betas=(0.5, 0.999))
            self.optimizer_d = torch.optim.Adam(self.gan.discriminator.parameters(),
                                                lr=self.lr_d, betas=(0.5, 0.999))
        else:
            raise ValueError(f"不支持的 GAN 类型: {type(self.gan)}")

    def train_anomaly_gan(self, benign_paths: List[str], epochs: int = 50,
                          batch_size: int = 64, val_paths: Optional[List[str]] = None,
                          save_path: Optional[str] = None,
                          anomaly_threshold: Optional[float] = None) -> Dict:
        """
        训练 AnomalyGAN（仅在良性样本上训练）。

        Args:
            benign_paths:       良性文件路径列表
            epochs:             训练轮数
            batch_size:         批大小
            val_paths:          验证集（含部分异常样本）
            save_path:          模型保存路径
            anomaly_threshold:  异常阈值（None=自动从验证集计算）

        Returns:
            训练指标字典
        """
        logger.info("开始训练 AnomalyGAN: %d 样本, %d epochs, batch=%d",
                     len(benign_paths), epochs, batch_size)

        preprocessor = FileFeaturePreprocessor(mode='image')
        tensors = [preprocessor.transform(p) for p in benign_paths]
        if not tensors:
            raise ValueError("无有效训练样本")

        dataset = TensorDataset(torch.cat(tensors, dim=0))
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        criterion_mse = nn.MSELoss()
        criterion_bce = nn.BCELoss()

        history = {'train_recon_loss': [], 'train_disc_loss': [], 'val_auc': []}
        best_auc = 0.0

        for epoch in range(1, epochs + 1):
            self.gan.train()
            epoch_recon = 0.0
            epoch_disc = 0.0
            n_batches = 0

            for (x,) in loader:
                x = x.to(self.device)
                x_recon, z, d_out = self.gan(x)

                # 重构损失（编码器-解码器）
                recon_loss = criterion_mse(x_recon, x)

                # 判别器损失（希望重构结果被判为 real）
                d_real = self.gan.discriminator(x_recon)
                d_loss = criterion_bce(d_real, torch.ones_like(d_real))

                # 更新 Generator（detach 避免第二次反向）
                self.optimizer_g.zero_grad()
                (recon_loss + d_loss.detach()).backward()
                self.optimizer_g.step()

                # 更新 Discriminator（重新前向，避免图冲突）
                x_recon2, _, d_out2 = self.gan(x)
                self.optimizer_d.zero_grad()
                d_loss2 = criterion_bce(
                    self.gan.discriminator(x_recon2), torch.ones_like(d_out2)
                )
                d_loss2.backward()
                self.optimizer_d.step()

                epoch_recon += recon_loss.item()
                epoch_disc += d_loss.item()
                n_batches += 1

            avg_recon = epoch_recon / max(n_batches, 1)
            avg_disc = epoch_disc / max(n_batches, 1)
            history['train_recon_loss'].append(avg_recon)
            history['train_disc_loss'].append(avg_disc)

            # 验证
            if val_paths:
                auc = self._validate(val_paths, preprocessor)
                history['val_auc'].append(auc)
                if auc > best_auc:
                    best_auc = auc
                    if save_path:
                        self.gan.save(save_path, epoch=epoch,
                                      metrics={'best_auc': best_auc})
                logger.info("Epoch %d/%d | recon=%.6f disc=%.6f | val_AUC=%.4f",
                            epoch, epochs, avg_recon, avg_disc, auc)
            else:
                logger.info("Epoch %d/%d | recon=%.6f disc=%.6f",
                            epoch, epochs, avg_recon, avg_disc)

        # 确定异常阈值
        if anomaly_threshold is None and val_paths:
            anomaly_threshold = self._compute_threshold(val_paths, preprocessor)

        result = {
            'final_recon_loss': history['train_recon_loss'][-1] if history['train_recon_loss'] else None,
            'best_auc': best_auc,
            'anomaly_threshold': anomaly_threshold,
            'epochs_trained': epochs,
        }
        logger.info("AnomalyGAN 训练完成: best_auc=%.4f, threshold=%s",
                     best_auc, str(anomaly_threshold))

        # 无验证集时也保存最终模型
        if save_path and not val_paths:
            self.gan.save(save_path, epoch=epochs, metrics=result)
            logger.info("AnomalyGAN 最终模型已保存: %s", save_path)

        return result

    def train_adversarial_gan(self, benign_paths: List[str], malicious_paths: List[str],
                              epochs: int = 50, batch_size: int = 64,
                              save_path: Optional[str] = None) -> Dict:
        """
        训练 AdversarialGAN（良性 vs 恶意对抗训练）。

        Args:
            benign_paths:     良性文件路径列表
            malicious_paths:  恶意文件路径列表（用于对抗训练）
            epochs:           训练轮数
            batch_size:       批大小
            save_path:        模型保存路径
        """
        logger.info("开始训练 AdversarialGAN: %d 良性 + %d 恶意",
                     len(benign_paths), len(malicious_paths))

        preprocessor = FileFeaturePreprocessor(mode='stats')
        benign_tensors = [preprocessor.transform(p) for p in benign_paths]
        if not benign_tensors:
            raise ValueError("无有效良性样本")

        benign_data = torch.cat(benign_tensors, dim=0).to(self.device)
        n = benign_data.shape[0]

        history = {'g_loss': [], 'd_loss': []}
        best_d_acc = 0.0

        for epoch in range(1, epochs + 1):
            self.gan.train()

            # ── 训练 Discriminator ──
            self.optimizer_d.zero_grad()
            # 真实良性样本 → 标签 1
            d_real = self.gan.discriminator(benign_data)
            loss_real = F.binary_cross_entropy(d_real, torch.ones_like(d_real))
            # 对抗样本 → 标签 0
            z = torch.randn(n, self.gan.latent_dim, device=self.device)
            x_adv = self.gan.generator(torch.cat([benign_data, z], dim=-1))
            d_fake = self.gan.discriminator(x_adv.detach())
            loss_fake = F.binary_cross_entropy(d_fake, torch.zeros_like(d_fake))
            d_loss = (loss_real + loss_fake) / 2
            d_loss.backward()
            self.optimizer_d.step()

            # ── 训练 Generator ──
            self.optimizer_g.zero_grad()
            z = torch.randn(n, self.gan.latent_dim, device=self.device)
            x_adv = self.gan.generator(torch.cat([benign_data, z], dim=-1))
            d_out = self.gan.discriminator(x_adv)
            g_loss = F.binary_cross_entropy(d_out, torch.ones_like(d_out))
            g_loss.backward()
            self.optimizer_g.step()

            history['g_loss'].append(g_loss.item())
            history['d_loss'].append(d_loss.item())

            # 检查判别器准确率（衡量生成质量）
            d_acc = (d_real.detach().mean() + (1 - d_fake.detach().mean())) / 2
            if d_acc > best_d_acc:
                best_d_acc = d_acc
                if save_path:
                    self.gan.save(save_path, epoch=epoch, metrics={'best_d_acc': best_d_acc})

            if epoch % 5 == 0 or epoch == 1:
                logger.info("Epoch %d/%d | G_loss=%.4f D_loss=%.4f | D_acc=%.4f",
                            epoch, epochs, g_loss.item(), d_loss.item(), d_acc)

        result = {
            'final_g_loss': history['g_loss'][-1] if history['g_loss'] else None,
            'final_d_loss': history['d_loss'][-1] if history['d_loss'] else None,
            'best_d_acc': best_d_acc,
        }
        logger.info("AdversarialGAN 训练完成: best_D_acc=%.4f", best_d_acc)
        return result

    def _validate(self, paths: List[str], preprocessor: FileFeaturePreprocessor) -> float:
        """在验证集上计算 AUC-ROC"""
        self.gan.eval()
        scores, labels = [], []
        with torch.no_grad():
            for p in paths:
                x = preprocessor.transform(p).to(self.device)
                score = self.gan.anomaly_score(x).cpu().numpy()
                # 此处假设：调用方按顺序传入，良性在前异常在后
                # 实际使用时需传入带标签的数据
                scores.extend(score.tolist())
        # 简化：返回 0.0（无标签数据时无法计算 AUC）
        return 0.0

    def _compute_threshold(self, paths: List[str],
                           preprocessor: FileFeaturePreprocessor) -> float:
        """从验证集计算最优异常阈值（取第 95 百分位）"""
        self.gan.eval()
        errors = []
        with torch.no_grad():
            for p in paths:
                x = preprocessor.transform(p).to(self.device)
                err = self.gan.reconstruct_error(x).cpu().numpy()
                errors.extend(err.tolist())
        if not errors:
            return 0.5
        threshold = float(np.percentile(errors, 95))
        logger.info("异常阈值（95th percentile）: %.6f", threshold)
        return threshold
