# -*- coding: utf-8 -*-
"""
AnomalyGAN 训练入口
用法:
    python train_anomaly_gan.py \\
        --train-dir ./data/training_samples/benign \\
        --val-dir ./data/training_samples/mixed \\
        --output models/anomaly_gan.pt \\
        --epochs 50 --batch-size 64
"""

import argparse
import logging
import os
import sys
import glob

import torch

# 确保 ai-service 在 Python path 中
sys.path.insert(0, os.path.dirname(__file__))

from gan.anomaly_gan import AnomalyGAN
from gan.preprocessor import FileFeaturePreprocessor
from gan.trainer import GANTrainer
from gan.metrics import compute_metrics, format_report

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('train_anomaly_gan')


def collect_files(directory: str, recursive: bool = True) -> list:
    """收集目录下所有文件路径"""
    pattern = '**/*' if recursive else '*'
    flags = {'recursive': True} if recursive else {}
    files = glob.glob(os.path.join(directory, pattern), **flags)
    return [f for f in files if os.path.isfile(f)]


def main():
    parser = argparse.ArgumentParser(description='AnomalyGAN 训练脚本')
    parser.add_argument('--train-dir', required=True,
                        help='良性训练样本目录')
    parser.add_argument('--val-dir', default=None,
                        help='验证集目录（可选，支持良性+异常混合）')
    parser.add_argument('--output', default='models/anomaly_gan.pt',
                        help='模型输出路径')
    parser.add_argument('--epochs', type=int, default=50,
                        help='训练轮数（默认 50）')
    parser.add_argument('--batch-size', type=int, default=64,
                        help='批大小（默认 64）')
    parser.add_argument('--lr', type=float, default=1e-3,
                        help='学习率（默认 1e-3）')
    parser.add_argument('--input-dim', type=int, default=784,
                        help='输入维度（默认 784 = 28×28）')
    parser.add_argument('--latent-dim', type=int, default=64,
                        help='隐空间维度（默认 64）')
    parser.add_argument('--device', default='cpu',
                        help='训练设备（cpu / cuda）')
    parser.add_argument('--min-samples', type=int, default=20,
                        help='最少样本数（默认 20）')
    args = parser.parse_args()

    # 绝对路径
    args.train_dir = os.path.abspath(args.train_dir)
    if args.val_dir:
        args.val_dir = os.path.abspath(args.val_dir)
    args.output = os.path.abspath(args.output)

    # 创建输出目录
    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)

    # 收集训练样本
    train_files = collect_files(args.train_dir)
    logger.info("训练样本: %d 个文件（目录: %s）", len(train_files), args.train_dir)

    if len(train_files) < args.min_samples:
        logger.error("样本不足 %d 个（当前 %d），请检查目录或减小 --min-samples",
                      args.min_samples, len(train_files))
        sys.exit(1)

    # 收集验证样本（如有）
    val_files = collect_files(args.val_dir) if args.val_dir else None
    if val_files:
        logger.info("验证样本: %d 个文件（目录: %s）", len(val_files), args.val_dir)

    # 初始化模型
    device = args.device if torch.cuda.is_available() else 'cpu'
    logger.info("使用设备: %s", device)

    gan = AnomalyGAN(input_dim=args.input_dim, latent_dim=args.latent_dim)
    trainer = GANTrainer(gan, device=device, lr_g=args.lr, lr_d=args.lr)

    # 开始训练
    logger.info("=" * 60)
    logger.info("开始 AnomalyGAN 训练")
    logger.info("  训练样本: %d | 验证样本: %s | epochs: %d | batch: %d",
                len(train_files), len(val_files) if val_files else 'N/A',
                args.epochs, args.batch_size)
    logger.info("=" * 60)

    start = __import__('time').time()
    result = trainer.train_anomaly_gan(
        benign_paths=train_files,
        epochs=args.epochs,
        batch_size=args.batch_size,
        val_paths=val_files,
        save_path=args.output,
    )
    elapsed = __import__('time').time() - start

    # 输出最终指标
    logger.info("=" * 60)
    logger.info("训练完成！耗时: %.1fs", elapsed)
    best_auc = float(result.get('best_auc', 0)) if result.get('best_auc') is not None else 0
    final_recon = float(result.get('final_recon_loss', 0)) if result.get('final_recon_loss') is not None else 0
    threshold = result.get('anomaly_threshold')
    threshold_str = f'{threshold:.6f}' if threshold is not None else 'auto'
    logger.info("  best_auc    : %.4f", best_auc)
    logger.info("  final_recon : %.6f", final_recon)
    logger.info("  threshold   : %s", threshold_str)
    logger.info("  模型路径    : %s", args.output)
    logger.info("=" * 60)

    # 保存训练指标
    metrics_path = args.output.replace('.pt', '_metrics.json')
    import json as _json
    with open(metrics_path, 'w', encoding='utf-8') as f:
        _json.dump({
            'best_auc': best_auc,
            'final_recon_loss': final_recon,
            'anomaly_threshold': threshold,
            'epochs': args.epochs,
            'batch_size': args.batch_size,
            'input_dim': args.input_dim,
            'latent_dim': args.latent_dim,
            'train_samples': len(train_files),
            'val_samples': len(val_files) if val_files else 0,
            'elapsed_seconds': round(elapsed, 1),
            'trained_at': __import__('datetime').datetime.now().isoformat(),
        }, f, ensure_ascii=False, indent=2)
    logger.info("指标已保存: %s", metrics_path)


if __name__ == '__main__':
    main()
