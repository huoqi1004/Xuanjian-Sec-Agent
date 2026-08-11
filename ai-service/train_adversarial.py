# -*- coding: utf-8 -*-
"""
AdversarialGAN 对抗训练入口
用法:
    python train_adversarial.py \\
        --benign-dir  ./data/training_samples/benign \\
        --output models/adversarial_gan.pt \\
        --epochs 30 --batch-size 64
"""

import argparse
import glob
import json
import logging
import os
import sys
import time

import torch

sys.path.insert(0, os.path.dirname(__file__))

from gan.adversarial_gan import AdversarialMalwareGAN
from gan.preprocessor import FileFeaturePreprocessor
from gan.trainer import GANTrainer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('train_adversarial_gan')


def collect_files(directory: str) -> list:
    return [f for f in glob.glob(os.path.join(directory, '**', '*'), recursive=True)
            if os.path.isfile(f)]


def main():
    parser = argparse.ArgumentParser(description='AdversarialGAN 对抗训练脚本')
    parser.add_argument('--benign-dir', required=True, help='良性样本目录')
    parser.add_argument('--output', default='models/adversarial_gan.pt',
                        help='模型输出路径')
    parser.add_argument('--epochs', type=int, default=30, help='训练轮数')
    parser.add_argument('--batch-size', type=int, default=64, help='批大小')
    parser.add_argument('--lr', type=float, default=1e-3, help='学习率')
    parser.add_argument('--device', default='cpu', help='训练设备')
    parser.add_argument('--min-samples', type=int, default=20, help='最少样本数')
    args = parser.parse_args()

    args.benign_dir = os.path.abspath(args.benign_dir)
    args.output = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)

    benign_files = collect_files(args.benign_dir)
    logger.info("良性样本: %d 个（目录: %s）", len(benign_files), args.benign_dir)

    if len(benign_files) < args.min_samples:
        logger.error("样本不足 %d 个（当前 %d）", args.min_samples, len(benign_files))
        sys.exit(1)

    device = args.device if torch.cuda.is_available() else 'cpu'
    logger.info("使用设备: %s", device)

    gan = AdversarialMalwareGAN()
    trainer = GANTrainer(gan, device=device, lr_g=args.lr, lr_d=args.lr)

    logger.info("=" * 60)
    logger.info("开始 AdversarialGAN 训练")
    logger.info("  良性样本: %d | epochs: %d | batch: %d",
                len(benign_files), args.epochs, args.batch_size)
    logger.info("=" * 60)

    start = time.time()
    result = trainer.train_adversarial_gan(
        benign_paths=benign_files,
        malicious_paths=[],  # 当前阶段仅用良性样本训练生成器
        epochs=args.epochs,
        batch_size=args.batch_size,
        save_path=args.output,
    )
    elapsed = time.time() - start

    logger.info("=" * 60)
    logger.info("训练完成！耗时: %.1fs", elapsed)
    best_d_acc = float(result.get('best_d_acc', 0)) if result.get('best_d_acc') is not None else 0
    final_g = float(result.get('final_g_loss', 0)) if result.get('final_g_loss') is not None else 0
    final_d = float(result.get('final_d_loss', 0)) if result.get('final_d_loss') is not None else 0
    logger.info("  best_D_acc : %.4f", best_d_acc)
    logger.info("  final_G_loss: %.4f", final_g)
    logger.info("  final_D_loss: %.4f", final_d)
    logger.info("  模型路径   : %s", args.output)
    logger.info("=" * 60)

    # 保存指标
    metrics_path = args.output.replace('.pt', '_metrics.json')
    with open(metrics_path, 'w', encoding='utf-8') as f:
        json.dump({
            'best_d_acc': best_d_acc,
            'final_g_loss': final_g,
            'final_d_loss': final_d,
            'epochs': args.epochs,
            'batch_size': args.batch_size,
            'benign_samples': len(benign_files),
            'elapsed_seconds': round(elapsed, 1),
            'trained_at': __import__('datetime').datetime.now().isoformat(),
        }, f, ensure_ascii=False, indent=2)
    logger.info("指标已保存: %s", metrics_path)


if __name__ == '__main__':
    main()
