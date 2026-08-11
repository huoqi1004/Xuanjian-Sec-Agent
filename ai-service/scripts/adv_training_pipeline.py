# -*- coding: utf-8 -*-
"""
对抗训练 Pipeline — 自动化对抗训练流程

完整流程：
  1. 加载 GAN 模型（adversarial_gan.pt）
  2. 从良性样本生成对抗变体
  3. 将对抗变体注入训练集
  4. 重新训练/更新 malware_detector
  5. 评估对抗鲁棒性（accuracy on adversarial test set）
  6. 保存新版本模型

用法:
  python scripts/adv_training_pipeline.py \\
      --benign-dir ./data/training_samples/benign \\
      --gan-model models/adversarial_gan.pt \\
      --malware-model models/malware_detector.pkl \\
      --output models/malware_detector_v2.pkl \\
      --eps 0.15 --n-variants 5
"""

import argparse
import glob
import json
import logging
import os
import sys
import time
from typing import Dict, List, Optional

import numpy as np

# 确保 ai-service 在 Python path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from gan.adversarial_gan import AdversarialMalwareGAN
from gan.preprocessor import FileFeaturePreprocessor
from gan.metrics import compute_metrics
from malware_detector import MalwareDetector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('adv_training_pipeline')


def collect_files(directory: str) -> List[str]:
    return [f for f in glob.glob(os.path.join(directory, '**', '*'), recursive=True)
            if os.path.isfile(f)]


def main():
    parser = argparse.ArgumentParser(description='对抗训练 Pipeline')
    parser.add_argument('--benign-dir', required=True, help='良性样本目录')
    parser.add_argument('--gan-model', required=True, help='AdversarialGAN 模型路径')
    parser.add_argument('--malware-model', default=None, help='现有 malware_detector 路径')
    parser.add_argument('--output', required=True, help='输出模型路径')
    parser.add_argument('--eps', type=float, default=0.15, help='扰动幅度')
    parser.add_argument('--n-variants', type=int, default=5, help='每个样本生成变体数')
    parser.add_argument('--min-samples', type=int, default=20, help='最少样本数')
    parser.add_argument('--device', default='cpu', help='设备')
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)

    # 1. 加载 GAN 模型
    logger.info('=' * 60)
    logger.info('对抗训练 Pipeline 启动')
    logger.info('=' * 60)

    device = args.device
    gan = AdversarialMalwareGAN()
    gan.load_from_state_dict(args.gan_model, device=device)
    gan.eval()
    logger.info('AdversarialGAN 已加载: %s', args.gan_model)

    # 2. 收集良性样本
    benign_files = collect_files(args.benign_dir)
    logger.info('良性样本: %d 个（目录: %s）', len(benign_files), args.benign_dir)

    if len(benign_files) < args.min_samples:
        logger.error('样本不足 %d 个（当前 %d）', args.min_samples, len(benign_files))
        sys.exit(1)

    # 3. 特征提取 + 对抗生成
    preprocessor = FileFeaturePreprocessor(mode='stats')
    benign_features = []
    benign_labels = []  # 0 = 良性
    adversarial_features = []
    adversarial_labels = []  # 1 = 恶意（对抗样本）

    start_time = time.time()
    total_generated = 0

    for i, fpath in enumerate(benign_files):
        try:
            x_clean = preprocessor.transform(fpath)
            benign_features.append(x_clean.squeeze(0).numpy())
            benign_labels.append(0)

            # 生成对抗变体
            x_clean_t = x_clean.to(device)
            variants = gan.generate_adversarial(x_clean_t, n_variants=args.n_variants, eps=args.eps)

            for v in variants:
                adversarial_features.append(v.cpu().numpy().squeeze(0))
                adversarial_labels.append(1)
                total_generated += 1

        except Exception as e:
            logger.warning('样本处理失败: %s, error=%s', fpath, e)
            continue

        if (i + 1) % 20 == 0:
            logger.info('特征提取进度: %d/%d', i + 1, len(benign_files))

    elapsed = time.time() - start_time
    logger.info('特征提取完成: %d 良性 + %d 对抗 = %d 总计，耗时 %.1fs',
                len(benign_features), len(adversarial_features),
                len(benign_features) + len(adversarial_features), elapsed)

    # 4. 合并训练集
    all_features = np.array(benign_features + adversarial_features)
    all_labels = np.array(benign_labels + adversarial_labels)

    # 打乱顺序
    perm = np.random.permutation(len(all_features))
    all_features = all_features[perm]
    all_labels = all_labels[perm]

    logger.info('训练集: %d 良性 + %d 恶意 = %d 总计',
                len(benign_features), len(adversarial_features), len(all_features))

    # 5. 训练 MalwareDetector（如果有现有模型则继续训练）
    malware_detector = MalwareDetector()
    if args.malware_model and os.path.isfile(args.malware_model):
        malware_detector.load_model()
        logger.info('现有模型已加载: %s', args.malware_model)
    else:
        logger.info('无现有模型，将训练新模型')

    # 6. 使用 sklearn GBDT 重新训练
    try:
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.model_selection import train_test_split

        X_train, X_test, y_train, y_test = train_test_split(
            all_features, all_labels, test_size=0.2, random_state=42, stratify=all_labels
        )

        clf = GradientBoostingClassifier(
            n_estimators=100, max_depth=4, learning_rate=0.1,
            random_state=42
        )
        clf.fit(X_train, y_train)

        # 评估
        train_acc = clf.score(X_train, y_train)
        test_acc = clf.score(X_test, y_test)

        # 对抗鲁棒性评估
        adv_test = X_test[y_test == 1]
        benign_test = X_test[y_test == 0]
        adv_pred = clf.predict(adv_test)
        benign_pred = clf.predict(benign_test)
        adv_acc = (adv_pred == 1).mean() if len(adv_test) > 0 else 0
        benign_acc = (benign_pred == 0).mean() if len(benign_test) > 0 else 0

        logger.info('=' * 60)
        logger.info('训练结果:')
        logger.info('  训练集准确率: %.4f', train_acc)
        logger.info('  测试集准确率: %.4f', test_acc)
        logger.info('  对抗样本识别率: %.4f', adv_acc)
        logger.info('  良性样本正确率: %.4f', benign_acc)
        logger.info('=' * 60)

        # 7. 保存模型
        import joblib
        model_data = {
            'model': clf,
            'feature_names': ['size_log', 'entropy', 'printable_ratio',
                              'zero_ratio', 'pe_header', 'section_count',
                              'import_count', 'string_count', 'code_ratio',
                              'data_ratio', 'entry_entropy', 'section_entropy_max',
                              'pe_characteristics', 'file_type'],
            'version': '2.0.0-adv',
            'trained_at': __import__('datetime').datetime.now().isoformat(),
            'training_stats': {
                'total_samples': len(all_features),
                'benign_samples': len(benign_features),
                'adversarial_samples': len(adversarial_features),
                'train_acc': float(train_acc),
                'test_acc': float(test_acc),
                'adv_acc': float(adv_acc),
                'benign_acc': float(benign_acc),
                'eps': args.eps,
                'n_variants': args.n_variants,
            }
        }
        joblib.dump(model_data, args.output)
        logger.info('模型已保存: %s', args.output)

        # 8. 保存训练指标
        metrics_path = args.output.replace('.pkl', '_metrics.json')
        with open(metrics_path, 'w', encoding='utf-8') as f:
            json.dump(model_data['training_stats'], f, indent=2, ensure_ascii=False)
        logger.info('训练指标已保存: %s', metrics_path)

        # 9. 替换 malware_detector 的 model 属性（使内存中的检测器也更新）
        malware_detector.model = clf
        malware_detector.model_loaded = True
        malware_detector.model_version = '2.0.0-adv'

    except ImportError as e:
        logger.error('sklearn 未安装，无法训练 GBDT: %s', e)
        sys.exit(1)
    except Exception as e:
        logger.error('训练失败: %s', e)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
