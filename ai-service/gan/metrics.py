# -*- coding: utf-8 -*-
"""
GAN 评估指标模块
提供 AUC-ROC、F1、精确率、召回率等标准异常检测指标。
"""

import logging
from typing import Dict, List

import numpy as np
from sklearn.metrics import (
    roc_auc_score, f1_score, precision_score, recall_score,
    confusion_matrix, classification_report,
)

logger = logging.getLogger(__name__)


def compute_metrics(y_true: List[int], y_scores: List[float],
                    threshold: float = 0.5) -> Dict[str, float]:
    """
    计算异常检测指标。

    Args:
        y_true:    真实标签（0=良性，1=异常）
        y_scores:  模型预测分数（越高越异常）
        threshold: 分类阈值（默认 0.5）

    Returns:
        {
            'auc_roc': float,
            'f1': float, 'precision': float, 'recall': float,
            'accuracy': float, 'tn': int, 'fp': int, 'fn': int, 'tp': int,
            'threshold': float,
        }
    """
    y_pred = [1 if s >= threshold else 0 for s in y_scores]

    auc = roc_auc_score(y_true, y_scores) if len(set(y_true)) > 1 else 0.0
    f1 = f1_score(y_true, y_pred, zero_division=0)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    acc = float(np.mean(np.array(y_pred) == np.array(y_true))) if y_true else 0.0

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

    return {
        'auc_roc': round(float(auc), 4),
        'f1': round(float(f1), 4),
        'precision': round(float(prec), 4),
        'recall': round(float(rec), 4),
        'accuracy': round(float(acc), 4),
        'tn': int(tn), 'fp': int(fp),
        'fn': int(fn), 'tp': int(tp),
        'threshold': threshold,
    }


def find_optimal_threshold(y_true: List[int], y_scores: List[float],
                           step: float = 0.01) -> float:
    """
    在 [0, 1] 范围内以 step 步进搜索最优 F1 阈值。

    Returns:
        最优阈值（浮点数）
    """
    best_f1 = 0.0
    best_t = 0.5
    thresholds = [i * step for i in range(int(1.0 / step) + 1)]

    for t in thresholds:
        y_pred = [1 if s >= t else 0 for s in y_scores]
        f1 = f1_score(y_true, y_pred, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_t = t

    logger.info("最优阈值: %.4f (F1=%.4f)", best_t, best_f1)
    return best_t


def format_report(metrics: Dict[str, float]) -> str:
    """将指标字典格式化为可读字符串"""
    lines = [
        f"  AUC-ROC : {metrics.get('auc_roc', 'N/A')}",
        f"  F1      : {metrics.get('f1', 'N/A')}",
        f"  Precision: {metrics.get('precision', 'N/A')}",
        f"  Recall  : {metrics.get('recall', 'N/A')}",
        f"  Accuracy: {metrics.get('accuracy', 'N/A')}",
        f"  TN={metrics.get('tn',0)} FP={metrics.get('fp',0)} "
        f"FN={metrics.get('fn',0)} TP={metrics.get('tp',0)}",
    ]
    return '\n'.join(lines)
