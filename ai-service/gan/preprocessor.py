# -*- coding: utf-8 -*-
"""
文件特征预处理模块
将二进制文件转为 GAN 输入特征向量，支持两种模式：
  - image:   将文件字节视为 28×28 灰度图像（784 维）
  - stats:   提取 14 维统计特征（与 features.py 对齐）
"""

import os
import logging
from typing import Literal

import numpy as np
import torch

from features import extract_features, FEATURE_NAMES

logger = logging.getLogger(__name__)


class FileFeaturePreprocessor:
    """文件特征预处理器"""

    def __init__(self, mode: Literal['image', 'stats'] = 'image', image_size: int = 784):
        """
        Args:
            mode:     'image' 使用字节图像模式，'stats' 使用 14 维统计模式
            image_size: 图像模式下的特征向量长度（默认 784 = 28×28）
        """
        self.mode = mode
        self.image_size = image_size

    def transform(self, file_path: str) -> torch.Tensor:
        """
        将文件转为 PyTorch 张量。

        Returns:
            Tensor of shape (1, image_size) for 'image' mode,
            or (1, 14) for 'stats' mode.
        """
        if not os.path.isfile(file_path):
            logger.warning("文件不存在，返回零张量: %s", file_path)
            return self._empty_tensor()

        file_size = os.path.getsize(file_path)
        max_read = min(file_size, 10 * 1024 * 1024)  # 最多读 10MB

        try:
            with open(file_path, 'rb') as f:
                raw = f.read(max_read)
        except OSError as e:
            logger.error("读取文件失败: %s, error=%s", file_path, e)
            return self._empty_tensor()

        if self.mode == 'image':
            return self._to_image_tensor(raw)
        else:
            return self._to_stats_tensor(file_path)

    def _to_image_tensor(self, raw: bytes) -> torch.Tensor:
        """
        将字节序列转为 28×28 灰度图像张量。
        - 文件不足 784 字节：末尾补零
        - 文件超过 784 字节：取前 784 字节
        """
        # 截取 / 填充至 image_size
        if len(raw) >= self.image_size:
            chunk = raw[:self.image_size]
        else:
            chunk = raw + b'\x00' * (self.image_size - len(raw))

        # 字节 → [0, 1] 浮点
        arr = np.frombuffer(chunk, dtype=np.uint8).astype(np.float32) / 255.0
        return torch.from_numpy(arr).unsqueeze(0)  # (1, 784)

    def _to_stats_tensor(self, file_path: str) -> torch.Tensor:
        """
        提取 14 维统计特征（与 features.py 对齐）。
        用于 AdversarialGAN 在特征空间生成对抗样本。
        """
        try:
            feats = extract_features(file_path)
            vec = np.array(
                [feats.get(name, 0.0) for name in FEATURE_NAMES],
                dtype=np.float32
            )
            # 归一化：size_log 和 counts 量纲差异大，做 min-max 到 [0,1]
            # 注意：此处不做全局归一化（无训练集统计量），直接原值输入
            return torch.from_numpy(vec).unsqueeze(0)  # (1, 14)
        except Exception as e:
            logger.warning("统计特征提取失败: %s, error=%s", file_path, e)
            return torch.zeros(1, len(FEATURE_NAMES), dtype=torch.float32)

    def _empty_tensor(self) -> torch.Tensor:
        """返回全零张量（文件不可读时的降级处理）"""
        size = self.image_size if self.mode == 'image' else len(FEATURE_NAMES)
        return torch.zeros(1, size, dtype=torch.float32)

    @property
    def input_dim(self) -> int:
        """返回当前模式的输入维度"""
        if self.mode == 'image':
            return self.image_size
        return len(FEATURE_NAMES)
