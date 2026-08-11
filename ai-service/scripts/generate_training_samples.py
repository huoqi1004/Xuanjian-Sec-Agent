# -*- coding: utf-8 -*-
"""
生成合成良性训练样本，用于 AnomalyGAN 初始化训练。
用法: python scripts/generate_training_samples.py [--n 50] [--output ./data/training_samples/benign]
"""

import os
import sys
import argparse
import random
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def generate_pe_like(path: str, size: int):
    """生成类 PE 结构的随机文件（模拟 Windows exe/dll）"""
    with open(path, 'wb') as f:
        # DOS header
        f.write(b'MZ' + os.urandom(58))
        # PE signature
        f.write(struct.pack('<I', 0x00004550))  # 'PE\x00\x00'
        # COFF header (simplified)
        f.write(struct.pack('<HHIIIH',
            0x8664,      # Machine: x64
            random.randint(1, 50),   # NumberOfSections
            0x5F000000,  # TimeDateStamp
            0,          # PointerToSymbolTable
            0,          # NumberOfSymbols
            random.choice([0x0022, 0x0002, 0x0102]),  # Characteristics
        ))
        # 填充到目标大小
        remaining = max(0, size - f.tell())
        f.write(os.urandom(remaining))


def generate_random_binary(path: str, size: int):
    """生成纯随机二进制文件"""
    with open(path, 'wb') as f:
        f.write(os.urandom(size))


def generate_text_like(path: str, size: int):
    """生成类文本文件（混合可打印字符）"""
    chars = (
        b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        b'abcdefghijklmnopqrstuvwxyz'
        b'0123456789 !@#$%^&*()_+-=[]{}|;:\'",.<>?/'
        b'\t\n\r'
    )
    with open(path, 'wb') as f:
        while f.tell() < size:
            f.write(bytes([random.choice(chars)]))


def main():
    parser = argparse.ArgumentParser(description='生成合成良性训练样本')
    parser.add_argument('--n', type=int, default=50, help='样本数量')
    parser.add_argument('--output', default='./data/training_samples/benign',
                        help='输出目录')
    parser.add_argument('--min-size', type=int, default=256, help='最小文件大小')
    parser.add_argument('--max-size', type=int, default=4096, help='最大文件大小')
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    generators = [generate_pe_like, generate_random_binary, generate_text_like]
    created = 0

    for i in range(args.n):
        size = random.randint(args.min_size, args.max_size)
        gen = random.choice(generators)
        ext = '.exe' if gen == generate_pe_like else '.bin'
        path = os.path.join(args.output, f'benign_{i:04d}{ext}')
        gen(path, size)
        created += 1
        if (i + 1) % 10 == 0:
            print(f'  已生成 {i + 1}/{args.n} 个样本...')

    print(f'✓ 训练样本已生成: {created} 个文件 → {args.output}')
    print(f'  文件大小范围: {args.min_size}~{args.max_size} bytes')


if __name__ == '__main__':
    main()
