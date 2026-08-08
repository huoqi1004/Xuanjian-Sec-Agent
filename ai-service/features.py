# -*- coding: utf-8 -*-
"""
真实静态特征提取模块
用于恶意代码检测模型训练与推理的特征工程：
- PE 文件结构特征（节区熵、节区比例、导入表、COFF 属性）
- 字节级统计特征（整体熵、可打印字符比例、零字节比例）
- 字符串特征（可疑模式计数）

依赖: 仅标准库 + numpy（不依赖 pefile 等第三方解析库）
"""

import os
import re
import math
import struct
import logging
from collections import Counter

import numpy as np

logger = logging.getLogger(__name__)

# 可疑字符串/行为模式（与检测规则共用）
SUSPICIOUS_PATTERNS = [
    rb'powershell\s+-enc', rb'cmd\.exe\s+/c', rb'WScript\.Shell',
    rb'CreateObject\s*\(\s*["\']WScript\.Shell', rb'RegRead|RegWrite|RegDelete',
    rb'XMLHTTP|WinHttp', rb'base64_decode|eval\s*\(|assert\s*\(',
    rb'process\.inject|memory\.write', rb'keylog|GetAsyncKeyState',
    rb'persistence|schtasks|RunAs', rb'crypto|mining|stratum',
    rb'nc\s+-[el]|ncat|netcat', rb'/etc/shadow|/etc/passwd',
    rb'disable\s*(antivirus|defender|firewall)', rb'shellcode|nop\s*sled',
    rb'GetDesktopWindow|screen\s*capture', rb'UAC\s*bypass',
]

# 常见恶意 DLL 名称特征（PE 导入表）
SUSPICIOUS_DLL_KEYWORDS = [
    b'kernel32', b'advapi32', b'user32', b'ntdll', b'ws2_32', b'wininet',
    b'urlmon', b'crypt32', b'psapi', b'wtsapi', b'iphlpapi', b'netapi32',
]

FEATURE_NAMES = [
    'size_log',              # 文件大小对数
    'entropy_total',         # 整体熵值
    'is_pe',                 # 是否为 PE 文件
    'pe_section_count',      # PE 节区数量
    'pe_entropy_mean',       # PE 节区平均熵
    'pe_entropy_max',        # PE 节区最大熵
    'pe_entropy_std',        # PE 节区熵标准差
    'pe_section_ratio_min',  # 节区原始大小/虚拟大小 最小比值
    'pe_imports_dll_count',  # 导入 DLL 数量
    'pe_suspicious_dlls',    # 可疑 DLL 命中数
    'printable_ratio',       # 可打印字符比例
    'null_byte_ratio',       # 零字节比例
    'suspicious_patterns',   # 可疑字符串模式命中数
    'embedded_signatures',   # 嵌入文件签名数（ZIP/PDF/PNG 等）
]

EMBEDDED_SIGNATURES = [b'PK\x03\x04', b'%PDF', b'\x89PNG', b'GIF8', b'\xff\xd8\xff', b'\x7fELF', b'<!DOCTYPE html']


def _calculate_entropy(data: bytes) -> float:
    """计算字节序列的香农熵"""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _parse_pe(data: bytes) -> dict:
    """
    手工解析 PE 文件核心结构（不依赖第三方库）
    返回节区信息与导入 DLL 列表；非 PE 文件返回 None
    """
    if len(data) < 0x40 or data[:2] != b'MZ':
        return None

    e_lfanew = struct.unpack('<I', data[0x3c:0x40])[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        return None

    try:
        coff = e_lfanew + 4
        machine, num_sections = struct.unpack('<HH', data[coff:coff + 4])
        optional_size = struct.unpack('<H', data[coff + 16:coff + 18])[0]
        characteristics = struct.unpack('<H', data[coff + 18:coff + 20])[0]

        section_table_offset = coff + 20 + optional_size
        if section_table_offset + num_sections * 40 > len(data):
            num_sections = max(0, (len(data) - section_table_offset) // 40)

        sections = []
        for i in range(num_sections):
            off = section_table_offset + i * 40
            if off + 40 > len(data):
                break
            # IMAGE_SECTION_HEADER
            raw_size, raw_ptr = struct.unpack('<II', data[off + 8:off + 16])
            virtual_size = struct.unpack('<I', data[off + 8 + 8:off + 8 + 12])[0]
            section_data = data[raw_ptr:raw_ptr + raw_size] if raw_ptr and raw_size else b''
            sections.append({
                'entropy': _calculate_entropy(section_data) if section_data else 0.0,
                'raw_size': raw_size,
                'virtual_size': virtual_size,
            })

        # 导入表 DLL 名称（搜索 .rdata 附近，简化：全局搜索常见 DLL 名）
        imports = []
        for kw in SUSPICIOUS_DLL_KEYWORDS:
            if data.find(kw) != -1:
                imports.append(kw)

        return {
            'machine': machine,
            'characteristics': characteristics,
            'sections': sections,
            'imports': imports,
        }
    except (struct.error, IndexError):
        return None


def extract_features(file_path: str) -> dict:
    """
    提取文件真实静态特征向量
    返回 dict: 特征名 -> 数值（与 FEATURE_NAMES 对齐）
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read(min(os.path.getsize(file_path), 50 * 1024 * 1024))
    except OSError as e:
        logger.error(f'特征提取: 读取文件失败 {file_path}: {e}')
        return {name: 0.0 for name in FEATURE_NAMES}

    total_entropy = _calculate_entropy(data)
    pe = _parse_pe(data)

    # PE 特征
    if pe:
        section_entropies = [s['entropy'] for s in pe['sections']] if pe['sections'] else [0.0]
        section_ratios = []
        for s in pe['sections']:
            if s['virtual_size'] > 0:
                section_ratios.append(min(1.0, s['raw_size'] / s['virtual_size']))
        imports = pe['imports']
        suspicious_dlls = sum(1 for kw in SUSPICIOUS_DLL_KEYWORDS if kw in imports)
    else:
        section_entropies = [0.0]
        section_ratios = [0.0]
        imports = []
        suspicious_dlls = 0

    # 字节统计
    n = max(len(data), 1)
    printable = sum(1 for b in data[:200000] if 32 <= b <= 126 or b in (9, 10, 13))
    null_bytes = data.count(b'\x00')

    # 字符串模式
    suspicious_count = 0
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, data, re.IGNORECASE):
            suspicious_count += 1

    # 嵌入签名
    embedded = sum(1 for sig in EMBEDDED_SIGNATURES if data.find(sig, 1) != -1)

    features = {
        'size_log': round(math.log2(n), 4) if n > 1 else 0.0,
        'entropy_total': round(total_entropy, 4),
        'is_pe': 1 if pe else 0,
        'pe_section_count': len(pe['sections']) if pe else 0,
        'pe_entropy_mean': round(float(np.mean(section_entropies)), 4),
        'pe_entropy_max': round(float(np.max(section_entropies)), 4),
        'pe_entropy_std': round(float(np.std(section_entropies)), 4),
        'pe_section_ratio_min': round(float(min(section_ratios)), 4) if section_ratios else 0.0,
        'pe_imports_dll_count': len(imports),
        'pe_suspicious_dlls': suspicious_dlls,
        'printable_ratio': round(printable / min(n, 200000), 4),
        'null_byte_ratio': round(null_bytes / n, 4),
        'suspicious_patterns': suspicious_count,
        'embedded_signatures': embedded,
    }
    return features


def feature_vector(features: dict) -> np.ndarray:
    """将特征 dict 转为模型输入向量（按 FEATURE_NAMES 固定顺序）"""
    return np.array([[features.get(name, 0.0) for name in FEATURE_NAMES]], dtype=np.float32)
