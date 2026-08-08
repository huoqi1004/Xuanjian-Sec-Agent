# -*- coding: utf-8 -*-
"""
投毒检测器
检测对象（明确定义）:
  1. 模型权重投毒: 加载/分发的模型文件（.pkl/.pt/.safetensors/.onnx/.bin）包含后门或数值异常
  2. 训练数据投毒: 数据集文件（JSON/CSV）含隐藏后门触发器、标签篡改、嵌入的对抗样本
  3. 供应链投毒: 分发包（exe/zip/脚本）含隐藏的可执行载荷、双重扩展名欺骗

方法: 确定性统计规则引擎（熵/模式/字节统计/元数据/内容分析），
      不依赖随机/合成数据训练的模型。检测依据均为可解释的异常规则。
"""

import os
import re
import math
import logging
from collections import Counter

import numpy as np

logger = logging.getLogger(__name__)

# 模型权重文件扩展名（专项检测对象）
MODEL_FILE_EXTS = ('.pkl', '.pt', '.pth', '.safetensors', '.onnx', '.bin', '.h5', '.joblib')

# 数据集文件扩展名
DATASET_FILE_EXTS = ('.json', '.csv', '.jsonl', '.parquet', '.npy', '.npz')

# 已知可解释的投毒标记模式（训练数据投毒）
POISONING_PATTERNS = [
    # 标签篡改
    (rb'label\s*=\s*["\']*(clean|benign|safe)["\']*', '可疑的标签篡改模式'),
    (rb'is_malicious\s*=\s*False', '可疑的恶意标记'),
    (rb'{"label":\s*0', '可疑的标签数据'),
    # 后门触发器
    (rb'backdoor\s*(trigger|pattern|key)', '检测到后门触发器模式'),
    (rb'targeted\s*(misclassification|attack)', '检测到定向误分类攻击模式'),
    (rb'clean\s*label\s*(poisoning|attack)', '检测到清洁标签投毒模式'),
    # 对抗样本
    (rb'adversarial\s*(perturbation|noise|example)', '检测到对抗性扰动模式'),
    (rb'gradient\s*(based|descent)\s*(attack|optimization)', '检测到基于梯度的攻击模式'),
    (rb'carlini|cw_attack|fgsm|pgd|deepfool', '检测到已知对抗攻击方法'),
    # 隐藏通信/载荷
    (rb'steganograph|hidden\s*data|covert\s*channel', '检测到隐写/隐蔽通信模式'),
    (rb'dns\s*tunnel|icmp\s*tunnel', '检测到隧道通信模式'),
    (rb'payload|shellcode', '检测到载荷相关模式'),
]


class PoisoningDetector:
    """投毒检测器（统计规则引擎，可解释、确定性）"""

    def __init__(self):
        self.model_loaded = False

    def is_loaded(self):
        # 统计引擎始终可用；model_loaded 标记用于健康检查兼容
        return True

    def load_model(self):
        """统计规则引擎无需外部模型，直接标记可用"""
        self.model_loaded = True
        logger.info('投毒检测: 统计规则引擎已就绪（检测对象: 模型权重/训练数据/供应链投毒）')

    def detect(self, file_path):
        """
        检测文件是否为投毒样本
        返回: {'is_poisoned': bool, 'score': float, 'method': str, 'details': dict, 'anomalies': list}
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f'文件不存在: {file_path}')

        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        ext = os.path.splitext(file_name)[1].lower()

        # 读取文件内容
        try:
            with open(file_path, 'rb') as f:
                content = f.read(min(file_size, 10 * 1024 * 1024))
        except Exception:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(min(file_size, 10 * 1024 * 1024)).encode('utf-8', errors='ignore')

        results = {
            'entropy_analysis': self._entropy_analysis(content),
            'pattern_analysis': self._pattern_analysis(content),
            'statistical_analysis': self._statistical_analysis(content),
            'metadata_analysis': self._metadata_analysis(content, file_name, file_size),
            'content_analysis': self._content_analysis(content),
        }

        # 模型文件 / 数据集文件专项检测
        if ext in MODEL_FILE_EXTS:
            results['model_file_analysis'] = self._model_file_analysis(content, ext)
        if ext in DATASET_FILE_EXTS:
            results['dataset_file_analysis'] = self._dataset_file_analysis(content)

        # 综合评分
        total_score = 0.0
        weights = {
            'entropy_analysis': 0.2,
            'pattern_analysis': 0.25,
            'statistical_analysis': 0.2,
            'metadata_analysis': 0.15,
            'content_analysis': 0.2,
            'model_file_analysis': 0.4,
            'dataset_file_analysis': 0.4,
        }
        weight_sum = 0.0
        for key, result in results.items():
            w = weights.get(key, 0.2)
            total_score += result['score'] * w
            weight_sum += w
        total_score = min(total_score / weight_sum if weight_sum > 0 else 0, 1.0)

        # 收集异常指标
        anomalies = []
        for key, result in results.items():
            if result.get('anomalies'):
                anomalies.extend(result['anomalies'])

        return {
            'is_poisoned': bool(total_score > 0.5),
            'poisoning_probability': round(float(total_score), 4),
            'score': round(float(total_score), 4),
            'method': 'statistical_rule_engine',
            'model_loaded': self.model_loaded,
            'details': results,
            'anomalies': anomalies,
            'isolation_forest_anomaly': False,  # 兼容旧字段：已移除随机模型
            'isolation_forest_score': None,
        }

    def _model_file_analysis(self, content, ext):
        """模型权重文件专项检测：数值异常（NaN/Inf）、分布异常、完整性"""
        anomalies = []
        score = 0.0

        # NaN / Inf 检测（数值层面）
        nan_count = content.count(b'NaN') + content.count(b'nan') + content.count(b'inf')
        if nan_count > 0:
            score += 0.4
            anomalies.append(f'模型文件包含 {nan_count} 处 NaN/Inf 数值，权重可能被恶意篡改')

        # 大权重矩阵的数值分布异常检测（尝试解析 numpy/pickle 浮点流）
        try:
            # 从原始字节中采样 8 字节小端浮点
            floats = []
            step = max(1, len(content) // 5000)
            for i in range(0, min(len(content), 20 * 1024 * 1024), step):
                chunk = content[i:i + 8]
                if len(chunk) == 8:
                    floats.append(np.frombuffer(chunk, dtype=np.float64)[0])
            if len(floats) > 100:
                arr = np.array(floats)
                finite = arr[np.isfinite(arr)]
                if len(finite) < len(arr) * 0.9:
                    score += 0.3
                    anomalies.append('模型权重包含大量非有限数值')
                elif len(finite) > 100:
                    # 权重应近似正态分布；若大量集中在异常区间则可疑
                    std = float(np.std(finite))
                    if std < 1e-6 and np.abs(np.mean(finite)) < 1e-4:
                        score += 0.2
                        anomalies.append('模型权重分布过于集中（疑似被初始化/清零攻击）')
        except Exception:
            pass

        # 嵌入可疑载荷
        for pat, desc in [(b'MZ', '可执行载荷'), (b'PK\x03\x04', '压缩包载荷'), (b'%PDF', '文档载荷')]:
            if pat in content:
                score += 0.15
                anomalies.append(f'模型文件内嵌{desc}')

        # 文件大小异常
        if len(content) > 200 * 1024 * 1024:
            score += 0.1
            anomalies.append('模型文件异常偏大')

        return {'score': min(score, 1.0), 'anomalies': anomalies}

    def _dataset_file_analysis(self, content):
        """数据集文件专项检测：标签分布异常、隐藏列、后门触发器"""
        anomalies = []
        score = 0.0

        # 标签分布异常（单一标签占比过高）
        text = content.decode('utf-8', errors='ignore')
        labels = re.findall(r'["\']?label["\']?\s*[:=]\s*["\']?(\d+)["\']?', text)
        if len(labels) > 100:
            counter = Counter(labels)
            top_label, top_count = counter.most_common(1)[0]
            if top_count / len(labels) > 0.9:
                score += 0.3
                anomalies.append(f'数据集标签分布异常（标签 {top_label} 占比 {top_count / len(labels):.0%}），疑似投毒')
        elif len(labels) == 0 and len(text) > 10000 and 'label' not in text.lower():
            score += 0.1
            anomalies.append('数据集缺少标签字段，结构可疑')

        # 隐藏后门触发器（像素块/特殊 token）
        for pat in [rb'\\x[0-9a-f]{2}' * 16, rb'aaaaaaaaaaaaaaaa', rb'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00']:
            if pat in content:
                score += 0.2
                anomalies.append('检测到疑似后门触发器的重复模式')

        return {'score': min(score, 1.0), 'anomalies': anomalies}

    def _entropy_analysis(self, content):
        """熵值分析 - 投毒样本通常具有异常的熵值分布"""
        anomalies = []
        score = 0.0

        total_entropy = self._calculate_entropy(content)
        sample_size = min(len(content), 100000)

        chunk_size = 1024
        chunks = []
        for i in range(0, sample_size, chunk_size):
            chunk = content[i:i + chunk_size]
            if len(chunk) > 0:
                chunks.append(self._calculate_entropy(chunk))

        if chunks:
            mean_entropy = float(np.mean(chunks))
            std_entropy = float(np.std(chunks))

            if total_entropy > 7.5:
                score += 0.3
                anomalies.append('文件整体熵值异常偏高，可能经过加密或混淆处理')

            if std_entropy > 2.0:
                score += 0.2
                anomalies.append('文件各部分熵值差异过大，可能存在嵌入的恶意内容')

            for i in range(1, len(chunks)):
                if abs(chunks[i] - chunks[i - 1]) > 3.0:
                    score += 0.15
                    anomalies.append(f'检测到熵值突变（位置: {i * chunk_size}）')
                    break

            low_entropy_chunks = [e for e in chunks if e < 2.0]
            if len(low_entropy_chunks) > len(chunks) * 0.3 and total_entropy > 5.0:
                score += 0.15
                anomalies.append('文件中存在大量低熵区域，可能是投毒标记')

        return {
            'score': min(score, 1.0),
            'total_entropy': round(total_entropy, 4),
            'anomalies': anomalies
        }

    def _pattern_analysis(self, content):
        """模式分析 - 检测投毒相关的特殊模式"""
        anomalies = []
        score = 0.0

        try:
            text_content = content.decode('utf-8', errors='ignore')
            for pattern, description in POISONING_PATTERNS:
                if re.search(pattern, text_content, re.IGNORECASE):
                    score += 0.2
                    anomalies.append(description)
        except Exception:
            pass

        if len(content) > 1024:
            chunk_size = 256
            chunks = [content[i:i + chunk_size] for i in range(0, min(len(content), 65536), chunk_size)]
            unique_ratio = len(set(chunks)) / max(len(chunks), 1)
            if unique_ratio < 0.1:
                score += 0.15
                anomalies.append('文件包含大量重复内容，可能是填充攻击')

        null_bytes = content.count(b'\x00')
        if null_bytes > len(content) * 0.3:
            score += 0.1
            anomalies.append('文件包含大量空字节')

        return {
            'score': min(score, 1.0),
            'anomalies': anomalies
        }

    def _statistical_analysis(self, content):
        """统计分析 - 检测统计特征异常"""
        anomalies = []
        score = 0.0

        if len(content) < 100:
            return {'score': 0, 'anomalies': []}

        byte_freq = Counter(content[:100000])
        total = sum(byte_freq.values())

        if total > 0:
            frequencies = np.array(list(byte_freq.values())) / total
            expected_freq = 1.0 / 256
            chi_square = float(np.sum((frequencies - expected_freq) ** 2 / expected_freq) / len(frequencies))

            if chi_square > 10:
                score += 0.15
                anomalies.append('字节频率分布异常，偏离均匀分布')

            ascii_bytes = sum(1 for b in content[:10000] if 32 <= b <= 126 or b in (9, 10, 13))
            ascii_ratio = ascii_bytes / min(len(content), 10000)

            if ascii_ratio > 0.95 and self._calculate_entropy(content[:10000]) > 6.0:
                score += 0.1
                anomalies.append('ASCII文件具有异常高的熵值，可能包含编码的恶意内容')

            rare_bytes = sum(1 for freq in byte_freq.values() if freq / total < 0.0001)
            if rare_bytes > 200:
                score += 0.1
                anomalies.append('文件使用了大量罕见字节值')

        embedded_signatures = [b'PK\x03\x04', b'%PDF', b'\x89PNG', b'GIF8', b'BM', b'\xff\xd8\xff']
        embedded_count = sum(content.count(sig, 1) for sig in embedded_signatures)
        if embedded_count > 2:
            score += 0.2
            anomalies.append(f'检测到 {embedded_count} 个嵌入文件，可能为多文件捆绑投毒')

        return {
            'score': min(score, 1.0),
            'anomalies': anomalies
        }

    def _metadata_analysis(self, content, file_name, file_size):
        """元数据分析 - 文件名欺骗、异常大小"""
        anomalies = []
        score = 0.0

        name_lower = file_name.lower()
        dangerous_exts = ['.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta']

        parts = file_name.split('.')
        if len(parts) > 2:
            for ext in dangerous_exts:
                if f'.{ext}' in file_name.lower():
                    score += 0.2
                    anomalies.append('检测到双重扩展名，可能为文件名欺骗')
                    break

        if file_size < 100 and any(name_lower.endswith(ext) for ext in dangerous_exts):
            score += 0.15
            anomalies.append('可执行文件大小异常偏小')

        if file_size > 100 * 1024 * 1024:
            score += 0.1
            anomalies.append('文件大小异常偏大')

        return {
            'score': min(score, 1.0),
            'anomalies': anomalies
        }

    def _content_analysis(self, content):
        """内容深度分析 - 编码/混淆特征、数据集投毒特征"""
        anomalies = []
        score = 0.0

        encoding_patterns = [
            (rb'base64', 'Base64编码'),
            (rb'\\x[0-9a-fA-F]{2}', '十六进制编码'),
            (rb'\\u[0-9a-fA-F]{4}', 'Unicode编码'),
            (rb'eval\s*\(', '动态执行'),
            (rb'atob\s*\(', 'Base64解码'),
            (rb'String\.fromCharCode', '字符编码构造'),
            (rb'unescape\s*\(', 'URL解码'),
            (rb'rot13|ROT13', 'ROT13编码'),
            (rb'encode|decode|cipher|encrypt', '加密/编码操作'),
        ]

        try:
            text = content.decode('utf-8', errors='ignore')
            for pattern, desc in encoding_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if len(matches) > 3:
                    score += 0.1
                    anomalies.append(f'检测到大量{desc}操作')
        except Exception:
            pass

        dataset_patterns = [
            (rb'{"label":\s*0', '可疑的标签数据'),
            (rb'{"class":\s*["\']benign["\']', '可疑的分类标签'),
            (rb'is_malicious\s*=\s*False', '可疑的恶意标记'),
            (rb'training_data|train_set|dataset', '训练数据集相关内容'),
        ]

        for pattern, desc in dataset_patterns:
            if pattern in content:
                score += 0.05
                anomalies.append(f'检测到{desc}')

        return {
            'score': min(score, 1.0),
            'anomalies': anomalies
        }

    def _calculate_entropy(self, data):
        """计算数据熵值"""
        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy
