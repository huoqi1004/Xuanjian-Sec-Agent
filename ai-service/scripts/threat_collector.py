# -*- coding: utf-8 -*-
"""
玄鉴威胁情报知识库 — 数据源定义与收集器

支持的数据源：
  1. NVD CVE API          — 公开漏洞库（MITRE）
  2. VirusTotal 报告      — 恶意软件特征（需 API Key）
  3. AlienVault OTX       — 开放威胁情报（OTX API）
  4. MITRE ATT&CK         — 战术技术知识（静态 CSV）
  5. 本地 CSV 导入        — 自定义 IOC / 威胁样本

用法：
  python -m scripts.threat_collector --sources cve,otx --days 30
  python -m scripts.threat_collector --sources local --file threat_feed.csv
  python -m scripts.threat_collector --sources all --batch
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)

# ── 数据源定义 ──────────────────────────────────────────────

SOURCES = {
    'cve': {
        'name': 'NVD CVE Feed',
        'api': 'https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start}&pubEndDate={end}&resultsPerPage=200',
        'required_api_key': False,
        'max_per_sync': 50,       # 免费 API 限流
    },
    'otx': {
        'name': 'AlienVault OTX',
        'api': 'https://otx.alienvault.com/api/v1/indicators/global/indicator_search',
        'required_api_key': True,
        'key_env': 'OTX_API_KEY',
    },
    'vt': {
        'name': 'VirusTotal Threat Feed',
        'api': 'https://www.virustotal.com/api/v3/files/{hash}',
        'required_api_key': True,
        'key_env': 'VT_API_KEY',
    },
    'mitre': {
        'name': 'MITRE ATT&CK Tactics',
        'static': True,
        'file': 'knowledge_base/mitre_attack_tactics.json',
    },
    'local': {
        'name': '本地 CSV/JSON 导入',
        'static': True,
    },
}

# ── 威胁情报条目标准化结构 ──────────────────────────────────

def normalize_entry(raw: dict, source: str, collected_at: str) -> dict:
    """将原始数据源条目标准化为知识库通用格式"""
    return {
        'id': _gen_id(raw.get('cve_id', raw.get('title', raw.get('ioc', '')), source),
        'category': _classify_category(raw),
        'source': source,
        'source_url': raw.get('url', '') or raw.get('reference', ''),
        'collected_at': collected_at,
        'title': raw.get('title', raw.get('cve_id', raw.get('description', '未知标题'))[:120],
        'content': _extract_content(raw),
        'keywords': _extract_keywords(raw),
        'severity': _normalize_severity(raw.get('severity', raw.get('score', ''))),
        'tags': raw.get('tags', []),
        'meta': {
            'cpe': raw.get('cpe', []),
            'references': raw.get('references', []),
            'published': raw.get('published', ''),
            'modified': raw.get('modified', ''),
        },
        'verified': False,
    }


def _gen_id( identifier: str, source: str) -> str:
    """生成稳定的条目 ID"""
    raw = f"{source}:{identifier}"
    return 'threat-' + hashlib.sha256(raw.encode()).hexdigest()[:12]


def _classify_category(raw: dict) -> str:
    """根据数据特征分类"""
    title = (raw.get('title', '') + ' ' + raw.get('description', '')).lower()

    if raw.get('type') == 'cve' or 'cve' in title or '漏洞' in title:
        return 'CVE漏洞'
    if any(kw in title for kw in ['恶意软件', 'ransomware', 'trojan', 'worm', '病毒', '恶意软件', 'malware']):
        return '恶意软件'
    if raw.get('type') == 'ioc' or 'ioc' in title or 'indicators' in title:
        return '威胁指标'
    if 'mitre' in raw.get('source', '').lower() or 'attack' in title:
        return '攻击战术'
    if any(kw in title for kw in ['流量', '流量分析', '网络流量', 'traffic', 'network']):
        return '流量特征'
    if any(kw in title for kw in ['应急响应', '处置', 'incident', 'forensics']):
        return '应急响应'
    if any(kw in title for kw in ['防护', '加固', 'hardening', 'best practice', '指南']):
        return '防护最佳实践'
    return '威胁情报'


def _extract_content(raw: dict) -> str:
    """提取可读内容"""
    parts = []
    if raw.get('description'):
        parts.append(raw['description'])
    if raw.get('title') and raw.get('title') not in raw.get('description', ''):
        parts.insert(0, raw['title'])
    if raw.get('references'):
        refs = '; '.join(raw['references'][:5])
        parts.append(f'参考链接: {refs}')
    if raw.get('cpe'):
        parts.append(f'受影响软件: {", ".join(raw["cpe"][:5])}')
    if raw.get('score'):
        parts.append(f'CVSS评分: {raw["score"]}')
    return ' '.join(parts) if parts else str(raw)


def _extract_keywords(raw: dict) -> List[str]:
    """提取关键词"""
    kw = set()
    for field in ['keywords', 'tags', 'cpe', 'references']:
        val = raw.get(field, [])
        if isinstance(val, list):
            kw.update(str(x) for x in val if x)
    # 从标题/描述提取中文关键词
    text = f"{raw.get('title', '')} {raw.get('description', '')}"
    for pattern in [r'CVE-\d{4}-\d{4,}', r'[a-z0-9-]{8,32}\.[a-z0-9-]{8,32}',
                    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', r'[a-z0-9\-]+\.(?:exe|dll|py|sh|bat)']:
        matches = re.findall(pattern, text.lower())
        kw.update(matches)
    return list(kw)[:20]


def _normalize_severity(sev) -> str:
    if not sev:
        return 'medium'
    s = str(sev).lower()
    if 'critical' in s or '高' in s:
        return 'critical'
    if 'high' in s or '严重' in s:
        return 'high'
    if 'medium' in s or '中' in s:
        return 'medium'
    if 'low' in s or '低' in s:
        return 'low'
    return 'medium'


# ── 数据源收集器 ────────────────────────────────────────────

class ThreatCollector:
    """威胁情报数据收集器"""

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or os.path.join(os.path.dirname(__file__), '..', 'knowledge_base', 'raw')
        os.makedirs(self.output_dir, exist_ok=True)

    def collect_all(self, days: int = 30, max_per_source: int = 30):
        """收集所有可用数据源"""
        all_entries = []
        today = datetime.utcnow().strftime('%Y-%m-%d')

        for source_name, cfg in SOURCES.items():
            if cfg.get('static'):
                continue  # 静态数据源单独处理
            if cfg.get('required_api_key'):
                env_key = cfg.get('key_env', '')
                if not os.environ.get(env_key):
                    logger.warning('[收集] 跳过 %s：未设置 %s', source_name, env_key)
                    continue
            try:
                entries = self._collect_source(source_name, cfg, days, max_per_source)
                all_entries.extend(entries)
                logger.info('[收集] %s 完成：%d 条', cfg.get('name', source_name), len(entries))
            except Exception as e:
                logger.error('[收集] %s 失败：%s', cfg.get('name', source_name), e)

        # 保存原始数据
        raw_file = os.path.join(self.output_dir, f'collected_{datetime.utcnow().strftime("%Y%m%d")}.json')
        with open(raw_file, 'w', encoding='utf-8') as f:
            json.dump(all_entries, f, ensure_ascii=False, indent=2)
        logger.info('[收集] 原始数据已保存: %s (%d 条)', raw_file, len(all_entries))
        return all_entries

    def _collect_source(self, source_name: str, cfg: dict, days: int, max_count: int) -> List[dict]:
        """收集单个数据源"""
        entries = []
        today = datetime.utcnow()

        if source_name == 'cve':
            start = (today - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%S')
            end = today.strftime('%Y-%m-%dT%H:%M:%S')
            url = cfg['api'].format(start=start, end=end)
            headers = {}
            api_key = os.environ.get('NVD_API_KEY', '')
            if api_key:
                headers['apiKey'] = api_key

            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            for cve in data.get('vulnerabilities', [])[:max_count]:
                cve_data = cve.get('cve', {})
                entries.append({
                    'type': 'cve',
                    'cve_id': cve_data.get('id', ''),
                    'title': cve_data.get('descriptions', [{}])[0].get('value', '')[:200],
                    'description': cve_data.get('descriptions', [{}])[0].get('value', ''),
                    'references': [r.get('url', '') for r in cve_data.get('references', [])[:10]],
                    'severity': cve_data.get('metrics', {}),
                    'score': _get_cvss_score(cve_data),
                    'published': cve_data.get('publishedDate', ''),
                    'modified': cve_data.get('lastModified', ''),
                })

        elif source_name == 'otx':
            api_key = os.environ.get('OTX_API_KEY', '')
            headers = {'Authorization': f'apikey {api_key}'}
            resp = requests.get(
                'https://otx.alienvault.com/api/v1/indicators/general/search_text',
                headers=headers, params={'search_text': 'ransomware OR malware OR exploit', 'limit': max_count},
                timeout=30
            )
            resp.raise_for_status()
            for item in resp.json().get('results', [])[:max_count]:
                entries.append({
                    'type': 'ioc',
                    'title': item.get('name', '') or item.get('indicator', ''),
                    'indicator': item.get('indicator', ''),
                    'indicator_type': item.get('type', ''),
                    'description': item.get('description', ''),
                    'tags': item.get('tags', []),
                    'references': item.get('references', []),
                })

        return entries

    def load_local(self, file_path: str) -> List[dict]:
        """从本地 CSV/JSON 文件加载威胁数据"""
        entries = []
        with open(file_path, 'r', encoding='utf-8') as f:
            if file_path.endswith('.json'):
                data = json.load(f)
                if isinstance(data, list):
                    entries = data
                elif isinstance(data, dict):
                    entries = [data]
            elif file_path.endswith('.csv'):
                import csv
                reader = csv.DictReader(f)
                for row in reader:
                    entries.append(row)
        return entries


def _get_cvss_score(cve_data: dict) -> str:
    """提取 CVSS 评分"""
    metrics = cve_data.get('metrics', {})
    for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if key in metrics and metrics[key]:
            for m in metrics[key]:
                return m.get('cvssData', {}).get('baseScore', '')
    return ''


# ── CLI 入口 ────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='威胁情报知识库收集器')
    parser.add_argument('--sources', default='cve', help='数据源列表（逗号分隔）')
    parser.add_argument('--days', type=int, default=30, help='回溯天数')
    parser.add_argument('--batch', action='store_true', help='收集所有可用源')
    parser.add_argument('--file', help='本地 CSV/JSON 文件路径')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

    collector = ThreatCollector()

    if args.batch:
        entries = collector.collect_all(days=args.days)
    elif args.sources == 'local' and args.file:
        entries = collector.load_local(args.file)
    else:
        sources = [s.strip() for s in args.sources.split(',')]
        all_entries = []
        for src in sources:
            cfg = SOURCES.get(src)
            if not cfg:
                logger.warning('未知数据源: %s', src)
                continue
            try:
                entries = collector._collect_source(src, cfg, args.days, max_per_source=30)
                all_entries.extend(entries)
            except Exception as e:
                logger.error('收集 %s 失败：%s', src, e)
        entries = all_entries

    # 输出摘要
    print(f'\n收集完成：{len(entries)} 条条目')
    if entries:
        cats = {}
        for e in entries:
            cat = _classify_category(e)
            cats[cat] = cats.get(cat, 0) + 1
        print('分类分布:', json.dumps(cats, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
