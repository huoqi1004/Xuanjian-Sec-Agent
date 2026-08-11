# -*- coding: utf-8 -*-
"""
玄鉴威胁知识库 — 构建与聚合脚本

功能：
  1. 扫描 knowledge_base/*.json 所有条目
  2. 去重（基于 id 和 SHA-256 content hash）
  3. 清洗（去除空字段、截断超长内容、标准化分类）
  4. 生成统一索引文件 knowledge_index.json
  5. 输出统计摘要

用法：
  python -m scripts.build_threat_kb
  python -m scripts.build_threat_kb --dry-run
  python -m scripts.build_threat_kb --stats
"""

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

KB_DIR = os.path.join(os.path.dirname(__file__), '..', 'knowledge_base')
INDEX_FILE = os.path.join(KB_DIR, 'knowledge_index.json')
STATS_FILE = os.path.join(KB_DIR, 'stats.json')


def _content_hash(item: dict) -> str:
    """计算内容哈希用于去重"""
    text = f"{item.get('title', '')}||{item.get('content', '')}"
    return hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]


def _normalize_item(raw: dict, source_file: str) -> dict:
    """标准化单个知识条目"""
    return {
        'id': raw.get('id', f'threat-{hashlib.md5(raw.get("title", "").encode()).hexdigest()[:8]}'),
        'category': raw.get('category', '威胁情报'),
        'source': raw.get('source', source_file),
        'source_file': source_file,
        'title': (raw.get('title', '') or '').strip(),
        'content': (raw.get('content', '') or '').strip(),
        'keywords': [kw.strip() for kw in raw.get('keywords', []) if kw],
        'severity': raw.get('severity', 'medium'),
        'references': raw.get('references', [])[:10],
        'ttps': raw.get('ttps', []),
        'mitigation': raw.get('mitigation', ''),
        'collected_at': raw.get('collected_at', datetime.utcnow().isoformat()),
        'hash': _content_hash(raw),
    }


def load_all_entries() -> List[dict]:
    """加载所有分类目录下的 JSON 文件"""
    entries = []
    seen_ids: Set[str] = set()
    seen_hashes: Set[str] = set()

    for root, dirs, files in os.walk(KB_DIR):
        # 跳过索引文件和统计文件
        dirs[:] = [d for d in dirs if d not in ('raw', '__pycache__')]

        for filename in sorted(files):
            if not filename.endswith('.json') or filename.startswith('_'):
                continue
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, KB_DIR)

            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception as e:
                logger.warning('加载失败 %s: %s', rel_path, e)
                continue

            if not isinstance(data, list):
                logger.warning('跳过非列表文件 %s', rel_path)
                continue

            for raw in data:
                if not isinstance(raw, dict):
                    continue
                if not raw.get('title') and not raw.get('content'):
                    continue

                item = _normalize_item(raw, rel_path)

                # 去重
                if item['id'] in seen_ids:
                    logger.debug('去重（ID重复）: %s', item['id'])
                    continue
                if item['hash'] in seen_hashes:
                    logger.debug('去重（内容重复）: %s', item['id'])
                    continue

                seen_ids.add(item['id'])
                seen_hashes.add(item['hash'])
                entries.append(item)

    return entries


def build_index(entries: List[dict]) -> dict:
    """生成统一知识索引"""
    # 按分类统计
    categories: Dict[str, int] = {}
    severities: Dict[str, int] = {}
    sources: Dict[str, int] = {}

    for item in entries:
        cat = item['category']
        categories[cat] = categories.get(cat, 0) + 1
        sev = item['severity']
        severities[sev] = severities.get(sev, 0) + 1
        src = item.get('source', 'unknown')
        sources[src] = sources.get(src, 0) + 1

    index = {
        'version': '1.0',
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'total_items': len(entries),
        'categories': categories,
        'severities': severities,
        'sources': sources,
        'items': entries,
    }
    return index


def main():
    parser = argparse.ArgumentParser(description='威胁知识库构建器')
    parser.add_argument('--dry-run', action='store_true', help='仅输出统计不写入文件')
    parser.add_argument('--stats', action='store_true', help='仅输出统计')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

    logger.info('开始扫描知识库目录: %s', KB_DIR)
    entries = load_all_entries()
    logger.info('加载完成：%d 条条目', len(entries))

    index = build_index(entries)

    if args.stats:
        print(json.dumps(index, ensure_ascii=False, indent=2))
        return

    if args.dry_run:
        print(f'【Dry Run】共 {index["total_items"]} 条，分类分布:')
        for cat, count in sorted(index['categories'].items(), key=lambda x: -x[1]):
            print(f'  {cat}: {count}')
        print(f'严重程度分布:')
        for sev, count in sorted(index['severities'].items(), key=lambda x: -x[1]):
            print(f'  {sev}: {count}')
        return

    # 写入索引
    with open(INDEX_FILE, 'w', encoding='utf-8') as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    logger.info('知识索引已写入: %s (%d 条)', INDEX_FILE, index['total_items'])

    # 写入统计
    with open(STATS_FILE, 'w', encoding='utf-8') as f:
        json.dump({k: v for k, v in index.items() if k != 'items'}, f, ensure_ascii=False, indent=2)
    logger.info('统计摘要已写入: %s', STATS_FILE)

    print(f'\n✅ 知识库构建完成：{index["total_items"]} 条条目')
    print(f'分类分布：{json.dumps(index["categories"], ensure_ascii=False)}')
    print(f'严重程度：{json.dumps(index["severities"], ensure_ascii=False)}')


if __name__ == '__main__':
    main()
