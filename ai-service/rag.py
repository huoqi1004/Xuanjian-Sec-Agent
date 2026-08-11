# -*- coding: utf-8 -*-
"""
玄鉴安全智能体 — 增强版 RAG 检索器

支持：
  1. TF-IDF 余弦相似度检索（原有）
  2. 关键词精确匹配（新增，权重更高）
  3. 分类过滤检索（新增）
  4. 严重级别过滤（新增）
  5. 自动索引重建（文件变更检测）

接口：
  POST /api/knowledge/search  { query, top_k, category?, severity? }
  GET  /api/knowledge          -> { items, total, stats }
  POST /api/knowledge/sync     -> { synced, added, updated, deleted }
"""
import json
import logging
import os
import time
from difflib import SequenceMatcher
from typing import Dict, List, Optional

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)

KB_DIR = os.path.join(os.path.dirname(__file__), 'knowledge_base')
INDEX_FILE = os.path.join(KB_DIR, 'knowledge_index.json')
TOP_K_DEFAULT = 5


class ThreatKnowledgeBase:
    """威胁知识库检索器（TF-IDF + 关键词混合检索）"""

    def __init__(self):
        self.items: List[dict] = []
        self._vectorizer = None
        self._tfidf_matrix = None
        self._keyword_index: Dict[str, int] = {}  # keyword -> item indices
        self._load_time = 0.0
        self.load()

    def load(self) -> int:
        """加载知识库（优先使用预构建索引，否则扫描目录）"""
        if os.path.exists(INDEX_FILE):
            try:
                with open(INDEX_FILE, 'r', encoding='utf-8') as f:
                    index = json.load(f)
                self.items = index.get('items', [])
                self._load_time = index.get('generated_at', '')
                logger.info('从索引加载知识库：%d 条（%s）', len(self.items), self._load_time)
            except Exception as e:
                logger.warning('索引加载失败，回退目录扫描: %s', e)
                self._load_from_directory()
        else:
            self._load_from_directory()
        self._build_index()
        return len(self.items)

    def _load_from_directory(self):
        """从目录扫描加载所有 JSON 文件"""
        items = []
        for root, dirs, files in os.walk(KB_DIR):
            dirs[:] = [d for d in dirs if d not in ('raw', '__pycache__')]
            for filename in sorted(files):
                if not filename.endswith('.json') or filename.startswith('_'):
                    continue
                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict) and item.get('title'):
                                item['source_file'] = os.path.relpath(filepath, KB_DIR)
                                items.append(item)
                except Exception as e:
                    logger.warning('加载失败 %s: %s', filename, e)
        self.items = items
        logger.info('目录扫描加载：%d 条条目', len(items))

    def _build_index(self):
        """构建 TF-IDF 索引和关键词倒排索引"""
        if not self.items:
            self._vectorizer = None
            self._tfidf_matrix = None
            self._keyword_index = {}
            return

        # TF-IDF
        corpus = [self._text_of(item) for item in self.items]
        self._vectorizer = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True,
        )
        self._tfidf_matrix = self._vectorizer.fit_transform(corpus)

        # 关键词倒排索引
        self._keyword_index = {}
        for idx, item in enumerate(self.items):
            for kw in item.get('keywords', []):
                kw_lower = kw.lower().strip()
                if kw_lower:
                    if kw_lower not in self._keyword_index:
                        self._keyword_index[kw_lower] = []
                    self._keyword_index[kw_lower].append(idx)
            # 标题词也加入索引
            title_words = [w.strip().lower() for w in item.get('title', '').split() if len(w.strip()) > 1]
            for w in title_words:
                if w not in self._keyword_index:
                    self._keyword_index[w] = []
                if idx not in self._keyword_index[w]:
                    self._keyword_index[w].append(idx)

        logger.info('索引构建完成：%d 个关键词', len(self._keyword_index))

    @staticmethod
    def _text_of(item: dict) -> str:
        keywords = ' '.join(item.get('keywords', []) or [])
        ttps = ' '.join(item.get('ttps', []) or [])
        return f"{item.get('title', '')} {item.get('content', '')} {keywords} {ttps}"

    def search(self, query: str, top_k: int = TOP_K_DEFAULT,
               category: Optional[str] = None,
               severity: Optional[str] = None) -> List[dict]:
        """混合检索：关键词精确匹配 + TF-IDF 向量相似度"""
        if not self.items or not query.strip():
            return []

        query_lower = query.lower().strip()
        query_keywords = set(query_lower.split())

        # 收集候选索引（关键词匹配）
        candidate_indices: Dict[int, float] = {}

        # 1. 关键词精确匹配（高权重）
        for kw in query_keywords:
            if kw in self._keyword_index:
                for idx in self._keyword_index[kw]:
                    candidate_indices[idx] = candidate_indices.get(idx, 0) + 2.0  # 关键词匹配权重高

        # 2. TF-IDF 余弦相似度
        if self._tfidf_matrix is not None:
            query_vec = self._vectorizer.transform([query])
            scores = cosine_similarity(query_vec, self._tfidf_matrix).flatten()
            for idx, score in enumerate(scores):
                if score > 0:
                    candidate_indices[idx] = candidate_indices.get(idx, 0) + float(score)

        # 过滤和排序
        filtered = []
        for idx, combined_score in candidate_indices.items():
            item = self.items[idx]
            if category and item.get('category') != category:
                continue
            if severity and item.get('severity') != severity:
                continue
            filtered.append((idx, combined_score, item))

        # 按综合分数排序
        filtered.sort(key=lambda x: -x[1])
        results = []
        for idx, score, item in filtered[: max(1, min(top_k, len(filtered)))]:
            results.append({
                'id': item.get('id', ''),
                'category': item.get('category', ''),
                'title': item.get('title', ''),
                'content': item.get('content', ''),
                'severity': item.get('severity', ''),
                'keywords': item.get('keywords', []),
                'score': round(score, 4),
                'source': item.get('source', ''),
                'source_file': item.get('source_file', ''),
            })
        return results

    def list_items(self, category: Optional[str] = None,
                   severity: Optional[str] = None,
                   limit: int = 100, offset: int = 0) -> tuple:
        """分页列表查询"""
        items = self.items
        if category:
            items = [i for i in items if i.get('category') == category]
        if severity:
            items = [i for i in items if i.get('severity') == severity]
        total = len(items)
        return items[offset:offset + limit], total

    def get_stats(self) -> dict:
        """知识库统计信息"""
        categories: Dict[str, int] = {}
        severities: Dict[str, int] = {}
        sources: Dict[str, int] = {}
        for item in self.items:
            cat = item.get('category', '未知')
            categories[cat] = categories.get(cat, 0) + 1
            sev = item.get('severity', 'unknown')
            severities[sev] = severities.get(sev, 0) + 1
            src = item.get('source', 'unknown')
            sources[src] = sources.get(src, 0) + 1
        return {
            'total_items': len(self.items),
            'categories': categories,
            'severities': severities,
            'sources': sources,
            'keyword_count': len(self._keyword_index),
            'loaded_at': self._load_time,
        }

    def sync_from_directory(self) -> dict:
        """重新扫描目录并增量更新"""
        old_items = {item.get('id'): item for item in self.items}
        self._load_from_directory()
        new_items = {item.get('id'): item for item in self.items}

        added = [v for k, v in new_items.items() if k not in old_items]
        deleted = [v for k, v in old_items.items() if k not in new_items]
        updated = []
        for k, new_v in new_items.items():
            if k in old_items and old_items[k].get('hash') != new_v.get('hash'):
                updated.append(new_v)

        self._build_index()
        return {'added': len(added), 'deleted': len(deleted), 'updated': len(updated), 'total': len(self.items)}


# 全局单例
kb = ThreatKnowledgeBase()
