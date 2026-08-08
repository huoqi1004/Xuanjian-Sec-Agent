# -*- coding: utf-8 -*-
"""
玄鉴安全智能体 - 本地向量检索（RAG 增强）

基于 TF-IDF + 余弦相似度实现轻量级本地知识检索，无需外部向量数据库。
知识源：knowledge_base/*.json（安全知识条目，含 CVE/等保/最佳实践/威胁情报）。

接口：
  POST /api/knowledge/search  { query, top_k } -> { results: [{id, title, content, category, score}] }
  GET  /api/knowledge          -> { items: [...], total }
"""
import json
import logging
import os

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)

KB_DIR = os.path.join(os.path.dirname(__file__), 'knowledge_base')
TOP_K_DEFAULT = 5


class KnowledgeBase:
    """本地知识库检索器"""

    def __init__(self):
        self.items = []
        self._vectorizer = None
        self._tfidf_matrix = None
        self.load()

    def _load_files(self):
        files = []
        if os.path.isdir(KB_DIR):
            files = sorted(
                f for f in os.listdir(KB_DIR)
                if f.endswith('.json') and not f.startswith('_')
            )
        return files

    def load(self):
        items = []
        for filename in self._load_files():
            path = os.path.join(KB_DIR, filename)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    items.extend(data)
                elif isinstance(data, dict) and isinstance(data.get('items'), list):
                    items.extend(data['items'])
            except Exception as e:  # noqa: BLE001
                logger.warning('知识库文件加载失败 %s: %s', filename, e)
        self.items = items
        self._build_index()
        logger.info('知识库加载完成：%d 条（来源 %d 个文件）', len(items), len(self._load_files()))
        return len(items)

    def _build_index(self):
        if not self.items:
            self._vectorizer = None
            self._tfidf_matrix = None
            return
        corpus = [self._text_of(item) for item in self.items]
        self._vectorizer = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(1, 2),
            min_df=1,
            sublinear_tf=True,
        )
        self._tfidf_matrix = self._vectorizer.fit_transform(corpus)

    @staticmethod
    def _text_of(item):
        keywords = ' '.join(item.get('keywords', []) or [])
        return f"{item.get('title', '')} {item.get('content', '')} {keywords}"

    def search(self, query, top_k=TOP_K_DEFAULT):
        """检索与 query 最相关的知识条目，返回降序结果（含相似度分数）"""
        if not self.items or self._vectorizer is None or not query.strip():
            return []
        query_vec = self._vectorizer.transform([query])
        scores = cosine_similarity(query_vec, self._tfidf_matrix).flatten()
        top_idx = scores.argsort()[::-1][: max(1, min(top_k, len(self.items)))]
        results = []
        for idx in top_idx:
            score = float(scores[idx])
            if score <= 0:
                continue
            item = self.items[idx]
            results.append({
                'id': item.get('id', ''),
                'category': item.get('category', ''),
                'title': item.get('title', ''),
                'content': item.get('content', ''),
                'severity': item.get('severity', ''),
                'score': round(score, 4),
            })
        return results

    def list_items(self, category=None, limit=100, offset=0):
        items = self.items
        if category:
            items = [i for i in items if i.get('category') == category]
        total = len(items)
        return items[offset:offset + limit], total


kb = KnowledgeBase()
