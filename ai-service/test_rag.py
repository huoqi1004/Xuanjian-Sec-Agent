# -*- coding: utf-8 -*-
"""知识库检索（RAG）契约测试"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from rag import KnowledgeBase  # noqa: E402


class TestRAG:
    def setup_method(self):
        self.kb = KnowledgeBase()

    def test_kb_loaded_with_items(self):
        assert len(self.kb.items) >= 10, '知识库应有 10 条以上条目'

    def test_search_returns_ranked_results(self):
        results = self.kb.search('SSH 暴力破解 防护 处置', top_k=3)
        assert isinstance(results, list) and 0 < len(results) <= 3
        for r in results:
            assert 'id' in r and 'content' in r and 'score' in r

    def test_search_relevant_topic(self):
        """检索"暴力破解"应优先命中相关条目"""
        results = self.kb.search('暴力破解 fail2ban 账号锁定', top_k=5)
        assert len(results) > 0
        assert results[0]['score'] > 0.05

    def test_search_empty_query(self):
        assert self.kb.search('', top_k=3) == []
        assert self.kb.search('   ', top_k=3) == []

    def test_list_items(self):
        items, total = self.kb.list_items(limit=5)
        assert len(items) <= 5
        assert total == len(self.kb.items)
