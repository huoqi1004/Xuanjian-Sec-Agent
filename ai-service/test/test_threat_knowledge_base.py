# -*- coding: utf-8 -*-
"""威胁知识库（RAG）完整测试"""
import json
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(__file__))

from rag import ThreatKnowledgeBase  # noqa: E402


class TestThreatKnowledgeBase:
    def setup_method(self):
        self.kb = ThreatKnowledgeBase()

    # ── 加载 ──────────────────────────────────────────────────
    def test_kb_loads_entries(self):
        """知识库应加载所有分类目录下的条目"""
        assert len(self.kb.items) >= 30, f'应加载 >=30 条，实际 {len(self.kb.items)}'

    def test_items_have_required_fields(self):
        """每条条目须含 id/title/category/content"""
        for item in self.kb.items:
            assert 'id' in item
            assert 'title' in item
            assert 'category' in item
            assert 'content' in item

    # ── 分类验证 ────────────────────────────────────────────────
    def test_categories_exist(self):
        """应包含多个分类"""
        categories = set(i['category'] for i in self.kb.items)
        assert len(categories) >= 5, f'分类数不足: {categories}'

    def test_severity_values(self):
        """严重级别须为合法值"""
        valid = {'critical', 'high', 'medium', 'low', ''}
        for item in self.kb.items:
            assert item.get('severity', '') in valid, f"无效 severity: {item.get('severity')}"

    # ── 检索测试 ────────────────────────────────────────────────
    def test_search_returns_results(self):
        results = self.kb.search('勒索软件 LockBit', top_k=5)
        assert isinstance(results, list)
        assert len(results) > 0
        for r in results:
            assert 'id' in r and 'title' in r and 'score' in r

    def test_search_cve_query(self):
        results = self.kb.search('CVE-2024-3094 XZ 后门', top_k=3)
        assert len(results) > 0
        assert results[0]['score'] > 0

    def test_search_ransomware(self):
        results = self.kb.search('勒索软件 勒索 加密', top_k=5)
        ransomware_results = [r for r in results if '勒索' in r['title'] or '勒索' in r['content']]
        assert len(ransomware_results) > 0

    def test_search_empty_query(self):
        assert self.kb.search('') == []
        assert self.kb.search('   ') == []

    def test_search_with_category_filter(self):
        results = self.kb.search('暴力破解', top_k=5, category='威胁情报')
        for r in results:
            assert r['category'] == '威胁情报'

    def test_search_with_severity_filter(self):
        results = self.kb.search('RCE 远程代码执行', top_k=5, severity='critical')
        for r in results:
            assert r['severity'] == 'critical' or len(results) == 0

    def test_search_mitre_ttps(self):
        results = self.kb.search('T1566 钓鱼 初始访问', top_k=3)
        assert len(results) > 0
        # 应优先命中 MITRE 条目
        assert any('MITRE' in r.get('source', '') or 'T1566' in r.get('content', '') for r in results)

    # ── 列表测试 ────────────────────────────────────────────────
    def test_list_items_pagination(self):
        items, total = self.kb.list_items(limit=5, offset=0)
        assert len(items) <= 5
        assert total == len(self.kb.items)

    def test_list_items_by_category(self):
        items, total = self.kb.list_items(category='CVE漏洞', limit=10)
        assert total > 0
        for i in items:
            assert i['category'] == 'CVE漏洞'

    def test_list_items_by_severity(self):
        items, total = self.kb.list_items(severity='critical', limit=10)
        assert total > 0
        for i in items:
            assert i['severity'] == 'critical'

    # ── 统计测试 ────────────────────────────────────────────────
    def test_get_stats(self):
        stats = self.kb.get_stats()
        assert stats['total_items'] == len(self.kb.items)
        assert isinstance(stats['categories'], dict)
        assert isinstance(stats['severities'], dict)
        assert stats['keyword_count'] > 0

    # ── 索引重建测试 ────────────────────────────────────────────
    def test_sync_from_directory(self):
        """同步后条目数应不变或增加"""
        old_count = len(self.kb.items)
        result = self.kb.sync_from_directory()
        assert 'added' in result
        assert 'total' in result
        assert result['total'] >= old_count

    # ── 混合检索权重验证 ─────────────────────────────────────────
    def test_keyword_match_ranks_higher(self):
        """关键词精确匹配的结果应比纯 TF-IDF 匹配排名更高"""
        # 搜索一个含精确关键词的条目
        results = self.kb.search('LockBit 勒索', top_k=5)
        if results:
            assert results[0]['score'] > 0
            # 第一条应包含 LockBit 关键词
            first = results[0]
            assert 'LockBit' in first['title'] or 'LockBit' in first['content']

    def test_keyword_index_built(self):
        """关键词倒排索引应被构建"""
        assert len(self.kb._keyword_index) > 0

    def test_ttps_in_search(self):
        """MITRE TTPs 应能被搜索到"""
        results = self.kb.search('横向移动 Pass-the-Hash', top_k=5)
        assert len(results) > 0
