# -*- coding: utf-8 -*-
"""
GAN 模型版本管理器

管理 GAN 模型的注册、版本控制、部署状态和清理策略。

核心功能：
  1. register_model() — 注册新模型版本
  2. deploy_model() — 部署指定版本
  3. get_active_model() — 获取当前活动模型
  4. list_models() — 列出所有模型版本
  5. cleanup_old_models() — 清理旧版本（保留最近 N 个）
  6. record_training() — 记录训练指标
"""

import json
import logging
import os
import hashlib
import threading
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# 模型状态常量
STATUS_PENDING = 'pending'
STATUS_DEPLOYED = 'deployed'
STATUS_DEPRECATED = 'deprecated'
STATUS_ERROR = 'error'

# 模型类型
MODEL_TYPE_ANOMALY = 'anomaly_gan'
MODEL_TYPE_ADV = 'adversarial_gan'
MODEL_TYPES = [MODEL_TYPE_ANOMALY, MODEL_TYPE_ADV]


class GANVersionManager:
    """
    GAN 模型版本管理器

    使用 SQLite 持久化模型版本信息（通过 ai-service 内部的 models.db）。
    如果 models.db 不可用，则使用内存回退。
    """

    def __init__(self, db_path: Optional[str] = None, max_versions_per_type: int = 5):
        """
        Args:
            db_path: SQLite 数据库路径（默认 ./models/gan_models.db）
            max_versions_per_type: 每种模型类型保留的最大版本数
        """
        self.max_versions_per_type = max_versions_per_type
        self.in_memory_models: Dict[str, List[Dict]] = {}
        self._lock = threading.Lock()  # 保护 in_memory_models 的并发读写

        if db_path:
            self.db_path = db_path
            os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
            self._init_db()
        else:
            self.db_path = None
            logger.warning('未指定数据库路径，使用内存回退模式')

    def _init_db(self):
        """初始化数据库表"""
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS gan_model_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_type TEXT NOT NULL,
                    version TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size_bytes INTEGER DEFAULT 0,
                    sha256_hash TEXT,
                    training_samples INTEGER DEFAULT 0,
                    train_accuracy REAL DEFAULT 0,
                    test_accuracy REAL DEFAULT 0,
                    adv_accuracy REAL DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    deployed_at DATETIME,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(model_type, version)
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_gmv_type ON gan_model_versions(model_type)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_gmv_status ON gan_model_versions(status)')
            conn.commit()
            conn.close()
            logger.info('GAN 模型版本数据库已初始化: %s', self.db_path)
        except Exception as e:
            logger.error('数据库初始化失败，使用内存回退: %s', e)
            self.db_path = None

    def _get_db_conn(self):
        """获取数据库连接（带内存回退）"""
        if self.db_path:
            try:
                import sqlite3
                return sqlite3.connect(self.db_path)
            except Exception:
                pass
        return None

    def register_model(self, model_type: str, version: str,
                       file_path: str, training_stats: Optional[Dict] = None,
                       notes: Optional[str] = None) -> Dict:
        """
        注册新模型版本

        Args:
            model_type: 模型类型（anomaly_gan / adversarial_gan）
            version: 版本号（如 "2.0.0-adv"）
            file_path: 模型文件路径
            training_stats: 训练指标（train_accuracy, test_accuracy, adv_accuracy 等）
            notes: 备注

        Returns:
            注册结果字典
        """
        if model_type not in MODEL_TYPES:
            raise ValueError(f'未知的模型类型: {model_type}，可选: {MODEL_TYPES}')

        if not os.path.isfile(file_path):
            raise FileNotFoundError(f'模型文件不存在: {file_path}')

        # 计算文件信息
        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()

        record = {
            'model_type': model_type,
            'version': version,
            'file_path': file_path,
            'file_size_bytes': file_size,
            'sha256_hash': sha256,
            'training_samples': training_stats.get('total_samples', 0) if training_stats else 0,
            'train_accuracy': training_stats.get('train_acc', 0) if training_stats else 0,
            'test_accuracy': training_stats.get('test_acc', 0) if training_stats else 0,
            'adv_accuracy': training_stats.get('adv_acc', 0) if training_stats else 0,
            'status': STATUS_PENDING,
            'notes': notes,
            'created_at': datetime.now().isoformat(),
        }

        # 保存到数据库
        conn = self._get_db_conn()
        if conn:
            try:
                conn.execute('''
                    INSERT OR REPLACE INTO gan_model_versions
                    (model_type, version, file_path, file_size_bytes, sha256_hash,
                     training_samples, train_accuracy, test_accuracy, adv_accuracy,
                     status, notes, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    record['model_type'], record['version'], record['file_path'],
                    record['file_size_bytes'], record['sha256_hash'],
                    record['training_samples'], record['train_accuracy'],
                    record['test_accuracy'], record['adv_accuracy'],
                    record['status'], record['notes'], record['created_at'],
                ))
                conn.commit()
                conn.close()
            except Exception as e:
                logger.warning('数据库保存失败，回退到内存: %s', e)
                self._save_to_memory(model_type, record)
        else:
            self._save_to_memory(model_type, record)

        logger.info('模型已注册: %s v%s | 大小=%dKB | 哈希=%s...',
                     model_type, version, file_size // 1024, sha256[:12])

        return record

    def deploy_model(self, model_type: str, version: str,
                     deployed_by: int = 1) -> Dict:
        """
        部署指定版本（将旧版本标记为 deprecated）

        Args:
            model_type: 模型类型
            version: 版本号
            deployed_by: 部署操作人 ID

        Returns:
            部署结果
        """
        conn = self._get_db_conn()
        now = datetime.now().isoformat()

        if conn:
            try:
                # 先取消同类型其他版本的部署状态
                conn.execute(
                    "UPDATE gan_model_versions SET status = ? WHERE model_type = ? AND status = ?",
                    (STATUS_DEPRECATED, model_type, STATUS_DEPLOYED)
                )
                # 更新目标版本为 deployed
                conn.execute(
                    "UPDATE gan_model_versions SET status = ?, deployed_at = ? WHERE model_type = ? AND version = ?",
                    (STATUS_DEPLOYED, now, model_type, version)
                )
                conn.commit()
                conn.close()
            except Exception as e:
                logger.warning('数据库更新失败，回退到内存: %s', e)
                self._deploy_memory(model_type, version, now)
        else:
            self._deploy_memory(model_type, version, now)

        logger.info('模型已部署: %s v%s', model_type, version)

        return {'model_type': model_type, 'version': version, 'status': STATUS_DEPLOYED, 'deployed_at': now}

    def get_active_model(self, model_type: str) -> Optional[Dict]:
        """
        获取当前活动的模型版本

        Args:
            model_type: 模型类型

        Returns:
            活动模型信息，无则返回 None
        """
        conn = self._get_db_conn()
        if conn:
            try:
                row = conn.execute(
                    "SELECT * FROM gan_model_versions WHERE model_type = ? AND status = ?",
                    (model_type, STATUS_DEPLOYED)
                ).fetchone()
                # 手动构建字典（避免 Windows 上 dict(row) 失败）
                if row:
                    cols = [d[1] for d in conn.execute("PRAGMA table_info(gan_model_versions)").fetchall()]
                    result = {cols[i]: row[i] for i in range(len(cols))}
                conn.close()
                return result if row else None
            except Exception as e:
                logger.warning('数据库查询失败，回退到内存: %s', e)

        # 内存回退
        models = self.in_memory_models.get(model_type, [])
        deployed = [m for m in models if m.get('status') == STATUS_DEPLOYED]
        return deployed[-1] if deployed else None

    def list_models(self, model_type: Optional[str] = None,
                    status: Optional[str] = None) -> List[Dict]:
        """
        列出模型版本

        Args:
            model_type: 过滤类型（None=全部）
            status: 过滤状态（None=全部）

        Returns:
            模型列表
        """
        conn = self._get_db_conn()
        if conn:
            try:
                conditions = []
                params = []
                if model_type:
                    conditions.append('model_type = ?')
                    params.append(model_type)
                if status:
                    conditions.append('status = ?')
                    params.append(status)
                where = (' WHERE ' + ' AND '.join(conditions)) if conditions else ''
                rows = conn.execute(
                    f'SELECT * FROM gan_model_versions {where} ORDER BY created_at DESC',
                    params
                ).fetchall()
                # 手动构建字典（避免 Windows 上 dict(row) 失败）
                cols = [d[1] for d in conn.execute("PRAGMA table_info(gan_model_versions)").fetchall()]
                result = [{cols[i]: r[i] for i in range(len(cols))} for r in rows]
                conn.close()
                return result
            except Exception as e:
                logger.warning('数据库查询失败，回退到内存: %s', e)

        # 内存回退
        result = []
        for mt, models in self.in_memory_models.items():
            if model_type and mt != model_type:
                continue
            for m in models:
                if status and m.get('status') != status:
                    continue
                result.append(m)
        return sorted(result, key=lambda x: x.get('created_at', ''), reverse=True)

    def cleanup_old_models(self, model_type: Optional[str] = None,
                           keep: Optional[int] = None) -> Dict:
        """
        清理旧版本（保留最近 keep 个）

        Args:
            model_type: 指定类型（None=全部类型）
            keep: 保留数量（None=使用配置值）

        Returns:
            清理结果统计
        """
        keep = keep or self.max_versions_per_type
        cleaned = 0

        types_to_clean = [model_type] if model_type else MODEL_TYPES

        for mt in types_to_clean:
            models = self.list_models(model_type=mt)
            if len(models) <= keep:
                continue

            # 保留最近的 keep 个，其余标记为 deprecated
            to_deprecate = models[keep:]
            for m in to_deprecate:
                if m.get('status') not in (STATUS_DEPRECATED, STATUS_ERROR):
                    self._deprecate_model(mt, m['version'])
                    cleaned += 1
                    logger.info('清理旧版本: %s v%s', mt, m['version'])

        return {
            'model_type': model_type or 'all',
            'cleaned_count': cleaned,
            'kept_per_type': keep,
        }

    def get_metrics_summary(self) -> Dict:
        """
        获取 GAN 模型监控摘要

        Returns:
            监控摘要，包含各模型版本的训练指标
        """
        all_models = self.list_models()

        summary = {
            'total_versions': len(all_models),
            'deployed_count': sum(1 for m in all_models if m.get('status') == STATUS_DEPLOYED),
            'by_type': {},
            'latest_versions': {},
        }

        for mt in MODEL_TYPES:
            models = [m for m in all_models if m.get('model_type') == mt]
            summary['by_type'][mt] = {
                'total': len(models),
                'deployed': sum(1 for m in models if m.get('status') == STATUS_DEPLOYED),
                'latest': models[0] if models else None,
            }
            if models:
                summary['latest_versions'][mt] = models[0]['version']

        return summary

    # ── 内存回退方法 ──────────────────────────────────────────

    def _save_to_memory(self, model_type: str, record: Dict):
        with self._lock:
            if model_type not in self.in_memory_models:
                self.in_memory_models[model_type] = []
            # 更新已存在的版本
            existing = [m for m in self.in_memory_models[model_type]
                        if m['version'] == record['version']]
            if existing:
                existing[0].update(record)
            else:
                self.in_memory_models[model_type].append(record)

    def _deploy_memory(self, model_type: str, version: str, now: str):
        with self._lock:
            models = self.in_memory_models.get(model_type, [])
            for m in models:
                if m.get('status') == STATUS_DEPLOYED:
                    m['status'] = STATUS_DEPRECATED
            for m in models:
                if m.get('version') == version:
                    m['status'] = STATUS_DEPLOYED
                    m['deployed_at'] = now

    def _deprecate_model(self, model_type: str, version: str):
        with self._lock:
            models = self.in_memory_models.get(model_type, [])
            for m in models:
                if m.get('version') == version and m.get('status') != STATUS_DEPRECATED:
                    m['status'] = STATUS_DEPRECATED

    # ── 类方法：便捷接口 ──────────────────────────────────────

    @classmethod
    def register_and_deploy(cls, db_path: str, model_type: str, version: str,
                            file_path: str, training_stats: Optional[Dict] = None,
                            notes: Optional[str] = None) -> Dict:
        """
        注册并立即部署（一步完成）
        """
        mgr = cls(db_path=db_path)
        mgr.register_model(model_type, version, file_path, training_stats, notes)
        mgr.deploy_model(model_type, version)
        return {'status': 'registered_and_deployed', 'model_type': model_type, 'version': version}


# 全局单例（延迟初始化）
_version_manager: Optional[GANVersionManager] = None


def get_version_manager(db_path: Optional[str] = None) -> GANVersionManager:
    global _version_manager
    if _version_manager is None:
        db = db_path or os.path.join(os.path.dirname(__file__), '..', 'models', 'gan_models.db')
        _version_manager = GANVersionManager(db_path=db)
    return _version_manager
