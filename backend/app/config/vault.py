"""
玄鉴安全智能体 - 密钥安全存储
支持多种后端：环境变量、加密文件、HashiCorp Vault
"""

import os
import json
import base64
import logging
from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class VaultBackend(ABC):
    """密钥存储后端抽象基类"""
    
    @abstractmethod
    def get_secret(self, key: str) -> Optional[str]:
        """获取密钥"""
        pass
    
    @abstractmethod
    def set_secret(self, key: str, value: str) -> bool:
        """设置密钥"""
        pass
    
    @abstractmethod
    def delete_secret(self, key: str) -> bool:
        """删除密钥"""
        pass
    
    @abstractmethod
    def list_secrets(self) -> list:
        """列出所有密钥名称"""
        pass


class EnvVaultBackend(VaultBackend):
    """环境变量后端 - 适用于开发环境"""
    
    def __init__(self, prefix: str = "XUANJIAN_SECRET_"):
        self.prefix = prefix
    
    def get_secret(self, key: str) -> Optional[str]:
        env_key = f"{self.prefix}{key.upper()}"
        value = os.environ.get(env_key)
        if value:
            logger.debug(f"Retrieved secret from env: {env_key}")
        return value
    
    def set_secret(self, key: str, value: str) -> bool:
        env_key = f"{self.prefix}{key.upper()}"
        os.environ[env_key] = value
        logger.info(f"Set secret in env: {env_key}")
        return True
    
    def delete_secret(self, key: str) -> bool:
        env_key = f"{self.prefix}{key.upper()}"
        if env_key in os.environ:
            del os.environ[env_key]
            logger.info(f"Deleted secret from env: {env_key}")
            return True
        return False
    
    def list_secrets(self) -> list:
        return [
            k.replace(self.prefix, "").lower()
            for k in os.environ.keys()
            if k.startswith(self.prefix)
        ]


class FileVaultBackend(VaultBackend):
    """加密文件后端 - 适用于单机生产环境"""
    
    def __init__(self, file_path: str = ".secrets", encryption_key: Optional[str] = None):
        self.file_path = Path(file_path)
        self._encryption_key = encryption_key or os.environ.get("XUANJIAN_VAULT_KEY")
        self._secrets: Dict[str, str] = {}
        self._load_secrets()
    
    def _get_cipher(self):
        """获取加密器"""
        try:
            from cryptography.fernet import Fernet
            if self._encryption_key:
                # 确保密钥是有效的Fernet密钥
                key = self._encryption_key.encode()
                if len(key) != 44:  # Fernet密钥长度
                    key = base64.urlsafe_b64encode(key[:32].ljust(32, b'0'))
                return Fernet(key)
        except ImportError:
            logger.warning("cryptography not installed, using plaintext storage")
        return None
    
    def _load_secrets(self):
        """加载密钥文件"""
        if not self.file_path.exists():
            self._secrets = {}
            return
        
        try:
            content = self.file_path.read_bytes()
            cipher = self._get_cipher()
            
            if cipher:
                content = cipher.decrypt(content)
            
            self._secrets = json.loads(content.decode('utf-8'))
            logger.info(f"Loaded {len(self._secrets)} secrets from {self.file_path}")
        except Exception as e:
            logger.error(f"Failed to load secrets: {e}")
            self._secrets = {}
    
    def _save_secrets(self):
        """保存密钥文件"""
        try:
            content = json.dumps(self._secrets, indent=2).encode('utf-8')
            cipher = self._get_cipher()
            
            if cipher:
                content = cipher.encrypt(content)
            
            self.file_path.write_bytes(content)
            logger.info(f"Saved {len(self._secrets)} secrets to {self.file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save secrets: {e}")
            return False
    
    def get_secret(self, key: str) -> Optional[str]:
        return self._secrets.get(key.lower())
    
    def set_secret(self, key: str, value: str) -> bool:
        self._secrets[key.lower()] = value
        return self._save_secrets()
    
    def delete_secret(self, key: str) -> bool:
        if key.lower() in self._secrets:
            del self._secrets[key.lower()]
            return self._save_secrets()
        return False
    
    def list_secrets(self) -> list:
        return list(self._secrets.keys())


class HashiCorpVaultBackend(VaultBackend):
    """HashiCorp Vault后端 - 适用于企业级部署"""
    
    def __init__(
        self,
        addr: Optional[str] = None,
        token: Optional[str] = None,
        mount_path: str = "secret",
        path_prefix: str = "xuanjian"
    ):
        self.addr = addr or os.environ.get("VAULT_ADDR", "http://localhost:8200")
        self.token = token or os.environ.get("VAULT_TOKEN")
        self.mount_path = mount_path
        self.path_prefix = path_prefix
        self._client = None
    
    def _get_client(self):
        """获取Vault客户端"""
        if self._client is None:
            try:
                import hvac
                self._client = hvac.Client(url=self.addr, token=self.token)
                if not self._client.is_authenticated():
                    logger.error("Vault authentication failed")
                    self._client = None
            except ImportError:
                logger.error("hvac not installed, HashiCorp Vault backend unavailable")
        return self._client
    
    def _full_path(self, key: str) -> str:
        return f"{self.path_prefix}/{key.lower()}"
    
    def get_secret(self, key: str) -> Optional[str]:
        client = self._get_client()
        if not client:
            return None
        
        try:
            secret = client.secrets.kv.v2.read_secret_version(
                path=self._full_path(key),
                mount_point=self.mount_path
            )
            return secret['data']['data'].get('value')
        except Exception as e:
            logger.error(f"Failed to get secret {key}: {e}")
            return None
    
    def set_secret(self, key: str, value: str) -> bool:
        client = self._get_client()
        if not client:
            return False
        
        try:
            client.secrets.kv.v2.create_or_update_secret(
                path=self._full_path(key),
                secret={'value': value},
                mount_point=self.mount_path
            )
            return True
        except Exception as e:
            logger.error(f"Failed to set secret {key}: {e}")
            return False
    
    def delete_secret(self, key: str) -> bool:
        client = self._get_client()
        if not client:
            return False
        
        try:
            client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=self._full_path(key),
                mount_point=self.mount_path
            )
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret {key}: {e}")
            return False
    
    def list_secrets(self) -> list:
        client = self._get_client()
        if not client:
            return []
        
        try:
            result = client.secrets.kv.v2.list_secrets(
                path=self.path_prefix,
                mount_point=self.mount_path
            )
            return result['data']['keys']
        except Exception as e:
            logger.error(f"Failed to list secrets: {e}")
            return []


class VaultManager:
    """
    密钥管理器
    统一的密钥访问接口，支持多后端切换
    """
    
    def __init__(self, backend: Optional[VaultBackend] = None):
        self.backend = backend or self._create_default_backend()
        self._audit_log: list = []
    
    def _create_default_backend(self) -> VaultBackend:
        """根据环境变量创建默认后端"""
        backend_type = os.environ.get("XUANJIAN_VAULT_BACKEND", "env").lower()
        
        if backend_type == "file":
            return FileVaultBackend(
                file_path=os.environ.get("XUANJIAN_SECRETS_FILE", ".secrets")
            )
        elif backend_type == "vault":
            return HashiCorpVaultBackend()
        else:
            return EnvVaultBackend()
    
    def _log_access(self, operation: str, key: str, success: bool):
        """记录访问日志"""
        self._audit_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "operation": operation,
            "key": key,
            "success": success
        })
        # 保持最近1000条记录
        if len(self._audit_log) > 1000:
            self._audit_log = self._audit_log[-1000:]
    
    def get_secret(self, key: str) -> Optional[str]:
        """获取密钥"""
        value = self.backend.get_secret(key)
        self._log_access("get", key, value is not None)
        return value
    
    def set_secret(self, key: str, value: str) -> bool:
        """设置密钥"""
        success = self.backend.set_secret(key, value)
        self._log_access("set", key, success)
        return success
    
    def delete_secret(self, key: str) -> bool:
        """删除密钥"""
        success = self.backend.delete_secret(key)
        self._log_access("delete", key, success)
        return success
    
    def list_secrets(self) -> list:
        """列出所有密钥名称"""
        return self.backend.list_secrets()
    
    def get_audit_log(self, limit: int = 100) -> list:
        """获取审计日志"""
        return self._audit_log[-limit:]
    
    def get_or_default(self, key: str, default: str = "") -> str:
        """获取密钥，如不存在则返回默认值"""
        value = self.get_secret(key)
        return value if value is not None else default


# 全局单例
_vault_manager: Optional[VaultManager] = None


@lru_cache()
def get_vault() -> VaultManager:
    """获取密钥管理器单例"""
    global _vault_manager
    if _vault_manager is None:
        _vault_manager = VaultManager()
    return _vault_manager
