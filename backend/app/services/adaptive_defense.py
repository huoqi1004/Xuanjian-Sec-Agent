#!/usr/bin/env python3
"""
Adaptive Defense System - 实时防御自适应调整模块
与Self-Improving Agent集成，实现实时动态防御
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from enum import Enum
import threading
import asyncio

logger = logging.getLogger(__name__)


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DefenseMode(str, Enum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    HIGH_ALERT = "high_alert"
    EMERGENCY = "emergency"


class AdaptationType(str, Enum):
    RULE_UPDATE = "rule_update"
    THRESHOLD_ADJUSTMENT = "threshold_adjustment"
    RESPONSE_STRATEGY = "response_strategy"
    SCAN_OPTIMIZATION = "scan_optimization"
    BLOCKING_POLICY = "blocking_policy"


class AdaptiveDefenseSystem:
    """
    实时防御自适应调整系统
    根据威胁情报和历史经验自动调整防御策略
    """
    
    def __init__(self, data_dir: str = None):
        self.data_dir = Path(data_dir) if data_dir else Path(__file__).parent.parent / "data" / "adaptive_defense"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.defense_config_file = self.data_dir / "defense_config.json"
        self.threat_history_file = self.data_dir / "threat_history.json"
        self.adaptation_log_file = self.data_dir / "adaptation_log.json"
        self.defense_rules_file = self.data_dir / "defense_rules.json"
        
        self._init_data_files()
        
        self.current_defense_mode = DefenseMode.NORMAL
        self.threat_level = ThreatLevel.INFO
        
        self._lock = threading.Lock()
        
        self.auto_adaptation_enabled = True
        self.adaptation_threshold = 0.7
        
        logger.info("AdaptiveDefenseSystem initialized")
    
    def _init_data_files(self):
        """初始化数据文件"""
        if not self.defense_config_file.exists():
            self._save_json(self.defense_config_file, {
                "defense_mode": DefenseMode.NORMAL.value,
                "threat_level": ThreatLevel.INFO.value,
                "auto_adaptation": True,
                "last_updated": datetime.now().isoformat(),
                "config": {
                    "scan_sensitivity": 0.7,
                    "block_threshold": 0.8,
                    "alert_threshold": 0.5,
                    "response_timeout": 30,
                    "max_block_duration": 3600
                }
            })
        
        if not self.threat_history_file.exists():
            self._save_json(self.threat_history_file, {
                "threats": [],
                "statistics": {
                    "total_threats": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0
                },
                "last_updated": datetime.now().isoformat()
            })
        
        if not self.adaptation_log_file.exists():
            self._save_json(self.adaptation_log_file, {
                "adaptations": [],
                "last_updated": datetime.now().isoformat()
            })
        
        if not self.defense_rules_file.exists():
            self._save_json(self.defense_rules_file, {
                "rules": [],
                "custom_rules": [],
                "disabled_rules": [],
                "last_updated": datetime.now().isoformat()
            })
    
    def _load_json(self, file_path: Path) -> Dict:
        """加载JSON文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return {}
    
    def _save_json(self, file_path: Path, data: Dict):
        """保存JSON文件"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving {file_path}: {e}")
    
    def analyze_threat(self, threat_data: Dict) -> Dict:
        """
        分析威胁并确定响应策略
        """
        threat_id = f"threat_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        threat = {
            "id": threat_id,
            "timestamp": datetime.now().isoformat(),
            "type": threat_data.get("type", "unknown"),
            "source": threat_data.get("source", "unknown"),
            "severity": threat_data.get("severity", "medium"),
            "details": threat_data.get("details", {}),
            "detection_method": threat_data.get("detection_method", "manual"),
            "response_taken": None,
            "effectiveness": None
        }
        
        severity_score = self._calculate_severity_score(threat)
        threat["severity_score"] = severity_score
        
        recommended_response = self._determine_response(severity_score)
        threat["recommended_response"] = recommended_response
        
        self._record_threat(threat)
        
        if self.auto_adaptation_enabled:
            self._auto_adapt(severity_score, threat)
        
        return threat
    
    def _calculate_severity_score(self, threat: Dict) -> float:
        """计算威胁严重性分数"""
        severity = threat.get("severity", "medium").lower()
        
        base_scores = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
            "info": 0.1
        }
        
        base_score = base_scores.get(severity, 0.5)
        
        if threat.get("type") in ["ransomware", "apt", "zero_day"]:
            base_score = min(1.0, base_score + 0.3)
        
        threat_source = threat.get("source", "")
        if "internal" in threat_source:
            base_score = min(1.0, base_score + 0.1)
        
        return base_score
    
    def _determine_response(self, severity_score: float) -> Dict:
        """确定响应策略"""
        if severity_score >= 0.9:
            response = {
                "action": "immediate_block",
                "priority": "critical",
                "mode": DefenseMode.EMERGENCY.value,
                "duration": 86400
            }
        elif severity_score >= 0.7:
            response = {
                "action": "isolate_and_analyze",
                "priority": "high",
                "mode": DefenseMode.HIGH_ALERT.value,
                "duration": 3600
            }
        elif severity_score >= 0.5:
            response = {
                "action": "enhanced_monitoring",
                "priority": "medium",
                "mode": DefenseMode.ELEVATED.value,
                "duration": 300
            }
        else:
            response = {
                "action": "log_and_alert",
                "priority": "low",
                "mode": DefenseMode.NORMAL.value,
                "duration": 60
            }
        
        return response
    
    def _record_threat(self, threat: Dict):
        """记录威胁"""
        data = self._load_json(self.threat_history_file)
        
        data["threats"].append(threat)
        
        if len(data["threats"]) > 1000:
            data["threats"] = data["threats"][-1000:]
        
        stats = data.get("statistics", {})
        stats["total_threats"] = stats.get("total_threats", 0) + 1
        
        severity = threat.get("severity", "medium").lower()
        if severity == "critical":
            stats["critical_count"] = stats.get("critical_count", 0) + 1
        elif severity == "high":
            stats["high_count"] = stats.get("high_count", 0) + 1
        elif severity == "medium":
            stats["medium_count"] = stats.get("medium_count", 0) + 1
        elif severity == "low":
            stats["low_count"] = stats.get("low_count", 0) + 1
        
        data["statistics"] = stats
        data["last_updated"] = datetime.now().isoformat()
        
        self._save_json(self.threat_history_file, data)
    
    def _auto_adapt(self, severity_score: float, threat: Dict):
        """自动适应调整"""
        current_config = self._load_json(self.defense_config_file)
        
        adaptation_made = False
        
        if severity_score >= 0.8:
            self.current_defense_mode = DefenseMode.HIGH_ALERT
            current_config["config"]["scan_sensitivity"] = min(
                1.0, current_config["config"].get("scan_sensitivity", 0.7) + 0.1
            )
            current_config["config"]["block_threshold"] = min(
                1.0, current_config["config"].get("block_threshold", 0.8) + 0.1
            )
            adaptation_made = True
            
            self._log_adaptation(
                AdaptationType.THRESHOLD_ADJUSTMENT,
                "Increased scan sensitivity due to high threat level",
                {"severity_score": severity_score}
            )
        
        elif severity_score >= 0.6:
            self.current_defense_mode = DefenseMode.ELEVATED
            adaptation_made = True
        
        current_config["defense_mode"] = self.current_defense_mode.value
        current_config["threat_level"] = self._calculate_threat_level(severity_score)
        current_config["last_updated"] = datetime.now().isoformat()
        
        self._save_json(self.defense_config_file, current_config)
        
        logger.info(f"Auto-adapted defense mode to: {self.current_defense_mode.value}")
    
    def _calculate_threat_level(self, severity_score: float) -> str:
        """计算威胁级别"""
        if severity_score >= 0.8:
            return ThreatLevel.CRITICAL.value
        elif severity_score >= 0.6:
            return ThreatLevel.HIGH.value
        elif severity_score >= 0.4:
            return ThreatLevel.MEDIUM.value
        elif severity_score >= 0.2:
            return ThreatLevel.LOW.value
        else:
            return ThreatLevel.INFO.value
    
    def _log_adaptation(self, adaptation_type: AdaptationType, description: str, details: Dict = None):
        """记录适应调整"""
        data = self._load_json(self.adaptation_log_file)
        
        adaptation = {
            "id": f"adapt_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "type": adaptation_type.value,
            "description": description,
            "details": details or {},
            "defense_mode": self.current_defense_mode.value
        }
        
        data["adaptations"].append(adaptation)
        
        if len(data["adaptations"]) > 500:
            data["adaptations"] = data["adaptations"][-500:]
        
        data["last_updated"] = datetime.now().isoformat()
        
        self._save_json(self.adaptation_log_file, data)
    
    def update_defense_rule(self, rule_id: str, updates: Dict) -> bool:
        """更新防御规则"""
        data = self._load_json(self.defense_rules_file)
        
        for rule in data.get("rules", []):
            if rule.get("id") == rule_id:
                rule.update(updates)
                rule["last_modified"] = datetime.now().isoformat()
                
                data["last_updated"] = datetime.now().isoformat()
                self._save_json(self.defense_rules_file, data)
                
                self._log_adaptation(
                    AdaptationType.RULE_UPDATE,
                    f"Updated rule: {rule_id}",
                    updates
                )
                
                return True
        
        return False
    
    def add_custom_rule(self, rule: Dict) -> str:
        """添加自定义规则"""
        data = self._load_json(self.defense_rules_file)
        
        rule_id = f"custom_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        new_rule = {
            "id": rule_id,
            "name": rule.get("name", "Custom Rule"),
            "pattern": rule.get("pattern", ""),
            "action": rule.get("action", "alert"),
            "severity": rule.get("severity", "medium"),
            "enabled": True,
            "created": datetime.now().isoformat(),
            "last_modified": datetime.now().isoformat(),
            "source": "self_improving"
        }
        
        data["custom_rules"].append(new_rule)
        data["last_updated"] = datetime.now().isoformat()
        
        self._save_json(self.defense_rules_file, data)
        
        self._log_adaptation(
            AdaptationType.RULE_UPDATE,
            f"Added custom rule: {rule_id}",
            {"rule_name": rule.get("name")}
        )
        
        return rule_id
    
    def optimize_scan_parameters(self, scan_results: Dict) -> Dict:
        """
        基于扫描结果优化扫描参数
        """
        optimization = {
            "timestamp": datetime.now().isoformat(),
            "scan_type": scan_results.get("type", "unknown"),
            "findings": scan_results.get("findings", []),
            "recommendations": []
        }
        
        findings = scan_results.get("findings", [])
        
        if not findings:
            optimization["recommendations"].append({
                "type": "decrease_sensitivity",
                "reason": "No threats found, can reduce scan intensity",
                "action": "reduce_scan_sensitivity"
            })
        
        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        if critical_count > 5:
            optimization["recommendations"].append({
                "type": "increase_sensitivity",
                "reason": f"Found {critical_count} critical threats",
                "action": "increase_scan_sensitivity"
            })
        
        false_positive_rate = scan_results.get("false_positive_rate", 0)
        if false_positive_rate > 0.3:
            optimization["recommendations"].append({
                "type": "tune_rules",
                "reason": f"High false positive rate: {false_positive_rate:.1%}",
                "action": "refine_detection_rules"
            })
        
        return optimization
    
    def get_current_defense_status(self) -> Dict:
        """获取当前防御状态"""
        config = self._load_json(self.defense_config_file)
        
        threat_history = self._load_json(self.threat_history_file)
        recent_threats = [
            t for t in threat_history.get("threats", [])
            if datetime.fromisoformat(t["timestamp"]) > datetime.now() - timedelta(hours=24)
        ]
        
        return {
            "defense_mode": self.current_defense_mode.value,
            "threat_level": self.threat_level.value,
            "config": config.get("config", {}),
            "recent_threats_count": len(recent_threats),
            "total_threats_24h": threat_history.get("statistics", {}).get("total_threats", 0),
            "auto_adaptation": self.auto_adaptation_enabled,
            "last_updated": config.get("last_updated")
        }
    
    def get_threat_statistics(self, days: int = 7) -> Dict:
        """获取威胁统计"""
        data = self._load_json(self.threat_history_file)
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        recent_threats = [
            t for t in data.get("threats", [])
            if datetime.fromisoformat(t["timestamp"]) >= cutoff_date
        ]
        
        stats = {
            "period_days": days,
            "total_threats": len(recent_threats),
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "by_type": {},
            "top_sources": []
        }
        
        for threat in recent_threats:
            severity = threat.get("severity", "medium").lower()
            if severity in stats["by_severity"]:
                stats["by_severity"][severity] += 1
            
            threat_type = threat.get("type", "unknown")
            stats["by_type"][threat_type] = stats["by_type"].get(threat_type, 0) + 1
        
        source_counts = {}
        for threat in recent_threats:
            source = threat.get("source", "unknown")
            source_counts[source] = source_counts.get(source, 0) + 1
        
        stats["top_sources"] = sorted(
            source_counts.items(), key=lambda x: x[1], reverse=True
        )[:5]
        
        return stats
    
    def get_adaptation_history(self, limit: int = 20) -> List[Dict]:
        """获取适应调整历史"""
        data = self._load_json(self.adaptation_log_file)
        
        return data.get("adaptations", [])[-limit:]
    
    def reset_defense_mode(self):
        """重置防御模式到正常"""
        with self._lock:
            self.current_defense_mode = DefenseMode.NORMAL
            self.threat_level = ThreatLevel.INFO
            
            config = self._load_json(self.defense_config_file)
            config["defense_mode"] = DefenseMode.NORMAL.value
            config["threat_level"] = ThreatLevel.INFO.value
            config["last_updated"] = datetime.now().isoformat()
            
            self._save_json(self.defense_config_file, config)
            
            self._log_adaptation(
                AdaptationType.THRESHOLD_ADJUSTMENT,
                "Defense mode reset to normal",
                {}
            )
            
            logger.info("Defense mode reset to NORMAL")


def get_adaptive_defense_system() -> AdaptiveDefenseSystem:
    """获取自适应防御系统单例"""
    if not hasattr(get_adaptive_defense_system, "_instance"):
        get_adaptive_defense_system._instance = AdaptiveDefenseSystem()
    return get_adaptive_defense_system._instance
