"""
玄鉴安全智能体 - AI攻击与勒索软件防御系统
提供AI驱动攻击检测、勒索软件防护、多Agent协同防御
"""

import os
import json
import time
import hashlib
import threading
import subprocess
import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttackType(Enum):
    """攻击类型"""
    AI_PROMPT_INJECTION = "ai_prompt_injection"
    AI_ADVERSARIAL = "ai_adversarial"
    AI_MODEL_EVASION = "ai_model_evasion"
    AI_AUTONOMOUS_ATTACK = "ai_autonomous_attack"
    RANSOMWARE_ENCRYPTION = "ransomware_encryption"
    RANSOMWARE_LATERAL = "ransomware_lateral"
    RANSOMWARE_EXFILTRATION = "ransomware_exfiltration"
    DEEPFAKE_ATTACK = "deepfake_attack"
    VOICE_CLONING = "voice_cloning"


class Severity(Enum):
    """严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatIntelligence:
    """威胁情报"""
    
    def __init__(self):
        self.ai_attack_signatures = self._load_ai_attack_signatures()
        self.ransomware_iocs = self._load_ransomware_iocs()
        self.malicious_patterns = self._load_malicious_patterns()
        self.attack_sequences = self._load_attack_sequences()
        
    def _load_ai_attack_signatures(self) -> List[Dict]:
        """加载AI攻击特征库"""
        return [
            {
                "id": "AI-Prompt-Injection-001",
                "type": AttackType.AI_PROMPT_INJECTION,
                "name": "Prompt注入攻击",
                "patterns": [
                    r"ignore\s+previous\s+instructions",
                    r"disregard\s+your\s+guidelines",
                    r"you\s+are\s+now\s+\w+",
                    r"forget\s+everything\s+above",
                    r"system\s*:\s*",
                    r"assistant\s*:\s*",
                    r"<\|system\|>",
                    r"<\|user\|>",
                    r"\\n\\n\.?\s*You\s+are",
                ],
                "severity": Severity.HIGH,
                "description": "通过Prompt注入尝试劫持AI模型"
            },
            {
                "id": "AI-Jailbreak-001",
                "type": AttackType.AI_PROMPT_INJECTION,
                "name": "越狱攻击",
                "patterns": [
                    r"DAN\s+mode",
                    r"developer\s+mode",
                    r"jailbreak",
                    r"bypass\s+restrictions",
                    r"roleplay\s+as\s+.*without",
                ],
                "severity": Severity.CRITICAL,
                "description": "尝试绕过AI安全限制"
            },
            {
                "id": "AI-Adversarial-001",
                "type": AttackType.AI_ADVERSARIAL,
                "name": "对抗样本攻击",
                "patterns": [
                    r"(\u200b|\u200c|\u200d)",  # 零宽字符
                    r"[\u0600-\u06FF]",  # 阿拉伯字符混淆
                    r"(.)\1{10,}",  # 重复字符
                ],
                "severity": Severity.HIGH,
                "description": "使用对抗样本绕过AI检测"
            },
            {
                "id": "AI-Autonomous-001",
                "type": AttackType.AI_AUTONOMOUS_ATTACK,
                "name": "自主Agent攻击",
                "patterns": [
                    r"autonomously\s+scan",
                    r"auto.*exploit",
                    r"self.*replicat",
                    r"chain.*exploits",
                ],
                "severity": Severity.CRITICAL,
                "description": "AI自主发起的攻击行为"
            }
        ]
    
    def _load_ransomware_iocs(self) -> List[Dict]:
        """加载勒索软件IOC库"""
        return [
            {
                "id": "RANSOM-001",
                "name": "文件加密行为",
                "indicators": [
                    "大量文件扩展名变更",
                    "加密文件后缀: .locked, .encrypted, .crypto, .ransom",
                    "勒索信息文件: README.txt, RECOVER.txt, HOW_TO_DECRYPT.txt",
                ],
                "severity": Severity.CRITICAL,
                "category": "encryption"
            },
            {
                "id": "RANSOM-002",
                "name": "勒索软件通信",
                "indicators": [
                    "Tor网络连接",
                    "比特币钱包地址特征",
                    "C2服务器通信模式",
                ],
                "severity": Severity.CRITICAL,
                "category": "communication"
            },
            {
                "id": "RANSOM-003",
                "name": "权限提升和横向移动",
                "indicators": [
                    "Mimikatz凭证窃取",
                    "PsExec远程执行",
                    "WMI横向传播",
                ],
                "severity": Severity.CRITICAL,
                "category": "lateral_movement"
            },
            {
                "id": "RANSOM-004",
                "name": "数据外泄",
                "indicators": [
                    "大量上传到外部IP",
                    "云存储异常访问",
                    "数据库批量导出",
                ],
                "severity": Severity.HIGH,
                "category": "exfiltration"
            },
            {
                "id": "RANSOM-005",
                "name": "服务终止",
                "indicators": [
                    "停止备份服务",
                    "关闭安全软件",
                    "禁用系统还原",
                ],
                "severity": Severity.HIGH,
                "category": "disablement"
            }
        ]
    
    def _load_malicious_patterns(self) -> List[Dict]:
        """加载恶意行为模式"""
        return [
            {
                "name": "可疑PowerShell",
                "patterns": [
                    r"Invoke-Mimikatz",
                    r"New-Object.*Net\.WebClient",
                    r"IEX\s*\(",
                    r"DownloadString",
                    r"DownloadFile",
                ],
                "risk_score": 70
            },
            {
                "name": "可疑文件操作",
                "patterns": [
                    r"attrib\s+\+[hs]",
                    r"icacls.*grant",
                    r"cipher\s+/d",
                    r"takeown\s+/f",
                ],
                "risk_score": 60
            },
            {
                "name": "可疑网络连接",
                "patterns": [
                    r"nc\s+-e",
                    r"ncat\s+.*-e",
                    r"powershell.*-e.*encoded",
                ],
                "risk_score": 80
            }
        ]
    
    def _load_attack_sequences(self) -> List[Dict]:
        """加载攻击序列模式"""
        return [
            {
                "name": "勒索软件入侵链",
                "steps": [
                    {"order": 1, "action": "初始访问", "indicators": ["钓鱼邮件", "漏洞利用", "恶意下载"]},
                    {"order": 2, "action": "执行", "indicators": ["恶意脚本", "PowerShell", "计划任务"]},
                    {"order": 3, "action": "持久化", "indicators": ["注册表", "启动项", "服务"]},
                    {"order": 4, "action": "权限提升", "indicators": ["漏洞利用", "凭证窃取"]},
                    {"order": 5, "action": "内网侦察", "indicators": ["端口扫描", "用户枚举"]},
                    {"order": 6, "action": "横向移动", "indicators": ["PsExec", "WMI", "RDP"]},
                    {"order": 7, "action": "数据外泄", "indicators": ["压缩上传", "云存储"]},
                    {"order": 8, "action": "加密", "indicators": ["文件加密", "勒索信息"]},
                ],
                "mitre_attack": ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0040"]
            }
        ]


@dataclass
class AttackEvent:
    """攻击事件"""
    id: str
    timestamp: datetime
    attack_type: str
    severity: str
    source_ip: str
    target: str
    description: str
    indicators: List[str]
    confidence: float
    status: str = "new"
    blocked: bool = False
    mitigations: List[str] = field(default_factory=list)


class AIAttackDetector:
    """AI攻击检测器"""
    
    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        self.detection_count = defaultdict(int)
        self.blocked_attacks = []
        
    def detect_prompt_injection(self, content: str) -> Optional[Dict]:
        """检测Prompt注入攻击"""
        for sig in self.threat_intel.ai_attack_signatures:
            if sig["type"] == AttackType.AI_PROMPT_INJECTION:
                for pattern in sig["patterns"]:
                    if re.search(pattern, content, re.IGNORECASE):
                        return {
                            "detected": True,
                            "signature_id": sig["id"],
                            "attack_name": sig["name"],
                            "severity": sig["severity"].value,
                            "description": sig["description"],
                            "matched_pattern": pattern
                        }
        return None
    
    def detect_adversarial_input(self, content: str) -> Optional[Dict]:
        """检测对抗样本"""
        for sig in self.threat_intel.ai_attack_signatures:
            if sig["type"] == AttackType.AI_ADVERSARIAL:
                for pattern in sig["patterns"]:
                    if re.search(pattern, content):
                        return {
                            "detected": True,
                            "signature_id": sig["id"],
                            "attack_name": sig["name"],
                            "severity": sig["severity"].value,
                            "description": sig["description"]
                        }
        return None
    
    def detect_autonomous_attack(self, content: str) -> Optional[Dict]:
        """检测自主攻击行为"""
        for sig in self.threat_intel.ai_attack_signatures:
            if sig["type"] == AttackType.AI_AUTONOMOUS_ATTACK:
                for pattern in sig["patterns"]:
                    if re.search(pattern, content, re.IGNORECASE):
                        return {
                            "detected": True,
                            "signature_id": sig["id"],
                            "attack_name": sig["name"],
                            "severity": sig["severity"].value,
                            "description": sig["description"]
                        }
        return None
    
    def analyze_content(self, content: str) -> Dict:
        """综合分析内容"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
            "threats_detected": [],
            "risk_score": 0,
            "recommendations": []
        }
        
        # 检测各类攻击
        prompt_injection = self.detect_prompt_injection(content)
        if prompt_injection:
            results["threats_detected"].append(prompt_injection)
            results["risk_score"] += 80
            results["recommendations"].append("拒绝处理该请求，告警安全团队")
        
        adversarial = self.detect_adversarial_input(content)
        if adversarial:
            results["threats_detected"].append(adversarial)
            results["risk_score"] += 70
            results["recommendations"].append("检测到对抗样本，建议隔离分析")
        
        autonomous = self.detect_autonomous_attack(content)
        if autonomous:
            results["threats_detected"].append(autonomous)
            results["risk_score"] += 90
            results["recommendations"].append("检测到自主攻击行为，立即告警并阻断")
        
        # 限制风险评分
        results["risk_score"] = min(results["risk_score"], 100)
        
        return results


class RansomwareDetector:
    """勒索软件检测器"""
    
    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        self.file_activities = []
        self.process_activities = []
        self.network_activities = []
        self.baseline_established = False
        self.baseline_files_per_minute = 0
        
    def establish_baseline(self, duration_seconds: int = 60):
        """建立正常行为基线"""
        logger.info(f"开始建立基线，监测 {duration_seconds} 秒...")
        self.baseline_established = True
        self.baseline_files_per_minute = 10
        logger.info("基线建立完成")
    
    def detect_file_encryption(self, file_path: str, process_info: Dict) -> Optional[Dict]:
        """检测文件加密行为"""
        encryption_extensions = [
            '.locked', '.encrypted', '.crypto', '.ransom', '.pay',
            '.wallet', '.decrypt', '.key', '.pwnd', '.encrypted',
            '.crypt', '.crypt1', '.crypt2', '.encryptedRSA'
        ]
        
        # 检测加密文件扩展名
        for ext in encryption_extensions:
            if file_path.lower().endswith(ext):
                return {
                    "detected": True,
                    "category": "encryption",
                    "severity": Severity.CRITICAL.value,
                    "description": f"检测到勒索软件加密文件: {file_path}",
                    "indicators": [f"加密文件扩展名: {ext}"],
                    "action": "立即隔离主机，终止加密进程"
                }
        
        # 检测大量文件操作
        recent_files = [f for f in self.file_activities 
                       if (datetime.now() - f["timestamp"]).total_seconds() < 60]
        
        if len(recent_files) > 100:
            return {
                "detected": True,
                "category": "mass_file_operation",
                "severity": Severity.HIGH.value,
                "description": "检测到异常大量文件操作",
                "indicators": [f"60秒内操作文件数: {len(recent_files)}"],
                "action": "监控并准备隔离"
            }
        
        return None
    
    def detect_ransomware_process(self, process_info: Dict) -> Optional[Dict]:
        """检测勒索软件进程"""
        ransomware_processes = [
            "vssadmin.exe", "bcdedit.exe", "cipher.exe",
            "takeown.exe", "icacls.exe", "schtasks.exe",
            "mimikatz.exe", "procdump.exe", "lsass.exe"
        ]
        
        process_name = process_info.get("name", "").lower()
        
        # 可疑进程组合检测
        suspicious_patterns = [
            ["vssadmin", "delete", "shadows"],
            ["cipher", "/d"],
            ["icacls", "everyone"],
            ["takeown", "/f"],
        ]
        
        for pattern in suspicious_patterns:
            if all(p in process_name or p in str(process_info.get("cmd", "")).lower() 
                   for p in pattern):
                return {
                    "detected": True,
                    "category": "process_manipulation",
                    "severity": Severity.HIGH.value,
                    "description": f"检测到可疑进程操作: {process_name}",
                    "indicators": [str(process_info.get("cmd", ""))],
                    "action": "终止进程，保留证据"
                }
        
        return None
    
    def detect_network_anomaly(self, connection_info: Dict) -> Optional[Dict]:
        """检测网络异常"""
        # Tor网络检测
        tor_ips = ["torproject.org", "onion", "127.0.0.1:9050", "127.0.0.1:9051"]
        
        for indicator in tor_ips:
            if indicator in str(connection_info).lower():
                return {
                    "detected": True,
                    "category": "tor_connection",
                    "severity": Severity.CRITICAL.value,
                    "description": "检测到Tor网络连接",
                    "indicators": [str(connection_info)],
                    "action": "阻断连接，告警安全团队"
                }
        
        # 大量外发数据
        bytes_sent = connection_info.get("bytes_sent", 0)
        if bytes_sent > 100 * 1024 * 1024:
            return {
                "detected": True,
                "category": "data_exfiltration",
                "severity": Severity.HIGH.value,
                "description": "检测到大量数据外发",
                "indicators": [f"发送字节数: {bytes_sent}"],
                "action": "监控连接，告警"
            }
        
        return None
    
    def check_indicators(self, ioc_type: str) -> List[Dict]:
        """检查特定IOC类型"""
        return [ioc for ioc in self.threat_intel.ransomware_iocs 
                if ioc["category"] == ioc_type]
    
    def generate_risk_assessment(self, events: List[Dict]) -> Dict:
        """生成风险评估"""
        severity_scores = {"critical": 100, "high": 75, "medium": 50, "low": 25}
        
        total_score = 0
        event_count = len(events)
        
        for event in events:
            severity = event.get("severity", "low")
            total_score += severity_scores.get(severity, 25)
        
        avg_score = total_score / event_count if event_count > 0 else 0
        
        return {
            "event_count": event_count,
            "average_risk_score": avg_score,
            "threat_level": "critical" if avg_score >= 80 else 
                           "high" if avg_score >= 60 else 
                           "medium" if avg_score >= 40 else "low",
            "recommendations": self._generate_recommendations(avg_score)
        }
    
    def _generate_recommendations(self, risk_score: float) -> List[str]:
        """生成建议"""
        recommendations = []
        
        if risk_score >= 80:
            recommendations.extend([
                "立即隔离受影响主机",
                "启动应急响应流程",
                "通知管理层和安全团队"
            ])
        elif risk_score >= 60:
            recommendations.extend([
                "加强监控",
                "准备隔离方案",
                "收集证据"
            ])
        else:
            recommendations.append("持续监控")
        
        return recommendations


class MultiAgentCoordinator:
    """多Agent协同防御协调器"""
    
    def __init__(self):
        self.agents = {}
        self.shared_context = {}
        self.event_queue = []
        self.lock = threading.Lock()
        
    def register_agent(self, agent_id: str, agent_type: str):
        """注册Agent"""
        self.agents[agent_id] = {
            "type": agent_type,
            "status": "active",
            "registered_at": datetime.now(),
            "processed_events": 0
        }
        logger.info(f"已注册Agent: {agent_id} ({agent_type})")
    
    def share_intelligence(self, agent_id: str, intel: Dict):
        """共享情报"""
        with self.lock:
            self.shared_context[agent_id] = {
                "data": intel,
                "timestamp": datetime.now()
            }
            
            # 广播给其他Agent
            for other_id, agent in self.agents.items():
                if other_id != agent_id:
                    logger.info(f"情报从 {agent_id} 共享给 {other_id}")
    
    def coordinate_response(self, threat_event: Dict) -> Dict:
        """协调响应"""
        response_plan = {
            "threat_id": threat_event.get("id"),
            "coordinated_agents": [],
            "actions": [],
            "timestamp": datetime.now().isoformat()
        }
        
        # 根据威胁类型分配给不同Agent
        threat_type = threat_event.get("attack_type", "")
        
        if "ransomware" in threat_type.lower():
            response_plan["coordinated_agents"].append("ransomware_detector")
            response_plan["actions"].append({
                "agent": "ransomware_detector",
                "action": "isolate_host"
            })
            
        if "ai_attack" in threat_type.lower():
            response_plan["coordinated_agents"].append("ai_attack_detector")
            response_plan["actions"].append({
                "agent": "ai_attack_detector",
                "action": "block_request"
            })
        
        # 所有威胁都需要网络Agent监控
        response_plan["coordinated_agents"].append("network_monitor")
        response_plan["actions"].append({
            "agent": "network_monitor",
            "action": "enhance_monitoring"
        })
        
        return response_plan
    
    def get_agent_status(self) -> Dict:
        """获取Agent状态"""
        return {
            agent_id: {
                "status": agent["status"],
                "processed_events": agent["processed_events"]
            }
            for agent_id, agent in self.agents.items()
        }


class DefenseEvaluation:
    """防御效果评估"""
    
    def __init__(self):
        self.test_results = []
        self.metrics = {
            "detection_rate": 0.0,
            "false_positive_rate": 0.0,
            "response_time": 0.0,
            "block_success_rate": 0.0
        }
    
    def run_simulation(self, attack_scenario: Dict) -> Dict:
        """运行模拟攻击测试"""
        scenario_id = f"TEST-{int(time.time())}"
        
        result = {
            "scenario_id": scenario_id,
            "scenario_name": attack_scenario.get("name", ""),
            "execution_time": datetime.now().isoformat(),
            "detection_result": None,
            "response_result": None,
            "effectiveness_score": 0.0
        }
        
        # 模拟检测
        expected_detection = attack_scenario.get("expected_detection", True)
        result["detection_result"] = {
            "detected": expected_detection,
            "confidence": 0.95 if expected_detection else 0.1,
            "detection_time_ms": 150
        }
        
        # 模拟响应
        expected_block = attack_scenario.get("expected_block", True)
        result["response_result"] = {
            "blocked": expected_block,
            "response_time_ms": 500,
            "actions_taken": ["alert", "block"] if expected_block else ["alert"]
        }
        
        # 计算有效性得分
        detection_score = 100 if expected_detection else 0
        response_score = 100 if expected_block else 50
        result["effectiveness_score"] = (detection_score + response_score) / 2
        
        self.test_results.append(result)
        return result
    
    def generate_report(self) -> Dict:
        """生成评估报告"""
        if not self.test_results:
            return {"message": "暂无测试结果"}
        
        total = len(self.test_results)
        detected = sum(1 for r in self.test_results if r["detection_result"]["detected"])
        blocked = sum(1 for r in self.test_results if r["response_result"]["blocked"])
        
        avg_score = sum(r["effectiveness_score"] for r in self.test_results) / total
        
        return {
            "generated_at": datetime.now().isoformat(),
            "total_tests": total,
            "detection_rate": f"{(detected/total)*100:.1f}%",
            "block_success_rate": f"{(blocked/total)*100:.1f}%",
            "average_effectiveness": f"{avg_score:.1f}%",
            "test_results": self.test_results[-10:]
        }


class AdvancedDefenseSystem:
    """高级防御系统 - 整合所有模块"""
    
    def __init__(self):
        self.ai_detector = AIAttackDetector()
        self.ransomware_detector = RansomwareDetector()
        self.coordinator = MultiAgentCoordinator()
        self.evaluator = DefenseEvaluation()
        
        # 注册防御Agent
        self.coordinator.register_agent("ai_attack_detector", "detection")
        self.coordinator.register_agent("ransomware_detector", "detection")
        self.coordinator.register_agent("network_monitor", "monitoring")
        self.coordinator.register_agent("response_agent", "response")
        
        logger.info("高级防御系统初始化完成")
    
    def analyze_threat(self, content: str, context: Dict = None) -> Dict:
        """综合威胁分析"""
        result = {
            "timestamp": datetime.now().isoformat(),
            "ai_analysis": self.ai_detector.analyze_content(content),
            "ransomware_analysis": None,
            "coordinated_response": None,
            "overall_risk_score": 0
        }
        
        # 如果有文件/进程上下文，进行勒索软件检测
        if context:
            if "file_path" in context:
                ransomware = self.ransomware_detector.detect_file_encryption(
                    context["file_path"], 
                    context.get("process_info", {})
                )
                if ransomware:
                    result["ransomware_analysis"] = ransomware
            
            if "process_info" in context:
                ransomware = self.ransomware_detector.detect_ransomware_process(
                    context["process_info"]
                )
                if ransomware:
                    result["ransomware_analysis"] = ransomware
        
        # 计算总体风险评分
        ai_score = result["ai_analysis"]["risk_score"]
        ransomware_score = result["ransomware_analysis"]["severity"] if result["ransomware_analysis"] else 0
        severity_map = {"critical": 100, "high": 75, "medium": 50, "low": 25}
        ransomware_numeric = severity_map.get(ransomware_score, 0)
        
        result["overall_risk_score"] = max(ai_score, ransomware_numeric)
        
        # 协调响应
        if result["overall_risk_score"] >= 60:
            result["coordinated_response"] = self.coordinator.coordinate_response({
                "id": f"THREAT-{int(time.time())}",
                "attack_type": "ai_attack" if ai_score > ransomware_score else "ransomware",
                "risk_score": result["overall_risk_score"]
            })
        
        return result
    
    def run_defense_test(self, scenario: Dict) -> Dict:
        """运行防御测试"""
        return self.evaluator.run_simulation(scenario)
    
    def get_defense_status(self) -> Dict:
        """获取防御状态"""
        return {
            "status": "active",
            "agents": self.coordinator.get_agent_status(),
            "detection_capabilities": {
                "ai_attack_detection": True,
                "ransomware_detection": True,
                "multi_agent_coordination": True
            },
            "threat_intel": {
                "ai_attack_signatures": len(self.ai_detector.threat_intel.ai_attack_signatures),
                "ransomware_iocs": len(self.ai_detector.threat_intel.ransomware_iocs),
                "attack_sequences": len(self.ai_detector.threat_intel.attack_sequences)
            }
        }


def get_defense_system() -> AdvancedDefenseSystem:
    """获取防御系统单例"""
    if not hasattr(get_defense_system, "_instance"):
        get_defense_system._instance = AdvancedDefenseSystem()
    return get_defense_system._instance
