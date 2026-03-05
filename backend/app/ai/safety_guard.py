"""
玄鉴安全智能体 - AI安全防护层
多层防护体系，防御Prompt注入、越狱等攻击
"""

import logging
import re
import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ============ 枚举定义 ============

class ThreatType(str, Enum):
    """威胁类型"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SCOPE_VIOLATION = "scope_violation"
    HARMFUL_OUTPUT = "harmful_output"
    BASELINE_ANOMALY = "baseline_anomaly"


class ThreatLevel(str, Enum):
    """威胁等级"""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"


class RecommendedAction(str, Enum):
    """建议动作"""
    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    ESCALATE = "escalate"


# ============ 数据结构 ============

class ThreatReport(BaseModel):
    """威胁报告"""
    threat_type: ThreatType
    level: ThreatLevel
    evidence: List[str] = Field(default_factory=list)
    matched_patterns: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0, le=1)
    recommended_action: RecommendedAction = Field(default=RecommendedAction.ALLOW)


class ValidationResult(BaseModel):
    """验证结果"""
    is_safe: bool = True
    action: RecommendedAction = Field(default=RecommendedAction.ALLOW)
    threats: List[ThreatReport] = Field(default_factory=list)
    sanitized_text: Optional[str] = None
    validation_time_ms: int = 0


class AuditResult(BaseModel):
    """审计结果"""
    is_safe: bool = True
    violations: List[str] = Field(default_factory=list)
    sanitized_output: Optional[str] = None


# ============ 检测模式库 ============

# Prompt注入特征
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"disregard\s+(all\s+)?(above|previous|prior)",
    r"forget\s+(everything|all|your)\s+(about|instructions?|rules?)",
    r"you\s+are\s+now\s+[a-zA-Z]+",
    r"act\s+as\s+(if\s+you\s+are|a)\s+",
    r"pretend\s+(to\s+be|you\s+are)",
    r"new\s+instructions?:",
    r"\[SYSTEM\]",
    r"<\|im_start\|>system",
    r"---+\s*new\s*(task|instruction)",
    r"override\s+(previous|all)\s+",
    r"bypass\s+(safety|security|filter)",
]

# 越狱特征
JAILBREAK_PATTERNS = [
    r"DAN\s*mode",
    r"developer\s*mode\s*(enabled|on)",
    r"jailbreak",
    r"ignore\s+ethical\s+(guidelines?|constraints?)",
    r"without\s+(any\s+)?restrictions?",
    r"no\s+(ethical|moral)\s+(boundaries|limits)",
    r"hypothetically\s+speaking",
    r"for\s+(educational|research)\s+purposes?\s+only",
    r"in\s+a\s+fictional\s+(scenario|world)",
    r"roleplay\s+as\s+",
    r"you\s+have\s+no\s+(restrictions?|limits?)",
]

# 敏感信息模式
SENSITIVE_PATTERNS = [
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # 邮箱
    r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # 电话号码
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # IP地址
    r"(password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+",  # 密钥
    r"\b[A-Za-z0-9]{32,}\b",  # 长token
]


# ============ 安全防护层 ============

class SafetyGuard:
    """
    AI安全防护层
    
    多层防御体系：
    - L1: 规则引擎（正则匹配）
    - L2: 语义分析
    - L3: 行为基线
    - L4: 输出审查
    - L5: 范围校验
    """
    
    def __init__(self):
        self._injection_detector = PromptInjectionDetector()
        self._jailbreak_detector = JailbreakDetector()
        self._output_auditor = OutputAuditor()
        self._behavior_monitor = BehaviorMonitor()
        self._dual_approval_manager = DualApprovalManager()
        
        # 会话累积威胁分数
        self._session_threat_scores: Dict[str, float] = {}
    
    async def validate_input(
        self,
        text: str,
        session_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """
        验证输入
        
        Args:
            text: 输入文本
            session_id: 会话ID
            context: 上下文
        
        Returns:
            验证结果
        """
        start_time = time.time()
        threats = []
        
        # L1: Prompt注入检测
        injection_report = self._injection_detector.detect(text)
        if injection_report.level != ThreatLevel.SAFE:
            threats.append(injection_report)
        
        # L2: 越狱检测
        jailbreak_report = self._jailbreak_detector.detect(text, session_id)
        if jailbreak_report.level != ThreatLevel.SAFE:
            threats.append(jailbreak_report)
        
        # L3: 行为基线检测
        if session_id:
            anomaly_report = self._behavior_monitor.check_anomaly(
                session_id, len(text)
            )
            if anomaly_report and anomaly_report.level != ThreatLevel.SAFE:
                threats.append(anomaly_report)
        
        # 计算综合结果
        is_safe = all(t.level == ThreatLevel.SAFE for t in threats)
        action = self._determine_action(threats)
        
        # 净化处理
        sanitized = text
        if action == RecommendedAction.SANITIZE:
            sanitized = self._sanitize_input(text)
        
        return ValidationResult(
            is_safe=is_safe,
            action=action,
            threats=threats,
            sanitized_text=sanitized if sanitized != text else None,
            validation_time_ms=int((time.time() - start_time) * 1000)
        )
    
    async def validate_output(
        self,
        output: str,
        task_context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """
        验证输出
        
        Args:
            output: 输出文本
            task_context: 任务上下文
        
        Returns:
            验证结果
        """
        start_time = time.time()
        
        # L4: 输出内容审查
        audit_result = self._output_auditor.audit(output, task_context)
        
        threats = []
        if not audit_result.is_safe:
            threats.append(ThreatReport(
                threat_type=ThreatType.HARMFUL_OUTPUT,
                level=ThreatLevel.DANGEROUS,
                evidence=audit_result.violations,
                confidence=0.8,
                recommended_action=RecommendedAction.SANITIZE
            ))
        
        return ValidationResult(
            is_safe=audit_result.is_safe,
            action=RecommendedAction.SANITIZE if not audit_result.is_safe else RecommendedAction.ALLOW,
            threats=threats,
            sanitized_text=audit_result.sanitized_output,
            validation_time_ms=int((time.time() - start_time) * 1000)
        )
    
    def _determine_action(self, threats: List[ThreatReport]) -> RecommendedAction:
        """决定处理动作"""
        if not threats:
            return RecommendedAction.ALLOW
        
        max_level = max(t.level for t in threats)
        
        if max_level == ThreatLevel.CRITICAL:
            return RecommendedAction.BLOCK
        elif max_level == ThreatLevel.DANGEROUS:
            return RecommendedAction.ESCALATE
        elif max_level == ThreatLevel.SUSPICIOUS:
            return RecommendedAction.SANITIZE
        
        return RecommendedAction.ALLOW
    
    def _sanitize_input(self, text: str) -> str:
        """净化输入"""
        sanitized = text
        
        # 移除可疑的注入模式
        for pattern in INJECTION_PATTERNS:
            sanitized = re.sub(pattern, "[REMOVED]", sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    async def request_dual_approval(
        self,
        operation_type: str,
        operation_detail: Dict[str, Any],
        requested_by: str
    ) -> bool:
        """
        请求双签审批
        
        Args:
            operation_type: 操作类型
            operation_detail: 操作详情
            requested_by: 请求者
        
        Returns:
            是否批准
        """
        return await self._dual_approval_manager.request_approval(
            operation_type, operation_detail, requested_by
        )
    
    def get_security_report(self, session_id: str) -> Dict[str, Any]:
        """获取安全报告"""
        return {
            "session_id": session_id,
            "threat_score": self._session_threat_scores.get(session_id, 0),
            "behavior_baseline": self._behavior_monitor.get_baseline(session_id),
            "timestamp": datetime.now().isoformat()
        }


# ============ 检测器实现 ============

class PromptInjectionDetector:
    """Prompt注入检测器"""
    
    def detect(self, text: str) -> ThreatReport:
        """检测Prompt注入"""
        evidence = []
        matched_patterns = []
        
        # 正则匹配检测
        for pattern in INJECTION_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                evidence.extend(matches if isinstance(matches[0], str) else [m[0] for m in matches])
                matched_patterns.append(pattern)
        
        # 计算置信度
        if not matched_patterns:
            return ThreatReport(
                threat_type=ThreatType.PROMPT_INJECTION,
                level=ThreatLevel.SAFE,
                confidence=0.0,
                recommended_action=RecommendedAction.ALLOW
            )
        
        confidence = min(len(matched_patterns) * 0.3, 1.0)
        level = self._calculate_level(confidence)
        
        return ThreatReport(
            threat_type=ThreatType.PROMPT_INJECTION,
            level=level,
            evidence=evidence[:5],  # 限制数量
            matched_patterns=matched_patterns,
            confidence=confidence,
            recommended_action=self._get_action(level)
        )
    
    def _calculate_level(self, confidence: float) -> ThreatLevel:
        if confidence >= 0.8:
            return ThreatLevel.CRITICAL
        elif confidence >= 0.6:
            return ThreatLevel.DANGEROUS
        elif confidence >= 0.3:
            return ThreatLevel.SUSPICIOUS
        return ThreatLevel.SAFE
    
    def _get_action(self, level: ThreatLevel) -> RecommendedAction:
        if level == ThreatLevel.CRITICAL:
            return RecommendedAction.BLOCK
        elif level == ThreatLevel.DANGEROUS:
            return RecommendedAction.ESCALATE
        elif level == ThreatLevel.SUSPICIOUS:
            return RecommendedAction.SANITIZE
        return RecommendedAction.ALLOW


class JailbreakDetector:
    """越狱检测器"""
    
    def __init__(self):
        self._session_scores: Dict[str, float] = {}
    
    def detect(self, text: str, session_id: Optional[str] = None) -> ThreatReport:
        """检测越狱尝试"""
        evidence = []
        matched_patterns = []
        
        for pattern in JAILBREAK_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                evidence.extend(matches if isinstance(matches[0], str) else [str(m) for m in matches])
                matched_patterns.append(pattern)
        
        # 累积会话威胁
        if session_id:
            current_score = self._session_scores.get(session_id, 0)
            current_score += len(matched_patterns) * 0.2
            self._session_scores[session_id] = min(current_score, 1.0)
        
        if not matched_patterns:
            return ThreatReport(
                threat_type=ThreatType.JAILBREAK_ATTEMPT,
                level=ThreatLevel.SAFE,
                confidence=0.0,
                recommended_action=RecommendedAction.ALLOW
            )
        
        confidence = min(len(matched_patterns) * 0.35, 1.0)
        
        # 加入累积分数
        if session_id:
            confidence = max(confidence, self._session_scores.get(session_id, 0))
        
        level = self._calculate_level(confidence)
        
        return ThreatReport(
            threat_type=ThreatType.JAILBREAK_ATTEMPT,
            level=level,
            evidence=evidence[:5],
            matched_patterns=matched_patterns,
            confidence=confidence,
            recommended_action=RecommendedAction.BLOCK if level == ThreatLevel.CRITICAL else RecommendedAction.SANITIZE
        )
    
    def _calculate_level(self, confidence: float) -> ThreatLevel:
        if confidence >= 0.7:
            return ThreatLevel.CRITICAL
        elif confidence >= 0.5:
            return ThreatLevel.DANGEROUS
        elif confidence >= 0.2:
            return ThreatLevel.SUSPICIOUS
        return ThreatLevel.SAFE


class OutputAuditor:
    """输出审计器"""
    
    def audit(
        self,
        output: str,
        task_context: Optional[Dict[str, Any]] = None
    ) -> AuditResult:
        """审计输出"""
        violations = []
        
        # 检测敏感信息
        for pattern in SENSITIVE_PATTERNS:
            if re.search(pattern, output, re.IGNORECASE):
                violations.append(f"包含敏感信息模式: {pattern[:30]}...")
        
        # 检测有害内容关键词
        harmful_keywords = ["密码", "password", "secret", "token", "api_key"]
        for keyword in harmful_keywords:
            if keyword.lower() in output.lower():
                # 检查是否真的暴露了敏感值
                pattern = rf"{keyword}\s*[=:]\s*\S+"
                if re.search(pattern, output, re.IGNORECASE):
                    violations.append(f"可能泄露敏感信息: {keyword}")
        
        # 净化输出
        sanitized = output
        if violations:
            for pattern in SENSITIVE_PATTERNS:
                sanitized = re.sub(pattern, "[REDACTED]", sanitized)
        
        return AuditResult(
            is_safe=len(violations) == 0,
            violations=violations,
            sanitized_output=sanitized if sanitized != output else None
        )


class BehaviorMonitor:
    """行为基线监控器"""
    
    def __init__(self):
        self._baselines: Dict[str, Dict[str, float]] = {}
        self._observations: Dict[str, List[int]] = {}
    
    def update_baseline(self, session_id: str, token_count: int):
        """更新基线"""
        if session_id not in self._observations:
            self._observations[session_id] = []
        
        self._observations[session_id].append(token_count)
        
        # 保持最近100次观察
        if len(self._observations[session_id]) > 100:
            self._observations[session_id] = self._observations[session_id][-100:]
        
        # 计算基线统计
        obs = self._observations[session_id]
        if len(obs) >= 5:
            import statistics
            self._baselines[session_id] = {
                "mean": statistics.mean(obs),
                "stdev": statistics.stdev(obs) if len(obs) > 1 else 0
            }
    
    def check_anomaly(self, session_id: str, token_count: int) -> Optional[ThreatReport]:
        """检查异常"""
        self.update_baseline(session_id, token_count)
        
        baseline = self._baselines.get(session_id)
        if not baseline or baseline["stdev"] == 0:
            return None
        
        # Z-score检测
        z_score = abs(token_count - baseline["mean"]) / baseline["stdev"]
        
        if z_score > 3:
            return ThreatReport(
                threat_type=ThreatType.BASELINE_ANOMALY,
                level=ThreatLevel.SUSPICIOUS,
                evidence=[f"Z-score: {z_score:.2f}"],
                confidence=min(z_score / 5, 1.0),
                recommended_action=RecommendedAction.SANITIZE
            )
        
        return None
    
    def get_baseline(self, session_id: str) -> Optional[Dict[str, float]]:
        """获取基线"""
        return self._baselines.get(session_id)


class DualApprovalManager:
    """双签审批管理器"""
    
    def __init__(self):
        self._pending_approvals: Dict[str, Dict[str, Any]] = {}
    
    async def request_approval(
        self,
        operation_type: str,
        operation_detail: Dict[str, Any],
        requested_by: str
    ) -> bool:
        """
        请求审批
        
        简化实现：记录请求，默认批准
        实际应用中需要等待人工审批
        """
        import uuid
        request_id = str(uuid.uuid4())
        
        self._pending_approvals[request_id] = {
            "operation_type": operation_type,
            "operation_detail": operation_detail,
            "requested_by": requested_by,
            "created_at": datetime.now().isoformat(),
            "status": "pending"
        }
        
        logger.warning(
            f"Dual approval requested: {operation_type} by {requested_by}"
        )
        
        # TODO: 实现真正的审批流程
        # - 发送通知到审批人
        # - 等待两人签名
        # - 超时处理
        
        # 简化：自动批准
        return True
