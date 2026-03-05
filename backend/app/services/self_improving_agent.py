#!/usr/bin/env python3
"""
Self-Improving Agent - 核心自改进Agent模块
集成self-improving-agent技能到玄鉴安全智能体系统
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


class ImprovementPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InitiativeStatus(str, Enum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED_SUCCESS = "completed_success"
    COMPLETED_PARTIAL = "completed_partial"
    FAILED = "failed"


class ReflectionCategory(str, Enum):
    TASK_EXECUTION = "task_execution"
    SECURITY_EVENT = "security_event"
    THREAT_DETECTION = "threat_detection"
    DEFENSE_RESPONSE = "defense_response"
    TOOL_USAGE = "tool_usage"
    AI_ANALYSIS = "ai_analysis"
    WORKFLOW = "workflow"


class SelfImprovingAgent:
    """
    自改进Agent - 具备自反思、自批评、自学习能力
    集成PDCA循环和反思实践模型
    """
    
    def __init__(self, data_dir: str = None):
        self.data_dir = Path(data_dir) if data_dir else Path(__file__).parent.parent / "data" / "self_improving"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.reflection_file = self.data_dir / "reflections.json"
        self.improvement_file = self.data_dir / "improvements.json"
        self.initiative_file = self.data_dir / "initiatives.json"
        self.knowledge_file = self.data_dir / "knowledge.json"
        self.metrics_file = self.data_dir / "metrics.json"
        
        self._init_data_files()
        
        self.learning_enabled = True
        self.reflection_interval = 300
        self.improvement_threshold = 7
        
        self._lock = threading.Lock()
        self._learning_thread = None
        self._running = False
        
        logger.info("SelfImprovingAgent initialized")
    
    def _init_data_files(self):
        """初始化数据文件"""
        if not self.reflection_file.exists():
            self._save_json(self.reflection_file, {
                "reflections": [],
                "last_updated": datetime.now().isoformat(),
                "version": "1.0"
            })
        
        if not self.improvement_file.exists():
            self._save_json(self.improvement_file, {
                "improvements": [],
                "last_updated": datetime.now().isoformat(),
                "version": "1.0"
            })
        
        if not self.initiative_file.exists():
            self._save_json(self.initiative_file, {
                "active_initiatives": [],
                "completed_initiatives": [],
                "last_updated": datetime.now().isoformat(),
                "version": "1.0"
            })
        
        if not self.knowledge_file.exists():
            self._save_json(self.knowledge_file, {
                "knowledge_graph": {},
                "patterns": [],
                "lessons": [],
                "last_updated": datetime.now().isoformat(),
                "version": "1.0"
            })
        
        if not self.metrics_file.exists():
            self._save_json(self.metrics_file, {
                "total_reflections": 0,
                "total_improvements": 0,
                "success_rate": 0.0,
                "learning_velocity": 0.0,
                "last_evaluation": datetime.now().isoformat(),
                "version": "1.0"
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
    
    def reflect_on_task(self, task_description: str, outcome: str, 
                       challenges: List[str] = None, category: str = "task_execution",
                       context: Dict = None) -> Dict:
        """
        反思任务执行
        核心方法：应用反思实践模型
        """
        with self._lock:
            reflection = {
                "id": f"ref_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "timestamp": datetime.now().isoformat(),
                "task": task_description,
                "outcome": outcome,
                "challenges": challenges or [],
                "category": category,
                "context": context or {},
                "lessons": [],
                "improvements": [],
                "outcome_type": self._classify_outcome(outcome),
                "pdca_phase": "check"
            }
            
            reflection = self._analyze_task(reflection)
            reflection = self._extract_lessons(reflection)
            reflection = self._plan_improvements(reflection)
            
            self._save_reflection(reflection)
            
            self._update_metrics("reflection")
            
            logger.info(f"Reflection completed: {reflection['id']}")
            
            return reflection
    
    def _classify_outcome(self, outcome: str) -> str:
        """分类结果类型"""
        outcome_lower = outcome.lower()
        
        success_keywords = ["success", "completed", "finished", "working", "good", "成功", "完成"]
        partial_keywords = ["partial", "some", "mixed", "issues", "部分", "部分完成"]
        failure_keywords = ["failed", "error", "broken", "not working", "bad", "失败", "错误"]
        
        for keyword in success_keywords:
            if keyword in outcome_lower:
                return "success"
        
        for keyword in partial_keywords:
            if keyword in outcome_lower:
                return "partial"
        
        for keyword in failure_keywords:
            if keyword in outcome_lower:
                return "failure"
        
        return "unknown"
    
    def _analyze_task(self, reflection: Dict) -> Dict:
        """分析任务"""
        task = reflection["task"].lower()
        outcome_type = reflection["outcome_type"]
        
        if outcome_type == "success":
            reflection["lessons"].append("识别本次任务成功的关键因素")
            reflection["improvements"].append("记录成功模式以便复用")
        
        elif outcome_type == "partial":
            reflection["lessons"].append("分析哪些部分有效，哪些无效")
            reflection["improvements"].append("重点改进问题区域")
        
        elif outcome_type == "failure":
            reflection["lessons"].append("理解失败的根因")
            reflection["improvements"].append("制定类似任务的备选方案")
        
        if "scan" in task or "检测" in task:
            reflection["lessons"].append("扫描和检测技术")
            reflection["improvements"].append("优化扫描策略和检测规则")
        
        if "defense" in task or "防御" in task:
            reflection["lessons"].append("防御策略有效性")
            reflection["improvements"].append("改进防御响应机制")
        
        if "analysis" in task or "分析" in task:
            reflection["lessons"].append("分析方法和框架")
            reflection["improvements"].append("提升分析准确性")
        
        return reflection
    
    def _extract_lessons(self, reflection: Dict) -> Dict:
        """提取经验教训"""
        outcome_type = reflection["outcome_type"]
        
        if outcome_type == "success":
            reflection["analysis"] = {
                "what": f"任务 '{reflection['task']}' 成功完成",
                "so_what": "当前方法有效，可以继续使用",
                "now_what": "记录成功经验，优化流程"
            }
        
        elif outcome_type == "partial":
            reflection["analysis"] = {
                "what": f"任务 '{reflection['task']}' 部分完成",
                "so_what": "存在需要改进的地方",
                "now_what": "识别瓶颈，制定改进计划"
            }
        
        elif outcome_type == "failure":
            reflection["analysis"] = {
                "what": f"任务 '{reflection['task']}' 失败",
                "so_what": "需要重新评估方法和策略",
                "now_what": "分析原因，寻找替代方案"
            }
        
        return reflection
    
    def _plan_improvements(self, reflection: Dict) -> Dict:
        """规划改进措施"""
        reflection["action_plan"] = []
        
        for improvement in reflection["improvements"]:
            reflection["action_plan"].append({
                "action": improvement,
                "priority": "high" if reflection["outcome_type"] == "failure" else "medium",
                "deadline": (datetime.now() + timedelta(days=7)).isoformat(),
                "status": "pending"
            })
        
        return reflection
    
    def _save_reflection(self, reflection: Dict):
        """保存反思记录"""
        data = self._load_json(self.reflection_file)
        data["reflections"].append(reflection)
        data["last_updated"] = datetime.now().isoformat()
        
        self._save_json(self.reflection_file, data)
        
        self._add_to_knowledge(reflection)
    
    def _add_to_knowledge(self, reflection: Dict):
        """将反思添加到知识图谱"""
        knowledge = self._load_json(self.knowledge_file)
        
        if "patterns" not in knowledge:
            knowledge["patterns"] = []
        
        if reflection.get("lessons"):
            for lesson in reflection["lessons"]:
                pattern = {
                    "type": "lesson",
                    "content": lesson,
                    "category": reflection.get("category", "general"),
                    "source": reflection["id"],
                    "timestamp": reflection["timestamp"],
                    "success_rate": 1.0 if reflection["outcome_type"] == "success" else 0.5
                }
                knowledge["patterns"].append(pattern)
        
        knowledge["last_updated"] = datetime.now().isoformat()
        self._save_json(self.knowledge_file, knowledge)
    
    def _update_metrics(self, metric_type: str):
        """更新指标"""
        metrics = self._load_json(self.metrics_file)
        
        if metric_type == "reflection":
            metrics["total_reflections"] = metrics.get("total_reflections", 0) + 1
        
        elif metric_type == "improvement":
            metrics["total_improvements"] = metrics.get("total_improvements", 0) + 1
        
        metrics["last_evaluation"] = datetime.now().isoformat()
        
        self._save_json(self.metrics_file, metrics)
    
    def record_improvement(self, area: str, action: str, impact: int,
                          category: str = "general") -> str:
        """
        记录改进措施
        应用PDCA循环
        """
        with self._lock:
            data = self._load_json(self.improvement_file)
            
            improvement = {
                "id": f"imp_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "timestamp": datetime.now().isoformat(),
                "area": area,
                "action": action,
                "impact": impact,
                "category": category,
                "verified": False,
                "pdca_phase": "act",
                "effectiveness": 0.0
            }
            
            data["improvements"].append(improvement)
            data["last_updated"] = datetime.now().isoformat()
            
            self._save_json(self.improvement_file, data)
            
            self._update_metrics("improvement")
            
            logger.info(f"Improvement recorded: {improvement['id']}")
            
            return improvement["id"]
    
    def create_initiative(self, area: str, description: str, goals: List[str],
                        priority: str = "medium", category: str = "general") -> str:
        """
        创建改进计划
        生命周期：Planned → In Progress → Completed
        """
        with self._lock:
            data = self._load_json(self.initiative_file)
            
            initiative = {
                "id": f"init_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "timestamp": datetime.now().isoformat(),
                "area": area,
                "description": description,
                "goals": goals if isinstance(goals, list) else [goals],
                "priority": priority,
                "category": category,
                "status": InitiativeStatus.PLANNED.value,
                "created": datetime.now().isoformat(),
                "start_date": None,
                "completion_date": None,
                "progress": 0,
                "notes": [],
                "metrics": {
                    "time_spent": 0,
                    "resources_used": [],
                    "impact_score": 0
                },
                "pdca_phase": "plan"
            }
            
            data["active_initiatives"].append(initiative)
            data["last_updated"] = datetime.now().isoformat()
            
            self._save_json(self.initiative_file, data)
            
            logger.info(f"Created initiative: {initiative['id']}")
            
            return initiative["id"]
    
    def start_initiative(self, initiative_id: str) -> bool:
        """开始执行计划"""
        with self._lock:
            data = self._load_json(self.initiative_file)
            
            for initiative in data["active_initiatives"]:
                if initiative["id"] == initiative_id:
                    initiative["status"] = InitiativeStatus.IN_PROGRESS.value
                    initiative["start_date"] = datetime.now().isoformat()
                    initiative["pdca_phase"] = "do"
                    
                    self._save_json(self.initiative_file, data)
                    
                    logger.info(f"Started initiative: {initiative_id}")
                    return True
            
            return False
    
    def update_progress(self, initiative_id: str, progress: int, notes: str = None) -> bool:
        """更新计划进度"""
        with self._lock:
            data = self._load_json(self.initiative_file)
            
            for initiative in data["active_initiatives"]:
                if initiative["id"] == initiative_id:
                    initiative["progress"] = max(0, min(100, progress))
                    
                    if notes:
                        initiative["notes"].append({
                            "timestamp": datetime.now().isoformat(),
                            "progress": progress,
                            "notes": notes
                        })
                    
                    self._save_json(self.initiative_file, data)
                    
                    logger.info(f"Updated {initiative_id}: {progress}%")
                    return True
            
            return False
    
    def complete_initiative(self, initiative_id: str, success: bool = True,
                           impact_score: int = 0) -> bool:
        """完成计划"""
        with self._lock:
            data = self._load_json(self.initiative_file)
            
            for i, initiative in enumerate(data["active_initiatives"]):
                if initiative["id"] == initiative_id:
                    initiative["status"] = (
                        InitiativeStatus.COMPLETED_SUCCESS.value 
                        if success 
                        else InitiativeStatus.COMPLETED_PARTIAL.value
                    )
                    initiative["completion_date"] = datetime.now().isoformat()
                    initiative["progress"] = 100
                    initiative["metrics"]["impact_score"] = impact_score
                    initiative["pdca_phase"] = "act"
                    
                    if initiative["start_date"]:
                        start = datetime.fromisoformat(initiative["start_date"])
                        time_spent = (datetime.now() - start).total_seconds() / 3600
                        initiative["metrics"]["time_spent"] = time_spent
                    
                    completed = data["active_initiatives"].pop(i)
                    data["completed_initiatives"].append(completed)
                    
                    self._save_json(self.initiative_file, data)
                    
                    logger.info(f"Completed initiative: {initiative_id}")
                    return True
            
            return False
    
    def get_recent_reflections(self, days: int = 7) -> List[Dict]:
        """获取近期的反思记录"""
        data = self._load_json(self.reflection_file)
        
        cutoff_date = datetime.now() - timedelta(days=days)
        recent = []
        
        for reflection in data["reflections"]:
            reflection_date = datetime.fromisoformat(reflection["timestamp"])
            if reflection_date >= cutoff_date:
                recent.append(reflection)
        
        return recent
    
    def get_active_initiatives(self) -> List[Dict]:
        """获取活跃的计划"""
        data = self._load_json(self.initiative_file)
        return data.get("active_initiatives", [])
    
    def get_metrics(self) -> Dict:
        """获取性能指标"""
        return self._load_json(self.metrics_file)
    
    def get_knowledge_patterns(self, category: str = None, limit: int = 10) -> List[Dict]:
        """获取知识模式"""
        knowledge = self._load_json(self.knowledge_file)
        patterns = knowledge.get("patterns", [])
        
        if category:
            patterns = [p for p in patterns if p.get("category") == category]
        
        return patterns[:limit]
    
    def generate_improvement_report(self, period_days: int = 30) -> Dict:
        """生成改进报告"""
        reflections = self.get_recent_reflections(period_days)
        
        metrics = self._load_json(self.metrics_file)
        initiatives_data = self._load_json(self.initiative_file)
        
        report = {
            "generated": datetime.now().isoformat(),
            "period_days": period_days,
            "summary": {
                "reflections_count": len(reflections),
                "total_improvements": metrics.get("total_improvements", 0),
                "active_initiatives": len(initiatives_data.get("active_initiatives", [])),
                "completed_initiatives": len(initiatives_data.get("completed_initiatives", []))
            },
            "key_lessons": [],
            "improvement_areas": [],
            "recommendations": [],
            "pdca_status": {
                "plan": 0,
                "do": 0,
                "check": 0,
                "act": 0
            }
        }
        
        lesson_counts = {}
        for reflection in reflections:
            for lesson in reflection.get("lessons", []):
                lesson_counts[lesson] = lesson_counts.get(lesson, 0) + 1
        
        sorted_lessons = sorted(lesson_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        report["key_lessons"] = [lesson for lesson, count in sorted_lessons]
        
        area_counts = {}
        for reflection in reflections:
            area = reflection.get("category", "general")
            area_counts[area] = area_counts.get(area, 0) + 1
        
        report["improvement_areas"] = sorted(
            area_counts.items(), key=lambda x: x[1], reverse=True
        )[:5]
        
        for initiative in initiatives_data.get("active_initiatives", []):
            phase = initiative.get("pdca_phase", "plan")
            if phase in report["pdca_status"]:
                report["pdca_status"][phase] += 1
        
        if len(reflections) > 0:
            if metrics.get("total_improvements", 0) < 5:
                report["recommendations"].append("增加改进措施的实施力度")
            
            if len(report["key_lessons"]) < 3:
                report["recommendations"].append("多样化学习经验")
            
            report["recommendations"].append("保持定期反思习惯")
        
        return report
    
    def start_learning_cycle(self):
        """启动学习循环"""
        if not self._running:
            self._running = True
            self._learning_thread = threading.Thread(target=self._learning_loop, daemon=True)
            self._learning_thread.start()
            logger.info("Learning cycle started")
    
    def stop_learning_cycle(self):
        """停止学习循环"""
        self._running = False
        if self._learning_thread:
            self._learning_thread.join(timeout=5)
        logger.info("Learning cycle stopped")
    
    def _learning_loop(self):
        """学习循环"""
        while self._running:
            try:
                self._perform_continuous_learning()
                asyncio.run(self._adaptive_defense_adjustment())
                asyncio.run(self._multi_agent_knowledge_share())
                
            except Exception as e:
                logger.error(f"Learning loop error: {e}")
            
            for _ in range(self.reflection_interval):
                if self._running:
                    import time
                    time.sleep(1)
    
    def _perform_continuous_learning(self):
        """执行持续学习"""
        reflections = self.get_recent_reflections(7)
        
        if not reflections:
            return
        
        success_count = sum(1 for r in reflections if r.get("outcome_type") == "success")
        total_count = len(reflections)
        
        if total_count > 0:
            success_rate = success_count / total_count
            
            if success_rate < 0.5:
                self.record_improvement(
                    area="performance",
                    action="success_rate_below_threshold",
                    impact=8,
                    category="learning"
                )
    
    async def _adaptive_defense_adjustment(self):
        """自适应防御调整"""
        pass
    
    async def _multi_agent_knowledge_share(self):
        """多Agent知识共享"""
        pass
    
    def apply_lesson(self, lesson: str, context: Dict = None) -> Dict:
        """应用经验教训"""
        reflection = self.reflect_on_task(
            task_description=f"应用经验: {lesson}",
            outcome="应用已记录的经验",
            category="ai_analysis",
            context=context
        )
        
        return reflection
    
    def get_optimization_suggestions(self) -> List[Dict]:
        """获取优化建议"""
        suggestions = []
        
        metrics = self.get_metrics()
        
        if metrics.get("total_reflections", 0) > 0:
            success_rate = metrics.get("success_rate", 0)
            
            if success_rate < 0.7:
                suggestions.append({
                    "type": "performance",
                    "priority": "high",
                    "suggestion": "成功率低于70%，建议优化工作流程",
                    "action": "analyze_failures"
                })
        
        initiatives = self.get_active_initiatives()
        
        if len(initiatives) > 10:
            suggestions.append({
                "type": "resource",
                "priority": "medium",
                "suggestion": f"当前有{len(initiatives)}个活跃计划，建议优先处理高优先级项",
                "action": "prioritize_initiatives"
            })
        
        return suggestions


def get_self_improving_agent() -> SelfImprovingAgent:
    """获取自改进Agent单例"""
    if not hasattr(get_self_improving_agent, "_instance"):
        get_self_improving_agent._instance = SelfImprovingAgent()
    return get_self_improving_agent._instance
