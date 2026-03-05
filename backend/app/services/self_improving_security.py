#!/usr/bin/env python3
"""
Self-Improving Security System - 统一集成模块
整合自改进Agent、自适应防御、多Agent协同学习和知识图谱
"""

import logging
from typing import Dict, List, Optional, Any
import threading
from datetime import datetime

logger = logging.getLogger(__name__)


class SelfImprovingSecuritySystem:
    """
    自改进安全系统 - 统一集成入口
    整合所有自改进能力，提供统一接口
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        
        self._initialized = True
        
        logger.info("Initializing Self-Improving Security System...")
        
        from .self_improving_agent import SelfImprovingAgent, get_self_improving_agent
        from .adaptive_defense import AdaptiveDefenseSystem, get_adaptive_defense_system
        from .multi_agent_learning import MultiAgentCollaborativeLearning, get_multi_agent_learning
        from .knowledge_graph import KnowledgeGraph, get_knowledge_graph
        
        self.self_improving_agent = get_self_improving_agent()
        self.adaptive_defense = get_adaptive_defense_system()
        self.multi_agent_learning = get_multi_agent_learning()
        self.knowledge_graph = get_knowledge_graph()
        
        self._register_core_agents()
        
        logger.info("Self-Improving Security System initialized successfully")
    
    def _register_core_agents(self):
        """注册核心Agent"""
        from .multi_agent_learning import AgentType
        
        self.multi_agent_learning.register_agent(
            "improver_agent",
            AgentType.IMPROVER,
            capabilities=["self_reflection", "improvement_tracking", "performance_evaluation"],
            metadata={"role": "self_improvement"}
        )
        
        self.multi_agent_learning.register_agent(
            "defense_agent",
            AgentType.RESPONDER,
            capabilities=["threat_response", "defense_adjustment", "adaptive_protection"],
            metadata={"role": "defense_coordinator"}
        )
        
        self.multi_agent_learning.register_agent(
            "detector_agent",
            AgentType.DETECTOR,
            capabilities=["threat_detection", "pattern_matching", "anomaly_detection"],
            metadata={"role": "threat_detector"}
        )
        
        self.multi_agent_learning.register_agent(
            "analyzer_agent",
            AgentType.ANALYZER,
            capabilities=["threat_analysis", "risk_evaluation", "attack_chain_analysis"],
            metadata={"role": "security_analyzer"}
        )
        
        self.multi_agent_learning.register_agent(
            "supervisor_agent",
            AgentType.SUPERVISOR,
            capabilities=["task_planning", "result_review", "security_check"],
            metadata={"role": "ai_supervisor"}
        )
    
    def process_security_event(self, event_data: Dict) -> Dict:
        """
        处理安全事件 - 完整的工作流
        """
        result = {
            "timestamp": datetime.now().isoformat(),
            "event": event_data,
            "analysis": {},
            "response": {},
            "learning": {}
        }
        
        threat_analysis = self.adaptive_defense.analyze_threat(event_data)
        result["analysis"]["threat"] = threat_analysis
        
        attack_indicators = event_data.get("indicators", [])
        if attack_indicators:
            attack_chain = self.knowledge_graph.analyze_attack_chain(attack_indicators)
            result["analysis"]["attack_chain"] = attack_chain
        
        defense_response = self._generate_defense_response(threat_analysis)
        result["response"] = defense_response
        
        reflection_result = self.self_improving_agent.reflect_on_task(
            task_description=f"处理安全事件: {event_data.get('type', 'unknown')}",
            outcome=f"威胁级别: {threat_analysis.get('severity', 'unknown')}",
            category="security_event",
            context=event_data
        )
        result["learning"]["reflection"] = reflection_result
        
        if threat_analysis.get("severity_score", 0) > 0.7:
            knowledge = {
                "type": "threat_pattern",
                "content": f"威胁类型: {event_data.get('type')}, 严重性: {threat_analysis.get('severity')}",
                "category": "security_event",
                "effectiveness_score": threat_analysis.get("severity_score", 0.5)
            }
            self.multi_agent_learning.share_knowledge("detector_agent", knowledge)
        
        return result
    
    def _generate_defense_response(self, threat_analysis: Dict) -> Dict:
        """生成防御响应"""
        response = threat_analysis.get("recommended_response", {})
        
        severity = threat_analysis.get("severity", "low")
        
        recommendations = self.knowledge_graph.get_defense_recommendations(
            threat_analysis.get("type", "unknown")
        )
        
        response["knowledge_recommendations"] = recommendations
        
        return response
    
    def execute_task_with_learning(self, task_description: str, task_func, 
                                 task_args: tuple = (), task_kwargs: dict = None,
                                 category: str = "task_execution") -> Dict:
        """
        执行任务并记录学习
        """
        task_kwargs = task_kwargs or {}
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "task": task_description,
            "success": False,
            "result": None,
            "error": None,
            "learning": {}
        }
        
        try:
            task_result = task_func(*task_args, **task_kwargs)
            result["result"] = task_result
            result["success"] = True
            outcome = "success"
            
        except Exception as e:
            result["error"] = str(e)
            outcome = f"failed: {str(e)}"
        
        reflection = self.self_improving_agent.reflect_on_task(
            task_description=task_description,
            outcome=outcome,
            category=category,
            context={"task_result": result.get("result")}
        )
        result["learning"]["reflection"] = reflection
        
        experience = {
            "task": task_description,
            "outcome": outcome,
            "category": category
        }
        learning = self.multi_agent_learning.learn_from_experience(
            "improver_agent", experience
        )
        result["learning"]["collaborative"] = learning
        
        return result
    
    def update_threat_intelligence(self, threat_data: Dict) -> str:
        """更新威胁情报"""
        threat_id = self.knowledge_graph.add_threat_intelligence(threat_data)
        
        knowledge = {
            "type": "threat_pattern",
            "content": f"新威胁情报: {threat_data.get('name')}",
            "category": threat_data.get("category", "threat_intel"),
            "effectiveness_score": 0.8,
            "tags": ["threat_intelligence", "update"]
        }
        self.multi_agent_learning.share_knowledge("detector_agent", knowledge)
        
        return threat_id
    
    def update_vulnerability(self, vuln_data: Dict) -> str:
        """更新漏洞信息"""
        vuln_id = self.knowledge_graph.add_vulnerability(vuln_data)
        
        self.self_improving_agent.record_improvement(
            area="vulnerability_management",
            action=f"更新漏洞: {vuln_data.get('name', 'unknown')}",
            impact=7,
            category="security"
        )
        
        return vuln_id
    
    def get_defense_status(self) -> Dict:
        """获取防御状态"""
        defense_status = self.adaptive_defense.get_current_defense_status()
        
        improvement_metrics = self.self_improving_agent.get_metrics()
        
        agent_network = self.multi_agent_learning.get_collaboration_network()
        
        kg_stats = self.knowledge_graph.get_statistics()
        
        return {
            "defense_mode": defense_status.get("defense_mode"),
            "threat_level": defense_status.get("threat_level"),
            "improvement_metrics": improvement_metrics,
            "agent_network": {
                "nodes_count": len(agent_network.get("nodes", [])),
                "edges_count": len(agent_network.get("edges", []))
            },
            "knowledge_graph": {
                "entities": kg_stats.get("total_entities", 0),
                "relations": kg_stats.get("total_relations", 0)
            },
            "timestamp": datetime.now().isoformat()
        }
    
    def get_optimization_recommendations(self) -> List[Dict]:
        """获取优化建议"""
        recommendations = []
        
        improvement_suggestions = self.self_improving_agent.get_optimization_suggestions()
        recommendations.extend(improvement_suggestions)
        
        threat_stats = self.adaptive_defense.get_threat_statistics(7)
        if threat_stats.get("total_threats", 0) > 100:
            recommendations.append({
                "type": "defense",
                "priority": "high",
                "suggestion": "过去7天威胁数量较多，建议增强防御",
                "action": "enhance_defense"
            })
        
        knowledge_stats = self.knowledge_graph.get_statistics()
        if knowledge_stats.get("total_entities", 0) < 50:
            recommendations.append({
                "type": "knowledge",
                "priority": "medium",
                "suggestion": "知识库内容较少，建议补充更多威胁情报",
                "action": "enrich_knowledge"
            })
        
        return recommendations
    
    def start_continuous_learning(self):
        """启动持续学习"""
        self.self_improving_agent.start_learning_cycle()
        logger.info("Continuous learning started")
    
    def stop_continuous_learning(self):
        """停止持续学习"""
        self.self_improving_agent.stop_learning_cycle()
        logger.info("Continuous learning stopped")
    
    def run_collaborative_cycle(self) -> Dict:
        """运行协作学习周期"""
        return self.multi_agent_learning.run_collaborative_learning_cycle()
    
    def generate_comprehensive_report(self, period_days: int = 30) -> Dict:
        """生成综合报告"""
        improvement_report = self.self_improving_agent.generate_improvement_report(period_days)
        
        threat_stats = self.adaptive_defense.get_threat_statistics(period_days)
        
        knowledge_stats = self.knowledge_graph.get_statistics()
        
        agent_stats = self.multi_agent_learning.get_knowledge_statistics()
        
        return {
            "period_days": period_days,
            "generated_at": datetime.now().isoformat(),
            "improvement": improvement_report,
            "threats": threat_stats,
            "knowledge_graph": knowledge_stats,
            "multi_agent": agent_stats,
            "recommendations": self.get_optimization_recommendations()
        }


def get_self_improving_security_system() -> SelfImprovingSecuritySystem:
    """获取自改进安全系统单例"""
    return SelfImprovingSecuritySystem()
