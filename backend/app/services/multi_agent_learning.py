#!/usr/bin/env python3
"""
Multi-Agent Collaborative Learning - 多Agent协同学习模块
实现Agent间的知识共享、协同学习和分布式智能
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from enum import Enum
import threading
import asyncio
import hashlib

logger = logging.getLogger(__name__)


class AgentType(str, Enum):
    SCANNER = "scanner"
    DETECTOR = "detector"
    ANALYZER = "analyzer"
    RESPONDER = "responder"
    SUPERVISOR = "supervisor"
    IMPROVER = "improver"


class KnowledgeType(str, Enum):
    THREAT_PATTERN = "threat_pattern"
    DEFENSE_STRATEGY = "defense_strategy"
    DETECTION_RULE = "detection_rule"
    RESPONSE_ACTION = "response_action"
    LEARNING_INSIGHT = "learning_insight"
    OPTIMIZATION_TIP = "optimization_tip"


class LearningPhase(str, Enum):
    OBSERVATION = "observation"
    ANALYSIS = "analysis"
    COLLABORATION = "collaboration"
    INTEGRATION = "integration"
    APPLICATION = "application"


class MultiAgentCollaborativeLearning:
    """
    多Agent协同学习系统
    实现跨Agent的知识共享、联合学习和协同决策
    """
    
    def __init__(self, data_dir: str = None):
        self.data_dir = Path(data_dir) if data_dir else Path(__file__).parent.parent / "data" / "multi_agent_learning"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.agents_file = self.data_dir / "agents.json"
        self.knowledge_base_file = self.data_dir / "knowledge_base.json"
        self.learning_events_file = self.data_dir / "learning_events.json"
        self.collaboration_log_file = self.data_dir / "collaboration_log.json"
        
        self._init_data_files()
        
        self._lock = threading.Lock()
        self._agent_cache = {}
        
        self.learning_interval = 60
        
        logger.info("MultiAgentCollaborativeLearning initialized")
    
    def _init_data_files(self):
        """初始化数据文件"""
        if not self.agents_file.exists():
            self._save_json(self.agents_file, {
                "agents": {},
                "registered_count": 0,
                "active_count": 0,
                "last_updated": datetime.now().isoformat()
            })
        
        if not self.knowledge_base_file.exists():
            self._save_json(self.knowledge_base_file, {
                "knowledge": [],
                "shared_knowledge": [],
                "learned_patterns": [],
                "last_updated": datetime.now().isoformat()
            })
        
        if not self.learning_events_file.exists():
            self._save_json(self.learning_events_file, {
                "events": [],
                "last_updated": datetime.now().isoformat()
            })
        
        if not self.collaboration_log_file.exists():
            self._save_json(self.collaboration_log_file, {
                "collaborations": [],
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
    
    def register_agent(self, agent_id: str, agent_type: AgentType, 
                      capabilities: List[str] = None, metadata: Dict = None) -> bool:
        """
        注册Agent到协同学习网络
        """
        with self._lock:
            data = self._load_json(self.agents_file)
            
            if agent_id in data["agents"]:
                logger.warning(f"Agent {agent_id} already registered")
                return False
            
            agent = {
                "id": agent_id,
                "type": agent_type.value,
                "capabilities": capabilities or [],
                "metadata": metadata or {},
                "registered_at": datetime.now().isoformat(),
                "last_active": datetime.now().isoformat(),
                "status": "active",
                "knowledge_shared": 0,
                "knowledge_received": 0,
                "collaborations": 0,
                "learned_count": 0,
                "expertise": []
            }
            
            data["agents"][agent_id] = agent
            data["registered_count"] += 1
            data["active_count"] = data.get("active_count", 0) + 1
            data["last_updated"] = datetime.now().isoformat()
            
            self._save_json(self.agents_file, data)
            
            self._log_collaboration(
                agent_id=agent_id,
                action="register",
                details={"agent_type": agent_type.value}
            )
            
            logger.info(f"Agent registered: {agent_id} ({agent_type.value})")
            return True
    
    def unregister_agent(self, agent_id: str) -> bool:
        """注销Agent"""
        with self._lock:
            data = self._load_json(self.agents_file)
            
            if agent_id not in data["agents"]:
                return False
            
            data["agents"][agent_id]["status"] = "inactive"
            data["agents"][agent_id]["last_active"] = datetime.now().isoformat()
            data["active_count"] -= 1
            
            data["last_updated"] = datetime.now().isoformat()
            self._save_json(self.agents_file, data)
            
            logger.info(f"Agent unregistered: {agent_id}")
            return True
    
    def update_agent_activity(self, agent_id: str):
        """更新Agent活跃状态"""
        data = self._load_json(self.agents_file)
        
        if agent_id in data["agents"]:
            data["agents"][agent_id]["last_active"] = datetime.now().isoformat()
            data["last_updated"] = datetime.now().isoformat()
            self._save_json(self.agents_file, data)
    
    def share_knowledge(self, agent_id: str, knowledge: Dict) -> str:
        """
        Agent共享知识到协同网络
        """
        with self._lock:
            data = self._load_json(self.agents_file)
            
            if agent_id not in data["agents"]:
                logger.warning(f"Agent {agent_id} not registered")
                return None
            
            knowledge_id = self._generate_knowledge_id(knowledge)
            
            shared_knowledge = {
                "id": knowledge_id,
                "agent_id": agent_id,
                "timestamp": datetime.now().isoformat(),
                "type": knowledge.get("type", KnowledgeType.LEARNING_INSIGHT.value),
                "content": knowledge.get("content", ""),
                "category": knowledge.get("category", "general"),
                "tags": knowledge.get("tags", []),
                "source_task": knowledge.get("source_task", ""),
                "effectiveness_score": knowledge.get("effectiveness_score", 0.5),
                "validation_status": "pending",
                "applicability": knowledge.get("applicability", []),
                "metadata": knowledge.get("metadata", {})
            }
            
            kb_data = self._load_json(self.knowledge_base_file)
            kb_data["shared_knowledge"].append(shared_knowledge)
            kb_data["last_updated"] = datetime.now().isoformat()
            
            self._save_json(self.knowledge_base_file, kb_data)
            
            data["agents"][agent_id]["knowledge_shared"] += 1
            data["last_updated"] = datetime.now().isoformat()
            self._save_json(self.agents_file, data)
            
            self._log_learning_event(
                agent_id=agent_id,
                event_type="knowledge_share",
                details={"knowledge_id": knowledge_id, "type": shared_knowledge["type"]}
            )
            
            self._distribute_knowledge(agent_id, shared_knowledge)
            
            logger.info(f"Knowledge shared by {agent_id}: {knowledge_id}")
            return knowledge_id
    
    def _generate_knowledge_id(self, knowledge: Dict) -> str:
        """生成知识ID"""
        content = json.dumps(knowledge, sort_keys=True)
        hash_value = hashlib.md5(content.encode()).hexdigest()[:12]
        return f"kn_{datetime.now().strftime('%Y%m%d')}_{hash_value}"
    
    def _distribute_knowledge(self, source_agent_id: str, knowledge: Dict):
        """分发知识给相关Agent"""
        data = self._load_json(self.agents_file)
        
        relevant_agents = []
        
        for agent_id, agent in data["agents"].items():
            if agent_id == source_agent_id or agent["status"] != "active":
                continue
            
            if self._is_agent_relevant(agent, knowledge):
                relevant_agents.append(agent_id)
                
                agent["knowledge_received"] += 1
                agent["learned_count"] += 1
                
                self._log_collaboration(
                    agent_id=agent_id,
                    action="receive_knowledge",
                    details={
                        "source": source_agent_id,
                        "knowledge_id": knowledge["id"]
                    }
                )
        
        data["last_updated"] = datetime.now().isoformat()
        self._save_json(self.agents_file, data)
        
        logger.info(f"Distributed knowledge to {len(relevant_agents)} agents")
    
    def _is_agent_relevant(self, agent: Dict, knowledge: Dict) -> bool:
        """判断Agent是否相关"""
        knowledge_type = knowledge.get("type", "")
        
        agent_type = agent.get("type", "")
        
        type_relevance = {
            "threat_pattern": [AgentType.DETECTOR.value, AgentType.ANALYZER.value],
            "defense_strategy": [AgentType.RESPONDER.value, AgentType.SUPERVISOR.value],
            "detection_rule": [AgentType.DETECTOR.value, AgentType.SCANNER.value],
            "response_action": [AgentType.RESPONDER.value],
            "learning_insight": [AgentType.IMPROVER.value, AgentType.SUPERVISOR.value],
            "optimization_tip": [AgentType.IMPROVER.value, AgentType.ANALYZER.value]
        }
        
        relevant_types = type_relevance.get(knowledge_type, [])
        
        return agent_type in relevant_types or not relevant_types
    
    def query_knowledge(self, agent_id: str, query: Dict, 
                       knowledge_types: List[KnowledgeType] = None) -> List[Dict]:
        """
        Agent查询知识库
        """
        kb_data = self._load_json(self.knowledge_base_file)
        
        results = []
        
        for knowledge in kb_data.get("shared_knowledge", []):
            if knowledge.get("validation_status") == "rejected":
                continue
            
            if self._matches_query(knowledge, query):
                if knowledge_types and knowledge.get("type") not in [kt.value for kt in knowledge_types]:
                    continue
                
                results.append(knowledge)
        
        results.sort(key=lambda x: x.get("effectiveness_score", 0), reverse=True)
        
        self.update_agent_activity(agent_id)
        
        return results[:10]
    
    def _matches_query(self, knowledge: Dict, query: Dict) -> bool:
        """检查知识是否匹配查询"""
        if "category" in query:
            if knowledge.get("category") != query["category"]:
                return False
        
        if "tags" in query:
            knowledge_tags = set(knowledge.get("tags", []))
            query_tags = set(query["tags"])
            if not knowledge_tags.intersection(query_tags):
                return False
        
        if "type" in query:
            if knowledge.get("type") != query["type"]:
                return False
        
        return True
    
    def learn_from_experience(self, agent_id: str, experience: Dict) -> Dict:
        """
        Agent从经验中学习
        """
        learning = {
            "id": f"learn_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "agent_id": agent_id,
            "timestamp": datetime.now().isoformat(),
            "experience": experience,
            "phase": LearningPhase.OBSERVATION.value,
            "insights": [],
            "knowledge_generated": []
        }
        
        learning = self._analyze_experience(learning)
        
        learning = self._collaborate_on_learning(learning)
        
        learning = self._integrate_learning(learning)
        
        self._store_learning_event(learning)
        
        return learning
    
    def _analyze_experience(self, learning: Dict) -> Dict:
        """分析经验"""
        experience = learning.get("experience", {})
        
        outcome = experience.get("outcome", "").lower()
        
        if "success" in outcome or "完成" in outcome:
            learning["phase"] = LearningPhase.ANALYSIS.value
            learning["insights"].append({
                "type": "success_factor",
                "description": "识别成功因素"
            })
            
            if "pattern" in experience:
                learning["knowledge_generated"].append({
                    "type": KnowledgeType.THREAT_PATTERN.value,
                    "content": f"成功模式: {experience.get('pattern')}",
                    "category": "success_pattern",
                    "effectiveness_score": 0.8
                })
        
        elif "fail" in outcome or "失败" in outcome:
            learning["phase"] = LearningPhase.ANALYSIS.value
            learning["insights"].append({
                "type": "failure_analysis",
                "description": "分析失败原因"
            })
            
            if "error" in experience:
                learning["knowledge_generated"].append({
                    "type": KnowledgeType.LEARNING_INSIGHT.value,
                    "content": f"错误教训: {experience.get('error')}",
                    "category": "failure_lesson",
                    "effectiveness_score": 0.6
                })
        
        return learning
    
    def _collaborate_on_learning(self, learning: Dict) -> Dict:
        """协作学习"""
        learning["phase"] = LearningPhase.COLLABORATION.value
        
        kb_data = self._load_json(self.knowledge_base_file)
        
        related_knowledge = []
        
        for knowledge in kb_data.get("shared_knowledge", []):
            if knowledge.get("validation_status") != "validated":
                continue
            
            if knowledge.get("category") == learning["experience"].get("category"):
                related_knowledge.append(knowledge)
        
        if related_knowledge:
            learning["insights"].append({
                "type": "collaborative_learning",
                "description": f"从{len(related_knowledge)}个相关知识中学习",
                "related_count": len(related_knowledge)
            })
        
        return learning
    
    def _integrate_learning(self, learning: Dict) -> Dict:
        """整合学习成果"""
        learning["phase"] = LearningPhase.INTEGRATION.value
        
        kb_data = self._load_json(self.knowledge_base_file)
        
        for knowledge in learning.get("knowledge_generated", []):
            knowledge["id"] = self._generate_knowledge_id(knowledge)
            knowledge["agent_id"] = learning["agent_id"]
            knowledge["timestamp"] = datetime.now().isoformat()
            knowledge["validation_status"] = "validated"
            
            kb_data["learned_patterns"].append(knowledge)
        
        kb_data["last_updated"] = datetime.now().isoformat()
        self._save_json(self.knowledge_base_file, kb_data)
        
        learning["phase"] = LearningPhase.APPLICATION.value
        
        return learning
    
    def _store_learning_event(self, learning: Dict):
        """存储学习事件"""
        data = self._load_json(self.learning_events_file)
        
        event = {
            "id": learning["id"],
            "agent_id": learning["agent_id"],
            "timestamp": learning["timestamp"],
            "phase": learning["phase"],
            "insights_count": len(learning.get("insights", [])),
            "knowledge_generated_count": len(learning.get("knowledge_generated", []))
        }
        
        data["events"].append(event)
        
        if len(data["events"]) > 1000:
            data["events"] = data["events"][-1000:]
        
        data["last_updated"] = datetime.now().isoformat()
        
        self._save_json(self.learning_events_file, data)
    
    def _log_collaboration(self, agent_id: str, action: str, details: Dict = None):
        """记录协作日志"""
        data = self._load_json(self.collaboration_log_file)
        
        collaboration = {
            "id": f"collab_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "agent_id": agent_id,
            "action": action,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        }
        
        data["collaborations"].append(collaboration)
        
        if len(data["collaborations"]) > 500:
            data["collaborations"] = data["collaborations"][-500:]
        
        data["last_updated"] = datetime.now().isoformat()
        
        self._save_json(self.collaboration_log_file, data)
    
    def _log_learning_event(self, agent_id: str, event_type: str, details: Dict = None):
        """记录学习事件"""
        self._log_collaboration(agent_id, event_type, details)
    
    def get_registered_agents(self) -> List[Dict]:
        """获取已注册的Agent列表"""
        data = self._load_json(self.agents_file)
        
        return [
            {
                "id": agent_id,
                "type": agent["type"],
                "status": agent["status"],
                "last_active": agent["last_active"],
                "knowledge_shared": agent["knowledge_shared"],
                "knowledge_received": agent["knowledge_received"],
                "capabilities": agent["capabilities"]
            }
            for agent_id, agent in data["agents"].items()
        ]
    
    def get_agent_statistics(self, agent_id: str) -> Dict:
        """获取Agent统计信息"""
        data = self._load_json(self.agents_file)
        
        if agent_id not in data["agents"]:
            return {}
        
        agent = data["agents"][agent_id]
        
        kb_data = self._load_json(self.knowledge_base_file)
        
        shared_count = sum(
            1 for k in kb_data.get("shared_knowledge", [])
            if k.get("agent_id") == agent_id
        )
        
        return {
            "agent_id": agent_id,
            "type": agent["type"],
            "status": agent["status"],
            "registered_at": agent["registered_at"],
            "last_active": agent["last_active"],
            "total_shared": agent["knowledge_shared"],
            "total_received": agent["knowledge_received"],
            "total_learned": agent["learned_count"],
            "current_collaborations": agent["collaborations"],
            "shared_count": shared_count
        }
    
    def get_knowledge_statistics(self) -> Dict:
        """获取知识库统计"""
        kb_data = self._load_json(self.knowledge_base_file)
        
        stats = {
            "total_shared": len(kb_data.get("shared_knowledge", [])),
            "total_learned": len(kb_data.get("learned_patterns", [])),
            "by_type": {},
            "by_category": {},
            "validated_count": 0,
            "pending_count": 0
        }
        
        for knowledge in kb_data.get("shared_knowledge", []):
            ktype = knowledge.get("type", "unknown")
            stats["by_type"][ktype] = stats["by_type"].get(ktype, 0) + 1
            
            category = knowledge.get("category", "unknown")
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1
            
            if knowledge.get("validation_status") == "validated":
                stats["validated_count"] += 1
            else:
                stats["pending_count"] += 1
        
        return stats
    
    def get_collaboration_network(self) -> Dict:
        """获取协作网络"""
        data = self._load_json(self.agents_file)
        
        agents = list(data["agents"].values())
        
        network = {
            "nodes": [],
            "edges": []
        }
        
        for agent in agents:
            network["nodes"].append({
                "id": agent["id"],
                "type": agent["type"],
                "status": agent["status"]
            })
        
        collab_data = self._load_json(self.collaboration_log_file)
        
        collaborations = collab_data.get("collaborations", [])
        
        recent_collabs = [
            c for c in collaborations
            if datetime.fromisoformat(c["timestamp"]) > datetime.now() - timedelta(hours=24)
        ]
        
        for collab in recent_collabs:
            if collab["action"] in ["receive_knowledge", "knowledge_share"]:
                network["edges"].append({
                    "source": collab.get("details", {}).get("source", collab["agent_id"]),
                    "target": collab["agent_id"],
                    "type": collab["action"]
                })
        
        return network
    
    def run_collaborative_learning_cycle(self) -> Dict:
        """运行协作学习周期"""
        agents_data = self._load_json(self.agents_file)
        
        active_agents = [
            agent_id for agent_id, agent in agents_data["agents"].items()
            if agent["status"] == "active"
        ]
        
        if len(active_agents) < 2:
            return {
                "status": "insufficient_agents",
                "message": "需要至少2个活跃Agent才能进行协作学习",
                "active_agents": len(active_agents)
            }
        
        cycle_result = {
            "timestamp": datetime.now().isoformat(),
            "participants": len(active_agents),
            "knowledge_shared": 0,
            "knowledge_distributed": 0,
            "insights_generated": 0
        }
        
        kb_data = self._load_json(self.knowledge_base_file)
        
        for knowledge in kb_data.get("shared_knowledge", [])[-10:]:
            if knowledge.get("validation_status") == "pending":
                knowledge["validation_status"] = "validated"
                cycle_result["knowledge_shared"] += 1
        
        kb_data["last_updated"] = datetime.now().isoformat()
        self._save_json(self.knowledge_base_file, kb_data)
        
        logger.info(f"Collaborative learning cycle completed: {cycle_result}")
        
        return cycle_result


def get_multi_agent_learning() -> MultiAgentCollaborativeLearning:
    """获取多Agent协同学习系统单例"""
    if not hasattr(get_multi_agent_learning, "_instance"):
        get_multi_agent_learning._instance = MultiAgentCollaborativeLearning()
    return get_multi_agent_learning._instance
