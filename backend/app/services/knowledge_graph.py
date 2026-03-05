#!/usr/bin/env python3
"""
Knowledge Graph - 知识图谱更新模块
实现威胁知识、防御策略、攻击模式的图谱化管理和动态更新
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum
import threading
import re

logger = logging.getLogger(__name__)


class EntityType(str, Enum):
    THREAT = "threat"
    VULNERABILITY = "vulnerability"
    ATTACK_PATTERN = "attack_pattern"
    DEFENSE_STRATEGY = "defense_strategy"
    TOOL = "tool"
    ASSET = "asset"
    INDICATOR = "indicator"
    CAMPAIGN = "campaign"
    ACTOR = "actor"
    MALWARE = "malware"


class RelationType(str, Enum):
    ATTACKS = "attacks"
    EXPLOITS = "exploits"
    USES = "uses"
    DETECTS = "detects"
    MITIGATES = "mitigates"
    BELONGS_TO = "belongs_to"
    RELATED_TO = "related_to"
    TARGETS = "targets"
    COMMUNICATES_WITH = "communicates_with"
    DROPS = "drops"


class UpdateSource(str, Enum):
    AUTOMATED = "automated"
    MANUAL = "manual"
    FEEDBACK = "feedback"
    INTEGRATION = "integration"
    AI_ANALYSIS = "ai_analysis"


class KnowledgeGraph:
    """
    知识图谱管理系统
    支持实体和关系的增删改查，提供图推理能力
    """
    
    def __init__(self, data_dir: str = None):
        self.data_dir = Path(data_dir) if data_dir else Path(__file__).parent.parent / "data" / "knowledge_graph"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.entities_file = self.data_dir / "entities.json"
        self.relations_file = self.data_dir / "relations.json"
        self.update_log_file = self.data_dir / "update_log.json"
        self.inference_cache_file = self.data_dir / "inference_cache.json"
        
        self._init_data_files()
        
        self._lock = threading.Lock()
        
        self.auto_update_enabled = True
        self.inference_depth = 3
        
        logger.info("KnowledgeGraph initialized")
    
    def _init_data_files(self):
        """初始化数据文件"""
        if not self.entities_file.exists():
            self._save_json(self.entities_file, {
                "entities": {},
                "index_by_type": {},
                "index_by_name": {},
                "last_updated": datetime.now().isoformat()
            })
        
        if not self.relations_file.exists():
            self._save_json(self.relations_file, {
                "relations": [],
                "index_by_type": {},
                "index_by_source": {},
                "index_by_target": {},
                "last_updated": datetime.now().isoformat()
            })
        
        if not self.update_log_file.exists():
            self._save_json(self.update_log_file, {
                "updates": [],
                "last_updated": datetime.now().isoformat()
            })
        
        if not self.inference_cache_file.exists():
            self._save_json(self.inference_cache_file, {
                "inferences": {},
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
    
    def add_entity(self, entity_type: EntityType, name: str, 
                  properties: Dict = None, sources: List[str] = None) -> str:
        """
        添加实体到知识图谱
        """
        with self._lock:
            data = self._load_json(self.entities_file)
            
            entity_id = self._generate_entity_id(name, entity_type)
            
            if entity_id in data["entities"]:
                logger.warning(f"Entity {entity_id} already exists")
                return entity_id
            
            entity = {
                "id": entity_id,
                "type": entity_type.value,
                "name": name,
                "properties": properties or {},
                "sources": sources or ["manual"],
                "confidence": 1.0,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                "last_referenced": datetime.now().isoformat(),
                "reference_count": 0,
                "tags": []
            }
            
            data["entities"][entity_id] = entity
            
            if entity_type.value not in data["index_by_type"]:
                data["index_by_type"][entity_type.value] = []
            data["index_by_type"][entity_type.value].append(entity_id)
            
            name_lower = name.lower()
            if name_lower not in data["index_by_name"]:
                data["index_by_name"][name_lower] = []
            data["index_by_name"][name_lower].append(entity_id)
            
            data["last_updated"] = datetime.now().isoformat()
            
            self._save_json(self.entities_file, data)
            
            self._log_update(
                UpdateSource.AUTOMATED,
                "add_entity",
                {"entity_id": entity_id, "type": entity_type.value, "name": name}
            )
            
            self._invalidate_cache()
            
            logger.info(f"Entity added: {entity_id}")
            return entity_id
    
    def _generate_entity_id(self, name: str, entity_type: EntityType) -> str:
        """生成实体ID"""
        name_normalized = re.sub(r'[^a-zA-Z0-9]', '_', name.lower())
        name_normalized = name_normalized[:50]
        return f"{entity_type.value}_{name_normalized}"
    
    def add_relation(self, source_id: str, target_id: str, 
                    relation_type: RelationType, properties: Dict = None) -> Optional[str]:
        """
        添加关系到知识图谱
        """
        with self._lock:
            entities_data = self._load_json(self.entities_file)
            
            if source_id not in entities_data["entities"]:
                logger.warning(f"Source entity {source_id} not found")
                return None
            
            if target_id not in entities_data["entities"]:
                logger.warning(f"Target entity {target_id} not found")
                return None
            
            rel_data = self._load_json(self.relations_file)
            
            relation_id = f"rel_{len(rel_data['relations']) + 1}"
            
            relation = {
                "id": relation_id,
                "source": source_id,
                "target": target_id,
                "type": relation_type.value,
                "properties": properties or {},
                "confidence": 1.0,
                "created_at": datetime.now().isoformat(),
                "validated": False
            }
            
            rel_data["relations"].append(relation)
            
            if relation_type.value not in rel_data["index_by_type"]:
                rel_data["index_by_type"][relation_type.value] = []
            rel_data["index_by_type"][relation_type.value].append(relation_id)
            
            if source_id not in rel_data["index_by_source"]:
                rel_data["index_by_source"][source_id] = []
            rel_data["index_by_source"][source_id].append(relation_id)
            
            if target_id not in rel_data["index_by_target"]:
                rel_data["index_by_target"][target_id] = []
            rel_data["index_by_target"][target_id].append(relation_id)
            
            rel_data["last_updated"] = datetime.now().isoformat()
            
            self._save_json(self.relations_file, rel_data)
            
            entities_data["entities"][source_id]["updated_at"] = datetime.now().isoformat()
            entities_data["entities"][target_id]["updated_at"] = datetime.now().isoformat()
            self._save_json(self.entities_file, entities_data)
            
            self._log_update(
                UpdateSource.AUTOMATED,
                "add_relation",
                {"relation_id": relation_id, "type": relation_type.value}
            )
            
            self._invalidate_cache()
            
            logger.info(f"Relation added: {relation_id}")
            return relation_id
    
    def _log_update(self, source: UpdateSource, action: str, details: Dict):
        """记录更新日志"""
        data = self._load_json(self.update_log_file)
        
        update = {
            "timestamp": datetime.now().isoformat(),
            "source": source.value,
            "action": action,
            "details": details
        }
        
        data["updates"].append(update)
        
        if len(data["updates"]) > 1000:
            data["updates"] = data["updates"][-1000:]
        
        data["last_updated"] = datetime.now().isoformat()
        
        self._save_json(self.update_log_file, data)
    
    def _invalidate_cache(self):
        """使推理缓存失效"""
        self._save_json(self.inference_cache_file, {
            "inferences": {},
            "last_updated": datetime.now().isoformat()
        })
    
    def get_entity(self, entity_id: str) -> Optional[Dict]:
        """获取实体"""
        data = self._load_json(self.entities_file)
        
        entity = data["entities"].get(entity_id)
        
        if entity:
            entity["reference_count"] += 1
            entity["last_referenced"] = datetime.now().isoformat()
            data["last_updated"] = datetime.now().isoformat()
            self._save_json(self.entities_file, data)
        
        return entity
    
    def search_entities(self, query: str, entity_type: EntityType = None, 
                       limit: int = 10) -> List[Dict]:
        """搜索实体"""
        data = self._load_json(self.entities_file)
        
        results = []
        query_lower = query.lower()
        
        for entity_id, entity in data["entities"].items():
            if entity_type and entity["type"] != entity_type.value:
                continue
            
            if query_lower in entity["name"].lower():
                results.append(entity)
                continue
            
            for tag in entity.get("tags", []):
                if query_lower in tag.lower():
                    results.append(entity)
                    break
        
        results.sort(key=lambda x: x.get("reference_count", 0), reverse=True)
        
        return results[:limit]
    
    def get_relations(self, entity_id: str, relation_type: RelationType = None,
                     direction: str = "both") -> List[Dict]:
        """获取实体相关关系"""
        rel_data = self._load_json(self.relations_file)
        
        results = []
        
        for relation in rel_data["relations"]:
            if relation_type and relation["type"] != relation_type.value:
                continue
            
            if direction in ["source", "both"] and relation["source"] == entity_id:
                results.append(relation)
            
            if direction in ["target", "both"] and relation["target"] == entity_id:
                results.append(relation)
        
        return results
    
    def get_neighbors(self, entity_id: str, depth: int = 1, 
                    relation_types: List[RelationType] = None) -> Dict[str, List[Dict]]:
        """获取邻居实体"""
        neighbors = {
            "direct": [],
            "indirect": []
        }
        
        direct_relations = self.get_relations(entity_id, direction="both")
        
        for rel in direct_relations:
            if relation_types and rel["type"] not in [rt.value for rt in relation_types]:
                continue
            
            neighbor_id = rel["target"] if rel["source"] == entity_id else rel["source"]
            neighbor = self.get_entity(neighbor_id)
            
            if neighbor:
                neighbors["direct"].append({
                    "entity": neighbor,
                    "relation": rel
                })
        
        if depth > 1:
            for neighbor in neighbors["direct"]:
                sub_neighbors = self.get_neighbors(
                    neighbor["entity"]["id"], 
                    depth=depth-1,
                    relation_types=relation_types
                )
                neighbors["indirect"].extend(sub_neighbors.get("direct", []))
        
        return neighbors
    
    def query_path(self, source_id: str, target_id: str, 
                  max_depth: int = 3) -> List[List[Dict]]:
        """查询两点之间的路径"""
        visited = set()
        paths = []
        
        def dfs(current: str, target: str, path: List[str], depth: int):
            if depth > max_depth:
                return
            
            if current == target:
                paths.append(path.copy())
                return
            
            visited.add(current)
            
            relations = self.get_relations(current, direction="source")
            
            for rel in relations:
                next_node = rel["target"]
                
                if next_node not in visited:
                    path.append(next_node)
                    dfs(next_node, target, path, depth + 1)
                    path.pop()
            
            visited.remove(current)
        
        dfs(source_id, target_id, [source_id], 0)
        
        return paths
    
    def update_entity(self, entity_id: str, updates: Dict) -> bool:
        """更新实体"""
        with self._lock:
            data = self._load_json(self.entities_file)
            
            if entity_id not in data["entities"]:
                return False
            
            entity = data["entities"][entity_id]
            
            entity.update(updates)
            entity["updated_at"] = datetime.now().isoformat()
            
            data["last_updated"] = datetime.now().isoformat()
            
            self._save_json(self.entities_file, data)
            
            self._log_update(
                UpdateSource.AUTOMATED,
                "update_entity",
                {"entity_id": entity_id}
            )
            
            self._invalidate_cache()
            
            return True
    
    def add_threat_intelligence(self, threat_data: Dict) -> str:
        """
        添加威胁情报到知识图谱
        """
        threat_name = threat_data.get("name", "Unknown Threat")
        
        threat_id = self.add_entity(
            EntityType.THREAT,
            threat_name,
            properties={
                "severity": threat_data.get("severity", "medium"),
                "category": threat_data.get("category", "unknown"),
                "description": threat_data.get("description", ""),
                "first_seen": threat_data.get("first_seen"),
                "last_seen": threat_data.get("last_seen"),
                "source": threat_data.get("source", "manual")
            },
            sources=[threat_data.get("source", "manual")]
        )
        
        if "attack_patterns" in threat_data:
            for pattern in threat_data["attack_patterns"]:
                pattern_id = self.add_entity(
                    EntityType.ATTACK_PATTERN,
                    pattern,
                    properties={"source_threat": threat_name}
                )
                self.add_relation(
                    threat_id, pattern_id, RelationType.ATTACKS
                )
        
        if "indicators" in threat_data:
            for indicator in threat_data["indicators"]:
                indicator_id = self.add_entity(
                    EntityType.INDICATOR,
                    indicator,
                    properties={"type": "ioc", "parent_threat": threat_name}
                )
                self.add_relation(
                    threat_id, indicator_id, RelationType.RELATED_TO
                )
        
        if "mitigations" in threat_data:
            for mitigation in threat_data["mitigations"]:
                mitigation_id = self.add_entity(
                    EntityType.DEFENSE_STRATEGY,
                    mitigation,
                    properties={"description": f"Mitigation for {threat_name}"}
                )
                self.add_relation(
                    threat_id, mitigation_id, RelationType.MITIGATES
                )
        
        logger.info(f"Threat intelligence added: {threat_id}")
        return threat_id
    
    def add_vulnerability(self, vuln_data: Dict) -> str:
        """添加漏洞到知识图谱"""
        vuln_name = vuln_data.get("name", "Unknown Vulnerability")
        
        vuln_id = self.add_entity(
            EntityType.VULNERABILITY,
            vuln_name,
            properties={
                "cve_id": vuln_data.get("cve_id"),
                "severity": vuln_data.get("severity", "medium"),
                "cvss_score": vuln_data.get("cvss_score"),
                "description": vuln_data.get("description", ""),
                "affected_products": vuln_data.get("affected_products", []),
                "exploit_available": vuln_data.get("exploit_available", False)
            },
            sources=["vulnerability_scanner"]
        )
        
        if "exploits" in vuln_data:
            for exploit in vuln_data["exploits"]:
                exploit_id = self.add_entity(
                    EntityType.ATTACK_PATTERN,
                    exploit,
                    properties={"type": "exploit"}
                )
                self.add_relation(
                    vuln_id, exploit_id, RelationType.EXPLOITS
                )
        
        return vuln_id
    
    def analyze_attack_chain(self, indicators: List[str]) -> Dict:
        """
        分析攻击链
        """
        entities_data = self._load_json(self.entities_file)
        
        matched_entities = []
        
        for indicator in indicators:
            search_results = self.search_entities(indicator, limit=5)
            matched_entities.extend(search_results)
        
        attack_chain = {
            "indicators": indicators,
            "matched_entities": matched_entities,
            "attack_steps": [],
            "recommendations": []
        }
        
        if matched_entities:
            for entity in matched_entities:
                if entity["type"] == EntityType.THREAT.value:
                    neighbors = self.get_neighbors(entity["id"])
                    
                    attack_chain["attack_steps"].append({
                        "threat": entity["name"],
                        "related_patterns": [n["entity"]["name"] for n in neighbors.get("direct", [])],
                        "mitigations": []
                    })
                    
                    for neighbor in neighbors.get("direct", []):
                        if neighbor["relation"]["type"] == RelationType.MITIGATES.value:
                            attack_chain["attack_steps"][-1]["mitigations"].append(
                                neighbor["entity"]["name"]
                            )
        
        if not attack_chain["attack_steps"]:
            attack_chain["recommendations"].append({
                "type": "investigation",
                "message": "未在知识图谱中找到匹配的威胁实体，建议进行进一步调查"
            })
        
        return attack_chain
    
    def get_defense_recommendations(self, threat_name: str) -> List[Dict]:
        """获取防御建议"""
        threat_results = self.search_entities(threat_name, EntityType.THREAT, limit=5)
        
        recommendations = []
        
        for threat in threat_results:
            neighbors = self.get_neighbors(threat["id"])
            
            for neighbor in neighbors.get("direct", []):
                if neighbor["relation"]["type"] == RelationType.MITIGATES.value:
                    recommendations.append({
                        "threat": threat["name"],
                        "mitigation": neighbor["entity"]["name"],
                        "priority": threat.get("properties", {}).get("severity", "medium"),
                        "entity": neighbor["entity"]
                    })
        
        return recommendations
    
    def get_statistics(self) -> Dict:
        """获取知识图谱统计"""
        entities_data = self._load_json(self.entities_file)
        rel_data = self._load_json(self.relations_file)
        
        stats = {
            "total_entities": len(entities_data["entities"]),
            "total_relations": len(rel_data["relations"]),
            "by_entity_type": {},
            "by_relation_type": {},
            "most_referenced": [],
            "recent_updates": []
        }
        
        for entity_id, entity in entities_data["entities"].items():
            etype = entity["type"]
            stats["by_entity_type"][etype] = stats["by_entity_type"].get(etype, 0) + 1
        
        for relation in rel_data["relations"]:
            rtype = relation["type"]
            stats["by_relation_type"][rtype] = stats["by_relation_type"].get(rtype, 0) + 1
        
        sorted_entities = sorted(
            entities_data["entities"].items(),
            key=lambda x: x[1].get("reference_count", 0),
            reverse=True
        )
        stats["most_referenced"] = [
            {"id": e[0], "name": e[1]["name"], "type": e[1]["type"]}
            for e in sorted_entities[:10]
        ]
        
        update_data = self._load_json(self.update_log_file)
        stats["recent_updates"] = update_data.get("updates", [])[-10:]
        
        return stats
    
    def export_graph(self, format: str = "json") -> Dict:
        """导出知识图谱"""
        entities = self._load_json(self.entities_file)
        relations = self._load_json(self.relations_file)
        
        return {
            "entities": entities["entities"],
            "relations": relations["relations"],
            "exported_at": datetime.now().isoformat(),
            "version": "1.0"
        }


def get_knowledge_graph() -> KnowledgeGraph:
    """获取知识图谱单例"""
    if not hasattr(get_knowledge_graph, "_instance"):
        get_knowledge_graph._instance = KnowledgeGraph()
    return get_knowledge_graph._instance
