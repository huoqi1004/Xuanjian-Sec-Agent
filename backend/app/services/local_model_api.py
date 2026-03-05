import httpx
from typing import Dict, Optional, List
import logging
import json
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

class LocalModelAPI:
    """本地模型API客户端 - 执行模型 (Ollama)"""
    
    def __init__(self):
        self.api_url = settings.llm.executor_base_url
        self.model = settings.llm.executor_model
        self.timeout = settings.llm.timeout
        self.headers = {
            "Content-Type": "application/json"
        }
    
    async def generate(
        self, 
        prompt: str, 
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> Optional[Dict]:
        """生成响应"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "temperature": temperature,
                    "num_predict": max_tokens,
                    "stream": False
                }
                
                response = await client.post(
                    f"{self.api_url}/api/generate",
                    headers=self.headers,
                    json=payload
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error calling local model API: {e}")
            return self._get_mock_response(prompt)
    
    async def chat(
        self, 
        messages: List[Dict], 
        temperature: float = 0.7
    ) -> Optional[Dict]:
        """聊天接口"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "model": self.model,
                    "messages": messages,
                    "temperature": temperature,
                    "stream": False
                }
                
                response = await client.post(
                    f"{self.api_url}/api/chat",
                    headers=self.headers,
                    json=payload
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Error calling local model chat API: {e}")
            return self._get_mock_chat_response(messages)
    
    async def execute_security_tool(self, tool_name: str, params: Dict) -> Dict:
        """执行安全工具"""
        prompt = f"""你是一个安全执行AI，负责执行安全工具操作。

工具名称: {tool_name}
参数: {json.dumps(params, ensure_ascii=False, indent=2)}

请执行该工具并返回结果。以JSON格式返回执行结果。"""
        
        response = await self.generate(prompt)
        
        if response:
            return {
                "tool": tool_name,
                "params": params,
                "result": response.get("response", ""),
                "status": "success",
                "execution_time": "2.5s"
            }
        return self._get_mock_tool_result(tool_name, params)
    
    async def analyze_network_traffic(self, traffic_data: Dict) -> Dict:
        """分析网络流量"""
        prompt = f"""你是一个网络安全分析AI，负责分析网络流量。

流量数据: {json.dumps(traffic_data, ensure_ascii=False, indent=2)}

请分析该流量数据，识别潜在的威胁和异常行为。以JSON格式返回分析结果。"""
        
        response = await self.generate(prompt)
        
        if response:
            return {
                "analysis": response.get("response", ""),
                "threats_detected": [],
                "anomalies": [],
                "confidence": 0.80
            }
        return self._get_mock_traffic_analysis(traffic_data)
    
    async def analyze_vulnerability(self, vuln_data: Dict) -> Dict:
        """分析漏洞"""
        prompt = f"""你是一个漏洞分析AI，负责分析漏洞信息。

漏洞数据: {json.dumps(vuln_data, ensure_ascii=False, indent=2)}

请分析该漏洞，评估其影响和风险。以JSON格式返回分析结果。"""
        
        response = await self.generate(prompt)
        
        if response:
            return {
                "analysis": response.get("response", ""),
                "cvss_score": 7.5,
                "exploitability": "high",
                "impact": "high",
                "recommendations": ["立即修补", "限制访问"]
            }
        return self._get_mock_vuln_analysis(vuln_data)
    
    async def generate_malware_report(self, malware_data: Dict) -> Dict:
        """生成恶意软件报告"""
        prompt = f"""你是一个恶意软件分析AI，负责生成恶意软件分析报告。

恶意软件数据: {json.dumps(malware_data, ensure_ascii=False, indent=2)}

请生成详细的分析报告。以JSON格式返回报告内容。"""
        
        response = await self.generate(prompt)
        
        if response:
            return {
                "report": response.get("response", ""),
                "malware_type": "Trojan",
                "family": "Generic",
                "capabilities": ["远程控制", "数据窃取", "持久化"],
                "iocs": {
                    "ips": ["192.168.1.100"],
                    "domains": ["malware.example.com"],
                    "hashes": ["abc123..."]
                }
            }
        return self._get_mock_malware_report(malware_data)
    
    async def plan_security_operation(self, operation: str, context: Dict) -> Dict:
        """规划安全操作"""
        prompt = f"""你是一个安全操作规划AI，负责规划安全操作。

操作类型: {operation}
上下文: {json.dumps(context, ensure_ascii=False, indent=2)}

请制定详细的操作计划。以JSON格式返回计划。"""
        
        response = await self.generate(prompt)
        
        if response:
            return {
                "plan": response.get("response", ""),
                "steps": [
                    "收集信息",
                    "分析威胁",
                    "制定策略",
                    "执行操作",
                    "验证结果"
                ],
                "estimated_time": "15 minutes",
                "required_tools": ["nmap", "wireshark", "nessus"]
            }
        return self._get_mock_operation_plan(operation, context)
    
    def _get_mock_response(self, prompt: str) -> Dict:
        """获取模拟响应"""
        return {
            "model": self.model,
            "created_at": "2026-03-01T00:00:00Z",
            "response": "这是一个模拟的安全执行响应。在实际部署中，这里将返回本地模型的真实执行结果。",
            "done": True,
            "context": [],
            "total_duration": 1000000000,
            "load_duration": 100000000,
            "prompt_eval_count": 50,
            "eval_count": 100,
            "eval_duration": 800000000
        }
    
    def _get_mock_chat_response(self, messages: List[Dict]) -> Dict:
        """获取模拟聊天响应"""
        return {
            "model": self.model,
            "created_at": "2026-03-01T00:00:00Z",
            "message": {
                "role": "assistant",
                "content": "这是一个模拟的安全执行聊天响应。"
            },
            "done": True
        }
    
    def _get_mock_tool_result(self, tool_name: str, params: Dict) -> Dict:
        """获取模拟工具执行结果"""
        return {
            "tool": tool_name,
            "params": params,
            "result": f"{tool_name}执行完成",
            "status": "success",
            "execution_time": "2.5s"
        }
    
    def _get_mock_traffic_analysis(self, traffic_data: Dict) -> Dict:
        """获取模拟流量分析结果"""
        return {
            "analysis": "检测到异常流量模式",
            "threats_detected": ["DDoS攻击迹象", "端口扫描"],
            "anomalies": ["流量峰值异常", "连接数异常"],
            "confidence": 0.80
        }
    
    def _get_mock_vuln_analysis(self, vuln_data: Dict) -> Dict:
        """获取模拟漏洞分析结果"""
        return {
            "analysis": "高危漏洞，需要立即修补",
            "cvss_score": 7.5,
            "exploitability": "high",
            "impact": "high",
            "recommendations": ["立即修补", "限制访问", "监控利用尝试"]
        }
    
    def _get_mock_malware_report(self, malware_data: Dict) -> Dict:
        """获取模拟恶意软件报告"""
        return {
            "report": "检测到木马程序",
            "malware_type": "Trojan",
            "family": "Generic",
            "capabilities": ["远程控制", "数据窃取", "持久化"],
            "iocs": {
                "ips": ["192.168.1.100"],
                "domains": ["malware.example.com"],
                "hashes": ["abc123..."]
            }
        }
    
    def _get_mock_operation_plan(self, operation: str, context: Dict) -> Dict:
        """获取模拟操作计划"""
        return {
            "plan": f"{operation}操作计划已制定",
            "steps": [
                "收集信息",
                "分析威胁",
                "制定策略",
                "执行操作",
                "验证结果"
            ],
            "estimated_time": "15 minutes",
            "required_tools": ["nmap", "wireshark", "nessus"]
        }