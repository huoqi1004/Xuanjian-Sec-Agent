# -*- coding: utf-8 -*-
"""
LLM报告生成器
使用大语言模型生成安全评估报告和修复建议
"""

import os
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class RAGRetriever:
    """基于关键词匹配的简单RAG检索器"""
    def __init__(self, knowledge_base_path=None):
        if knowledge_base_path is None:
            knowledge_base_path = os.path.join(os.path.dirname(__file__), 'knowledge_base', 'security_knowledge.json')
        self.documents = []
        if os.path.exists(knowledge_base_path):
            try:
                with open(knowledge_base_path, 'r', encoding='utf-8') as f:
                    self.documents = json.load(f)
                logger.info(f'RAG: 已加载 {len(self.documents)} 条知识库文档')
            except Exception as e:
                logger.error(f'RAG: 知识库加载失败: {e}')

    def retrieve(self, query, top_k=3):
        """基于关键词匹配检索相关文档"""
        if not self.documents:
            return []

        query_lower = query.lower()
        scored_docs = []

        for doc in self.documents:
            score = 0
            # 关键词匹配
            for keyword in doc.get('keywords', []):
                if keyword.lower() in query_lower:
                    score += 2
            # 标题匹配
            if any(word in doc['title'].lower() for word in query_lower.split() if len(word) > 1):
                score += 1
            # 类别匹配
            if doc.get('category', '').lower() in query_lower:
                score += 1
            # 内容包含
            if any(word in doc.get('content', '').lower() for word in query_lower.split() if len(word) > 2):
                score += 0.5

            if score > 0:
                scored_docs.append((doc, score))

        # 按分数排序，返回top_k
        scored_docs.sort(key=lambda x: x[1], reverse=True)
        return [doc for doc, score in scored_docs[:top_k]]


class LLMReportGenerator:
    """LLM报告生成器"""

    def __init__(self):
        self.api_key = os.getenv('LLM_API_KEY', '')
        self.api_base = os.getenv('LLM_API_BASE', 'https://api.openai.com/v1')
        self.model = os.getenv('LLM_MODEL', 'gpt-4')
        self.client = None

        if self.api_key:
            try:
                from openai import OpenAI
                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url=self.api_base
                )
                logger.info(f'LLM客户端初始化成功，模型: {self.model}')
            except ImportError:
                logger.warning('openai 包未安装，将使用模板生成报告')
            except Exception as e:
                logger.warning(f'LLM客户端初始化失败: {str(e)}')

    def generate_security_report(self, dashboard, report_type='weekly'):
        """
        生成安全评估报告
        """
        if self.client:
            try:
                return self._generate_with_llm(dashboard, report_type)
            except Exception as e:
                logger.warning(f'LLM报告生成失败，使用模板: {str(e)}')

        return self._generate_template_report(dashboard, report_type)

    def generate_baseline_report(self, results):
        """
        生成基线检查报告
        """
        if self.client:
            try:
                return self._generate_baseline_with_llm(results)
            except Exception as e:
                logger.warning(f'LLM基线报告生成失败，使用模板: {str(e)}')

        return self._generate_baseline_template(results)

    def generate_scan_report(self, scan_data):
        """
        生成病毒扫描报告
        """
        if self.client:
            try:
                return self._generate_scan_with_llm(scan_data)
            except Exception as e:
                logger.warning(f'LLM扫描报告生成失败，使用模板: {str(e)}')

        return self._generate_scan_template(scan_data)

    def _generate_scan_with_llm(self, scan_data):
        """使用LLM生成病毒扫描报告"""
        # RAG检索增强
        rag = RAGRetriever()
        keywords = []
        file_name = scan_data.get('fileName', '')
        decision = scan_data.get('decision', {})
        verdict = decision.get('verdict', '')

        keywords.append(file_name)
        keywords.append(verdict)

        # 从引擎结果中提取关键词
        for engine in scan_data.get('engineSummary', []):
            if engine.get('verdict') in ('malicious', 'suspicious'):
                keywords.append(engine.get('engine', ''))
                keywords.append(engine.get('detail', ''))

        context_docs = rag.retrieve(' '.join(keywords), top_k=3)

        system_prompt = '你是一位资深恶意软件分析专家，擅长撰写专业的病毒扫描分析报告。'
        if context_docs:
            context_text = "\n\n".join([f"【{d['title']}】{d['content']}" for d in context_docs])
            system_prompt += f"\n\n参考知识库内容：\n{context_text}\n\n请结合以上知识库信息生成更专业的扫描报告。"

        # 构建引擎结果表格
        engine_summary = scan_data.get('engineSummary', [])
        engine_table = "| 引擎名称 | 检测状态 | 判定结果 | 置信度 | 响应时间 |\n"
        engine_table += "|----------|----------|----------|--------|----------|\n"
        for eng in engine_summary:
            engine_table += f"| {eng.get('engine', 'N/A')} | {eng.get('status', 'N/A')} | {eng.get('verdict', 'N/A')} | {eng.get('confidence', 0)} | {eng.get('responseTime', 'N/A')} |\n"

        # 构建哈希信息
        hashes = scan_data.get('hashes', {})
        hash_info = ""
        if hashes.get('md5'):
            hash_info += f"- MD5: {hashes['md5']}\n"
        if hashes.get('sha1'):
            hash_info += f"- SHA1: {hashes['sha1']}\n"
        if hashes.get('sha256'):
            hash_info += f"- SHA256: {hashes['sha256']}\n"

        prompt = f"""你是一位资深恶意软件分析专家。请根据以下多引擎病毒扫描结果，生成一份专业的病毒扫描分析报告。

## 扫描数据

### 文件信息
- 文件名: {file_name}
- 文件大小: {scan_data.get('fileSize', 'N/A')} 字节
{hash_info}

### 综合判定
- 判定结果: {verdict}
- 置信度: {decision.get('confidence', 0)}
- 建议: {decision.get('recommendation', 'N/A')}
- 主要依据引擎: {decision.get('primaryEngine', 'N/A')}

### 各引擎扫描结果
{engine_table}

### 检测详情（恶意/可疑引擎）
"""

        # 添加恶意引擎的详细信息
        for eng in engine_summary:
            if eng.get('verdict') in ('malicious', 'suspicious'):
                prompt += f"- **{eng.get('engine', '')}**: {eng.get('detail', '无详细信息')}\n"

        prompt += f"""
### 扫描时间
- 扫描时间: {scan_data.get('scanTime', 'N/A')}
- 总耗时: {scan_data.get('totalTime', 'N/A')}秒

请按照以下格式生成报告（使用中文）：
1. **查杀结论** - 综合判定结果概述
2. **文件信息** - 文件基本信息和哈希值
3. **各引擎扫描结果** - 以表格形式展示所有引擎的检测结果
4. **检测详情** - 对标记为恶意或可疑的引擎结果进行详细分析
5. **处置建议** - 针对当前判定结果给出具体的处置建议和安全措施

请使用专业但易懂的语言，报告要具体、有针对性。"""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': prompt}
            ],
            temperature=0.7,
            max_tokens=4000
        )

        return response.choices[0].message.content

    def _generate_scan_template(self, scan_data):
        """使用模板生成病毒扫描报告"""
        file_name = scan_data.get('fileName', '未知文件')
        file_size = scan_data.get('fileSize', 0)
        hashes = scan_data.get('hashes', {})
        engine_summary = scan_data.get('engineSummary', [])
        decision = scan_data.get('decision', {})
        verdict = decision.get('verdict', 'unknown')
        confidence = decision.get('confidence', 0)
        recommendation = decision.get('recommendation', '无')
        primary_engine = decision.get('primaryEngine', '无')
        scan_time = scan_data.get('scanTime', '未知')
        total_time = scan_data.get('totalTime', '未知')

        # 判定结果映射
        verdict_map = {
            'clean': '安全',
            'suspicious': '可疑',
            'malicious': '恶意',
            'unknown': '未知'
        }
        verdict_cn = verdict_map.get(verdict, verdict)

        # 构建报告
        report = f"""# 病毒扫描分析报告

**报告生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**扫描时间**: {scan_time}

---

## 一、查杀结论

**综合判定**: {verdict_cn}
**置信度**: {confidence * 100:.1f}%
**判定建议**: {recommendation}
**主要依据引擎**: {primary_engine}
**扫描总耗时**: {total_time}秒

"""

        # 添加结论描述
        if verdict == 'clean':
            report += "该文件经多引擎扫描分析，未发现恶意代码特征，判定为**安全文件**。\n"
        elif verdict == 'suspicious':
            report += "该文件经多引擎扫描分析，部分引擎检出可疑特征，判定为**可疑文件**，建议进一步分析确认。\n"
        elif verdict == 'malicious':
            report += "该文件经多引擎扫描分析，多个引擎检出恶意特征，判定为**恶意文件**，建议立即隔离处理。\n"
        else:
            report += "该文件扫描结果不明确，建议进一步分析。\n"

        report += f"""
---

## 二、文件信息

| 属性 | 值 |
|------|------|
| 文件名 | {file_name} |
| 文件大小 | {file_size} 字节 |
"""

        if hashes.get('md5'):
            report += f"| MD5 | `{hashes['md5']}` |\n"
        if hashes.get('sha1'):
            report += f"| SHA1 | `{hashes['sha1']}` |\n"
        if hashes.get('sha256'):
            report += f"| SHA256 | `{hashes['sha256']}` |\n"

        report += f"""
---

## 三、各引擎扫描结果

| 引擎名称 | 检测状态 | 判定结果 | 置信度 | 响应时间 |
|----------|----------|----------|--------|----------|
"""

        for eng in engine_summary:
            eng_verdict = eng.get('verdict', 'N/A')
            eng_verdict_cn = verdict_map.get(eng_verdict, eng_verdict)
            report += f"| {eng.get('engine', 'N/A')} | {eng.get('status', 'N/A')} | {eng_verdict_cn} | {eng.get('confidence', 0)} | {eng.get('responseTime', 'N/A')} |\n"

        # 统计引擎结果
        total_engines = len(engine_summary)
        malicious_engines = [e for e in engine_summary if e.get('verdict') == 'malicious']
        suspicious_engines = [e for e in engine_summary if e.get('verdict') == 'suspicious']
        clean_engines = [e for e in engine_summary if e.get('verdict') == 'clean']

        report += f"""
**统计**: 共 {total_engines} 个引擎参与扫描，其中 {len(clean_engines)} 个判定为安全，{len(suspicious_engines)} 个判定为可疑，{len(malicious_engines)} 个判定为恶意。

---

## 四、检测详情

"""

        # 恶意引擎详情
        if malicious_engines:
            report += "### 恶意检出引擎\n\n"
            for eng in malicious_engines:
                report += f"#### {eng.get('engine', '未知引擎')}\n"
                report += f"- **判定**: 恶意\n"
                report += f"- **置信度**: {eng.get('confidence', 0)}\n"
                report += f"- **详情**: {eng.get('detail', '无详细信息')}\n"
                report += f"- **响应时间**: {eng.get('responseTime', 'N/A')}\n\n"
        else:
            report += "### 恶意检出引擎\n\n无引擎检出恶意特征。\n\n"

        # 可疑引擎详情
        if suspicious_engines:
            report += "### 可疑检出引擎\n\n"
            for eng in suspicious_engines:
                report += f"#### {eng.get('engine', '未知引擎')}\n"
                report += f"- **判定**: 可疑\n"
                report += f"- **置信度**: {eng.get('confidence', 0)}\n"
                report += f"- **详情**: {eng.get('detail', '无详细信息')}\n"
                report += f"- **响应时间**: {eng.get('responseTime', 'N/A')}\n\n"

        report += f"""
---

## 五、处置建议

"""

        if verdict == 'malicious':
            report += """1. **立即隔离**: 将该文件移动至隔离区，防止进一步传播和执行
2. **禁止访问**: 限制该文件的访问权限，确保其他用户无法打开或执行
3. **深入分析**: 对该文件进行逆向分析，确认其恶意行为和影响范围
4. **全网排查**: 根据文件哈希值在全网范围内排查相同文件
5. **溯源追踪**: 追踪文件的来源和传播路径，评估安全影响
6. **更新防护**: 更新病毒库和安全规则，确保同类威胁可被检测
"""
        elif verdict == 'suspicious':
            report += """1. **隔离观察**: 将该文件暂时隔离，避免在未确认安全前继续使用
2. **深度检测**: 使用沙箱或人工分析对该文件进行更深入的检测
3. **监控追踪**: 持续监控该文件的相关活动，关注后续安全动态
4. **备份保留**: 保留文件样本备份，以便后续分析和取证
5. **定期复查**: 在病毒库更新后重新扫描该文件
"""
        else:
            report += """1. **常规使用**: 该文件未检出恶意特征，可正常使用
2. **持续监控**: 建议将该文件纳入常规安全监控范围
3. **定期复查**: 建议定期重新扫描，确保文件未被篡改
4. **安全意识**: 保持良好的安全习惯，不随意下载和执行来源不明的文件
"""

        report += f"\n---\n*本报告由玄鉴安全智能体自动生成，仅供参考。*\n"

        return report

    def _generate_with_llm(self, dashboard, report_type):
        """使用LLM生成安全报告"""
        # RAG检索增强
        rag = RAGRetriever()
        alert_types = []
        alerts_data = dashboard.get('alerts', {})
        if alerts_data.get('critical_count', 0) > 0:
            alert_types.append('严重告警')
        if alerts_data.get('high_count', 0) > 0:
            alert_types.append('高危告警')
        if alerts_data.get('medium_count', 0) > 0:
            alert_types.append('中危告警')
        context_docs = rag.retrieve(f"{report_type} {', '.join(alert_types)}", top_k=3)

        system_prompt = '你是一位资深网络安全专家，擅长撰写安全评估报告。'
        if context_docs:
            context_text = "\n\n".join([f"【{d['title']}】{d['content']}" for d in context_docs])
            system_prompt += f"\n\n参考知识库内容：\n{context_text}\n\n请结合以上知识库信息生成更专业的安全报告。"

        prompt = f"""你是一位资深网络安全专家。请根据以下安全态势数据，生成一份专业的{report_type}安全评估报告。

## 安全态势数据

### 安全评分: {dashboard.get('security_score', 'N/A')}/100

### 告警统计
- 总告警数: {dashboard.get('alerts', {}).get('total', 0)}
- 新告警: {dashboard.get('alerts', {}).get('new_count', 0)}
- 严重告警: {dashboard.get('alerts', {}).get('critical_count', 0)}
- 高危告警: {dashboard.get('alerts', {}).get('high_count', 0)}
- 中危告警: {dashboard.get('alerts', {}).get('medium_count', 0)}
- 低危告警: {dashboard.get('alerts', {}).get('low_count', 0)}

### 威胁情报
- 总情报数: {dashboard.get('threat_intel', {}).get('total', 0)}
- IP情报: {dashboard.get('threat_intel', {}).get('ip_count', 0)}
- 域名情报: {dashboard.get('threat_intel', {}).get('domain_count', 0)}
- CVE情报: {dashboard.get('threat_intel', {}).get('cve_count', 0)}
- 平均置信度: {dashboard.get('threat_intel', {}).get('avg_confidence', 0)}

### 扫描概况
- 总任务数: {dashboard.get('scans', {}).get('total_tasks', 0)}
- 运行中: {dashboard.get('scans', {}).get('running_tasks', 0)}
- 已完成: {dashboard.get('scans', {}).get('completed_tasks', 0)}
- 开放端口: {dashboard.get('scans', {}).get('open_ports', 0)}

### 病毒检测
- 总扫描数: {dashboard.get('virus_detection', {}).get('total_scans', 0)}
- 恶意文件: {dashboard.get('virus_detection', {}).get('malicious_count', 0)}
- 可疑文件: {dashboard.get('virus_detection', {}).get('suspicious_count', 0)}

### 防御策略
- 总策略数: {dashboard.get('defense', {}).get('total_policies', 0)}
- 启用策略: {dashboard.get('defense', {}).get('enabled_policies', 0)}
- 无人值守策略: {dashboard.get('defense', {}).get('unattended_policies', 0)}

### 设备状态
- 总设备数: {dashboard.get('devices', {}).get('total_devices', 0)}
- 在线设备: {dashboard.get('devices', {}).get('online_devices', 0)}

请按照以下格式生成报告：
1. 执行摘要（概述当前安全态势）
2. 风险分析（详细分析各类安全风险）
3. 趋势分析（安全态势变化趋势）
4. 改进建议（具体可操作的安全建议）
5. 结论（总结和下一步行动）

请使用专业但易懂的语言，报告要具体、有针对性。"""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': prompt}
            ],
            temperature=0.7,
            max_tokens=4000
        )

        return response.choices[0].message.content

    def _generate_baseline_with_llm(self, results):
        """使用LLM生成基线检查报告"""
        stats = results.get('stats', {})
        failed = results.get('failed_checks', [])
        warnings = results.get('warning_checks', [])

        prompt = f"""你是一位资深网络安全合规专家。请根据以下基线检查结果，生成一份专业的合规评估报告。

## 检查统计
- 总检查项: {stats.get('total', 0)}
- 通过: {stats.get('pass', 0)}
- 失败: {stats.get('fail', 0)}
- 警告: {stats.get('warn', 0)}
- 合规率: {stats.get('compliance_rate', 0)}%

## 失败项
{json.dumps(failed, ensure_ascii=False, indent=2) if failed else '无'}

## 警告项
{json.dumps(warnings, ensure_ascii=False, indent=2) if warnings else '无'}

请生成包含以下内容的报告：
1. 合规概述
2. 不合规项详细分析
3. 修复建议（按优先级排序）
4. 合规改进路线图"""

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {'role': 'system', 'content': '你是一位资深网络安全合规专家，擅长撰写合规评估报告。'},
                {'role': 'user', 'content': prompt}
            ],
            temperature=0.7,
            max_tokens=4000
        )

        return response.choices[0].message.content

    def _generate_template_report(self, dashboard, report_type):
        """使用模板生成安全报告"""
        score = dashboard.get('security_score', 0)
        alerts = dashboard.get('alerts', {})
        intel = dashboard.get('threat_intel', {})
        scans = dashboard.get('scans', {})
        virus = dashboard.get('virus_detection', {})
        defense = dashboard.get('defense', {})
        devices = dashboard.get('devices', {})

        # 安全等级评定
        if score >= 90:
            level = '优秀'
            level_color = 'green'
        elif score >= 75:
            level = '良好'
            level_color = 'blue'
        elif score >= 60:
            level = '中等'
            level_color = 'yellow'
        elif score >= 40:
            level = '较差'
            level_color = 'orange'
        else:
            level = '危险'
            level_color = 'red'

        report = f"""# 玄鉴安全智能体 - {report_type}安全评估报告

**报告生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**报告类型**: {report_type}
**安全评分**: {score}/100 ({level})

---

## 一、执行摘要

当前系统安全态势评级为 **{level}**，综合安全评分为 **{score}** 分。

- 系统共有 **{alerts.get('total', 0)}** 条安全告警，其中未处理告警 **{alerts.get('new_count', 0)}** 条
- 威胁情报库收录 **{intel.get('total', 0)}** 条情报，平均置信度 **{intel.get('avg_confidence', 0) * 100:.1f}%**
- 已完成 **{scans.get('completed_tasks', 0)}** 次网络扫描，发现 **{scans.get('open_ports', 0)}** 个开放端口
- 文件检测共 **{virus.get('total_scans', 0)}** 次，发现恶意文件 **{virus.get('malicious_count', 0)}** 个
- 部署 **{defense.get('enabled_policies', 0)}** 条自动化防御策略
- 接入 **{devices.get('total_devices', 0)}** 台边缘设备，在线 **{devices.get('online_devices', 0)}** 台

---

## 二、风险分析

### 2.1 告警风险
"""

        # 告警分析
        if alerts.get('critical_count', 0) > 0:
            report += f"- **严重告警**: {alerts['critical_count']} 条，需立即处理\n"
        if alerts.get('high_count', 0) > 0:
            report += f"- **高危告警**: {alerts['high_count']} 条，需优先处理\n"
        if alerts.get('medium_count', 0) > 0:
            report += f"- **中危告警**: {alerts['medium_count']} 条，需安排处理\n"
        if alerts.get('low_count', 0) > 0:
            report += f"- **低危告警**: {alerts['low_count']} 条，建议关注\n"

        report += f"""
### 2.2 威胁情报分析
- IP类情报: {intel.get('ip_count', 0)} 条
- 域名类情报: {intel.get('domain_count', 0)} 条
- 哈希类情报: {intel.get('hash_count', 0)} 条
- CVE漏洞情报: {intel.get('cve_count', 0)} 条

### 2.3 文件安全分析
- 恶意文件检出率: {(virus.get('malicious_count', 0) / max(virus.get('total_scans', 1), 1) * 100):.1f}%
- 可疑文件数量: {virus.get('suspicious_count', 0)} 个
- 投毒样本数量: {virus.get('poisoned_count', 0)} 个

---

## 三、改进建议

### 3.1 紧急措施（24小时内）
"""

        if alerts.get('critical_count', 0) > 0:
            report += f"1. 立即处理 {alerts['critical_count']} 条严重告警\n"
        if virus.get('malicious_count', 0) > 0:
            report += f"2. 隔离并清除 {virus['malicious_count']} 个恶意文件\n"

        report += """
### 3.2 短期措施（一周内）
1. 完成所有高危告警的处理和确认
2. 更新威胁情报库，确保情报时效性
3. 对新发现的开放端口进行服务评估
4. 审查自动化防御策略的有效性

### 3.3 长期措施（一个月内）
1. 建立定期安全评估机制
2. 完善安全事件响应流程
3. 加强边缘设备的安全监控
4. 定期进行安全培训和演练

---

## 四、结论

"""

        if score >= 80:
            report += "当前系统安全状况良好，建议继续保持现有安全措施，并定期进行安全评估。"
        elif score >= 60:
            report += "当前系统存在一定的安全风险，建议按照上述改进建议逐步加强安全防护。"
        else:
            report += "当前系统安全状况较差，存在较多安全风险，建议立即采取紧急措施进行整改。"

        report += f"\n\n---\n*本报告由玄鉴安全智能体自动生成，仅供参考。*\n"

        return report

    def _generate_baseline_template(self, results):
        """使用模板生成基线检查报告"""
        stats = results.get('stats', {})
        failed = results.get('failed_checks', [])
        warnings = results.get('warning_checks', [])
        by_severity = results.get('bySeverity', {})

        report = f"""# 基线安全检查报告

**报告生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 一、检查概述

| 指标 | 数值 |
|------|------|
| 总检查项 | {stats.get('total', 0)} |
| 通过 | {stats.get('pass', 0)} |
| 失败 | {stats.get('fail', 0)} |
| 警告 | {stats.get('warn', 0)} |
| **合规率** | **{stats.get('compliance_rate', 0)}%** |

---

## 二、不合规项详情

### 严重级别 (Critical)
"""

        critical = by_severity.get('critical', [])
        if critical:
            for item in critical:
                report += f"- **{item.get('check_name', '')}** ({item.get('check_id', '')})\n"
                report += f"  - 修复建议: {item.get('remediation', 'N/A')}\n\n"
        else:
            report += "无严重级别不合规项\n\n"

        report += "### 高级别 (High)\n"
        high = by_severity.get('high', [])
        if high:
            for item in high:
                report += f"- **{item.get('check_name', '')}** ({item.get('check_id', '')})\n"
                report += f"  - 修复建议: {item.get('remediation', 'N/A')}\n\n"
        else:
            report += "无高级别不合规项\n\n"

        report += "### 中级别 (Medium)\n"
        medium = by_severity.get('medium', [])
        if medium:
            for item in medium:
                report += f"- **{item.get('check_name', '')}** ({item.get('check_id', '')})\n"
                report += f"  - 修复建议: {item.get('remediation', 'N/A')}\n\n"
        else:
            report += "无中级别不合规项\n\n"

        report += "### 低级别 (Low)\n"
        low = by_severity.get('low', [])
        if low:
            for item in low:
                report += f"- **{item.get('check_name', '')}** ({item.get('check_id', '')})\n"
                report += f"  - 修复建议: {item.get('remediation', 'N/A')}\n\n"
        else:
            report += "无低级别不合规项\n\n"

        report += "---\n*本报告由玄鉴安全智能体自动生成，仅供参考。*\n"

        return report
