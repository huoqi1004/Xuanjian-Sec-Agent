
# 威胁分析与建模 (Threat Analysis & Modeling)

## 描述
基于威胁情报（IOC）和内部日志数据，分析外部威胁，建立威胁模型，识别攻击者战术、技术和过程（TTPs）。支持对接微步在线威胁情报API和MISP平台，自动关联内部资产，输出结构化威胁情报。

## 输入参数
| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| `iocs` | array | 是 | IOC列表，每个IOC可包含IP、域名、URL、文件哈希等 |
| `time_range` | string | 否 | 查询时间范围，如`last_24h`、`2025-01-01..2025-01-07` |
| `enrich` | boolean | 否 | 是否进行情报富化（关联家族、攻击组织等），默认true |
| `model_framework` | string | 否 | 威胁模型框架：`mitre-attack`、`diamond`，默认`mitre-attack` |

## 输出结果
返回一个JSON对象，包含：
- `matched_iocs`: 命中威胁情报的IOC列表及详情（来源、置信度、家族等）
- `threat_intel`: 关联的威胁情报摘要（攻击组织、恶意软件家族、相关报告）
- `ttp_mapping`: 根据IOC和行为映射的MITRE ATT&CK技术点
- `threat_model`: 构建的威胁模型图（节点：资产、攻击者、IOC，边：关系）
- `raw_data`: 微步/MISP原始返回数据（可选）

## 调用方式
通过MCP协议调用微步在线API进行情报查询，同时查询本地MISP实例，合并内外情报。结果可进一步通过大模型生成自然语言威胁报告。

## 依赖工具/API
- 微步在线API（威胁情报）
- MISP（内部威胁情报平台）
- 本地大模型（用于生成报告和关联分析）
- MITRE ATT&CK知识库（本地映射）

## 示例
```json
{
  "input": {
    "iocs": [
      {"type": "ip", "value": "45.227.253.242"},
      {"type": "domain", "value": "evil.example.com"}
    ],
    "time_range": "last_7d",
    "enrich": true
  },
  "output": {
    "matched_iocs": [
      {
        "ioc": "45.227.253.242",
        "type": "ip",
        "threat_type": "C2",
        "family": "Emotet",
        "confidence": "high",
        "source": "微步在线"
      }
    ],
    "threat_intel": {
      "actor": "TA542",
      "malware": "Emotet",
      "description": "Emotet is a banking trojan often used as a downloader for other malware.",
      "references": ["https://attack.mitre.org/software/S0367/"]
    },
    "ttp_mapping": [
      {"technique": "T1071", "name": "Application Layer Protocol", "description": "C2 communication via HTTP"}
    ]
  }
}