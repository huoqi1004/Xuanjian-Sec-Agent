# 代码审计 (Code Audit)

## 基本信息
- **ID**: code_audit
- **类别**: 应用安全
- **图标**: 💻
- **版本**: 1.0.0
- **状态**: active

## 描述
对源代码进行安全审计，识别潜在的安全漏洞和代码质量问题。支持多种编程语言和框架，可检测常见的安全漏洞和代码缺陷。

## 输入参数
| 参数名 | 类型 | 必填 | 默认值 | 描述 |
|--------|------|------|--------|------|
| `target` | string | 是 | - | 代码目录或文件路径 |
| `language` | string | 否 | "auto" | 编程语言，如`java`、`python`、`javascript`等，默认自动检测 |
| `severity` | string | 否 | "all" | 漏洞严重程度过滤：`all`、`critical`、`high`、`medium`、`low` |
| `output_format` | string | 否 | "json" | 输出格式：`json`、`html`、`sonarqube` |
| `include_code_quality` | boolean | 否 | true | 是否包含代码质量分析 |

## 输出结果
返回一个JSON对象，包含：
- `audit_summary`: 审计摘要：
  - `audit_time`: 审计时间
  - `audit_duration`: 审计持续时间
  - `files_analyzed`: 分析的文件数
  - `issues_found`: 发现的问题数
- `vulnerabilities`: 安全漏洞列表，每个漏洞包含：
  - `id`: 漏洞ID
  - `title`: 漏洞标题
  - `severity`: 严重程度
  - `file_path`: 文件路径
  - `line_number`: 行号
  - `description`: 漏洞描述
  - `fix_recommendation`: 修复建议
- `code_quality`: 代码质量分析（如果启用）
- `recommendations`: 安全建议

## 调用方式
1. 分析目标代码，识别编程语言和框架
2. 使用SonarQube或其他代码分析工具进行安全审计
3. 检测常见的安全漏洞，如注入漏洞、认证缺陷等
4. 分析代码质量和维护性
5. 生成审计报告和修复建议
6. 可选：与CI/CD管道集成

## 依赖工具/API
- SonarQube（代码分析）
- SAST工具（静态代码安全分析）
- 代码分析引擎
- 本地大模型（漏洞分析和修复建议）

## 示例
```json
{
  "input": {
    "target": "/path/to/project",
    "language": "javascript",
    "severity": "high",
    "output_format": "json",
    "include_code_quality": true
  },
  "output": {
    "audit_summary": {
      "audit_time": "2024-01-01T12:00:00Z",
      "audit_duration": 300,
      "files_analyzed": 50,
      "issues_found": 5
    },
    "vulnerabilities": [
      {
        "id": "VULN-001",
        "title": "SQL注入漏洞",
        "severity": "high",
        "file_path": "src/database.js",
        "line_number": 42,
        "description": "直接拼接SQL语句，存在SQL注入风险",
        "fix_recommendation": "使用参数化查询或ORM框架"
      },
      {
        "id": "VULN-002",
        "title": "XSS漏洞",
        "severity": "medium",
        "file_path": "src/views/home.js",
        "line_number": 28,
        "description": "未对用户输入进行转义",
        "fix_recommendation": "使用HTML转义函数"
      }
    ],
    "code_quality": {
      "duplication_rate": 5.2,
      "complexity": 12.5,
      "test_coverage": 80.0
    },
    "recommendations": [
      "定期进行代码安全审计",
      "实施安全编码规范",
      "增加自动化安全测试"
    ]
  }
}
```