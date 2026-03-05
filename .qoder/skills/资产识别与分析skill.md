
### 文件名：asset_identification.skill.md

```markdown
# 资产识别与分析 (Asset Identification & Analysis)

## 描述
对内网或互联网资产进行主动扫描和被动发现，识别主机、服务、开放端口、操作系统、中间件等信息。支持通过Censys API进行互联网资产测绘，通过nmap进行内网扫描，并结合ELK中的日志数据进行资产指纹补充。

## 输入参数
| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| `scope` | string | 是 | 扫描范围，如IP/CIDR、域名列表、或“internal”表示内网 |
| `scan_type` | string | 否 | 扫描方式：`censys`（互联网）、`nmap`（内网）、`passive`（被动从日志提取），默认`nmap` |
| `ports` | string | 否 | 指定端口范围，如`1-1000`或`80,443,8080`，默认常用端口 |
| `rate` | int | 否 | 扫描速率（仅nmap有效），默认1000包/秒 |
| `timeout` | int | 否 | 超时时间（秒），默认300 |

## 输出结果
返回一个JSON对象，包含：
- `assets`: 资产列表，每个资产包含：
  - `ip`: IP地址
  - `hostname`: 主机名（如有）
  - `os`: 操作系统及版本
  - `ports`: 端口列表，每个端口含端口号、协议、服务、版本、状态
  - `mac`: MAC地址（内网）
  - `tags`: 资产标签（如web服务器、数据库等）
- `summary`: 统计信息（资产总数、开放端口总数、服务分布）
- `raw_output`: 扫描工具原始输出（可选）

## 调用方式
根据`scan_type`调用相应工具：若为`censys`，通过Censys API查询；若为`nmap`，执行本地nmap命令；若为`passive`，从ELK索引中提取最近出现的IP和端口信息。

## 依赖工具/API
- Censys API（互联网资产）
- Nmap（内网扫描）
- ELK Stack（被动资产数据源）
- 本地大模型（用于资产打标和智能识别）

## 示例
```json
{
  "input": {
    "scope": "192.168.1.0/24",
    "scan_type": "nmap",
    "ports": "1-1000",
    "rate": 500
  },
  "output": {
    "assets": [
      {
        "ip": "192.168.1.10",
        "hostname": "web-server",
        "os": "Linux 5.4",
        "ports": [
          {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 7.9", "state": "open"},
          {"port": 80, "protocol": "tcp", "service": "http", "version": "nginx 1.18", "state": "open"}
        ],
        "mac": "00:1a:2b:3c:4d:5e",
        "tags": ["web", "linux"]
      }
    ],
    "summary": {
      "total_assets": 1,
      "total_open_ports": 2,
      "services": {"ssh":1, "http":1}
    }
  }
}