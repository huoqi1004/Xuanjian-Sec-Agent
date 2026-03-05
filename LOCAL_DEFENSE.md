# 本地安全防御系统配置

## 网络环境

### 网络适配器
| 名称 | 类型 | IP地址 | 状态 |
|------|------|--------|------ 主|
| WLAN |网络 | 192.168.x.x | ✅ 在线 |
| VMnet8 | VMware NAT | 192.168.233.1 | ✅ 在线 |
| VMnet1 | VMware Host-Only | 192.168.10.1 | ✅ 在线 |

## 安全工具配置

### 1. Nmap 扫描器
```bash
# 安装 Nmap
choco install nmap -y

# 基本扫描命令
nmap -sV -sC -O 192.168.1.0/24
nmap -p- -A 目标IP
nmap --script vuln 目标IP
```

### 2. 本地WAF配置 (雷池)
```bash
# 雷池WAF安装 (Docker)
docker run -d --name leechi-waf \
  -p 8000:8000 \
  -v /var/leechi:/var/lib/leechi \
  chaitin/leechi:latest
```

### 3. 防火墙配置 (Windows Defender)
```powershell
# 查看防火墙状态
Get-NetFirewallProfile

# 创建入站规则
New-NetFirewallRule -DisplayName "Block Malicious IP" -Direction Inbound -Action Block -RemoteAddress "恶意IP"
```

## 监控目标

### 内网资产发现
- 192.168.1.0/24 (主网络)
- 192.168.10.0/24 (VMware Host-Only)
- 192.168.233.0/24 (VMware NAT)

### 常用服务端口
| 端口 | 服务 |
|------|------|
| 22 | SSH |
| 80/443 | HTTP/HTTPS |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 27017 | MongoDB |
| 3389 | RDP |
| 21 | FTP |

## 安全策略

### 告警阈值
- SSH暴力破解: 5次失败/分钟
- SQL注入: 立即告警
- 端口扫描: 10个端口/分钟
- 异常流量: 100MB/分钟

### 自动响应
1. 检测到恶意IP → 自动封禁
2. 检测到漏洞 → 创建工单
3. 检测到异常行为 → 告警通知

## 集成状态

| 组件 | 状态 | 说明 |
|------|------|------|
| Nmap扫描 | ✅ 已集成 | 本地防御系统已集成Nmap扫描功能 |
| WAF | ✅ 已集成 | 本地防御系统已集成WAF管理功能 |
| 防火墙 | ✅ 可用 | Windows Defender已配置 |
| 入侵检测 | ✅ 已集成 | 本地防御系统已集成入侵检测功能 |
| 高级防御 | ✅ 已集成 | AI驱动的高级防御系统已部署 |
