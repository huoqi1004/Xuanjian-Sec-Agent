# 玄鉴安全智能体 - 多引擎协同安全评估系统

## 项目简介

玄鉴安全智能体是一个集成了多种安全评估引擎的综合安全评估系统，提供网络扫描、基线排查、病毒查杀、态势感知、自动化防御和边缘设备管理等功能。

## 项目结构

```
xuanjian-security-agent/
├── server/                    # Node.js 后端服务
│   ├── server.js              # 主入口
│   ├── config/                # 配置管理
│   ├── db/                    # 数据库（SQLite）
│   ├── middleware/             # 中间件（认证/权限/审计）
│   ├── routes/                # API路由
│   ├── services/              # 业务服务
│   ├── utils/                 # 工具函数
│   └── uploads/               # 上传文件目录
├── ai-service/                # Python AI微服务
│   ├── app.py                 # AI服务入口
│   ├── malware_detector.py    # 恶意代码检测
│   ├── poisoning_detector.py  # 投毒检测
│   ├── llm_report.py          # LLM报告生成
│   └── models/                # AI模型文件
├── frontend/                  # 旧版前端（已由 frontend-app 取代，兼容保留）
├── frontend-app/              # 前端工程（Vite + Vue3 + TypeScript + Pinia）
│   ├── src/views/             # 12 个业务页面组件
│   ├── src/api/               # API 封装（axios + 拦截器）
│   ├── src/stores/            # Pinia 状态管理
│   ├── src/layouts/           # 主布局（侧边栏/顶栏）
│   └── dist/                  # 构建产物（npm run build 生成，后端自动托管）
├── docker-compose.yml         # Docker编排
├── Dockerfile.server          # 后端Dockerfile
├── Dockerfile.ai              # AI服务Dockerfile
└── .env.example               # 环境变量模板
```

## 功能模块

| 模块 | 说明 |
|------|------|
| 网络扫描 | TCP Connect端口扫描、Banner抓取、服务指纹识别 |
| 基线排查 | CIS/等保2.0基线检查、合规率统计、修复建议 |
| 病毒查杀 | 多引擎检测（本地库+VirusTotal+AI模型）、投毒检测 |
| 态势感知 | 威胁情报、告警管理、安全仪表盘、LLM报告 |
| 自动化防御 | 规则引擎、条件-动作策略、自动封禁、告警联动 |
| 边缘设备 | 设备注册、心跳检测、WebSocket通信、指令下发 |

## 快速开始

### 环境要求

- Node.js >= 18
- Python >= 3.10（AI服务）
- SQLite3

### 安装步骤

1. **克隆项目**
```bash
git clone <repository-url>
cd xuanjian-security-agent
```

2. **配置环境变量**
```bash
cp .env.example .env
# 编辑 .env 文件，配置必要的参数
```

3. **启动后端服务**
```bash
cd server
npm install
npm run dev
```

4. **启动AI微服务（可选）**
```bash
cd ai-service
pip install -r requirements.txt
python app.py
```

5. **前端开发（可选）**
```bash
cd frontend-app
npm install
npm run dev        # 开发模式 http://localhost:5173（代理 /api 与 /ws 到 3000）
npm run build      # 生产构建，产物 dist/ 由后端自动托管
```

6. **使用Docker部署（推荐）**
```bash
docker-compose up -d
```

### 默认账号

- 用户名: `admin`
- 密码: `admin123`

## API文档

服务启动后访问 `http://localhost:3000`，API前缀为 `/api`。

### 认证接口
- `POST /api/auth/login` - 用户登录
- `POST /api/auth/register` - 用户注册（管理员）
- `GET /api/auth/profile` - 获取用户信息
- `PUT /api/auth/password` - 修改密码

### 扫描接口
- `POST /api/scan/start` - 启动扫描
- `GET /api/scan/tasks` - 任务列表
- `GET /api/scan/tasks/:id` - 任务详情

### 基线接口
- `GET /api/baseline/policies` - 策略列表
- `POST /api/baseline/check` - 启动检查
- `GET /api/baseline/results/:taskId` - 检查结果

### 病毒检测接口
- `POST /api/virus/upload` - 上传检测
- `GET /api/virus/records` - 检测历史

### 态势感知接口
- `GET /api/situational/dashboard` - 仪表盘数据
- `GET /api/situational/alerts` - 告警列表
- `GET /api/situational/threat-intel` - 威胁情报

### 防御策略接口
- `GET /api/defense/policies` - 策略列表
- `POST /api/defense/policies` - 创建策略
- `GET /api/defense/action-logs` - 动作日志

### 设备管理接口
- `GET /api/device/list` - 设备列表
- `POST /api/device/register` - 设备注册
- `POST /api/device/:id/command` - 下发指令

## 技术栈

- **后端**: Express.js, better-sqlite3, jsonwebtoken, json-rules-engine
- **AI服务**: Flask, Transformers, PyTorch, OpenAI API
- **通信**: REST API, WebSocket
- **部署**: Docker, Docker Compose

## 统一响应格式

```json
{
  "code": 0,
  "message": "操作成功",
  "data": {}
}
```

- `code: 0` 表示成功，`code: 1` 表示失败
