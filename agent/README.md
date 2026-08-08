# -*- coding: utf-8 -*-
# 部署说明（Node.js Agent）
# 1. npm install
# 2. 复制 .env.example 为 .env，配置服务端地址与设备凭据
# 3. npm start
#
# 安全说明:
# - Agent 只接受服务端下发的白名单指令（command_result 带指令ID）
# - 基线/等保检查只允许执行内置白名单命令（checks.js），不接受任意 shell 命令
# - 设备 Token 由管理员在平台注册后获取，Agent 部署时写入 .env
