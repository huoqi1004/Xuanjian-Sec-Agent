# N-06 MySQL 测试环境一键脚本（Windows PowerShell / bash 双语法）
# 用途：本地启动 MySQL 容器并跑双驱动适配测试（对应报告 Phase D）
#
# 用法：
#   PowerShell:  .\scripts\n06\start-mysql.ps1
#   bash:        bash scripts/n06/start-mysql.sh
#
# 依赖：已安装 Docker Desktop

param(
  [string]$Port = "3306",
  [string]$Database = "xuanjian",
  [string]$User = "xuanjian",
  [string]$Password = "xuanjian123",
  [string]$RootPassword = "root123456"
)

$ErrorActionPreference = "Stop"
$container = "xuanjian-mysql-test"

# 1. 启动 MySQL 8 容器（已存在则复用）
$existing = docker ps -a --filter "name=$container" --format "{{.Names}}" 2>$null
if ($existing -eq $container) {
  Write-Host "[N-06] 复用已有容器 $container"
  docker start $container | Out-Null
} else {
  Write-Host "[N-06] 启动 MySQL 容器 $container ..."
  docker run -d --name $container `
    -e MYSQL_ROOT_PASSWORD=$RootPassword `
    -e MYSQL_DATABASE=$Database `
    -e MYSQL_USER=$User `
    -e MYSQL_PASSWORD=$Password `
    -p "${Port}:3306" `
    mysql:8.0 `
    --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci | Out-Null
}

# 2. 等待就绪（最多 60s）
Write-Host "[N-06] 等待 MySQL 就绪 ..."
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Seconds 2
  $ok = docker exec $container mysqladmin ping -h 127.0.0.1 -u$User -p$Password --silent 2>$null
  if ($LASTEXITCODE -eq 0) { $ready = $true; break }
}
if (-not $ready) { Write-Error "[N-06] MySQL 启动超时"; exit 1 }

Write-Host "[N-06] MySQL 就绪: 127.0.0.1:$Port/$Database (user=$User)"

# 3. 建表 + seed 迁移
Write-Host "[N-06] 应用 schema 与迁移 ..."
$env:DB_DRIVER = "mysql"
$env:DB_HOST = "127.0.0.1"
$env:DB_PORT = $Port
$env:DB_USER = $User
$env:DB_PASSWORD = $Password
$env:DB_NAME = $Database
node scripts/n06/run-migrations.js
if ($LASTEXITCODE -ne 0) { Write-Error "[N-06] 迁移失败"; exit 1 }

# 4. 双驱动适配测试
Write-Host "[N-06] 运行 MySQL 驱动适配测试 ..."
Push-Location server
$env:DB_DRIVER = "mysql"
npx jest test/db-adapters.test.js --forceExit
$code = $LASTEXITCODE
Pop-Location

if ($code -ne 0) {
  Write-Host "[N-06] MySQL 测试失败 (exit=$code)"
} else {
  Write-Host "[N-06] ✅ MySQL 双跑测试通过"
}
exit $code
