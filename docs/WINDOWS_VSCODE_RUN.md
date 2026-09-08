# Windows 与 VS Code 本地运行指南

## 目录说明

实际项目根目录：

```text
C:\Users\DELL\Documents\ChatGPT\new agent
```

日常开发只打开该目录。`new agent 2\agenttrust-v10-review` 是历史评审副本，不是运行目录；星限是独立项目，不参与 AgentTrust 的安装或启动。

| 路径 | 用途 |
|---|---|
| `backend\app` | FastAPI、安全控制面和运行时服务 |
| `backend\tests` | 后端与安全回归测试 |
| `backend\.venv` | 本机 Python 虚拟环境，不提交 Git |
| `backend\data` | 本地 SQLite 数据，不提交 Git |
| `frontend\src` | React 控制台源码 |
| `frontend\dist` | 前端生产构建产物，不提交 Git |
| `scripts` | Windows 初始化、启动和验证脚本 |
| `.vscode\tasks.json` | VS Code 一键任务 |
| `benchmarks\promptfoo` | 固定版本外部安全 smoke benchmark |

## 首次安装

打开 Windows PowerShell，执行：

```powershell
Set-Location -LiteralPath 'C:\Users\DELL\Documents\ChatGPT\new agent'
code .
```

在新打开的 VS Code 中选择 **终端 → 新建终端**，执行：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\setup-windows.ps1
```

初始化脚本只在缺少时创建 `backend\.venv`，随后从锁定的 requirements 和 package-lock 安装依赖。真实 API Key 不需要用于默认演示。

## 推荐启动方式：VS Code Tasks

1. 按 `Ctrl+Shift+P`。
2. 输入并选择 `Tasks: Run Task`（任务：运行任务）。
3. 首次运行选择 `AgentTrust: Setup`。
4. 安装完成后选择 `AgentTrust: Start full stack`。
5. VS Code 会在集成终端中并行启动 API 和控制台。

访问地址：

- 产品控制台：<http://127.0.0.1:5173>
- FastAPI 文档：<http://127.0.0.1:8010/docs>
- 健康检查：<http://127.0.0.1:8010/health>

停止服务时，在两个运行终端中分别按 `Ctrl+C`。

## 纯命令行启动方式

终端 1：

```powershell
Set-Location -LiteralPath 'C:\Users\DELL\Documents\ChatGPT\new agent\backend'
& '.\.venv\Scripts\python.exe' -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8010
```

终端 2：

```powershell
Set-Location -LiteralPath 'C:\Users\DELL\Documents\ChatGPT\new agent\frontend'
npm run dev
```

也可以从项目根目录运行：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\start-dev.ps1
```

## 单端口生产预览

先构建前端，再由 FastAPI 托管 `frontend\dist`：

```powershell
Set-Location -LiteralPath 'C:\Users\DELL\Documents\ChatGPT\new agent'
npm --prefix .\frontend run build
Set-Location .\backend
& '.\.venv\Scripts\python.exe' -m uvicorn app.main:app --host 127.0.0.1 --port 8010
```

随后只访问 <http://127.0.0.1:8010>。

## 完整质量门禁

在项目根目录执行：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\verify.ps1
```

也可以从 VS Code 运行任务 `AgentTrust: Verify`。该门禁运行 Ruff、Bandit、后端测试、75% 分支覆盖率检查和前端生产构建。

## 可选模型配置

默认 demo 不需要模型密钥。只有需要调用 Qwen 或其他显式允许的目标时才创建本地环境文件：

```powershell
Copy-Item .\backend\.env.example .\backend\.env
code .\backend\.env
```

不要提交 `.env`。使用环境文件启动：

```powershell
Set-Location .\backend
& '.\.venv\Scripts\python.exe' -m uvicorn app.main:app --reload --env-file .env --host 127.0.0.1 --port 8010
```

## 常见问题

- `python` 不可用：在 VS Code 中按 `Ctrl+Shift+P`，选择 `Python: Select Interpreter`，指定已安装的 Python 3.12。
- PowerShell 禁止脚本：只为当前终端执行 `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`，不要修改系统全局策略。
- `npm` 不可用：重新安装 Node.js 24 LTS，并重启 VS Code。
- 端口占用：执行 `Get-NetTCPConnection -LocalPort 8010,5173 -ErrorAction SilentlyContinue` 查找冲突；停止对应进程后重启任务。
- 页面可以打开但 API 请求失败：确认 `8010` 的后端终端仍在运行，并访问 `/health` 检查状态。
