$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BackendDirectory = Join-Path $ProjectRoot "backend"
$FrontendDirectory = Join-Path $ProjectRoot "frontend"
$BackendPython = Join-Path $BackendDirectory ".venv\Scripts\python.exe"

Write-Host "Preparing AgentTrust in $ProjectRoot" -ForegroundColor Cyan

if (-not (Test-Path -LiteralPath $BackendPython)) {
  Write-Host "Creating Python virtual environment..." -ForegroundColor Yellow
  python -m venv (Join-Path $BackendDirectory ".venv")
  if ($LASTEXITCODE -ne 0) { throw "Python virtual environment creation failed." }
}

Write-Host "Installing locked Python development dependencies..." -ForegroundColor Yellow
& $BackendPython -m pip install -r (Join-Path $BackendDirectory "requirements-dev.txt")
if ($LASTEXITCODE -ne 0) { throw "Python dependency installation failed." }

Write-Host "Installing locked frontend dependencies..." -ForegroundColor Yellow
npm --prefix $FrontendDirectory ci
if ($LASTEXITCODE -ne 0) { throw "Frontend dependency installation failed." }

Write-Host "AgentTrust setup completed." -ForegroundColor Green
Write-Host "In VS Code, run the task: AgentTrust: Start full stack"
