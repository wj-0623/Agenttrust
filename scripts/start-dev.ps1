$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BackendPython = Join-Path $ProjectRoot "backend\.venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $BackendPython)) {
  $BackendPython = "python"
}

Write-Host "Starting AgentTrust API on http://127.0.0.1:8010" -ForegroundColor Green
Start-Process powershell -ArgumentList @(
  "-NoExit",
  "-Command",
  "Set-Location -LiteralPath '$ProjectRoot\backend'; & '$BackendPython' -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8010"
) -WindowStyle Hidden

Write-Host "Starting AgentTrust Console on http://127.0.0.1:5173" -ForegroundColor Green
Set-Location -LiteralPath "$ProjectRoot\frontend"
npm run dev
