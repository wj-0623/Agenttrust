$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot

Push-Location "$ProjectRoot\backend"
try {
  $BackendPython = Join-Path $ProjectRoot "backend\.venv\Scripts\python.exe"
  if (-not (Test-Path -LiteralPath $BackendPython)) {
    $BackendPython = "python"
  }
  & $BackendPython -m ruff check app tests --no-cache
  if ($LASTEXITCODE -ne 0) { throw "Ruff checks failed with exit code $LASTEXITCODE" }
  & $BackendPython -m bandit -r app -q
  if ($LASTEXITCODE -ne 0) { throw "Bandit checks failed with exit code $LASTEXITCODE" }
  & $BackendPython -B -m pytest -q -p no:cacheprovider `
    --cov=app --cov-branch --cov-config="..\pyproject.toml" `
    --cov-report="term-missing:skip-covered" --cov-fail-under=75
  if ($LASTEXITCODE -ne 0) { throw "Backend tests failed with exit code $LASTEXITCODE" }
} finally {
  Pop-Location
}

Push-Location "$ProjectRoot\frontend"
try {
  npm run build
  if ($LASTEXITCODE -ne 0) { throw "Frontend build failed with exit code $LASTEXITCODE" }
} finally {
  Pop-Location
}
