param(
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$LogDir = Join-Path $Root "data\logs"
$PidFile = Join-Path $Root "data\apireconx-processes.json"

function Assert-PortFree {
    param([int]$Port)
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($listener) {
        throw "Port $Port is already in use by process $($listener.OwningProcess). Run scripts\stop-apireconx.ps1 or choose another port."
    }
}

Set-Location $Root
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

Assert-PortFree 8000
Assert-PortFree 9000
Assert-PortFree 5173

if (-not $SkipInstall) {
    python -m pip install -r requirements.txt
    if (-not (Test-Path (Join-Path $Root "frontend\node_modules"))) {
        npm --prefix (Join-Path $Root "frontend") install
    }
}

$backend = Start-Process -FilePath python `
    -ArgumentList @("-m", "uvicorn", "apireconx.main:app", "--host", "127.0.0.1", "--port", "8000") `
    -WorkingDirectory $Root `
    -RedirectStandardOutput (Join-Path $LogDir "apireconx-backend.out.log") `
    -RedirectStandardError (Join-Path $LogDir "apireconx-backend.err.log") `
    -PassThru `
    -WindowStyle Hidden

$demo = Start-Process -FilePath python `
    -ArgumentList @("-m", "uvicorn", "apireconx.demo_target:app", "--host", "127.0.0.1", "--port", "9000") `
    -WorkingDirectory $Root `
    -RedirectStandardOutput (Join-Path $LogDir "apireconx-demo.out.log") `
    -RedirectStandardError (Join-Path $LogDir "apireconx-demo.err.log") `
    -PassThru `
    -WindowStyle Hidden

$frontend = Start-Process -FilePath npm.cmd `
    -ArgumentList @("run", "dev", "--", "--port", "5173") `
    -WorkingDirectory (Join-Path $Root "frontend") `
    -RedirectStandardOutput (Join-Path $LogDir "apireconx-frontend.out.log") `
    -RedirectStandardError (Join-Path $LogDir "apireconx-frontend.err.log") `
    -PassThru `
    -WindowStyle Hidden

@(
    @{ name = "backend"; pid = $backend.Id; port = 8000; url = "http://127.0.0.1:8000" },
    @{ name = "demo-target"; pid = $demo.Id; port = 9000; url = "http://127.0.0.1:9000" },
    @{ name = "frontend"; pid = $frontend.Id; port = 5173; url = "http://127.0.0.1:5173" }
) | ConvertTo-Json | Set-Content -Path $PidFile -Encoding UTF8

Start-Sleep -Seconds 2

Write-Host "APIRECON-X is live:"
Write-Host "  Console:     http://127.0.0.1:5173"
Write-Host "  API docs:    http://127.0.0.1:8000/docs"
Write-Host "  Demo target: http://127.0.0.1:9000/docs"
Write-Host "Logs: $LogDir"
