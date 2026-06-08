$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$PidFile = Join-Path $Root "data\apireconx-processes.json"

if (-not (Test-Path $PidFile)) {
    Write-Host "No APIRECON-X process file found."
    exit 0
}

$processes = Get-Content -Path $PidFile -Raw | ConvertFrom-Json
foreach ($processInfo in $processes) {
    $process = Get-Process -Id $processInfo.pid -ErrorAction SilentlyContinue
    if ($process) {
        Stop-Process -Id $processInfo.pid -Force
        Write-Host "Stopped $($processInfo.name) ($($processInfo.pid))"
    }
    if ($processInfo.port) {
        $listeners = Get-NetTCPConnection -LocalPort $processInfo.port -State Listen -ErrorAction SilentlyContinue
        foreach ($listener in $listeners) {
            Stop-Process -Id $listener.OwningProcess -Force -ErrorAction SilentlyContinue
            Write-Host "Stopped listener on port $($processInfo.port) ($($listener.OwningProcess))"
        }
    }
}
