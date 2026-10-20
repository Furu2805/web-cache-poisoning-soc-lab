$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Invoke-Docker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed: $args" }
}

Write-Host '[1/4] Building Backend Lab, Nginx and supporting services...'
Invoke-Docker compose up --build -d --wait

Write-Host '[2/4] Validating Nginx configuration...'
Invoke-Docker compose exec proxy nginx -t

Write-Host '[3/4] Running Phase-1 tests...'
Invoke-Docker compose run --rm runner python -m pytest tests/test_phase1.py tests/test_core.py -q

Write-Host '[4/4] Phase 1 is ready.'
Write-Host 'Open: http://127.0.0.1:8080/'
Write-Host 'Logs: docker compose logs -f proxy'
Write-Host 'Reset cache: .\reset-cache.ps1'
