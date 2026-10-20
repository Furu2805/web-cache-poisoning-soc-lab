$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
function Invoke-Docker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed: $args" }
}
Invoke-Docker compose up --build -d --wait
Invoke-Docker compose run --rm runner python -m pytest -q
& "$PSScriptRoot\scripts\run_stage14.ps1"
if ($LASTEXITCODE -ne 0) { throw "Stage 14 benchmark failed: $LASTEXITCODE" }
Write-Host 'Hoan tat. Xem results/stage14/ va docs/REPORT_MAPPING.md.'
