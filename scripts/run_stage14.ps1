[CmdletBinding()]
param(
    [ValidateRange(100, 100000)]
    [int]$RequestsPerPhase = 100,
    [ValidateRange(1, 100)]
    [int]$Repeats = 3,
    [ValidateRange(1, 100)]
    [int]$HotKeys = 8,
    [string]$RunId = ("stage14-" + (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ"))
)

# Run from the project root. This script does not edit the student-facing
# 8086 detector mode: Compose publishes static localhost-only 8090/8091
# benchmark endpoints whose modes are fixed in nginx/fusion-detector-mode.conf.
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ProjectRoot
$OutputDir = "results/stage14/$RunId"

function Invoke-Compose {
    param([Parameter(Mandatory = $true)][string[]]$ComposeArgs)
    & docker compose @ComposeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose $($ComposeArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Assert-BenchmarkEndpoint {
    param([int]$Port, [string]$ExpectedMode)
    $response = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/labs/query/?cb=stage14-ready-$ExpectedMode" -TimeoutSec 15
    if ($response.StatusCode -ne 200 -or $response.Headers["X-Fusion-Detector-Mode"] -ne $ExpectedMode) {
        throw "Port $Port did not expose expected Stage 14 mode $ExpectedMode."
    }
}

Write-Host "[G14] Validate and recreate the local proxy so 8090/8091 are published..."
Invoke-Compose -ComposeArgs @("config", "-q")
# Recreating the local proxy intentionally clears its in-container cache. Each
# workload still has fresh per-run keys, so cold/warm separation does not rely
# on this side effect.
Invoke-Compose -ComposeArgs @("up", "-d", "--force-recreate", "proxy")
Invoke-Compose -ComposeArgs @("exec", "-T", "proxy", "nginx", "-t")

Assert-BenchmarkEndpoint -Port 8086 -ExpectedMode off
Assert-BenchmarkEndpoint -Port 8090 -ExpectedMode observe
Assert-BenchmarkEndpoint -Port 8091 -ExpectedMode enforce

foreach ($mode in @("off", "observe", "enforce")) {
    Write-Host "[G14] Benchmark mode=$mode, requests/phase=$RequestsPerPhase, repeats=$Repeats"
    Invoke-Compose -ComposeArgs @(
        "run", "--rm", "-e", "PYTHONPATH=/app", "runner", "python", "-m", "traffic.fusion_benchmark",
        "--host", "proxy", "--mode", $mode, "--run-id", $RunId, "--output-dir", $OutputDir,
        "--requests-per-phase", "$RequestsPerPhase", "--repeats", "$Repeats", "--hot-keys", "$HotKeys"
    )
}

Write-Host "[G14] Aggregate raw samples and monitoring evidence..."
Invoke-Compose -ComposeArgs @(
    "run", "--rm", "-e", "PYTHONPATH=/app", "runner", "python", "-m", "traffic.fusion_benchmark",
    "--aggregate", "--output-dir", $OutputDir
)

Write-Host "[G14] Complete. Evidence: $OutputDir"
Write-Host "[G14] Student-facing 8086 remains detector mode off."
