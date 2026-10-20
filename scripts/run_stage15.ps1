[CmdletBinding()]
param(
    [ValidateSet("xfh", "query", "utm", "fatget")]
    [string]$Scenario = "xfh",
    [string]$RunId = ("stage15-" + (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ"))
)

# G15 is a local, controlled replay. It uses 8091=enforce and never changes
# the student-facing 8086=off lab mode. Triage/Incident calls are post-event.
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ProjectRoot
$OutputDir = "results/stage15/$RunId"

function Invoke-Compose {
    param([Parameter(Mandatory = $true)][string[]]$ComposeArgs)
    & docker compose @ComposeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose $($ComposeArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

Invoke-Compose -ComposeArgs @("config", "-q")
# Do not use an unscoped `docker compose up` here. If Triage has already been
# started with the operator's local .env.triage, Compose would otherwise
# recreate it with the process environment and silently remove its optional
# LLM configuration. The G15 dependencies below are sufficient for the demo.
Invoke-Compose -ComposeArgs @("up", "-d", "--wait", "proxy", "loki", "alloy", "grafana")

$triageContainer = @(& docker compose ps --status running -q triage | Where-Object { $_ })
if ($LASTEXITCODE -ne 0) {
    throw "Unable to determine whether the triage service is running."
}

if ($triageContainer.Count -eq 0) {
    if (Test-Path -LiteralPath ".env.triage") {
        Write-Host "[G15] Starting triage with local .env.triage configuration."
        & docker compose --env-file .env.triage up -d --wait triage
        if ($LASTEXITCODE -ne 0) {
            throw "docker compose could not start triage with .env.triage."
        }
    }
    else {
        Write-Warning "[G15] .env.triage is absent; triage will use deterministic evidence rules."
        Invoke-Compose -ComposeArgs @("up", "-d", "--wait", "triage")
    }
}
else {
    Write-Host "[G15] Preserving the already-running triage container and its runtime configuration."
}
Invoke-Compose -ComposeArgs @("exec", "-T", "proxy", "nginx", "-t")

$enforce = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8091/labs/query/?cb=stage15-ready" -TimeoutSec 15
$default = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8086/labs/query/?cb=stage15-default" -TimeoutSec 15
if ($enforce.Headers["X-Fusion-Detector-Mode"] -ne "enforce" -or $default.Headers["X-Fusion-Detector-Mode"] -ne "off") {
    throw "Stage 15 requires 8091=enforce and 8086=off. Check fusion-detector-mode.conf."
}

Write-Host "[G15] Run local $Scenario replay through enforce → Loki → triage → Incident Report..."
Invoke-Compose -ComposeArgs @(
    "run", "--rm", "-e", "PYTHONPATH=/app", "runner", "python", "-m", "traffic.fusion_e2e_demo",
    "--host", "proxy", "--scenario", $Scenario, "--run-id", $RunId, "--output-dir", $OutputDir
)

Write-Host "[G15] Complete. Sanitized evidence: $OutputDir/stage15_e2e_summary.json"
Write-Host "[G15] Open Grafana: http://127.0.0.1:13000/d/fusion-cache-security"
