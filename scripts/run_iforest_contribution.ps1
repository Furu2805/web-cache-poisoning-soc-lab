[CmdletBinding()]
param(
    [ValidateRange(100, 5000)]
    [int]$NormalPerLab = 300,
    [ValidateRange(50, 2000)]
    [int]$AttackPerLab = 100,
    [int]$Seed = 20260924,
    [switch]$Promote,
    [switch]$PromoteOnly,
    [string]$RunId = ("iforest-contribution-" + (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ"))
)

# This candidate workflow never changes the student-facing lab routes. It
# creates a fresh collector/model/evaluation lineage and promotes only through
# the explicit IF-only contribution gate.
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ProjectRoot

$Raw = "data/fusion/raw/fusion_dataset_$RunId.jsonl"
$Processed = "data/fusion/processed_$RunId"
$Candidate = "models/candidates/$RunId/isolation_forest.joblib"
$Results = "results/$RunId"

function Invoke-Compose {
    param([Parameter(Mandatory = $true)][string[]]$ComposeArgs)
    & docker compose @ComposeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose $($ComposeArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

if (-not $PromoteOnly) {
    try {
        $ready = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8086/labs/utm/" -TimeoutSec 15
        if ($ready.StatusCode -ne 200) { throw "Fusion lab on 8086 is not ready" }
    } catch {
        throw "Start the existing Docker stack first. This workflow intentionally does not start or recreate it. $_"
    }

    Write-Host "[IF] Collect expanded benign diversity and the four local attack families..."
    Invoke-Compose -ComposeArgs @(
        "run", "--rm", "-e", "PYTHONPATH=/app", "runner", "python", "-m", "traffic.fusion_collect",
        "--origin", "http://proxy:8086", "--normal-per-lab", "$NormalPerLab", "--attack-per-lab", "$AttackPerLab",
        "--seed", "$Seed", "--output", $Raw
    )

    Write-Host "[IF] Build request-only features and train a candidate; attacks remain held-out..."
    Invoke-Compose -ComposeArgs @("run", "--rm", "-e", "PYTHONPATH=/app", "runner", "python", "-m", "traffic.fusion_features", "--input", $Raw, "--output-dir", $Processed)
    Invoke-Compose -ComposeArgs @("run", "--rm", "-e", "PYTHONPATH=/app", "runner", "python", "-m", "ml.tune", "--dataset", "$Processed/ml_dataset.jsonl", "--profile", "$Processed/feature_profile.json", "--output-dir", $Results)
    Invoke-Compose -ComposeArgs @("run", "--rm", "-e", "PYTHONPATH=/app", "runner", "python", "-m", "ml.train", "--dataset", "$Processed/ml_dataset.jsonl", "--profile", "$Processed/feature_profile.json", "--model", $Candidate)
    Invoke-Compose -ComposeArgs @("run", "--rm", "-e", "PYTHONPATH=/app", "runner", "python", "-m", "ml.evaluate", "--dataset", "$Processed/ml_dataset.jsonl", "--model", $Candidate, "--output-dir", $Results)
}

if (-not (Test-Path -LiteralPath "$Results/iforest_contribution.json")) {
    throw "No contribution evidence exists for run $RunId. Run without -PromoteOnly first."
}
$Contribution = Get-Content -Raw -Encoding utf8 "$Results/iforest_contribution.json" | ConvertFrom-Json
Write-Host ("[IF] IF-only TP={0}; IF-only FP={1}; incremental={2}" -f $Contribution.iforest_only_true_positives, $Contribution.iforest_only_false_positives, $Contribution.iforest_has_measured_incremental_value)

if (-not $Promote) {
    Write-Host "[IF] Candidate retained only. Review $Results/iforest_contribution.json before promotion."
    Write-Host "[IF] To promote after review: rerun with -RunId $RunId -PromoteOnly -Promote."
    exit 0
}

Write-Host "[IF] Apply contribution gate before replacing the runtime model..."
Invoke-Compose -ComposeArgs @("run", "--rm", "-e", "PYTHONPATH=/app", "runner", "python", "-m", "ml.promote", "--candidate-model", $Candidate, "--evaluation-dir", $Results, "--target-model", "models/isolation_forest.joblib")
Write-Host "[IF] Candidate promoted. Restart only the detector service when ready to load the approved bundle."
