# Full demo guide

Use this 5 to 10 minute walkthrough after the [quick demo](../README.md#quick-demo). The lab uses local synthetic traffic; it does not establish production detection quality.

## Start the lab

From the repository root:

```powershell
git lfs install
git lfs pull
docker compose up --build -d --wait
docker compose ps
```

If Windows blocks local PowerShell scripts, use `-ExecutionPolicy Bypass` for the single script process shown below. This does not change the machine or user policy.

## Run the compact proof

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\demo-quick.ps1
```

The script waits for Loki, Grafana, and triage, recreates only the Nginx proxy to clear its cache, then verifies a harmless `MISS -> HIT` marker. It sends one XFH anomaly through observe mode and waits for the SOC background correlator to create a case once Nginx, baseline detector, and completed ML shadow evidence arrive. Expected output includes `PoisonCache: MISS`, `CleanVictimCache: HIT`, `CaseStatus`, `CaseId`, and the source list. Open the lab at <http://127.0.0.1:8080/> and select **Cases & evidence** to inspect the case.

## Show all four routes

Send representative normal requests through the detector's observe endpoint:

```powershell
$demo = 'cv-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
$urls = @(
  "http://127.0.0.1:8090/labs/query/?cb=$demo&page=1&view=grid",
  "http://127.0.0.1:8090/labs/xfh/shop?cb=$demo&category=electronics",
  "http://127.0.0.1:8090/labs/utm/js/geolocate.js?callback=setCountryCookie&locale=vi&cb=$demo",
  "http://127.0.0.1:8090/labs/fatget/js/geolocate.js?callback=setCountryCookie&locale=vi&cb=$demo"
)
$urls | ForEach-Object {
  $r = Invoke-WebRequest -UseBasicParsing -Uri $_
  [pscustomobject]@{
    Status = $r.StatusCode
    RequestId = $r.Headers['X-Request-ID']
    Cache = $r.Headers['X-Cache-Status']
    DetectorMode = $r.Headers['X-Fusion-Detector-Mode']
    Baseline = $r.Headers['X-Fusion-Detector-Decision']
  }
}
```

Send an XFH anomaly and correlate its request ID through triage:

```powershell
$r = Invoke-WebRequest -UseBasicParsing `
  -Uri "http://127.0.0.1:8090/labs/xfh/shop?cb=$demo" `
  -Headers @{ 'X-Forwarded-Host' = '127.0.0.1:8087' }
$requestId = $r.Headers['X-Request-ID']
$case = $null
for ($i = 0; $i -lt 30 -and $null -eq $case; $i++) {
  $caseCandidates = Invoke-RestMethod "http://127.0.0.1:8002/cases?q=$requestId"
  foreach ($match in $caseCandidates) {
    $candidate = Invoke-RestMethod "http://127.0.0.1:8002/cases/$($match.case_id)"
    $relatedIds = @($candidate.case.related_requests | ForEach-Object { $_.request_id })
    if ($relatedIds -contains $requestId) { $case = $candidate; break }
  }
  if ($null -eq $case) { Start-Sleep -Seconds 2 }
}
if ($null -eq $case) { throw "Automatic SOC case not found for $requestId" }
$case | ConvertTo-Json -Depth 8
```

## Open the SOC view

- Grafana dashboard: <http://127.0.0.1:13000/d/fusion-cache-security>
- ML shadow dashboard: <http://127.0.0.1:13000/d/fusion-ml-shadow>
- Local Grafana credentials: `fusion-admin` / `fusion-local-admin`
- Triage health: <http://127.0.0.1:8002/health>
- Loki readiness: <http://127.0.0.1:13100/ready>

Use the request ID to follow detector and triage evidence. Candidate ML stays in shadow mode and cannot change cache actions. The local case queue includes severity/state/route/time filters, campaign grouping, analyst notes, mitigation review, and an audit trail. For each case, compare the affected route with its fixed route, verify the cache result, record the evidence and assign an analyst. Keep mitigation decisions pending until a named reviewer approves them, then apply and verify any manual change. The SOC API has no authentication/RBAC; keep this stack bound to localhost. See [Evaluation](EVALUATION.md) and [Shadow runtime scope](SHADOW_RUNTIME.md) for detector limitations.

## Ports

| Port | Purpose |
| --- | --- |
| `8086` | Vulnerable cache lab, detector off |
| `8090` | Detector observe mode with ML shadow |
| `8002` | Post-event triage API |
| `13000` | Grafana |
| `13100` | Loki |

The local SOC UI is served at <http://127.0.0.1:8080/> under **Cases & evidence**. Automatic case creation is enabled by the Compose profile and groups matching route/technique fingerprints over 15 minutes. An offline replay metric report can be generated with `python scripts/evaluate_soc_replay.py --events data/events/fusion-nginx-access.jsonl --events data/events/detector-events.jsonl --events data/events/ml-shadow-events.jsonl --run-id replay-001 --machine "CPU and RAM profile" --concurrency 1 --output data/reports/replay-001.json`. The script records the current Git commit when available and hashes each input. Add `--labels "labels.json"` and `--actions data/events/case-audit-events.jsonl` to calculate analyst-labelled false-positive rate and MTTA/MTTR; missing labels remain `N/A`.

Create a checksum-manifested local backup with `python scripts/backup_soc_data.py`. Preview closed cases past the default 90-day local retention with `python scripts/maintain_soc_data.py`; use `--apply` only after checking the listed IDs. Pruned reports are archived first and audit logs are retained.

Stop containers with `docker compose down`. This keeps named volumes. Avoid `-v` if you want to keep local Grafana and MongoDB state.
