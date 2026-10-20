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

The script waits for Loki, Grafana, and triage, recreates only the Nginx proxy to clear its cache, then verifies a harmless `MISS -> HIT` marker. It sends one XFH anomaly through observe mode and creates a redacted incident report. Expected output includes `PoisonCache: MISS`, `CleanVictimCache: HIT`, `TriageVerdict`, and an `IncidentId`.

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
Invoke-RestMethod "http://127.0.0.1:8002/triage/$requestId" | ConvertTo-Json -Depth 8
Invoke-RestMethod -Method Post "http://127.0.0.1:8002/incidents/$requestId" | ConvertTo-Json -Depth 8
```

## Open the SOC view

- Grafana dashboard: <http://127.0.0.1:13000/d/fusion-cache-security>
- ML shadow dashboard: <http://127.0.0.1:13000/d/fusion-ml-shadow>
- Local Grafana credentials: `fusion-admin` / `fusion-local-admin`
- Triage health: <http://127.0.0.1:8002/health>
- Loki readiness: <http://127.0.0.1:13100/ready>

Use the request ID to follow detector and triage evidence. Candidate ML stays in shadow mode and cannot change cache actions. For evaluation caveats and the reason old aggregate scores are omitted, see [Evaluation](EVALUATION.md) and [Shadow runtime scope](SHADOW_RUNTIME.md).

## Ports

| Port | Purpose |
| --- | --- |
| `8086` | Vulnerable cache lab, detector off |
| `8090` | Detector observe mode with ML shadow |
| `8002` | Post-event triage API |
| `13000` | Grafana |
| `13100` | Loki |

Stop containers with `docker compose down`. This keeps named volumes. Avoid `-v` if you want to keep local Grafana and MongoDB state.
