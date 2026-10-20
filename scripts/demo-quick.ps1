$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

Write-Host '[1/4] Checking local services...'
function Wait-HttpReady {
    param([string]$Url, [string]$Name, [int]$Attempts = 20)
    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        try {
            $null = Invoke-RestMethod -Uri $Url -TimeoutSec 3
            return
        } catch {
            if ($attempt -eq $Attempts - 1) {
                throw "$Name did not become ready at $Url. $($_.Exception.Message)"
            }
            Start-Sleep -Seconds 2
        }
    }
}

Wait-HttpReady 'http://127.0.0.1:13100/ready' 'Loki'
Wait-HttpReady 'http://127.0.0.1:13000/api/health' 'Grafana'
Wait-HttpReady 'http://127.0.0.1:8002/health' 'Triage'

Write-Host '[2/4] Resetting cache and proving WCP with a harmless marker...'
& .\reset-cache.ps1
if ($LASTEXITCODE -ne 0) { throw 'Cache reset failed.' }
$demo = [guid]::NewGuid().ToString('N').Substring(0, 12)
$marker = "WCP_$demo"
$poison = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8086/labs/query/?utm_content=$marker"
$victim = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8086/labs/query/'
$poisonCache = $poison.Headers['X-Cache-Status']
$victimCache = $victim.Headers['X-Cache-Status']
if ($poisonCache -notin @('MISS', 'EXPIRED') -or $victimCache -ne 'HIT' -or -not $victim.Content.Contains($marker)) {
    throw "WCP proof did not match expectations (poison=$poisonCache, victim=$victimCache). Reset the cache and retry."
}

Write-Host '[3/4] Sending an XFH anomaly through observe mode...'
$event = Invoke-WebRequest -UseBasicParsing `
    -Uri "http://127.0.0.1:8090/labs/xfh/shop?cb=$demo" `
    -Headers @{ 'X-Forwarded-Host' = '127.0.0.1:8087' }
$requestId = $event.Headers['X-Request-ID']
if (-not $requestId) { throw 'Observe response did not include X-Request-ID.' }

Write-Host '[4/4] Waiting for correlated evidence and creating a redacted incident report...'
$triage = $null
for ($i = 0; $i -lt 12 -and $null -eq $triage; $i++) {
    try {
        $triage = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8002/triage/$requestId"
    } catch {
        $status = 0
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        if ($status -notin @(404, 409)) { throw }
        Start-Sleep -Seconds 2
    }
}
if ($null -eq $triage) { throw "Evidence did not arrive for request $requestId within 24 seconds." }
$incident = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8002/incidents/$requestId"

[pscustomobject]@{
    PoisonCache = $poisonCache
    CleanVictimCache = $victimCache
    MarkerReachedVictim = $true
    RequestId = $requestId
    DetectorMode = $event.Headers['X-Fusion-Detector-Mode']
    Baseline = $event.Headers['X-Fusion-Detector-Decision']
    TriageVerdict = $triage.verdict
    Severity = $triage.severity
    IncidentId = $incident.report.incident_id
    Grafana = 'http://127.0.0.1:13000/d/fusion-cache-security'
}
