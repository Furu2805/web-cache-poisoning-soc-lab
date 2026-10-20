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
$triageHealth = Invoke-RestMethod -Uri 'http://127.0.0.1:8002/health'
if (-not $triageHealth.auto_cases_enabled) { throw 'Automatic SOC cases are disabled. Start the Compose stack with the repository configuration.' }

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

Write-Host '[4/4] Waiting for the SOC correlator to create a case from complete evidence...'
$case = $null
for ($i = 0; $i -lt 30 -and $null -eq $case; $i++) {
    try {
        $caseCandidates = Invoke-RestMethod -Uri "http://127.0.0.1:8002/cases?q=$requestId&limit=200"
        foreach ($match in $caseCandidates) {
            $candidate = Invoke-RestMethod -Uri "http://127.0.0.1:8002/cases/$($match.case_id)"
            $relatedIds = @($candidate.case.related_requests | ForEach-Object { $_.request_id })
            if ($relatedIds -contains $requestId) {
                $case = $candidate
                break
            }
        }
    } catch {
        $status = 0
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        if ($status -notin @(404, 409)) { throw }
    }
    if ($null -eq $case) { Start-Sleep -Seconds 2 }
}
if ($null -eq $case) { throw "The automatic case did not appear for request $requestId within 60 seconds." }

[pscustomobject]@{
    PoisonCache = $poisonCache
    CleanVictimCache = $victimCache
    MarkerReachedVictim = $true
    RequestId = $requestId
    DetectorMode = $event.Headers['X-Fusion-Detector-Mode']
    Baseline = $event.Headers['X-Fusion-Detector-Decision']
    CaseStatus = $case.case.status
    Severity = $case.case.severity
    CaseId = $case.case.case_id
    EvidenceSources = (($case.timeline | ForEach-Object { $_.source } | Select-Object -Unique) -join ', ')
    Grafana = 'http://127.0.0.1:13000/d/fusion-cache-security'
    SocCases = 'http://127.0.0.1:8080/ (select Cases & evidence)'
}
