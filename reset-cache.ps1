$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

Write-Host 'Recreating only the Nginx proxy container to clear its local cache...'
& docker compose up -d --force-recreate --no-deps proxy
if ($LASTEXITCODE -ne 0) { throw 'Could not recreate the proxy container.' }
& docker compose exec proxy nginx -t
if ($LASTEXITCODE -ne 0) { throw 'Nginx configuration is invalid after reset.' }
Write-Host 'Cache reset completed. The next cacheable request should return MISS.'
