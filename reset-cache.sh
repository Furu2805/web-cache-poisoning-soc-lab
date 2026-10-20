#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo 'Recreating only the Nginx proxy container to clear its local cache...'
docker compose up -d --force-recreate --no-deps proxy
docker compose exec proxy nginx -t
echo 'Cache reset completed. The next cacheable request should return MISS.'
