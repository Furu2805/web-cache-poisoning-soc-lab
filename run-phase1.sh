#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo '[1/4] Building Backend Lab, Nginx and supporting services...'
docker compose up --build -d --wait
echo '[2/4] Validating Nginx configuration...'
docker compose exec proxy nginx -t
echo '[3/4] Running Phase-1 tests...'
docker compose run --rm runner python -m pytest tests/test_phase1.py tests/test_core.py -q
echo '[4/4] Phase 1 is ready.'
echo 'Open: http://127.0.0.1:8080/'
echo 'Logs: docker compose logs -f proxy'
echo 'Reset cache: bash reset-cache.sh'
