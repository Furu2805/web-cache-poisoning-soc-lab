#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker compose up --build -d --wait
docker compose run --rm runner python -m pytest -q
docker compose up -d --force-recreate proxy
docker compose exec -T proxy nginx -t
run_id="stage14-$(date -u +%Y%m%dT%H%M%SZ)"
output_dir="results/stage14/${run_id}"
for mode in off observe enforce; do
  docker compose run --rm -e PYTHONPATH=/app runner python -m traffic.fusion_benchmark \
    --host proxy --mode "$mode" --run-id "$run_id" --output-dir "$output_dir"
done
docker compose run --rm -e PYTHONPATH=/app runner python -m traffic.fusion_benchmark \
  --aggregate --output-dir "$output_dir"
echo "Hoan tat. Xem ${output_dir}/ va docs/REPORT_MAPPING.md."
