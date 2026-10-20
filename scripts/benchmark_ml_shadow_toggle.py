"""Benchmark the same observe-mode Detection API with ML Shadow off and on."""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

from benchmark_shadow_runtime import phase


# Gọi Docker Compose để bật/tắt Shadow trong benchmark.
def compose(*args):
    subprocess.run(["docker", "compose", *args], check=True)


# Chờ các service cần thiết đạt health check.
def wait_healthy(timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            ["docker", "inspect", "--format={{.State.Health.Status}}", "web-cache-ai-lab-ml-shadow-1"],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and result.stdout.strip() == "healthy":
            return True
        time.sleep(.5)
    return False


# Đọc số event ML Shadow của lượt đo.
def ml_events(event_dir):
    rows = []
    for path in Path(event_dir).glob("ml-shadow-events.jsonl*"):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


# So sánh benchmark khi Shadow tắt và bật.
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--event-dir", type=Path, default=Path("data/events"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        compose("stop", "ml-shadow")
        disabled = phase("observe-ml-shadow-disabled", "http://127.0.0.1:8090", args.requests, args.concurrency)
        compose("up", "-d", "ml-shadow")
        healthy = wait_healthy()
        enabled = phase("observe-ml-shadow-enabled", "http://127.0.0.1:8090", args.requests, args.concurrency)
        time.sleep(15)
    finally:
        compose("up", "-d", "ml-shadow")
    request_ids = set(enabled["request_ids"])
    events = [row for row in ml_events(args.event_dir) if row.get("request_id") in request_ids]
    completed = {row["request_id"] for row in events if row.get("event_type") == "shadow_completed"}
    failures = [row for row in events if row.get("event_type") == "shadow_failed"]
    queue_lag = [float(row["queue_wait_ms"]) for row in events if row.get("event_type") == "shadow_completed"]
    report = {
        "schema_version": "section10-ml-shadow-toggle-v1",
        "ml_shadow_recovered_healthy": healthy,
        "disabled": disabled,
        "enabled": enabled,
        "candidate": {
            "eligible_request_ids": len(request_ids), "completed_request_ids": len(completed),
            "coverage": len(completed) / len(request_ids) if request_ids else 0,
            "queue_overflow": sum(row.get("fallback_reason") == "queue_overflow" for row in failures),
            "registry_failures": sum(str(row.get("fallback_reason", "")).startswith("registry_") for row in failures),
            "other_failures": sum(row.get("fallback_reason") != "queue_overflow" and not str(row.get("fallback_reason", "")).startswith("registry_") for row in failures),
            "queue_wait_ms_first_half_mean": sum(queue_lag[:len(queue_lag)//2]) / max(1, len(queue_lag)//2),
            "queue_wait_ms_second_half_mean": sum(queue_lag[len(queue_lag)//2:]) / max(1, len(queue_lag) - len(queue_lag)//2),
        },
    }
    report["acceptance"] = {
        "http_success_100_percent": disabled["error_count"] == enabled["error_count"] == 0,
        "detector_p95_below_150_ms": enabled["detector_ms"]["p95"] < 150,
        "detector_p99_below_250_ms": enabled["detector_ms"]["p99"] < 250,
        "throughput_at_least_20_rps": enabled["throughput_rps"] >= 20,
        "candidate_coverage_at_least_99_percent": report["candidate"]["coverage"] >= .99,
        "queue_overflow_zero": report["candidate"]["queue_overflow"] == 0,
        "registry_failures_zero": report["candidate"]["registry_failures"] == 0,
        "cache_bypass_unchanged": disabled["cache_bypass_count"] == enabled["cache_bypass_count"] == 0,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
