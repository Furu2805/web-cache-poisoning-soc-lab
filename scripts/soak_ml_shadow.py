"""Thirty-minute steady-state soak for Detection API and ML Shadow."""
from __future__ import annotations

import argparse
import json
import math
import statistics
import subprocess
import time
import urllib.request
from pathlib import Path

from benchmark_shadow_runtime import ROUTES, percentile

CONTAINERS = ("web-cache-ai-lab-detector-1", "web-cache-ai-lab-ml-shadow-1")


# Đổi số byte memory sang MiB.
def memory_mib(value):
    number, unit = value.split()[0][:-3], value.split()[0][-3:]
    amount = float(number)
    return amount * {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024}[unit]


# Đo tài nguyên process/container theo thời gian.
def resources(elapsed):
    result = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}", *CONTAINERS],
        check=True, capture_output=True, text=True,
    )
    sample = {"elapsed_seconds": round(elapsed, 3), "containers": {}}
    for line in result.stdout.splitlines():
        row = json.loads(line)
        sample["containers"][row["Name"]] = {
            "cpu_percent": float(row["CPUPerc"].rstrip("%")),
            "memory_mib": memory_mib(row["MemUsage"].split("/")[0].strip()),
            "pids": int(row["PIDs"]),
        }
    return sample


# Đọc độ sâu central inference queue.
def queue_depth():
    command = [
        "docker", "exec", "web-cache-ai-lab-ml-shadow-1", "python", "-c",
        "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:8003/health'))['queue_depth'])",
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return int(result.stdout.strip())


# Đọc các event Shadow của lượt soak.
def event_rows(event_dir):
    rows = []
    for path in Path(event_dir).glob("ml-shadow-events.jsonl*"):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


# Chạy soak và tổng hợp ổn định queue/latency.
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration-seconds", type=int, default=1800)
    parser.add_argument("--rate", type=float, default=1.0)
    parser.add_argument("--sample-seconds", type=int, default=60)
    parser.add_argument("--event-dir", type=Path, default=Path("data/events"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    token = time.time_ns()
    started = time.monotonic()
    next_request = started
    next_sample = started
    rows, samples, request_ids = [], [], []
    index = 0
    while time.monotonic() - started < args.duration_seconds:
        now = time.monotonic()
        if now >= next_sample:
            sample = resources(now - started)
            sample["queue_depth"] = queue_depth()
            samples.append(sample)
            print(json.dumps({"progress_seconds": round(now - started), "requests": len(rows),
                              "queue_depth": sample["queue_depth"]}), flush=True)
            next_sample += args.sample_seconds
        if now < next_request:
            time.sleep(min(.1, next_request - now))
            continue
        path = ROUTES[index % len(ROUTES)]
        separator = "&" if "?" in path else "?"
        url = f"http://127.0.0.1:8090{path}{separator}soak={token}-{index}"
        request_started = time.perf_counter()
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "ml-shadow-soak/1"})
            with urllib.request.urlopen(request, timeout=5) as response:
                response.read()
                row = {
                    "ok": response.status == 200,
                    "latency_ms": (time.perf_counter() - request_started) * 1000,
                    "detector_ms": float(response.headers.get("X-Detector-Ms")),
                    "request_id": response.headers.get("X-Request-ID"),
                    "cache_status": response.headers.get("X-Cache-Status"),
                    "cache_bypass": response.headers.get("X-Fusion-Cache-Bypass") == "1",
                }
                request_ids.append(row["request_id"])
        except Exception as exc:
            row = {"ok": False, "error": type(exc).__name__,
                   "latency_ms": (time.perf_counter() - request_started) * 1000}
        rows.append(row)
        index += 1
        next_request += 1 / args.rate
    time.sleep(15)
    final_sample = resources(time.monotonic() - started)
    final_sample["queue_depth"] = queue_depth()
    samples.append(final_sample)
    ids = set(request_ids)
    events = [row for row in event_rows(args.event_dir) if row.get("request_id") in ids]
    completed_rows = [row for row in events if row.get("event_type") == "shadow_completed"]
    completed = {row["request_id"] for row in completed_rows}
    failures = [row for row in events if row.get("event_type") == "shadow_failed"]
    queue_wait = [float(row["queue_wait_ms"]) for row in completed_rows]
    detector_latency = [row["detector_ms"] for row in rows if row.get("detector_ms") is not None]
    mem = {name: [sample["containers"][name]["memory_mib"] for sample in samples] for name in CONTAINERS}
    duration = time.monotonic() - started
    report = {
        "schema_version": "section10-ml-shadow-soak-v1",
        "configured_duration_seconds": args.duration_seconds,
        "observed_duration_seconds": duration,
        "rate_rps": args.rate,
        "requests": len(rows), "success_count": sum(row["ok"] for row in rows),
        "error_count": sum(not row["ok"] for row in rows),
        "detector_ms": {"p95": percentile(detector_latency, .95), "p99": percentile(detector_latency, .99)},
        "candidate": {
            "completed": len(completed), "coverage": len(completed) / len(ids) if ids else 0,
            "queue_overflow": sum(row.get("fallback_reason") == "queue_overflow" for row in failures),
            "registry_failures": sum(str(row.get("fallback_reason", "")).startswith("registry_") for row in failures),
            "queue_wait_ms": {"p95": percentile(queue_wait, .95), "max": max(queue_wait) if queue_wait else None,
                              "first_half_mean": statistics.fmean(queue_wait[:len(queue_wait)//2]),
                              "second_half_mean": statistics.fmean(queue_wait[len(queue_wait)//2:])},
            "final_queue_depth": final_sample["queue_depth"],
        },
        "cache": {
            "bypass_count": sum(row.get("cache_bypass", False) for row in rows),
            "status_counts": {key: sum(row.get("cache_status") == key for row in rows)
                              for key in ("HIT", "MISS", "EXPIRED", "BYPASS")},
        },
        "resources": {
            name: {"start_memory_mib": values[0], "end_memory_mib": values[-1],
                   "delta_memory_mib": values[-1] - values[0], "max_memory_mib": max(values),
                   "max_cpu_percent": max(sample["containers"][name]["cpu_percent"] for sample in samples)}
            for name, values in mem.items()
        },
        "samples": samples,
    }
    lag = report["candidate"]["queue_wait_ms"]
    report["acceptance"] = {
        "duration_at_least_30_minutes": duration >= 1800,
        "http_success_100_percent": report["error_count"] == 0,
        "coverage_at_least_99_percent": report["candidate"]["coverage"] >= .99,
        "queue_overflow_zero": report["candidate"]["queue_overflow"] == 0,
        "registry_failures_zero": report["candidate"]["registry_failures"] == 0,
        "queue_drained": report["candidate"]["final_queue_depth"] == 0,
        "queue_lag_not_continuously_increasing": lag["second_half_mean"] <= lag["first_half_mean"] * 1.5 + 10,
        "memory_stable": all(abs(item["delta_memory_mib"]) <= 64 for item in report["resources"].values()),
        "candidate_did_not_bypass_cache": report["cache"]["bypass_count"] == 0,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"complete": True, "acceptance": report["acceptance"]}), flush=True)


if __name__ == "__main__":
    main()
