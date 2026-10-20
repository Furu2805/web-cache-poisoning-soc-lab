"""Concurrent local benchmark for the route-aware shadow integration."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import statistics
import time
import urllib.error
import urllib.request
from pathlib import Path

ROUTES = (
    "/labs/query/?cb=bench&page=1&view=grid&utm_content=summer",
    "/labs/xfh/shop?cb=bench&category=electronics",
    "/labs/utm/js/geolocate.js?callback=ready&locale=vi",
    "/labs/fatget/js/geolocate.js?callback=ready&locale=vi",
)


# Tính percentile latency của phase benchmark.
def percentile(values, q):
    ordered = sorted(values)
    if not ordered:
        return None
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


# Gửi một request benchmark và đo latency.
def one(base, index, timeout=5.0):
    path = ROUTES[index % len(ROUTES)]
    separator = "&" if "?" in path else "?"
    url = f"{base}{path}{separator}run={index}"
    started = time.perf_counter()
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "shadow-benchmark/1"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read()
            latency = (time.perf_counter() - started) * 1000
            detector = response.headers.get("X-Detector-Ms")
            return {
                "ok": response.status == 200,
                "status": response.status,
                "latency_ms": latency,
                "detector_ms": float(detector) if detector else None,
                "cache_status": response.headers.get("X-Cache-Status"),
                "mode": response.headers.get("X-Fusion-Detector-Mode"),
                "request_id": response.headers.get("X-Request-ID"),
                "cache_bypass": response.headers.get("X-Fusion-Cache-Bypass"),
            }
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__, "latency_ms": (time.perf_counter() - started) * 1000}


# Chạy nhiều request với mức concurrency cấu hình.
def phase(name, base, requests, concurrency):
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        rows = list(pool.map(lambda index: one(base, index), range(requests)))
    elapsed = time.perf_counter() - started
    latencies = [row["latency_ms"] for row in rows]
    detector = [row["detector_ms"] for row in rows if row.get("detector_ms") is not None]
    cache = {}
    for row in rows:
        key = row.get("cache_status") or "none"
        cache[key] = cache.get(key, 0) + 1
    return {
        "name": name,
        "base_url": base,
        "requests": requests,
        "concurrency": concurrency,
        "elapsed_seconds": elapsed,
        "throughput_rps": requests / elapsed,
        "success_count": sum(bool(row["ok"]) for row in rows),
        "error_count": sum(not row["ok"] for row in rows),
        "error_rate": sum(not row["ok"] for row in rows) / requests,
        "latency_ms": {
            "mean": statistics.fmean(latencies), "p50": percentile(latencies, .50),
            "p95": percentile(latencies, .95), "p99": percentile(latencies, .99),
            "max": max(latencies),
        },
        "detector_ms": {
            "count": len(detector),
            "mean": statistics.fmean(detector) if detector else None,
            "p50": percentile(detector, .50), "p95": percentile(detector, .95),
            "p99": percentile(detector, .99),
        },
        "cache_status_counts": cache,
        "request_ids": [row["request_id"] for row in rows if row.get("request_id")],
        "cache_bypass_count": sum(row.get("cache_bypass") == "1" for row in rows),
    }


# So sánh hiệu năng runtime theo phase.
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    phases = [
        phase("off-sequential", "http://127.0.0.1:8086", args.requests, 1),
        phase("shadow-sequential", "http://127.0.0.1:8090", args.requests, 1),
    ]
    for concurrency in (4, 8, 16, 32):
        phases.append(phase(f"shadow-concurrency-{concurrency}", "http://127.0.0.1:8090", args.requests, concurrency))
    report = {
        "schema_version": "shadow-runtime-benchmark-v1",
        "thresholds": {"detector_p95_ms": 150, "detector_p99_ms": 250, "minimum_rps": 20, "maximum_error_rate": .01},
        "phases": phases,
    }
    eligible = [item for item in phases if item["name"].startswith("shadow-")]
    report["acceptance"] = {
        "detector_p95": max(item["detector_ms"]["p95"] or 0 for item in eligible) <= 150,
        "detector_p99": max(item["detector_ms"]["p99"] or 0 for item in eligible) <= 250,
        "throughput": max(item["throughput_rps"] for item in eligible) >= 20,
        "error_rate": max(item["error_rate"] for item in eligible) <= .01,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
