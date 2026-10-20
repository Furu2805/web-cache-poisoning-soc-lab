"""Measure per-route artifact cost and JSONL logging overhead for Section 10."""
from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "ml-detector" / "config" / "model_registry.json"


def percentile(values, q):
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] if lower == upper else ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def rss_bytes():
    if os.name == "nt":
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"(Get-Process -Id {os.getpid()}).WorkingSet64"],
            check=True, capture_output=True, text=True,
        )
        return int(result.stdout.strip())
    status = Path("/proc/self/status").read_text(encoding="ascii")
    return int(next(line.split()[1] for line in status.splitlines() if line.startswith("VmRSS:"))) * 1024


def profile_route(route):
    entry = json.loads(REGISTRY.read_text(encoding="utf-8"))["routes"][route]
    path = ROOT / entry["model_path"]
    before = rss_bytes()
    artifact = joblib.load(path)
    after = rss_bytes()
    models = []
    if artifact.get("structural_model") is not None:
        models.append((artifact["structural_model"], len(artifact["structural_feature_names"])))
    models.append((artifact["relationship_model"], len(artifact["relationship_feature_names"])))
    for model, width in models:
        model.score_samples(np.zeros((1, width)))
    timings = []
    started_cpu = time.process_time()
    for _ in range(100):
        started = time.perf_counter()
        for model, width in models:
            model.score_samples(np.zeros((1, width)))
        timings.append((time.perf_counter() - started) * 1000)
    cpu_ms = (time.process_time() - started_cpu) * 1000
    return {
        "route": route,
        "artifact_bytes": path.stat().st_size,
        "rss_before_bytes": before,
        "rss_after_bytes": after,
        "rss_delta_bytes": max(0, after - before),
        "model_components": len(models),
        "score_wall_ms": {"mean": statistics.fmean(timings), "p95": percentile(timings, .95), "p99": percentile(timings, .99)},
        "score_cpu_ms_per_call": cpu_ms / len(timings),
    }


def child_main(route):
    print(json.dumps(profile_route(route)))


def logging_profile():
    sys.path.insert(0, str(ROOT))
    import detector.app as detector_app
    metadata = {"uri": "/labs/query/?cb=profile"}
    with tempfile.TemporaryDirectory() as directory:
        detector_app.EVENT_LOG = Path(directory) / "events.jsonl"
        timings = []
        for index in range(1000):
            started = time.perf_counter()
            detector_app.write_fusion_event(
                request_id=f"section10-{index}", metadata=metadata, detector_mode="observe",
                classification="normal", anomaly_score=0.1, action="observe",
                recommended_cache_action="cache-normal", cache_bypass=False,
                indicators={}, detector_ms=1.0,
            )
            timings.append((time.perf_counter() - started) * 1000)
        size = detector_app.EVENT_LOG.stat().st_size
    return {"events": 1000, "total_bytes": size, "bytes_per_event": size / 1000,
            "append_ms": {"mean": statistics.fmean(timings), "p95": percentile(timings, .95), "p99": percentile(timings, .99)}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--child-route", choices=("query", "xfh", "utm", "fatget"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.child_route:
        child_main(args.child_route)
        return
    routes = []
    for route in ("query", "xfh", "utm", "fatget"):
        result = subprocess.run([sys.executable, __file__, "--child-route", route], cwd=ROOT, check=True, capture_output=True, text=True)
        routes.append(json.loads(result.stdout))
    report = {"schema_version": "section10-component-profile-v1", "route_models": routes, "logging": logging_profile()}
    payload = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    print(payload)


if __name__ == "__main__":
    main()
