"""Summarize operational shadow telemetry without inventing ground-truth labels."""
from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import Counter
from pathlib import Path


def percentile(values, q):
    values = sorted(values)
    if not values:
        return None
    position = (len(values) - 1) * q
    lower, upper = math.floor(position), math.ceil(position)
    return values[lower] if lower == upper else values[lower] + (values[upper] - values[lower]) * (position - lower)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("data/events/detector-events.jsonl"))
    parser.add_argument("--route", default="query")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    requests, rows = [], []
    for line in args.input.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("schema") == "fusion-detector-event-v2" and event.get("scenario") == args.route:
            requests.append(event)
        elif event.get("schema") == "fusion-shadow-candidate-event-v1" and event.get("route") == args.route:
            rows.append(event)
    latencies = [float(row["shadow_latency_ms"]) for row in rows if row.get("shadow_latency_ms") is not None]
    fallback = Counter((row.get("fallback_reason") or "none") for row in rows)
    complete = [row for row in rows if row.get("model_version") and row.get("fallback_reason") is None]
    invariant = [row for row in requests if row.get("detector_mode") == "observe" and row.get("cache_bypass") is False]
    report = {
        "schema_version": "shadow-operational-summary-v1", "route": args.route,
        "scope": "local synthetic/integration traffic; no production labels",
        "events": len(requests), "candidate_events": len(rows),
        "first_timestamp": requests[0].get("timestamp") if requests else None,
        "last_timestamp": rows[-1].get("timestamp") if rows else None,
        "candidate_coverage_rate": len(complete) / len(requests) if requests else None,
        "fallback_rate": sum(value for key, value in fallback.items() if key != "none") / len(requests) if requests else None,
        "fallback_reasons": dict(fallback),
        "observe_non_enforcement_rate": len(invariant) / len(requests) if requests else None,
        "candidate_anomaly_rate": sum(row.get("final_anomaly") is True for row in complete) / len(complete) if complete else None,
        "shadow_latency_ms": {"mean": statistics.fmean(latencies) if latencies else None,
                              "p95": percentile(latencies, .95), "p99": percentile(latencies, .99)},
        "promotion_eligible": False,
        "promotion_blocker": "synthetic integration traffic has no independent production ground truth",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
