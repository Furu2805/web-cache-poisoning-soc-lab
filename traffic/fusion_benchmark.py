"""Repeatable Stage 14 performance measurement for the Fusion four-labs.

The benchmark is deliberately sequential (concurrency=1).  It measures client
latency through Nginx and separates cold keys from pre-warmed keys; it is not a
throughput or production-capacity test.  The three operator-owned endpoints are
``8086=off``, ``8090=observe`` and ``8091=enforce``.  No client input selects a
detector mode.

Examples
--------
    python -m traffic.fusion_benchmark --host proxy --mode off \
        --output-dir results/stage14/<run-id>
    python -m traffic.fusion_benchmark --aggregate \
        --output-dir results/stage14/<run-id>
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import http.client
import json
import math
import os
import statistics
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlencode, urlsplit

from traffic.fusion_scenarios import LABS, FusionCase, normal_case


MODE_PORTS = {"off": 8086, "observe": 8090, "enforce": 8091}
MODE_CODES = {"off": "a0", "observe": "b1", "enforce": "c2"}
DEFAULT_RUN_ID = "manual-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/146.0 Safari/537.36"
LANGUAGE = "vi-VN,vi;q=0.9,en-US;q=0.8"
SAMPLE_COLUMNS = (
    "run_id", "mode", "repeat", "phase", "sequence", "lab", "key_slot",
    "status", "latency_ms", "cache_status", "detector_mode", "classification",
    "detector_action", "cache_bypass", "detector_ms", "request_id",
)
SUMMARY_COLUMNS = (
    "run_id", "mode", "phase", "repeats", "requests", "mean_ms", "p50_ms", "p95_ms",
    "p99_ms", "min_ms", "max_ms", "cache_hit_ratio", "cache_hits", "cache_misses",
    "cache_expired", "cache_bypass", "non_hit_requests", "detector_calls",
    "detector_mean_ms", "detector_p50_ms", "detector_p95_ms", "detector_anomalies",
)


# Tính percentile latency từ các mẫu benchmark.
def percentile(values: Iterable[float], quantile: float) -> float | None:
    """Return an interpolated percentile without a NumPy runtime dependency."""
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return None
    if not 0 <= quantile <= 1:
        raise ValueError("quantile must be between 0 and 1")
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


# Chuẩn hóa số để ghi bảng kết quả.
def _number(value: float | None) -> str | float:
    return "" if value is None else round(value, 3)


# Tạo token cache key riêng cho từng phase/mode benchmark.
def _token(run_id: str, mode: str, phase: str, repeat: int, key_slot: int) -> str:
    """Make a fixed-length, per-mode cache key using only benign input."""
    digest = hashlib.sha256(f"g14|{run_id}|{phase}|{repeat}|{key_slot}".encode("utf-8")).hexdigest()
    # `normal_case` uses the full token for cb and its first eight characters
    # for JSONP callbacks.  A two-character mode code therefore isolates every
    # cache key while preserving request length/features across conditions.
    return MODE_CODES[mode] + digest[:22]


# Sinh FusionCase cho một lượt đo theo mode và phase.
def benchmark_case(run_id: str, mode: str, phase: str, repeat: int, key_slot: int, sequence: int) -> FusionCase:
    """Build one normal request whose shape is shared across all three modes."""
    lab = LABS[sequence % len(LABS)]
    return normal_case(
        lab,
        _token(run_id, mode, phase, repeat, key_slot),
        USER_AGENT,
        LANGUAGE,
        variant_index=sequence % 6,
        method="GET",
    )


# Rút gọn header HTTP của response benchmark.
def _headers(response: http.client.HTTPResponse) -> dict[str, str]:
    return {name.lower(): value for name, value in response.getheaders()}


# Gửi request lab và đo status, cache status, latency.
def send_case(host: str, port: int, case: FusionCase, expected_mode: str) -> dict[str, object]:
    """Send one complete request and retain only non-sensitive response metadata."""
    connection = http.client.HTTPConnection(host, port, timeout=20)
    started = time.perf_counter()
    try:
        connection.request(case.method, case.uri, headers=case.headers)
        response = connection.getresponse()
        response.read()
        elapsed_ms = (time.perf_counter() - started) * 1000
        headers = _headers(response)
    finally:
        connection.close()
    mode = headers.get("x-fusion-detector-mode", "")
    if response.status != 200:
        raise RuntimeError(f"{case.lab} benchmark request returned HTTP {response.status}")
    if mode != expected_mode:
        raise RuntimeError(
            f"benchmark endpoint reports detector mode {mode!r}; expected {expected_mode!r}"
        )
    request_id = headers.get("x-request-id", "")
    if not request_id:
        raise RuntimeError("Fusion benchmark response is missing X-Request-ID")
    raw_detector_ms = headers.get("x-detector-ms", "")
    try:
        detector_ms = float(raw_detector_ms) if raw_detector_ms else None
    except ValueError:
        detector_ms = None
    return {
        "status": response.status,
        "latency_ms": round(elapsed_ms, 3),
        "cache_status": headers.get("x-cache-status", "not-cacheable"),
        "detector_mode": mode,
        "classification": headers.get("x-fusion-detector-decision", "not-evaluated"),
        "detector_action": headers.get("x-fusion-detector-action", "not-evaluated"),
        "cache_bypass": headers.get("x-fusion-cache-bypass", "0"),
        "detector_ms": detector_ms,
        "request_id": request_id,
    }


# Ghi vị trí cuối log trước lượt đo.
def _event_offset(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


# Đọc các event JSONL mới từ vị trí đã ghi.
def _events_since(path: Path, offset: int) -> list[tuple[dict[str, object], int]]:
    if not path.exists():
        return []
    events: list[tuple[dict[str, object], int]] = []
    with path.open("rb") as stream:
        stream.seek(offset)
        for raw in stream:
            try:
                events.append((json.loads(raw.decode("utf-8")), len(raw)))
            except (UnicodeDecodeError, json.JSONDecodeError):
                # A malformed external log line must not make a benchmark
                # report look successful. It is omitted and counted nowhere.
                continue
    return events


# Đếm dung lượng và số event tương ứng request_ids.
def log_volume(paths: dict[str, Path], offsets: dict[str, int], request_ids: set[str]) -> dict[str, object]:
    """Count only sanitized event lines produced by this benchmark invocation."""
    result: dict[str, object] = {}
    for source, path in paths.items():
        selected = [size for event, size in _events_since(path, offsets[source]) if event.get("request_id") in request_ids]
        result[f"{source}_event_count"] = len(selected)
        result[f"{source}_bytes"] = sum(selected)
    request_count = max(1, len(request_ids))
    result["events_per_request"] = round(
        (int(result["nginx_event_count"]) + int(result["detector_event_count"])) / request_count, 3
    )
    result["log_bytes_per_request"] = round(
        (int(result["nginx_bytes"]) + int(result["detector_bytes"])) / request_count, 3
    )
    return result


# Kiểm tra endpoint phụ thuộc và đo thời gian phản hồi.
def _http_status_latency(url: str) -> dict[str, object]:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or not parsed.hostname:
        return {"ok": False, "status": None, "latency_ms": None}
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=5)
    started = time.perf_counter()
    try:
        connection.request("GET", parsed.path or "/")
        response = connection.getresponse()
        response.read()
        return {"ok": response.status == 200, "status": response.status,
                "latency_ms": round((time.perf_counter() - started) * 1000, 3)}
    except OSError:
        return {"ok": False, "status": None, "latency_ms": None}
    finally:
        connection.close()


# Tìm field evidence theo job trong Loki.
def _loki_has_field(loki_url: str, job: str, field: str, value: str) -> bool:
    parsed = urlsplit(loki_url)
    if parsed.scheme != "http" or not parsed.hostname:
        return False
    now = time.time_ns()
    if field not in {"request_id", "incident_id"}:
        raise ValueError("unsupported Loki correlation field")
    query = f'{{job="{job}"}} | json | {field}="{value}"'
    path = "/loki/api/v1/query_range?" + urlencode({
        "query": query,
        "start": str(now - 60_000_000_000),
        "end": str(now),
        "limit": "20",
    })
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        return response.status == 200 and bool(payload.get("data", {}).get("result", []))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    finally:
        connection.close()


# Chờ log benchmark được chuyển sang Loki.
def wait_for_loki(loki_url: str, job: str, value: str, timeout_seconds: float = 15.0,
                  field: str = "request_id") -> dict[str, object]:
    """Measure post-request shipping delay; this never contributes to client latency."""
    started = time.perf_counter()
    while time.perf_counter() - started < timeout_seconds:
        if _loki_has_field(loki_url, job, field, value):
            return {"delivered": True, "delivery_ms": round((time.perf_counter() - started) * 1000, 3)}
        time.sleep(0.25)
    return {"delivered": False, "delivery_ms": None}


# Tổng hợp success, throughput, latency và cache status.
def summarize(mode: str, run_id: str, records: list[dict[str, object]], repeats: int) -> list[dict[str, object]]:
    """Produce a cold/warm table from raw measured samples."""
    summaries: list[dict[str, object]] = []
    for phase in ("cold", "warm"):
        group = [row for row in records if row["phase"] == phase]
        latency = [float(row["latency_ms"]) for row in group]
        detector = [float(row["detector_ms"]) for row in group if row["detector_ms"] is not None]
        cache = Counter(str(row["cache_status"]) for row in group)
        summaries.append({
            "run_id": run_id,
            "mode": mode,
            "phase": phase,
            "repeats": repeats,
            "requests": len(group),
            "mean_ms": _number(statistics.fmean(latency) if latency else None),
            "p50_ms": _number(percentile(latency, 0.50)),
            "p95_ms": _number(percentile(latency, 0.95)),
            "p99_ms": _number(percentile(latency, 0.99)),
            "min_ms": _number(min(latency) if latency else None),
            "max_ms": _number(max(latency) if latency else None),
            "cache_hit_ratio": round(cache["HIT"] / len(group), 4) if group else 0.0,
            "cache_hits": cache["HIT"],
            "cache_misses": cache["MISS"],
            "cache_expired": cache["EXPIRED"],
            "cache_bypass": cache["BYPASS"],
            "non_hit_requests": len(group) - cache["HIT"],
            "detector_calls": len(detector),
            "detector_mean_ms": _number(statistics.fmean(detector) if detector else None),
            "detector_p50_ms": _number(percentile(detector, 0.50)),
            "detector_p95_ms": _number(percentile(detector, 0.95)),
            "detector_anomalies": sum(row["classification"] == "anomaly" for row in group),
        })
    return summaries


# Ghi bảng metric benchmark thành CSV.
def _write_csv(path: Path, columns: Iterable[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(columns), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# Chạy benchmark cho một detector mode và thu evidence.
def run_mode(host: str, mode: str, run_id: str, output_dir: Path, requests_per_phase: int,
             repeats: int, hot_keys: int, events_dir: Path, loki_url: str, grafana_url: str) -> dict[str, object]:
    """Run one mode against its fixed operator endpoint and write raw evidence."""
    if mode not in MODE_PORTS:
        raise ValueError(f"unsupported mode: {mode}")
    if requests_per_phase < 1 or repeats < 1 or hot_keys < 1:
        raise ValueError("requests-per-phase, repeats and hot-keys must be positive")
    port = MODE_PORTS[mode]
    paths = {
        "nginx": events_dir / "fusion-nginx-access.jsonl",
        "detector": events_dir / "detector-events.jsonl",
    }
    offsets = {name: _event_offset(path) for name, path in paths.items()}
    measured: list[dict[str, object]] = []
    all_request_ids: set[str] = set()
    prewarm_count = 0

    # Ghi một mẫu request và các metric vào lượt đo.
    def record(case: FusionCase, phase: str, repeat: int, sequence: int, key_slot: int, measured_sample: bool) -> None:
        nonlocal prewarm_count
        response = send_case(host, port, case, mode)
        response.update({
            "run_id": run_id,
            "mode": mode,
            "repeat": repeat,
            "phase": phase,
            "sequence": sequence,
            "lab": case.lab,
            "key_slot": key_slot,
        })
        all_request_ids.add(str(response["request_id"]))
        if measured_sample:
            measured.append(response)
        else:
            prewarm_count += 1

    for repeat in range(1, repeats + 1):
        for sequence in range(requests_per_phase):
            case = benchmark_case(run_id, mode, "cold", repeat, sequence, sequence)
            record(case, "cold", repeat, sequence, sequence, True)

        hot_cases = [
            benchmark_case(run_id, mode, "warm", repeat, key_slot, key_slot)
            for key_slot in range(hot_keys * len(LABS))
        ]
        for key_slot, case in enumerate(hot_cases):
            record(case, "prewarm", repeat, key_slot, key_slot, False)
        for sequence in range(requests_per_phase):
            key_slot = sequence % len(hot_cases)
            record(hot_cases[key_slot], "warm", repeat, sequence, key_slot, True)

    # Nginx/uvicorn append logs synchronously in this lab; a short grace period
    # avoids sampling a just-opened log line while still excluding Loki polling.
    time.sleep(0.1)
    logging_metrics = log_volume(paths, offsets, all_request_ids)
    latest_request_id = str(measured[-1]["request_id"])
    monitoring = {
        "loki_nginx": wait_for_loki(loki_url, "fusion-nginx", latest_request_id),
        "loki_detector": (
            wait_for_loki(loki_url, "fusion-detector", latest_request_id)
            if mode != "off" else {"delivered": None, "delivery_ms": None}
        ),
        # Grafana is intentionally probed after the workload. Its HTTP health
        # is not on the Nginx request path, so it cannot be added to E2E latency.
        "grafana_health": _http_status_latency(grafana_url.rstrip("/") + "/api/health"),
    }
    summaries = summarize(mode, run_id, measured, repeats)
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(output_dir / f"stage14_{mode}_samples.csv", SAMPLE_COLUMNS, measured)
    _write_csv(output_dir / f"stage14_{mode}_summary.csv", SUMMARY_COLUMNS, summaries)
    mode_manifest = {
        "schema": "fusion-stage14-mode-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "mode": mode,
        "origin": f"http://{host}:{port}",
        "requests_per_phase": requests_per_phase,
        "repeats": repeats,
        "hot_keys": hot_keys,
        "prewarm_requests": prewarm_count,
        "measured_requests": len(measured),
        "logging": logging_metrics,
        "monitoring": monitoring,
        "limitations": [
            "Sequential local-lab benchmark only; it is not a capacity or production benchmark.",
            "Cold and warm keys are distinct and all requests are benign normal templates.",
            "Logging volume is measured from sanitized JSONL bytes; its isolated I/O latency is not measured.",
            "Loki delivery and Grafana health are post-request observations, excluded from client latency.",
        ],
    }
    (output_dir / f"stage14_{mode}_monitoring.json").write_text(
        json.dumps(mode_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return mode_manifest


# Gộp các mode thành bảng so sánh cuối cùng.
def aggregate(output_dir: Path) -> dict[str, object]:
    """Join per-mode files into one report-friendly Stage 14 artefact set."""
    rows: list[dict[str, object]] = []
    monitoring: dict[str, object] = {}
    for mode in MODE_PORTS:
        summary_path = output_dir / f"stage14_{mode}_summary.csv"
        monitoring_path = output_dir / f"stage14_{mode}_monitoring.json"
        if not summary_path.exists() or not monitoring_path.exists():
            raise ValueError(f"missing Stage 14 artefacts for mode {mode}")
        with summary_path.open(encoding="utf-8", newline="") as stream:
            rows.extend(csv.DictReader(stream))
        monitoring[mode] = json.loads(monitoring_path.read_text(encoding="utf-8"))
    _write_csv(output_dir / "stage14_summary.csv", SUMMARY_COLUMNS, rows)
    manifest = {
        "schema": "fusion-stage14-run-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "modes": list(MODE_PORTS),
        "summary": "stage14_summary.csv",
        "mode_monitoring": monitoring,
        "reporting_rules": [
            "Compare a mode within the same phase first; cold and warm are reported separately.",
            "Detector overhead is reported from X-Detector-Ms and end-to-end client latency separately.",
            "Do not add Loki delivery or Grafana health time to Nginx client latency.",
        ],
    }
    (output_dir / "stage14_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    _write_plot(output_dir, rows)
    return manifest


# Vẽ biểu đồ benchmark từ các metric đã tổng hợp.
def _write_plot(output_dir: Path, rows: list[dict[str, object]]) -> None:
    """Create a compact chart when matplotlib is available in the runner image."""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        return
    warm = [row for row in rows if row["phase"] == "warm"]
    labels = [row["mode"] for row in warm]
    p95 = [float(row["p95_ms"]) for row in warm]
    hit_ratio = [float(row["cache_hit_ratio"]) * 100 for row in warm]
    figure, (latency_axis, cache_axis) = plt.subplots(1, 2, figsize=(9, 3.6))
    latency_axis.bar(labels, p95, color="#2563eb")
    latency_axis.set_title("Warm p95 client latency")
    latency_axis.set_ylabel("milliseconds")
    cache_axis.bar(labels, hit_ratio, color="#16a34a")
    cache_axis.set_title("Warm cache HIT ratio")
    cache_axis.set_ylabel("percent")
    cache_axis.set_ylim(0, 100)
    figure.tight_layout()
    figure.savefig(output_dir / "stage14_warm_latency_cache.png", dpi=160)
    plt.close(figure)


# Đọc CLI và chạy benchmark Fusion.
def main() -> None:
    parser = argparse.ArgumentParser(description="Stage 14 Fusion cache/detector performance benchmark")
    parser.add_argument("--mode", choices=tuple(MODE_PORTS))
    parser.add_argument("--aggregate", action="store_true")
    parser.add_argument("--host", default=os.getenv("LAB_HOST", "127.0.0.1"))
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    parser.add_argument("--output-dir", type=Path, default=Path("results/stage14") / DEFAULT_RUN_ID)
    parser.add_argument("--requests-per-phase", type=int, default=100)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--hot-keys", type=int, default=8)
    parser.add_argument("--events-dir", type=Path, default=Path("data/events"))
    parser.add_argument("--loki-url", default="http://loki:3100")
    parser.add_argument("--grafana-url", default="http://grafana:3000")
    parser.add_argument("--allow-small", action="store_true", help="allow fewer than 100 samples per phase for a smoke test")
    args = parser.parse_args()
    if args.aggregate:
        if args.mode:
            parser.error("--aggregate cannot be combined with --mode")
        print(json.dumps(aggregate(args.output_dir), ensure_ascii=False, indent=2))
        return
    if not args.mode:
        parser.error("--mode is required unless --aggregate is used")
    if args.requests_per_phase < 100 and not args.allow_small:
        parser.error("--requests-per-phase must be at least 100 for G14; use --allow-small only for smoke tests")
    result = run_mode(
        args.host, args.mode, args.run_id, args.output_dir, args.requests_per_phase,
        args.repeats, args.hot_keys, args.events_dir, args.loki_url, args.grafana_url,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
