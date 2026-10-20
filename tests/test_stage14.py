import csv
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from traffic import fusion_benchmark as stage14


def _record(phase, latency, cache_status, detector_ms=None, classification="normal"):
    return {
        "phase": phase,
        "latency_ms": latency,
        "cache_status": cache_status,
        "detector_ms": detector_ms,
        "classification": classification,
    }


def test_stage14_uses_fixed_length_mode_isolated_normal_keys():
    off = stage14.benchmark_case("run-a", "off", "cold", 1, 0, 0)
    observe = stage14.benchmark_case("run-a", "observe", "cold", 1, 0, 0)
    off_token = parse_qs(urlsplit(off.uri).query)["cb"][0]
    observe_token = parse_qs(urlsplit(observe.uri).query)["cb"][0]

    assert off.label == observe.label == "normal"
    assert off.lab == observe.lab == "xfh"
    assert len(off_token) == len(observe_token) == 24
    assert off_token != observe_token
    # A new run must use fresh keys even with the same phase/repeat/slot.
    assert off_token != parse_qs(urlsplit(stage14.benchmark_case("run-b", "off", "cold", 1, 0, 0).uri).query)["cb"][0]


def test_stage14_summary_separates_warm_cache_and_detector_duration():
    rows = [
        _record("cold", 10, "MISS", 1.0),
        _record("cold", 30, "MISS", 3.0),
        _record("warm", 4, "HIT", 1.5),
        _record("warm", 6, "HIT", 2.5, "anomaly"),
    ]
    cold, warm = stage14.summarize("observe", "run-a", rows, repeats=1)

    assert cold["cache_hit_ratio"] == 0.0
    assert cold["p50_ms"] == 20.0
    assert warm["cache_hit_ratio"] == 1.0
    assert warm["detector_calls"] == 2
    assert warm["detector_p95_ms"] == 2.45
    assert warm["detector_anomalies"] == 1


def test_stage14_aggregate_requires_all_modes_and_keeps_cold_warm_rows(tmp_path, monkeypatch):
    monkeypatch.setattr(stage14, "_write_plot", lambda *_: None)
    for mode in stage14.MODE_PORTS:
        rows = stage14.summarize(mode, "run-a", [
            _record("cold", 10, "MISS"),
            _record("warm", 5, "HIT"),
        ], repeats=1)
        stage14._write_csv(tmp_path / f"stage14_{mode}_summary.csv", stage14.SUMMARY_COLUMNS, rows)
        (tmp_path / f"stage14_{mode}_monitoring.json").write_text(
            json.dumps({"mode": mode, "logging": {}}), encoding="utf-8"
        )

    manifest = stage14.aggregate(tmp_path)
    with (tmp_path / "stage14_summary.csv").open(encoding="utf-8", newline="") as stream:
        joined = list(csv.DictReader(stream))

    assert manifest["schema"] == "fusion-stage14-run-v1"
    assert len(joined) == 6
    assert {(row["mode"], row["phase"]) for row in joined} == {
        (mode, phase) for mode in stage14.MODE_PORTS for phase in ("cold", "warm")
    }


def test_stage14_benchmark_ports_are_local_operator_modes():
    root = Path(__file__).resolve().parents[1]
    mode_config = (root / "nginx" / "fusion-detector-mode.conf").read_text(encoding="utf-8")
    servers = (root / "nginx" / "servers.conf").read_text(encoding="utf-8")
    compose = (root / "compose.yaml").read_text(encoding="utf-8")

    assert "8086 off;" in mode_config
    assert "8090 observe;" in mode_config
    assert "8091 enforce;" in mode_config
    assert "$http_x_fusion_detector_mode" not in mode_config
    assert "listen 8090;" in servers and "listen 8091;" in servers
    assert '127.0.0.1:8090:8090' in compose and '127.0.0.1:8091:8091' in compose
