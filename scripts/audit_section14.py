"""Create a machine-readable final audit for the separated ML-shadow design."""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.route_detector import load_registry


def read(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def http_ok(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return {"ok": response.status == 200, "status": response.status}
    except Exception as exc:  # live-state evidence must not abort artifact audit
        return {"ok": False, "error": type(exc).__name__}


def docker_services() -> dict:
    names = (
        "detector", "ml-shadow", "triage", "proxy", "loki", "alloy", "grafana",
        "fusion-mongo", "fusion-backend", "fusion-storefront",
    )
    rows = {}
    for service in names:
        query = subprocess.run(
            ["docker", "compose", "ps", "-q", service], cwd=ROOT,
            capture_output=True, text=True, check=False,
        )
        container = query.stdout.strip()
        if not container:
            rows[service] = {"running": False, "health": "missing"}
            continue
        state = subprocess.run(
            ["docker", "inspect", "--format={{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", container],
            capture_output=True, text=True, check=False,
        ).stdout.strip().split("|", 1)
        rows[service] = {
            "running": bool(state and state[0] == "true"),
            "health": state[1] if len(state) > 1 else "unknown",
        }
    return rows


def main() -> None:
    registry = load_registry()
    replay = read("ml-detector/artifacts/runtime_replay_v1/evaluation.json")
    acceptance = read("results/section10/section10_acceptance.json")
    resilience = read("results/section9/resilience_security_audit.json")
    loki = read("results/section6/loki_ingestion_smoke.json")
    grafana = read("results/section7/grafana_shadow_monitoring_smoke.json")
    triage = read("results/section8/triage_golden_eval.json")
    triage_join = read("results/section8/triage_loki_join_smoke.json")

    blind_docs = {
        "query": read("ml-detector/artifacts/query_v8_blind_v1/evaluation.json"),
        "xfh": read("ml-detector/artifacts/xfh_blind_test_v2/evaluation.json"),
        "utm": read("ml-detector/artifacts/blind_test_v1/evaluation.json")["routes"]["utm"],
        "fatget": read("ml-detector/artifacts/fatget_blind_test_v2/evaluation.json"),
    }
    blind = {
        route: {
            "recall": doc["metrics"]["if_only"]["recall"],
            "false_positive_rate": doc["metrics"]["if_only"]["false_positive_rate"],
        }
        for route, doc in blind_docs.items()
    }
    blind_pass = all(v["recall"] >= 0.90 and v["false_positive_rate"] <= 0.02 for v in blind.values())
    services = docker_services()

    gates = {
        "registry_loaded": sorted(registry) == ["fatget", "query", "utm", "xfh"],
        "all_routes_shadow_only": all(item["mode"] == "shadow" for item in registry.values()),
        "runtime_parity": all(replay["acceptance"].values()),
        "blind_metrics": blind_pass,
        "section9_resilience_security": all(resilience["gates"].values())
        and resilience["live_ml_shadow_outage"]["main_request_fail_open"]
        and resilience["live_ml_shadow_outage"]["candidate_remained_non_enforcing"],
        "section10_performance_stability": bool(acceptance["section_passed"])
        and acceptance["benchmark"]["all_required_gates_passed"]
        and acceptance["soak"]["all_required_gates_passed"],
        "cache_behavior_unchanged": acceptance["cache_parity"]["warm_hit_ratio_delta"] == 0
        and acceptance["benchmark"]["cache_bypass_enabled"] == 0
        and acceptance["soak"]["cache_bypass_count"] == 0,
        "loki_ml_shadow_ingestion": loki["alloy"]["config_loaded"]
        and loki["alloy"]["mount_read_only"]
        and loki["loki_lifecycle_counts"]["shadow_completed"] > 0
        and loki["correlation"]["correlated"],
        "grafana_ml_shadow_monitoring": bool(grafana["services_healthy"])
        and grafana["dashboard"]["panel_count"] >= 10
        and grafana["alerts"]["provisioned"] >= 5,
        "triage_safe": triage["metrics"]["unsupported_information_rate"] == 0
        and not triage["safety"]["automatic_block_capability"]
        and not triage["safety"]["cache_configuration_write_capability"]
        and triage_join["separation"]["baseline_authoritative_for_cache"]
        and not triage_join["separation"]["candidate_authoritative_for_cache"],
        "full_regression": acceptance["regression"]["passed"] == 91
        and acceptance["regression"]["failed"] == 0,
    }

    report = {
        "schema": "fusion-section11-final-audit-v1",
        "scope": "local Docker shadow validation; not production readiness",
        "architecture": {
            "baseline_authoritative_for_cache": True,
            "route_aware_candidates_shadow_only": True,
            "automatic_promotion": False,
            "manual_approval_required_for_mode_change": True,
        },
        "blind": {
            "metrics": blind,
            "synthetic_lab_data": True,
            "production_ground_truth_available": False,
            "external_ood_validation_available": False,
        },
        "performance": acceptance,
        "gates": gates,
        "mandatory_gates_passed": all(gates.values()),
        "live_state": {
            "docker_services": services,
            "endpoints": {
                "triage": http_ok("http://127.0.0.1:8002/health"),
                "loki": http_ok("http://127.0.0.1:13100/ready"),
                "grafana": http_ok("http://127.0.0.1:13000/api/health"),
                "alloy": http_ok("http://127.0.0.1:12345/-/ready"),
            },
        },
        "decision": {
            "shadow_mode_stable_at_defined_local_target": all(gates.values()),
            "enforcement_authorized": False,
            "reason": "Evidence supports continued shadow validation only; mode change requires manual approval.",
        },
    }
    output = ROOT / "results" / "section11" / "final_audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"mandatory_gates_passed": report["mandatory_gates_passed"], "gates": gates}, indent=2))


if __name__ == "__main__":
    main()
