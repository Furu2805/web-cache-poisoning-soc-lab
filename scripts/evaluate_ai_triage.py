"""Deterministic golden-vector evaluation for Section 12 AI triage."""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from triage.app import build_triage
from triage.llm import sanitized_evidence

ROUTES = {
    "query": ("unkeyed-query-parameter", "cache key", "query_length"),
    "xfh": ("unkeyed-x-forwarded-host", "X-Forwarded-Host", "host_mismatch"),
    "utm": ("parameter-cloaking", "Canonicalize", "semicolon_hidden_callback"),
    "fatget": ("fat-get-request", "GET", "has_body_on_get"),
}
SECRETS = ("raw-secret.invalid", "session=super-secret", "callback=raw-payload")
FORBIDDEN_CLAIMS = ("confirmed successful exploitation", "production compromised", "victim confirmed")


def events(route, index, classification="anomaly"):
    request_id = f"section12-{route}-{index}"
    indicator = ROUTES[route][2]
    nginx = {
        "schema": "fusion-nginx-access-v1", "request_id": request_id, "scenario": route,
        "uri_path": f"/labs/{route}/resource", "cache_status": "MISS",
        "cookie": SECRETS[1], "raw_query": SECRETS[2],
    }
    detector = {
        "schema": "fusion-detector-event-v2", "request_id": request_id,
        "detector_mode": "observe", "scenario": route, "uri_path": f"/labs/{route}/resource",
        "classification": classification, "anomaly_score": 0.61, "action": "observe",
        "recommended_cache_action": "bypass-no-cache" if classification == "anomaly" else "cache-normal",
        "cache_bypass": False, "model_version": f"{route}-golden", "if_anomaly": classification == "anomaly",
        "profile_anomaly": classification == "anomaly", "component_scores": {"relationship": 0.61},
        "thresholds": {"relationship": 0.58},
        "indicators": {"normal_profile_deviations": [indicator], "raw_header": SECRETS[0],
                       "shadow_candidate": {"route": route, "profile_reasons": [indicator]}},
    }
    shadow = {
        "schema": "fusion-ml-shadow-event-v1", "event_type": "shadow_completed",
        "request_id": request_id, "status": "completed", "mode": "shadow", "route": route,
        "candidate_id": f"{route}-golden", "model_version": f"{route}-golden",
        "if_anomaly": classification == "anomaly", "profile_anomaly": classification == "anomaly",
        "final_anomaly": classification == "anomaly", "component_scores": {"relationship": 0.61},
        "thresholds": {"relationship": 0.58}, "profile_reasons": [indicator],
        "monitor_closely": route == "fatget", "fallback_reason": None,
    }
    return request_id, nginx, detector, shadow


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()
    cases = []
    timings = []
    for index in range(args.iterations):
        route = tuple(ROUTES)[index % len(ROUTES)]
        classification = "normal" if index % 5 == 4 else "anomaly"
        request_id, nginx, detector, shadow = events(route, index, classification)
        started = time.perf_counter()
        result = build_triage(request_id, nginx, detector, shadow)
        sanitized = sanitized_evidence(result)
        timings.append((time.perf_counter() - started) * 1000)
        serialized = json.dumps({"result": result, "provider_evidence": sanitized})
        expected_technique = ROUTES[route][0] if classification == "anomaly" else None
        expected_verdict = "suspected" if classification == "anomaly" else "not-suspicious"
        expected_indicator = ROUTES[route][2]
        summary_ok = (expected_verdict in result["incident_summary"] and classification in result["incident_summary"]
                      and "MISS" in result["incident_summary"])
        technique_ok = ((result["possible_technique"] or {}).get("id") if result["possible_technique"] else None) == expected_technique
        indicator_ok = expected_indicator in result["suspicious_indicators"]
        mitigation_ok = bool(result["mitigation_suggestions"]) and (
            classification == "normal" or ROUTES[route][1].lower() in " ".join(result["mitigation_suggestions"]).lower()
        )
        unsupported = any(value in serialized for value in SECRETS + FORBIDDEN_CLAIMS)
        cases.append({"summary_ok": summary_ok, "technique_ok": technique_ok, "indicator_ok": indicator_ok,
                      "mitigation_ok": mitigation_ok, "unsupported": unsupported})
    total = len(cases)
    correct_fields = sum(sum(case[key] for key in ("summary_ok", "technique_ok", "indicator_ok", "mitigation_ok")) for case in cases)
    report = {
        "schema_version": "section12-triage-eval-v1", "engine": "evidence-rules-v1",
        "scope": "local deterministic golden vectors; not production validation", "cases": total,
        "metrics": {
            "incident_summary_accuracy": sum(case["summary_ok"] for case in cases) / total,
            "technique_accuracy": sum(case["technique_ok"] for case in cases) / total,
            "indicator_recall": sum(case["indicator_ok"] for case in cases) / total,
            "mitigation_relevance": sum(case["mitigation_ok"] for case in cases) / total,
            "unsupported_information_rate": sum(case["unsupported"] for case in cases) / total,
            "human_edit_field_rate": 1 - correct_fields / (total * 4),
            "latency_ms": {"mean": statistics.fmean(timings), "p95": sorted(timings)[int(.95 * (total - 1))],
                           "max": max(timings)},
        },
        "safety": {"raw_secret_or_payload_forwarded": any(case["unsupported"] for case in cases),
                   "automatic_block_capability": False, "cache_configuration_write_capability": False,
                   "insufficient_evidence_contract": "HTTP error detail decision=không đủ dữ liệu"},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
