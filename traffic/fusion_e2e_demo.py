"""Stage 15 deterministic end-to-end demo for the local Fusion lab.

The demo intentionally uses the localhost-only :8091 enforcement endpoint. It
sends one local cache-poisoning primitive, proves the cache bypass/no-cache
decision with a clean follow-up request, then correlates that request through
Loki, G12 triage and a G13 Incident Report.  It never changes the public lab's
default :8086 mode and never sends traffic outside the Docker lab.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from traffic.fusion_benchmark import _http_status_latency, wait_for_loki
from traffic.fusion_scenarios import LABS, FusionCase, attack_case


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/146.0 Safari/537.36"
LANGUAGE = "vi-VN,vi;q=0.9,en-US;q=0.8"
ENFORCE_PORT = 8091


class DemoHTTPError(RuntimeError):
    """Bounded HTTP status error without serializing a potentially sensitive body."""

    # Lưu status và endpoint khi demo HTTP lỗi.
    def __init__(self, status: int, endpoint: str):
        super().__init__(f"{endpoint} returned HTTP {status}")
        self.status = status


# Tạo request victim sạch tương ứng với attacker case.
def clean_follow_up(case: FusionCase) -> tuple[str, dict[str, str], str, str]:
    """Return a clean request with the exact vulnerable cache key of one attack."""
    headers = {
        name: value for name, value in case.headers.items()
        if name.lower() not in {"x-forwarded-host", "x-forwarded-proto", "content-type", "content-length"}
    }
    if case.lab == "xfh":
        return case.uri, headers, "", "127.0.0.1:8087/resources/js/tracking.js"
    if case.lab == "query":
        return case.uri.split("&utm_content=", 1)[0], headers, "", "alert("
    if case.lab == "utm":
        return case.uri.split("&utm_content=", 1)[0], headers, "", "alert("
    if case.lab == "fatget":
        return case.uri, headers, "", "alert("
    raise ValueError(f"unsupported Fusion scenario: {case.lab}")


# Gửi raw HTTP request và thu status/header/body cần cho evidence.
def send_request(host: str, port: int, method: str, uri: str, headers: dict[str, str], body: str) -> dict[str, object]:
    """Send one local HTTP request and expose only bounded response metadata."""
    connection = http.client.HTTPConnection(host, port, timeout=20)
    started = time.perf_counter()
    try:
        payload = body.encode("utf-8") if body else None
        connection.request(method, uri, body=payload, headers=headers)
        response = connection.getresponse()
        response_body = response.read().decode("utf-8", "replace")
        response_headers = {name.lower(): value for name, value in response.getheaders()}
    finally:
        connection.close()
    request_id = response_headers.get("x-request-id", "")
    if not request_id:
        raise RuntimeError("Fusion response is missing X-Request-ID")
    return {
        "status": response.status,
        "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        "request_id": request_id,
        "cache_status": response_headers.get("x-cache-status", "not-cacheable"),
        "detector_mode": response_headers.get("x-fusion-detector-mode", ""),
        "classification": response_headers.get("x-fusion-detector-decision", ""),
        "detector_action": response_headers.get("x-fusion-detector-action", ""),
        "recommended_cache_action": response_headers.get("x-fusion-detector-recommendation", ""),
        "cache_bypass": response_headers.get("x-fusion-cache-bypass", "0"),
        "detector_ms": response_headers.get("x-detector-ms", ""),
        # Response body is used only in-memory to prove cache isolation. It is
        # never written into a Stage 15 evidence file.
        "_body": response_body,
    }


# Gọi endpoint JSON của triage/report và đọc kết quả.
def request_json(base_url: str, method: str, path: str) -> tuple[int, dict[str, object]]:
    parsed = urlsplit(base_url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("service URL must be an http URL with a hostname")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=45)
    try:
        connection.request(method, path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        return response.status, payload
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"unable to use local service {parsed.hostname}") from exc
    finally:
        connection.close()


# Thử lại triage sau khi ba nguồn event xuất hiện bất đồng bộ.
def post_with_evidence_retry(triage_url: str, path: str, retries: int = 24) -> dict[str, object]:
    """Wait only for asynchronous Loki shipping; do not hide provider failures."""
    for attempt in range(retries):
        status, payload = request_json(triage_url, "POST", path)
        if status in {200, 201}:
            return payload
        if status in {404, 409} and attempt + 1 < retries:
            time.sleep(0.5)
            continue
        raise DemoHTTPError(status, path)
    raise RuntimeError("unreachable evidence retry state")


# Rút gọn response thành bằng chứng an toàn để ghi demo.
def _compact_response(response: dict[str, object], effect_observed: bool) -> dict[str, object]:
    return {
        key: response[key]
        for key in (
            "status", "latency_ms", "request_id", "cache_status", "detector_mode",
            "classification", "detector_action", "recommended_cache_action", "cache_bypass", "detector_ms",
        )
    } | {"local_effect_observed": effect_observed}


# Ghép attacker/victim/cache/triage/report thành summary end-to-end.
def build_summary(run_id: str, scenario: str, attacker: dict[str, object], clean: dict[str, object],
                  attack_effect: bool, clean_effect: bool, triage: dict[str, object],
                  incident_payload: dict[str, object], observability: dict[str, object]) -> dict[str, object]:
    """Build a report-friendly record that deliberately omits raw traffic and LLM text."""
    report = incident_payload["report"]
    technique = triage.get("possible_technique") or {}
    checks = {
        "attacker_http_200": attacker["status"] == 200,
        "enforce_mode": attacker["detector_mode"] == "enforce",
        "attacker_classified_anomaly": attacker["classification"] == "anomaly",
        "bypass_no_cache": attacker["cache_bypass"] == "1" and attacker["cache_status"] == "BYPASS",
        "local_attack_effect_reached_origin": attack_effect,
        "clean_client_not_poisoned": clean["status"] == 200 and clean["cache_status"] == "MISS" and not clean_effect,
        "loki_nginx_event": bool(observability["loki_nginx"].get("delivered")),
        "loki_detector_event": bool(observability["loki_detector"].get("delivered")),
        "loki_triage_event": bool(observability["loki_triage"].get("delivered")),
        "loki_incident_event": bool(observability["loki_incident"].get("delivered")),
        "grafana_ready": bool(observability["grafana_health"].get("ok")),
        "incident_report_redacted": report["suspicious_input"].get("raw_values_available") is False,
    }
    llm = triage.get("llm", {})
    return {
        "schema": "fusion-stage15-e2e-demo-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "scope": "local-educational-fusion-lab",
        "scenario": scenario,
        "attacker_request": _compact_response(attacker, attack_effect),
        "clean_client_request": _compact_response(clean, clean_effect),
        "triage": {
            "request_id": triage["request_id"],
            "engine": triage["triage_engine"]["name"],
            "verdict": triage["verdict"],
            "severity": triage["severity"],
            "possible_technique_id": technique.get("id"),
            "incident_summary": triage["incident_summary"],
            "mitigation_suggestions": triage["mitigation_suggestions"],
            "llm_provider": llm.get("provider"),
            "llm_status": llm.get("status"),
            "llm_model": llm.get("model"),
            "generative_model_used": bool(llm.get("generative_model_used", False)),
        },
        "incident_report": {
            "incident_id": report["incident_id"],
            "created": bool(incident_payload.get("created")),
            "schema": report["schema"],
            "raw_values_available": report["suspicious_input"]["raw_values_available"],
        },
        "observability": observability,
        "assertions": checks,
        "passed": all(checks.values()),
        "limitations": [
            "The sender is a deterministic local HTTP replay. Send the documented equivalent request through Burp Repeater for an interactive Burp screenshot.",
            "Grafana renders the same Loki source confirmed here; this record checks its health and Loki delivery, not a browser screenshot.",
            "The detector verdict and mitigation are deterministic evidence rules. Optional LLM narration is post-event only and has no cache authority.",
        ],
    }


# Chạy một kịch bản từ request attacker tới incident report.
def run_demo(host: str, scenario: str, run_id: str, output_dir: Path, triage_url: str,
             loki_url: str, grafana_url: str) -> dict[str, object]:
    if scenario not in LABS:
        raise ValueError(f"unsupported scenario: {scenario}")
    token = uuid.uuid4().hex[:24]
    attack_case_value = attack_case(scenario, token, USER_AGENT, LANGUAGE)
    attacker = send_request(
        host, ENFORCE_PORT, attack_case_value.method, attack_case_value.uri,
        attack_case_value.headers, attack_case_value.body,
    )
    clean_uri, clean_headers, clean_body, marker = clean_follow_up(attack_case_value)
    clean = send_request(host, ENFORCE_PORT, attack_case_value.method, clean_uri, clean_headers, clean_body)
    attack_effect = marker in str(attacker["_body"])
    clean_effect = marker in str(clean["_body"])
    attack_request_id = str(attacker["request_id"])

    observability = {
        "loki_nginx": wait_for_loki(loki_url, "fusion-nginx", attack_request_id),
        "loki_detector": wait_for_loki(loki_url, "fusion-detector", attack_request_id),
    }
    triage = post_with_evidence_retry(triage_url, f"/triage/{attack_request_id}")
    incident_payload = post_with_evidence_retry(triage_url, f"/incidents/{attack_request_id}")
    incident_id = str(incident_payload["report"]["incident_id"])
    observability.update({
        "loki_triage": wait_for_loki(loki_url, "fusion-triage", attack_request_id),
        "loki_incident": wait_for_loki(loki_url, "fusion-incident-report", incident_id, field="incident_id"),
        "grafana_health": _http_status_latency(grafana_url.rstrip("/") + "/api/health"),
        "grafana_dashboard_url": "http://127.0.0.1:13000/d/fusion-cache-security",
    })
    summary = build_summary(
        run_id, scenario, attacker, clean, attack_effect, clean_effect, triage, incident_payload, observability,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "stage15_e2e_summary.json"
    output_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not summary["passed"]:
        failed = [name for name, value in summary["assertions"].items() if not value]
        raise RuntimeError("Stage 15 assertions failed: " + ", ".join(failed))
    return summary


# Đọc CLI và khởi chạy demo.
def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Stage 15 Fusion end-to-end demo")
    parser.add_argument("--host", default=os.getenv("LAB_HOST", "127.0.0.1"))
    parser.add_argument("--scenario", choices=LABS, default="xfh")
    parser.add_argument("--run-id", default="stage15-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--triage-url", default="http://triage:8002")
    parser.add_argument("--loki-url", default="http://loki:3100")
    parser.add_argument("--grafana-url", default="http://grafana:3000")
    args = parser.parse_args()
    output_dir = args.output_dir or Path("results/stage15") / args.run_id
    summary = run_demo(
        args.host, args.scenario, args.run_id, output_dir, args.triage_url, args.loki_url, args.grafana_url,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
