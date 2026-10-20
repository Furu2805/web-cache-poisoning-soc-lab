"""Bounded, file-backed Incident Report helpers for Stage 13.

Reports are derived only from the already-sanitized Nginx, detector and triage
objects. They intentionally contain no raw payload, cookie, query string or
header value.
"""

import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path


REPORT_SCHEMA = "fusion-incident-report-v1"
REPORT_EVENT_SCHEMA = "fusion-incident-report-event-v1"
INCIDENT_ID_RE = re.compile(r"^INC-\d{8}T\d{6}Z-[a-f0-9]{12}$")
REPORT_LOCK = threading.Lock()


# Chuẩn hóa thời điểm event về UTC.
def _utc_timestamp(value):
    """Return a valid UTC timestamp for a log event or the current time."""
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


# Tạo incident_id ổn định từ request evidence.
def incident_id_for(request_id, detected_at):
    """Build one stable incident ID per correlated request."""
    moment = _utc_timestamp(detected_at)
    suffix = hashlib.sha256(request_id.encode("utf-8")).hexdigest()[:12]
    return f"INC-{moment.strftime('%Y%m%dT%H%M%SZ')}-{suffix}"


# Phân nhóm input tấn công theo scenario.
def _input_class(scenario):
    """Describe a lab input class without preserving user-controlled values."""
    values = {
        "xfh": "X-Forwarded-Host header (value intentionally omitted)",
        "query": "response-affecting query parameter (name/value intentionally omitted)",
        "utm": "query parameter parsing/cloaking (raw parameters intentionally omitted)",
        "fatget": "GET request body parameter handling (body intentionally omitted)",
    }
    return values.get(str(scenario).removesuffix("-fixed"), "sanitized request anomaly indicators")


# Tạo report redacted từ Nginx, Detector và triage evidence.
def build_incident_report(incident_id, nginx_event, detector_event, triage_result):
    """Create the fixed G13 report template from sanitized, correlated inputs."""
    observed = triage_result["observed"]
    cache = triage_result["cache_assessment"]
    technique = triage_result.get("possible_technique")
    llm = triage_result.get("llm", {})
    scenario = observed.get("scenario")
    return {
        "schema": REPORT_SCHEMA,
        "report_version": 1,
        "incident_id": incident_id,
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
        "detection_time": detector_event.get("timestamp") or nginx_event.get("timestamp"),
        "scope": "local-educational-fusion-lab",
        "request": {
            "request_id": triage_result["request_id"],
            "client_ip": nginx_event.get("client_ip", "unavailable"),
            "method": nginx_event.get("method", "unavailable"),
            "uri_path": observed.get("uri_path"),
            "scenario": scenario,
        },
        "suspicious_input": {
            "input_class": _input_class(scenario),
            "indicator_codes": triage_result.get("suspicious_indicators", []),
            "raw_values_available": False,
            "note": "Raw headers, parameters, bodies, cookies and payloads are intentionally excluded.",
        },
        "detection": {
            "role": "baseline-if-profile",
            "prediction": observed.get("classification"),
            "anomaly_score": observed.get("anomaly_score"),
            "detector_mode": cache.get("detector_mode"),
            "authoritative_for_cache": True,
        },
        "candidate_assessment": {
            **triage_result.get("candidate_assessment", {}),
            "role": "route-aware-ml-shadow",
            "authoritative_for_cache": False,
        },
        "cache": {
            "status": cache.get("cache_status"),
            "observed_effect": cache.get("observed_effect"),
        },
        "suspected_technique": technique,
        "evidence": triage_result.get("evidence", []),
        "triage": {
            "verdict": triage_result.get("verdict"),
            "severity": triage_result.get("severity"),
            "incident_summary": triage_result.get("incident_summary"),
            "lab_impact": triage_result.get("lab_impact"),
        },
        "system_action": {
            "detector_action": cache.get("detector_action"),
            "recommended_cache_action": cache.get("recommended_cache_action"),
            "cache_bypass": cache.get("cache_bypass"),
        },
        "mitigation_suggestions": triage_result.get("mitigation_suggestions", []),
        "llm_narration": {
            "provider": llm.get("provider", "rules"),
            "status": llm.get("status", "disabled"),
            "model": llm.get("model"),
            "generative_model_used": bool(llm.get("generative_model_used", False)),
            "assessment": llm.get("assessment"),
        },
        "limitations": triage_result.get("limitations", []),
    }


# Giải đường dẫn report theo incident_id an toàn.
def report_path(report_dir, incident_id):
    if not INCIDENT_ID_RE.fullmatch(incident_id):
        raise ValueError("invalid-incident-id")
    return Path(report_dir) / f"{incident_id}.json"


# Đọc incident report đã lưu.
def load_report(report_dir, incident_id):
    path = report_path(report_dir, incident_id)
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as stream:
        report = json.load(stream)
    if not isinstance(report, dict) or report.get("schema") != REPORT_SCHEMA:
        raise ValueError("invalid-stored-report")
    return report


# Lưu report idempotent để không nhân bản cùng incident.
def store_report(report_dir, report):
    """Atomically persist a report, returning false if its stable ID exists."""
    incident_id = report["incident_id"]
    path = report_path(report_dir, incident_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_LOCK:
        if path.exists():
            return False
        temporary = path.with_suffix(".json.tmp")
        try:
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink(missing_ok=True)
    return True


# Ghi event tạo report vào log điều tra.
def write_report_event(event_log, report):
    """Append only compact report metadata for Loki, never the report body."""
    technique = report.get("suspected_technique") or {}
    event = {
        "schema": REPORT_EVENT_SCHEMA,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "incident-report-created",
        "incident_id": report["incident_id"],
        "request_id": report["request"]["request_id"],
        "scenario": report["request"]["scenario"],
        "verdict": report["triage"]["verdict"],
        "severity": report["triage"]["severity"],
        "classification": report["detection"]["prediction"],
        "anomaly_score": report["detection"]["anomaly_score"],
        "cache_status": report["cache"]["status"],
        "recommended_cache_action": report["system_action"]["recommended_cache_action"],
        "possible_technique_id": technique.get("id"),
        "llm_provider": report["llm_narration"]["provider"],
        "llm_status": report["llm_narration"]["status"],
        "llm_model": report["llm_narration"]["model"],
    }
    path = Path(event_log)
    with REPORT_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
