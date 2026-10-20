"""Local SOC case lifecycle, campaign correlation and audit helpers.

Case records extend the existing redacted incident reports. Only allowlisted
fields from the three telemetry sources are copied into the evidence timeline.
"""

import hashlib
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from triage.incidents import INCIDENT_ID_RE, REPORT_LOCK, load_report, report_path


CASE_STATUSES = {"open", "investigating", "contained", "resolved", "false_positive"}
ACTIVE_STATUSES = {"open", "investigating", "contained"}
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CAMPAIGN_WINDOW_SECONDS = 15 * 60
CASE_AUDIT_SCHEMA = "fusion-case-audit-v1"
PIPELINE_EVENT_SCHEMA = "fusion-case-pipeline-event-v1"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def parse_time(value):
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _route_bucket(uri_path, scenario):
    """Return a stable route class without carrying attacker-controlled path text."""
    base = str(scenario or "unknown").removesuffix("-fixed")
    if base not in {"xfh", "query", "utm", "fatget"}:
        return "/other"
    parts = [part for part in urlsplit(str(uri_path or "/")).path.split("/") if part]
    if len(parts) >= 3 and parts[:2] == ["labs", base]:
        if "fixed" in parts[2:]:
            return f"/labs/{base}/fixed"
        if parts[-1] == "geolocate.js":
            return f"/labs/{base}/js/geolocate.js"
        return f"/labs/{base}/shop" if "shop" in parts[2:] else f"/labs/{base}/"
    return f"/labs/{base}/"


def case_fingerprint(report):
    request = report.get("request", {})
    technique = report.get("suspected_technique") or {}
    scenario = str(request.get("scenario") or "unknown")[:32]
    route = _route_bucket(request.get("uri_path"), scenario)
    stable = "|".join((scenario, route, str(technique.get("id") or "unknown")[:64]))
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:24], route


def _safe_num(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _timeline(report, nginx_event, detector_event, shadow_event, triage_result):
    request_id = report["request"]["request_id"]
    scenario = report["request"].get("scenario")
    route = _route_bucket(report["request"].get("uri_path"), scenario)
    cache = triage_result.get("cache_assessment", {})
    candidate = triage_result.get("candidate_assessment", {})
    baseline = triage_result.get("baseline_detection", {})
    now = utc_now()
    return [
        {
            "source": "nginx",
            "timestamp": nginx_event.get("timestamp") or report.get("detection_time") or now,
            "request_id": request_id,
            "route": route,
            "method": str(nginx_event.get("method") or "unknown")[:12],
            "status": str(nginx_event.get("status") or "unknown")[:12],
            "cache_status": str(cache.get("cache_status") or "unknown")[:16],
        },
        {
            "source": "baseline_detector",
            "timestamp": detector_event.get("timestamp") or report.get("detection_time") or now,
            "request_id": request_id,
            "route": route,
            "classification": str(baseline.get("classification") or "unknown")[:24],
            "anomaly_score": _safe_num(baseline.get("anomaly_score")),
            "action": str(cache.get("detector_action") or "unknown")[:32],
            "recommended_cache_action": str(cache.get("recommended_cache_action") or "unknown")[:32],
            "indicator_codes": list(report.get("suspicious_input", {}).get("indicator_codes", []))[:16],
        },
        {
            "source": "ml_shadow",
            "timestamp": shadow_event.get("timestamp") or report.get("detection_time") or now,
            "request_id": request_id,
            "route": route,
            "status": str(candidate.get("status") or "unknown")[:24],
            "model_version": str(candidate.get("model_version") or "unknown")[:80],
            "final_anomaly": bool(candidate.get("final_anomaly", False)),
            "component_scores": {
                key: _safe_num(value) for key, value in (candidate.get("component_scores") or {}).items()
                if key in {"structural", "relationship"} and _safe_num(value) is not None
            },
        },
        {
            "source": "triage",
            "timestamp": triage_result.get("timestamp") or now,
            "request_id": request_id,
            "route": route,
            "verdict": str(triage_result.get("verdict") or "unknown")[:32],
            "severity": str(triage_result.get("severity") or "unknown")[:16],
            "summary": str(triage_result.get("incident_summary") or "")[:500],
        },
    ]


def _write_json(report_dir, report):
    path = report_path(report_dir, report["incident_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def append_jsonl(event_log, event):
    path = Path(event_log)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")


def write_audit_event(event_log, *, case_id, actor, event_type, details):
    event = {
        "schema": CASE_AUDIT_SCHEMA,
        "timestamp": utc_now(),
        "case_id": case_id,
        "actor": str(actor or "local-analyst")[:80],
        "event_type": event_type,
        "details": details,
    }
    with REPORT_LOCK:
        append_jsonl(event_log, event)
    return event


def write_pipeline_event(event_log, *, event_type, request_id, **details):
    event = {
        "schema": PIPELINE_EVENT_SCHEMA,
        "timestamp": utc_now(),
        "event_type": event_type,
        "request_id": request_id,
        **details,
    }
    with REPORT_LOCK:
        append_jsonl(event_log, event)
    return event


def _case_files(report_dir):
    return sorted(Path(report_dir).glob("INC-*.json"), key=lambda item: item.name)


def _read_cases(report_dir):
    result = []
    for path in _case_files(report_dir):
        try:
            report = load_report(report_dir, path.stem)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if report and isinstance(report.get("case"), dict):
            result.append(report)
    return result


def _severity_max(left, right):
    return max((left, right), key=lambda item: SEVERITY_RANK.get(item, -1))


def create_or_link_case(report, nginx_event, detector_event, shadow_event, triage_result,
                        report_dir, audit_log, campaign_window_seconds=CAMPAIGN_WINDOW_SECONDS):
    """Create a case or attach a new related request to an active campaign."""
    fingerprint, route = case_fingerprint(report)
    request_id = report["request"]["request_id"]
    detected_at = parse_time(report.get("detection_time"))
    timeline = _timeline(report, nginx_event, detector_event, shadow_event, triage_result)
    with REPORT_LOCK:
        cases = _read_cases(report_dir)
        for existing in cases:
            case = existing["case"]
            if request_id in {entry.get("request_id") for entry in case.get("related_requests", [])}:
                return existing, False, "already-linked"

        group = None
        for existing in cases:
            case = existing["case"]
            if case.get("fingerprint") != fingerprint or case.get("status") not in ACTIVE_STATUSES:
                continue
            last_seen = parse_time(case.get("last_seen"))
            if timedelta(0) <= detected_at - last_seen <= timedelta(seconds=campaign_window_seconds):
                group = existing
        if group is not None:
            case = group["case"]
            related = case.setdefault("related_requests", [])
            related.append({
                "request_id": request_id,
                "detection_time": report.get("detection_time"),
                "severity": report.get("triage", {}).get("severity", "unknown"),
                "verdict": report.get("triage", {}).get("verdict", "unknown"),
            })
            seen_timeline = {(item.get("request_id"), item.get("source")) for item in group.get("timeline", [])}
            group.setdefault("timeline", []).extend(
                item for item in timeline if (item.get("request_id"), item.get("source")) not in seen_timeline
            )
            case["request_count"] = len(related)
            case["last_seen"] = max(case.get("last_seen", ""), report.get("detection_time") or utc_now())
            case["updated_at"] = utc_now()
            case["severity"] = _severity_max(case.get("severity", "low"), report.get("triage", {}).get("severity", "low"))
            _write_json(report_dir, group)
            write_audit_event(audit_log, case_id=case["case_id"], actor="auto-correlator",
                              event_type="request-linked", details={"request_id": request_id, "fingerprint": fingerprint})
            return group, False, "linked-to-campaign"

        report["case"] = {
            "case_id": report["incident_id"],
            "status": "open",
            "severity": report.get("triage", {}).get("severity", "low"),
            "analyst_label": None,
            "assignee": None,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "first_seen": report.get("detection_time") or utc_now(),
            "last_seen": report.get("detection_time") or utc_now(),
            "fingerprint": fingerprint,
            "route": route,
            "campaign_window_seconds": campaign_window_seconds,
            "request_count": 1,
            "related_requests": [{
                "request_id": request_id,
                "detection_time": report.get("detection_time"),
                "severity": report.get("triage", {}).get("severity", "unknown"),
                "verdict": report.get("triage", {}).get("verdict", "unknown"),
            }],
            "notes": [],
            "mitigation_decisions": [],
        }
        report["timeline"] = timeline
        _write_json(report_dir, report)
        write_audit_event(audit_log, case_id=report["incident_id"], actor="auto-correlator",
                          event_type="case-created", details={"request_id": request_id, "fingerprint": fingerprint})
        return report, True, "created"


def save_case(report_dir, report):
    with REPORT_LOCK:
        _write_json(report_dir, report)


def load_case(report_dir, case_id):
    if not INCIDENT_ID_RE.fullmatch(case_id):
        return None
    report = load_report(report_dir, case_id)
    return report if report and isinstance(report.get("case"), dict) else None


def list_cases(report_dir, *, severity=None, status=None, route=None, query=None,
               since=None, until=None, limit=100):
    cases = _read_cases(report_dir)
    since_time = parse_time(since) if since else None
    until_time = parse_time(until) if until else None
    query_value = str(query or "").casefold()
    result = []
    for report in cases:
        case = report["case"]
        item_severity = case.get("severity") or report.get("triage", {}).get("severity")
        item_route = case.get("route") or "/other"
        detected = parse_time(case.get("last_seen") or report.get("detection_time"))
        technique = report.get("suspected_technique") or {}
        searchable = " ".join((
            case.get("case_id", ""), report.get("incident_id", ""),
            report.get("request", {}).get("request_id", ""), item_route,
            str(technique.get("name", "")),
            " ".join(entry.get("request_id", "") for entry in case.get("related_requests", [])),
        )).casefold()
        if severity and item_severity != severity:
            continue
        if status and case.get("status") != status:
            continue
        if route and route.casefold() not in item_route.casefold():
            continue
        if since_time and detected < since_time:
            continue
        if until_time and detected > until_time:
            continue
        if query_value and query_value not in searchable:
            continue
        result.append(report)
    result.sort(key=lambda report: report.get("case", {}).get("updated_at", ""), reverse=True)
    return result[:limit]


def compact_case(report):
    case = report["case"]
    return {
        "case_id": case.get("case_id", report["incident_id"]),
        "status": case.get("status", "open"),
        "analyst_label": case.get("analyst_label"),
        "assignee": case.get("assignee"),
        "created_at": case.get("created_at"),
        "updated_at": case.get("updated_at"),
        "first_seen": case.get("first_seen"),
        "last_seen": case.get("last_seen"),
        "severity": case.get("severity", report.get("triage", {}).get("severity")),
        "route": case.get("route", "/other"),
        "request_count": case.get("request_count", 1),
        "verdict": report.get("triage", {}).get("verdict"),
        "incident_summary": report.get("triage", {}).get("incident_summary"),
        "fingerprint": case.get("fingerprint"),
    }


def read_jsonl(path):
    path = Path(path)
    if not path.is_file():
        return []
    events = []
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict):
                    events.append(event)
    except OSError:
        return []
    return events


def calculate_metrics(report_dir, pipeline_log, audit_log):
    pipeline = read_jsonl(pipeline_log)
    audit = read_jsonl(audit_log)
    cases = _read_cases(report_dir)
    alerts = {event.get("request_id") for event in pipeline if event.get("event_type") == "alert-observed" and event.get("request_id")}
    complete = {event.get("request_id") for event in pipeline if event.get("event_type") == "evidence-complete" and event.get("request_id")}
    linked = {event.get("request_id") for event in pipeline if event.get("event_type") in {"case-created", "case-linked"} and event.get("request_id")}
    duplicate = {event.get("request_id") for event in pipeline if event.get("event_type") == "case-linked" and event.get("request_id")}
    closed = [report for report in cases if report.get("case", {}).get("status") in {"resolved", "false_positive"}]
    labeled = [report for report in cases if report.get("case", {}).get("analyst_label") in {"true_positive", "false_positive"}]
    false_positive = sum(report["case"].get("analyst_label") == "false_positive" for report in labeled)
    audit_by_case = {}
    for event in audit:
        audit_by_case.setdefault(event.get("case_id"), []).append(event)
    mtta = []
    mttr = []
    for report in cases:
        case = report["case"]
        created = parse_time(case.get("created_at"))
        history = sorted(audit_by_case.get(case.get("case_id"), []), key=lambda event: event.get("timestamp", ""))
        first_ack = next((event for event in history if event.get("event_type") == "status-changed" and event.get("details", {}).get("to") in {"investigating", "contained"}), None)
        if first_ack:
            mtta.append(max(0.0, (parse_time(first_ack.get("timestamp")) - created).total_seconds()))
        resolved = next((event for event in history if event.get("event_type") == "status-changed" and event.get("details", {}).get("to") == "resolved"), None)
        if resolved:
            mttr.append(max(0.0, (parse_time(resolved.get("timestamp")) - created).total_seconds()))
    return {
        "scope": "local-lab case pipeline; analyst labels required for false-positive rate",
        "sample_sizes": {
            "alerts_observed": len(alerts),
            "complete_evidence_alerts": len(complete),
            "alerts_linked_to_case": len(linked),
            "campaign_duplicates_collapsed": len(duplicate),
            "cases": len(cases),
            "closed_cases": len(closed),
            "analyst_labeled_cases": len(labeled),
            "analyst_acknowledged_cases": len(mtta),
            "resolved_cases": len(mttr),
        },
        "metrics": {
            "alert_to_case_rate": len(linked) / len(alerts) if alerts else None,
            "complete_evidence_case_rate": len(linked) / len(complete) if complete else None,
            "duplicate_rate": len(duplicate) / len(complete) if complete else None,
            "false_positive_rate": false_positive / len(labeled) if labeled else None,
            "evidence_completeness": len(complete) / len(alerts) if alerts else None,
            "mtta_seconds_mean": sum(mtta) / len(mtta) if mtta else None,
            "mttr_seconds_mean": sum(mttr) / len(mttr) if mttr else None,
        },
    }
