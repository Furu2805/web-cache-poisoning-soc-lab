"""Stage 12 post-event triage service.

This component is deliberately outside the Nginx request/cache path. It reads
only the sanitized Stage 9 records already stored in Loki, correlates them by
request ID, and produces a bounded lab triage result. The detector's ML output
and technique mapping are deterministic. An optional LLM can narrate only the
sanitized result and has no authority over cache controls or the verdict.
"""

import json
import logging
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from triage.incidents import (
    INCIDENT_ID_RE,
    build_incident_report,
    incident_id_for,
    load_report,
    store_report,
    write_report_event,
)
from triage.llm import LLMUnavailable, enrich, provider_config


LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100").rstrip("/")
EVENT_LOG = Path(os.getenv("TRIAGE_EVENT_LOG", "data/events/triage-events.jsonl"))
REPORT_DIR = Path(os.getenv("INCIDENT_REPORT_DIR", "data/reports"))
INCIDENT_EVENT_LOG = Path(os.getenv("INCIDENT_EVENT_LOG", "data/events/incident-report-events.jsonl"))
LOOKBACK_SECONDS = max(60, min(int(os.getenv("TRIAGE_LOOKBACK_SECONDS", "604800")), 604800))
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
INDICATOR_RE = re.compile(r"^[a-z0-9_:-]{1,64}$")
EVENT_LOCK = threading.Lock()
LOGGER = logging.getLogger(__name__)


TECHNIQUES = {
    "xfh": {
        "id": "unkeyed-x-forwarded-host",
        "name": "Web cache poisoning via unkeyed X-Forwarded-Host header",
        "impact": "An unkeyed forwarding header can influence a cacheable response and may affect later visitors sharing that cache key.",
        "mitigations": [
            "Strip client-supplied X-Forwarded-Host at the public edge and accept it only from trusted proxies.",
            "Do not construct cacheable absolute resource URLs from an untrusted forwarding header.",
            "If a trusted forwarded host affects a cacheable response, include its normalized value in the cache key.",
        ],
    },
    "query": {
        "id": "unkeyed-query-parameter",
        "name": "Web cache poisoning via an unkeyed query parameter",
        "impact": "A parameter excluded from the cache key can alter a cacheable response that is later served to another visitor.",
        "mitigations": [
            "Include every response-affecting query parameter in a canonical cache key.",
            "Alternatively remove the parameter's influence on cacheable output.",
            "Apply context-appropriate output encoding and reject unexpected parameters.",
        ],
    },
    "utm": {
        "id": "parameter-cloaking",
        "name": "Web cache poisoning via parameter cloaking",
        "impact": "Different parameter parsing between cache and backend can hide a response-affecting parameter from the cache key.",
        "mitigations": [
            "Canonicalize query parsing consistently at the proxy and backend before deriving a cache key.",
            "Do not exclude attribution parameters when they can contain semicolon-appended parameters.",
            "Allowlist callback names and include normalized callback input in the cache key.",
        ],
    },
    "fatget": {
        "id": "fat-get-request",
        "name": "Web cache poisoning via a fat GET request",
        "impact": "A GET body can alter backend output while the cache key ignores that body, allowing a shared cache entry to be poisoned.",
        "mitigations": [
            "Reject GET requests that contain a body for cacheable routes.",
            "Do not cache a response whose representation depends on a GET body.",
            "Keep proxy and backend request parsing rules consistent.",
        ],
    },
}


# Tạo truy vấn Loki lọc event theo job và request_id.
def _query_for(job, request_id):
    return f'{{job="{job}"}} | json | request_id="{request_id}"'


# Chuyển kết quả Loki thành các JSON event.
def _parse_loki_events(payload):
    """Extract JSON event lines from a Loki query-range response."""
    events = []
    for stream in payload.get("data", {}).get("result", []):
        for value in stream.get("values", []):
            if not isinstance(value, list) or len(value) < 2:
                continue
            try:
                event = json.loads(value[1])
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(event, dict):
                events.append(event)
    return sorted(events, key=lambda event: str(event.get("timestamp", "")))


# Lấy evidence của một nguồn log từ Loki.
def get_loki_events(job, request_id):
    """Fetch bounded, request-ID-filtered events from the local Loki service."""
    now = datetime.now(timezone.utc)
    params = {
        "query": _query_for(job, request_id),
        "limit": "20",
        "start": str(int((now - timedelta(seconds=LOOKBACK_SECONDS)).timestamp() * 1_000_000_000)),
        "end": str(int(now.timestamp() * 1_000_000_000)),
        "direction": "backward",
    }
    with httpx.Client(timeout=5.0) as client:
        response = client.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params)
        response.raise_for_status()
    return _parse_loki_events(response.json())


# Gộp indicator từ Baseline và Shadow.
def _indicator_codes(detector_event, shadow_event):
    indicators = detector_event.get("indicators", {})
    if not isinstance(indicators, dict):
        return []
    raw_values = indicators.get("normal_profile_deviations", [])
    values = list(raw_values) if isinstance(raw_values, list) else []
    reasons = shadow_event.get("profile_reasons", [])
    if isinstance(reasons, list):
        values.extend(reasons)
    return sorted({value for value in values if isinstance(value, str) and INDICATOR_RE.fullmatch(value)})


# Chiếu assessment Shadow thành evidence dùng cho triage.
def _model_evidence(shadow_event):
    """Project only bounded metadata from the dedicated ML shadow event."""
    scores = shadow_event.get("component_scores")
    thresholds = shadow_event.get("thresholds")
    safe_scores = {
        key: float(value) for key, value in (scores or {}).items()
        if key in {"structural", "relationship"} and isinstance(value, (int, float))
    }
    safe_thresholds = {
        key: float(value) for key, value in (thresholds or {}).items()
        if key in {"structural", "relationship"} and isinstance(value, (int, float))
    }
    return {
        "status": shadow_event.get("status"),
        "route": shadow_event.get("route"),
        "model_version": shadow_event.get("model_version") or shadow_event.get("candidate_id"),
        "component_scores": safe_scores,
        "thresholds": safe_thresholds,
        "if_anomaly": shadow_event.get("if_anomaly"),
        "profile_anomaly": shadow_event.get("profile_anomaly"),
        "final_anomaly": shadow_event.get("final_anomaly"),
        "profile_reasons": sorted({
            value for value in shadow_event.get("profile_reasons", [])
            if isinstance(value, str) and INDICATOR_RE.fullmatch(value)
        }),
        "fallback_reason": shadow_event.get("fallback_reason"),
        "monitor_closely": bool(shadow_event.get("monitor_closely", False)),
        "shadow_latency_ms": shadow_event.get("shadow_latency_ms"),
    }


# Tra mô tả technique theo scenario Fusion.
def _scenario_details(scenario):
    fixed = scenario.endswith("-fixed")
    base = scenario[:-6] if fixed else scenario
    return base, fixed, TECHNIQUES.get(base)


# Đánh giá cache evidence từ Nginx và Detector.
def _cache_assessment(nginx_event, detector_event):
    cache_status = nginx_event.get("cache_status", "unknown")
    recommended = detector_event.get("recommended_cache_action", "unknown")
    action = detector_event.get("action", "unknown")
    bypass = bool(detector_event.get("cache_bypass", False)) or cache_status == "BYPASS"
    if bypass:
        observed_effect = "Cache bypass/no-cache was observed or selected for this request."
    elif cache_status == "HIT":
        observed_effect = "A cached response was served; investigate whether its representation was affected before caching."
    elif cache_status in {"MISS", "EXPIRED"}:
        observed_effect = "The response was not served from an existing cache entry; the detector recommendation must still be reviewed."
    else:
        observed_effect = "Cache state is unavailable or not cacheable for this request."
    return {
        "cache_status": cache_status,
        "detector_mode": detector_event.get("detector_mode", "unknown"),
        "detector_action": action,
        "recommended_cache_action": recommended,
        "cache_bypass": bypass,
        "observed_effect": observed_effect,
    }


# Dùng rule xác định để tạo verdict, severity và mitigation.
def build_triage(request_id, nginx_event, detector_event, shadow_event):
    """Build a constrained summary from three correlated sanitized events."""
    if any(event.get("request_id") != request_id for event in (nginx_event, detector_event, shadow_event)):
        raise ValueError("correlation-mismatch")

    scenario = str(detector_event.get("scenario") or nginx_event.get("scenario") or "not-fusion")
    classification = str(detector_event.get("classification", "unknown"))
    indicators = _indicator_codes(detector_event, shadow_event)
    cache = _cache_assessment(nginx_event, detector_event)
    base_scenario, fixed_route, technique = _scenario_details(scenario)
    score = detector_event.get("anomaly_score")

    if classification == "normal":
        verdict = "not-suspicious"
        severity = "informational"
        possible_technique = None
        lab_impact = "No anomaly was detected for this request. This is a control result, not evidence that the lab is secure."
        mitigations = ["No additional cache action is recommended from this normal event; retain normal cache-key and input-validation controls."]
    elif classification == "unavailable":
        verdict = "needs-review"
        severity = "medium"
        possible_technique = None
        lab_impact = "Detector evidence was unavailable. Treat the cache bypass recommendation as a safety control and investigate service availability."
        mitigations = ["Restore detector availability and keep bypass/no-cache enabled for inspection failures."]
    elif classification != "anomaly":
        verdict = "needs-review"
        severity = "low"
        possible_technique = None
        lab_impact = "The event cannot be classified reliably from the available sanitized evidence."
        mitigations = ["Review the correlated Nginx and detector records before taking a cache action."]
    elif fixed_route:
        verdict = "suspected-but-mitigated"
        severity = "informational"
        possible_technique = {
            "id": f"{base_scenario}-fixed-route",
            "name": f"{TECHNIQUES.get(base_scenario, {}).get('name', base_scenario)} on fixed route",
        }
        lab_impact = "The request targeted a fixed lab route. The anomaly is evidence for review, not proof that the fixed variant was exploitable."
        mitigations = ["Retest the fixed route with a clean cache key and verify the malicious representation is neither cached nor served to another client."]
    elif technique:
        verdict = "suspected"
        severity = "high" if cache["cache_status"] == "HIT" else "medium"
        possible_technique = {"id": technique["id"], "name": technique["name"]}
        lab_impact = technique["impact"]
        mitigations = technique["mitigations"]
    else:
        verdict = "suspected"
        severity = "medium"
        possible_technique = {"id": "unknown-fusion-cache-anomaly", "name": "Unknown Fusion web-cache anomaly"}
        lab_impact = "An anomalous request targeted an unsupported Fusion scenario; do not infer an exploit technique without more evidence."
        mitigations = ["Review cache-key inputs, request normalization, and response-affecting inputs for this route."]

    technique_name = possible_technique["name"] if possible_technique else "no suspected cache-poisoning technique"
    summary = (
        f"Request {request_id} is {verdict} for {technique_name}. "
        f"Detector classification is {classification}; cache status is {cache['cache_status']}; "
        f"detector action is {cache['detector_action']} with recommendation {cache['recommended_cache_action']}. "
        "This is evidence for a local lab investigation, not a production security verdict."
    )
    return {
        "schema": "fusion-triage-result-v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "triage_engine": {
            "name": "evidence-rules-v1",
            "uses_detector_ml_output": True,
            "generative_model_used": False,
            "claim": "Deterministic evidence mapping is authoritative; optional LLM narration cannot change it.",
        },
        "evidence_window_seconds": LOOKBACK_SECONDS,
        "verdict": verdict,
        "severity": severity,
        "possible_technique": possible_technique,
        "lab_impact": lab_impact,
        "observed": {
            "scenario": scenario,
            "uri_path": detector_event.get("uri_path") or nginx_event.get("uri_path"),
            "classification": classification,
            "anomaly_score": score,
        },
        "baseline_detection": {
            "classification": classification,
            "anomaly_score": score,
            "detector_mode": detector_event.get("detector_mode", "unknown"),
            "authoritative_for_cache": True,
        },
        "candidate_assessment": {
            **_model_evidence(shadow_event),
            "mode": "shadow",
            "authoritative_for_cache": False,
        },
        "model_evidence": _model_evidence(shadow_event),
        "cache_assessment": cache,
        "suspicious_indicators": indicators,
        "evidence": [
            {"source": "fusion-nginx-access-v1", "request_id": request_id, "cache_status": cache["cache_status"]},
            {
                "source": detector_event.get("schema", "fusion-detector-event-v2"),
                "request_id": request_id,
                "classification": classification,
                "anomaly_score": score,
                "indicator_codes": indicators,
            },
            {
                "source": shadow_event.get("schema", "fusion-ml-shadow-event-v1"),
                "request_id": request_id,
                "route": shadow_event.get("route"),
                "candidate_id": shadow_event.get("candidate_id"),
                "final_anomaly": shadow_event.get("final_anomaly"),
            },
        ],
        "incident_summary": summary,
        "mitigation_suggestions": mitigations,
        "limitations": [
            "The triage reads sanitized local-lab logs only; it does not inspect raw payloads, cookies, query values, or header values.",
            "A suspected technique is not proof of successful cache poisoning or production impact.",
        ],
    }


# Ghi event triage đã sanitize để điều tra.
def write_triage_event(result):
    """Write an auditable, sanitized post-event record for later G13 reporting."""
    event = {
        "schema": "fusion-triage-event-v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "triage-completed",
        "request_id": result["request_id"],
        "triage_engine": result["triage_engine"]["name"],
        "verdict": result["verdict"],
        "severity": result["severity"],
        "scenario": result["observed"]["scenario"],
        "uri_path": result["observed"]["uri_path"],
        "classification": result["observed"]["classification"],
        "anomaly_score": result["observed"]["anomaly_score"],
        "candidate_model_version": result["candidate_assessment"].get("model_version"),
        "candidate_final_anomaly": result["candidate_assessment"].get("final_anomaly"),
        "candidate_monitor_closely": result["candidate_assessment"].get("monitor_closely", False),
        "cache_status": result["cache_assessment"]["cache_status"],
        "recommended_cache_action": result["cache_assessment"]["recommended_cache_action"],
        "indicator_codes": result["suspicious_indicators"],
        "possible_technique": result["possible_technique"],
        "llm_provider": result.get("llm", {}).get("provider", "rules"),
        "llm_status": result.get("llm", {}).get("status", "disabled"),
        "llm_model": result.get("llm", {}).get("model"),
        "llm_response_id": result.get("llm", {}).get("response_id"),
    }
    try:
        with EVENT_LOCK:
            EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
            with EVENT_LOG.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    except OSError as exc:
        LOGGER.warning("triage event log unavailable: %s", type(exc).__name__)


app = FastAPI(title="Fusion evidence triage service")


@app.get("/health")
# Kiểm tra khả năng hoạt động của triage và phụ thuộc.
def health():
    llm = provider_config()
    return {
        "ok": True,
        "mode": "post-event-evidence-only",
        "llm_provider": llm["provider"],
        "llm_ready": bool(llm["provider"] in {"openai-responses", "zai-chat-completions"} and llm["model"] and llm["api_key_configured"]),
        "llm_required": llm["required"],
        "llm_timeout_seconds": llm["timeout_seconds"],
        "zai_max_tokens": llm["zai_max_tokens"] if llm["provider"] == "zai-chat-completions" else None,
        "zai_reasoning_effort": llm["zai_reasoning_effort"] if llm["provider"] == "zai-chat-completions" else None,
        "loki_url_configured": bool(LOKI_URL),
    }


# Ghép ba nguồn evidence theo cùng request_id.
def correlated_event_bundle(request_id):
    """Fetch Nginx, baseline detector and completed ML evidence in one lookback."""
    try:
        nginx_events = get_loki_events("fusion-nginx", request_id)
        detector_events = get_loki_events("fusion-detector", request_id)
        shadow_events = get_loki_events("fusion-ml-shadow", request_id)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail={"error": "loki-unavailable", "reason": type(exc).__name__}) from exc

    completed_shadow = [event for event in shadow_events if event.get("event_type") == "shadow_completed"]
    if not nginx_events and not detector_events and not shadow_events:
        raise HTTPException(status_code=404, detail={"error": "triage-evidence-not-found", "request_id": request_id,
                                                     "decision": "không đủ dữ liệu"})
    if not nginx_events or not detector_events or not completed_shadow:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "triage-evidence-incomplete",
                "request_id": request_id,
                "nginx_events": len(nginx_events),
                "detector_events": len(detector_events),
                "ml_shadow_events": len(shadow_events),
                "ml_shadow_completed_events": len(completed_shadow),
                "lookback_seconds": LOOKBACK_SECONDS,
                "decision": "không đủ dữ liệu",
            },
        )
    return nginx_events[-1], detector_events[-1], completed_shadow[-1]


# Bổ sung phần diễn giải LLM mà không đổi verdict rule.
def enriched_triage(request_id, nginx_event, detector_event, shadow_event):
    """Make one deterministic triage result and add optional post-event narration."""
    try:
        result = build_triage(request_id, nginx_event, detector_event, shadow_event)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail={"error": str(exc), "request_id": request_id}) from exc
    try:
        # This enrichment is post-event narration only. The LLM has no write
        # path to cache controls and cannot alter deterministic evidence fields.
        result["llm"] = enrich(result)
    except LLMUnavailable as exc:
        raise HTTPException(status_code=503, detail={"error": "llm-unavailable", "reason": str(exc)}) from exc
    return result


@app.post("/triage/{request_id}")
# Endpoint trả triage cho request_id.
def triage_request(request_id: str):
    """Correlate a completed Fusion request from Loki and produce triage output."""
    if not REQUEST_ID_RE.fullmatch(request_id):
        raise HTTPException(status_code=422, detail={"error": "invalid-request-id"})
    nginx_event, detector_event, shadow_event = correlated_event_bundle(request_id)
    result = enriched_triage(request_id, nginx_event, detector_event, shadow_event)
    write_triage_event(result)
    return result


@app.post("/incidents/{request_id}", status_code=201)
# Tạo report từ evidence/triage của request_id.
def create_incident_report(request_id: str):
    """Create one stable, sanitized G13 Incident Report for a correlated event."""
    if not REQUEST_ID_RE.fullmatch(request_id):
        raise HTTPException(status_code=422, detail={"error": "invalid-request-id"})
    nginx_event, detector_event, shadow_event = correlated_event_bundle(request_id)
    incident_id = incident_id_for(request_id, detector_event.get("timestamp") or nginx_event.get("timestamp"))
    try:
        existing = load_report(REPORT_DIR, incident_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail={"error": "incident-storage-unavailable", "reason": type(exc).__name__}) from exc
    if existing is not None:
        return JSONResponse(status_code=200, content={"created": False, "report": existing})

    result = enriched_triage(request_id, nginx_event, detector_event, shadow_event)
    report = build_incident_report(incident_id, nginx_event, detector_event, result)
    try:
        created = store_report(REPORT_DIR, report)
        if not created:
            existing = load_report(REPORT_DIR, incident_id)
            return JSONResponse(status_code=200, content={"created": False, "report": existing})
        write_report_event(INCIDENT_EVENT_LOG, report)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail={"error": "incident-storage-unavailable", "reason": type(exc).__name__}) from exc
    return {"created": True, "report": report}


@app.get("/incidents/{incident_id}")
# Đọc report đã lưu theo incident_id.
def get_incident_report(incident_id: str):
    """Read one local G13 report by its stable Incident ID."""
    if not INCIDENT_ID_RE.fullmatch(incident_id):
        raise HTTPException(status_code=422, detail={"error": "invalid-incident-id"})
    try:
        report = load_report(REPORT_DIR, incident_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail={"error": "incident-storage-unavailable", "reason": type(exc).__name__}) from exc
    if report is None:
        raise HTTPException(status_code=404, detail={"error": "incident-report-not-found", "incident_id": incident_id})
    return report


@app.get("/incidents")
# Liệt kê report đã lưu với giới hạn số bản ghi.
def list_incident_reports(limit: int = 20):
    """List compact metadata only; obtain the full report with its Incident ID."""
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail={"error": "invalid-limit"})
    try:
        paths = sorted(REPORT_DIR.glob("INC-*.json"), key=lambda path: path.name, reverse=True)[:limit]
        reports = [load_report(REPORT_DIR, path.stem) for path in paths]
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail={"error": "incident-storage-unavailable", "reason": type(exc).__name__}) from exc
    return [
        {
            "incident_id": report["incident_id"],
            "detection_time": report["detection_time"],
            "request_id": report["request"]["request_id"],
            "scenario": report["request"]["scenario"],
            "verdict": report["triage"]["verdict"],
            "severity": report["triage"]["severity"],
        }
        for report in reports
        if report is not None
    ]
