import json
import logging
import os
import sqlite3
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Full, Queue
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlsplit

try:
    import fcntl
except ImportError:  # Windows unit tests; production image is Linux.
    fcntl = None

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from common.features import from_proxy_headers, rule_reasons
from ml.model import inspect_request, load_bundle, score_request

MODEL = Path(os.getenv("MODEL_PATH", "models/isolation_forest.joblib"))
DB = Path(os.getenv("DETECTOR_DB", "data/detector.sqlite3"))
EVENT_LOG = Path(os.getenv("DETECTOR_EVENT_LOG", "data/events/detector-events.jsonl"))
LOCK = threading.Lock()
EVENT_LOCK = threading.Lock()
LOGGER = logging.getLogger(__name__)
ML_SHADOW_URL = os.getenv(
    "ML_SHADOW_URL", "http://ml-shadow:8003/internal/v1/shadow/events"
)
ML_SHADOW_DELIVERY_QUEUE_SIZE = int(os.getenv("ML_SHADOW_DELIVERY_QUEUE_SIZE", "128"))
ML_SHADOW_DELIVERY_TIMEOUT_MS = float(os.getenv("ML_SHADOW_DELIVERY_TIMEOUT_MS", "250"))
if ML_SHADOW_DELIVERY_QUEUE_SIZE < 1 or not 10 <= ML_SHADOW_DELIVERY_TIMEOUT_MS <= 2000:
    raise ValueError("invalid ML shadow delivery configuration")


# Chỉ chọn metadata allowlist để gửi bất đồng bộ sang ML Shadow.
def shadow_delivery_payload(request_id, route, metadata):
    """Project only the fields accepted by the internal ML service."""
    headers = {str(name).lower(): str(value) for name, value in metadata["headers"].items()}
    try:
        content_length = max(0, int(headers.get("content-length", "0")))
    except ValueError:
        content_length = 0
    return {
        "request_id": request_id,
        "route": route,
        "metadata": {
            "method": str(metadata["method"]).upper(),
            "uri": str(metadata["uri"]),
            "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", ""),
            "accept": headers.get("accept", ""),
            "accept_language": headers.get("accept-language", ""),
            "x_forwarded_host": headers.get("x-forwarded-host", ""),
            "content_length": min(content_length, 10_000_000),
        },
    }


class ShadowDeliveryClient:
    """Bounded, no-retry sender that keeps ML work off the request path."""

    # Khởi tạo queue hữu hạn và worker nền để chuyển event sang Shadow.
    def __init__(self, url=ML_SHADOW_URL, maxsize=ML_SHADOW_DELIVERY_QUEUE_SIZE,
                 timeout_ms=ML_SHADOW_DELIVERY_TIMEOUT_MS):
        self.url = url
        self.timeout_s = timeout_ms / 1000.0
        self.queue = Queue(maxsize=maxsize)
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._run, name="ml-shadow-delivery", daemon=True)
        self.thread.start()

    # Đưa payload vào delivery queue nếu còn chỗ.
    def submit(self, payload):
        try:
            self.queue.put_nowait(payload)
            return True
        except Full:
            return False

    # Dừng worker gửi Shadow khi ứng dụng kết thúc.
    def close(self):
        self.stopping.set()
        self.thread.join(timeout=max(2, self.timeout_s * 2))

    # Lấy event khỏi queue và gửi tới Shadow ngoài critical path.
    def _run(self):
        while not self.stopping.is_set() or not self.queue.empty():
            try:
                payload = self.queue.get(timeout=0.1)
            except Empty:
                continue
            try:
                body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                outbound = urllib_request.Request(
                    self.url, data=body, method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with urllib_request.urlopen(outbound, timeout=self.timeout_s) as response:
                    response.read()
            except (OSError, TimeoutError, urllib_error.URLError, urllib_error.HTTPError) as exc:
                LOGGER.warning(
                    "ml shadow delivery failed request_id=%s reason=%s",
                    payload["request_id"], type(exc).__name__,
                )
            finally:
                self.queue.task_done()


# Ghi một Detection event đã sanitize vào JSONL.
def append_event(event):
    """Append one JSONL record atomically across Uvicorn worker processes."""
    payload = (json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(EVENT_LOG, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o640)
    try:
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise OSError("short JSONL append")
    finally:
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


# Khởi tạo tài nguyên Baseline cần cho Detection API.
def initialize_database():
    """Serialize SQLite WAL initialization across Uvicorn worker processes."""
    DB.parent.mkdir(parents=True, exist_ok=True)
    lock_path = DB.with_name(f"{DB.name}.init.lock")
    lock_descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o640)
    try:
        if fcntl is not None:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        with sqlite3.connect(DB, timeout=30) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS observations(record_id TEXT PRIMARY KEY, request_json TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS decisions(ts REAL, mode TEXT, score REAL, bypass INTEGER, reason TEXT)")
    finally:
        if fcntl is not None:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


# Suy ra tên lab Fusion từ URI request.
def fusion_scenario(uri):
    """Return a bounded lab identifier without retaining raw query data."""
    parts = [part for part in urlsplit(uri).path.split("/") if part]
    if len(parts) < 2 or parts[0] != "labs":
        return "not-fusion"
    scenario = parts[1]
    if scenario not in {"xfh", "query", "utm", "fatget"}:
        return "not-fusion"
    return f"{scenario}-fixed" if len(parts) > 2 and parts[2] == "fixed" else scenario


# Ghi evidence Detection cho Fusion lab với request_id.
def write_fusion_event(*, request_id, metadata, detector_mode, classification,
                       anomaly_score, action, recommended_cache_action,
                       cache_bypass, indicators, detector_ms=None, shadow=None):
    """Append the Stage 9 detector event without raw header/query values.

    The event is intentionally request-only and contains no cookie, payload,
    complete query string, response, label, or cache key. Logging failure is
    non-fatal: telemetry must not turn an otherwise available inspection into
    a service outage.
    """
    path = urlsplit(metadata["uri"]).path or "/"
    event = {
        "schema": "fusion-detector-event-v2",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "inspection",
        "request_id": request_id,
        "detector_mode": detector_mode,
        "scenario": fusion_scenario(metadata["uri"]),
        "uri_path": path,
        "classification": classification,
        "anomaly_score": anomaly_score,
        "action": action,
        "recommended_cache_action": recommended_cache_action,
        "cache_bypass": bool(cache_bypass),
        "detector_latency_ms": detector_ms,
        "indicators": indicators,
        "shadow_mode": shadow["mode"] if shadow else None,
        "shadow_status": shadow.get("status") if shadow else None,
        "model_version": shadow["model_version"] if shadow else None,
        "feature_schema_version": shadow["feature_schema_version"] if shadow else None,
        "component_scores": shadow["component_scores"] if shadow else None,
        "thresholds": shadow["threshold"] if shadow else None,
        "if_anomaly": shadow["if_anomaly"] if shadow else None,
        "profile_anomaly": shadow["profile_anomaly"] if shadow else None,
        "final_anomaly": shadow["final_anomaly"] if shadow else None,
        "shadow_latency_ms": shadow["latency_ms"] if shadow else None,
        "fallback_reason": shadow["fallback_reason"] if shadow else None,
        "monitor_closely": shadow["monitor_closely"] if shadow else False,
    }
    try:
        with EVENT_LOCK:
            append_event(event)
    except OSError as exc:
        LOGGER.warning("fusion detector event log unavailable: %s", type(exc).__name__)
    return event


@asynccontextmanager
# Nạp model và quản lý vòng đời delivery client của API.
async def lifespan(app):
    initialize_database()
    try:
        app.state.bundle = load_bundle(MODEL)
        app.state.model_error = None
    except Exception as exc:
        app.state.bundle = None
        app.state.model_error = type(exc).__name__
    app.state.shadow_delivery = ShadowDeliveryClient()
    yield
    app.state.shadow_delivery.close()


app = FastAPI(title="Cache detection service", lifespan=lifespan)


# Dựng metadata đánh giá từ internal subrequest của Nginx.
def fusion_inspection_input(request: Request):
    """Validate the small, Nginx-compatible metadata contract for Fusion.

    The endpoint deliberately consumes only the selected request metadata used
    at train time.  Request ID is required for correlation, but it is never a
    model feature.  This function does not read the request body, response,
    cache state, label, or any previous detector decision.
    """
    headers = request.headers
    required = {
        "x-request-id": "X-Request-ID",
        "x-meta-method": "X-Meta-Method",
        "x-meta-uri": "X-Meta-URI",
        "x-meta-host": "X-Meta-Host",
    }
    missing = [display for name, display in required.items() if not headers.get(name, "").strip()]
    if missing:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "missing-fusion-metadata",
                "missing": missing,
                "message": "Send Nginx request metadata and X-Request-ID to /inspect.",
            },
        )

    request_id = headers["x-request-id"].strip()
    if len(request_id) > 128:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid-request-id",
                "request_id": request_id,
                "message": "X-Request-ID is too long.",
            },
        )
    uri = headers["x-meta-uri"].strip()
    if not uri.startswith("/"):
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid-fusion-uri",
                "request_id": request_id,
                "message": "X-Meta-URI must start with '/'.",
            },
        )
    return request_id, from_proxy_headers(headers)


# Xác định mode detector do proxy cấu hình cho request.
def fusion_detector_mode(request: Request):
    """Return the server-selected Stage 8 enforcement mode.

    The header is supplied only by Nginx's internal auth subrequest.  It is
    not a public client control: Fusion's operator-owned Nginx config decides
    whether the service is called in observe or enforce mode.  Direct Stage 7
    API calls default to observe for backwards-compatible, side-effect-free
    inspection.
    """
    mode = request.headers.get("x-fusion-detector-mode", "observe").strip().lower()
    if mode not in {"observe", "enforce"}:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid-detector-mode",
                "message": "X-Fusion-Detector-Mode must be observe or enforce.",
            },
        )
    return mode


# Chuyển assessment request sang queue Shadow mà không chờ inference.
def enqueue_external_shadow(request_id, metadata, delivery):
    """Enqueue a bounded, allowlisted handoff without waiting for inference."""
    route = fusion_scenario(metadata["uri"])
    eligible = route in {"query", "xfh", "utm", "fatget"}
    queued = bool(eligible and delivery.submit(shadow_delivery_payload(request_id, route, metadata)))
    return {
        "request_id": request_id,
        "route": route,
        "mode": "shadow",
        "status": "queued" if queued else "not_queued" if eligible else "not_eligible",
        "model_version": None,
        "feature_schema_version": None,
        "component_scores": None,
        "threshold": None,
        "if_anomaly": None,
        "profile_anomaly": None,
        "final_anomaly": None,
        "profile_reasons": [],
        "monitor_closely": route == "fatget",
        "fallback_reason": None if queued else "queue_overflow" if eligible else "route_not_eligible",
        "latency_ms": 0.0,
    }


@app.get("/health")
# Báo trạng thái sẵn sàng của Detection API.
def health():
    return {"ok": True, "model_ready": app.state.bundle is not None,
            "model_error": app.state.model_error,
            "shadow_runtime": "externalized",
            "shadow_models_loaded_here": False,
            "shadow_delivery_queue_capacity": ML_SHADOW_DELIVERY_QUEUE_SIZE}


@app.get("/inspect")
# Chấm request bằng Baseline và ghi evidence; Shadow chỉ nhận bản sao.
def inspect(request: Request):
    """Inspect one Fusion request before later Nginx cache integration.

    This is an observe-only API in Stage 7: no result emitted here changes a
    cache read/write.  Stage 8 will use ``recommended_cache_action`` through
    an explicit ``off|observe|enforce`` integration path.
    """
    start = time.perf_counter()
    request_id, metadata = fusion_inspection_input(request)
    detector_mode = fusion_detector_mode(request)
    if app.state.bundle is None:
        write_fusion_event(
            request_id=request_id,
            metadata=metadata,
            detector_mode=detector_mode,
            classification="unavailable",
            anomaly_score=None,
            action="bypass-no-cache",
            recommended_cache_action="bypass-no-cache",
            cache_bypass=True,
            indicators={"detector_error": app.state.model_error or "model-unavailable"},
        )
        raise HTTPException(
            status_code=503,
            detail={
                "error": "model-unavailable",
                "request_id": request_id,
                "message": "The inspection model is not ready.",
            },
        )

    score, iforest_anomaly, profile_deviations = inspect_request(app.state.bundle, metadata)
    anomaly = bool(iforest_anomaly or profile_deviations)
    recommended_cache_action = "bypass-no-cache" if anomaly else "cache-normal"
    cache_bypass = bool(detector_mode == "enforce" and anomaly)
    action = "bypass-no-cache" if cache_bypass else (
        "observe" if detector_mode == "observe" else "cache-normal"
    )
    shadow = enqueue_external_shadow(request_id, metadata, app.state.shadow_delivery)
    detector_ms = round((time.perf_counter() - start) * 1000, 3)
    payload = {
        "request_id": request_id,
        "classification": "anomaly" if anomaly else "normal",
        # The value is an Isolation Forest anomaly score, not a probability.
        "anomaly_score": score,
        "score_convention": app.state.bundle["score_convention"],
        # In a direct Stage 7 call the mode defaults to observe.  Stage 8's
        # internal Nginx subrequest selects enforce from operator config.
        "detector_mode": detector_mode,
        "action": action,
        "recommended_cache_action": recommended_cache_action,
        "components": {
            "isolation_forest_anomaly": iforest_anomaly,
            "normal_profile_deviations": profile_deviations,
        },
        # Candidate output is telemetry only. It does not feed action,
        # recommended_cache_action, cache_bypass, or the legacy classification.
        "shadow_candidate": shadow,
        "detector_ms": detector_ms,
    }
    write_fusion_event(
        request_id=request_id,
        metadata=metadata,
        detector_mode=detector_mode,
        classification=payload["classification"],
        anomaly_score=score,
        action=action,
        recommended_cache_action=recommended_cache_action,
        cache_bypass=cache_bypass,
        indicators={
            **payload["components"],
            "shadow_candidate": shadow,
        },
        detector_ms=detector_ms,
        shadow=shadow,
    )
    # auth_request discards the JSON body. These headers are the narrow,
    # explicit control contract Nginx consumes in Stage 8.
    return JSONResponse(content=payload, headers={
        "Cache-Control": "no-store",
        "X-Request-ID": request_id,
        "X-Fusion-Classification": payload["classification"],
        "X-Fusion-Detector-Mode": detector_mode,
        "X-Fusion-Action": action,
        "X-Fusion-Recommended-Cache-Action": recommended_cache_action,
        "X-Fusion-Cache-Bypass": str(int(cache_bypass)),
        "X-Anomaly-Score": f"{score:.6f}",
        "X-Detector-Ms": f"{detector_ms:.3f}",
    })


@app.get("/check")
# Cung cấp endpoint kiểm tra theo hợp đồng của proxy.
def check(request: Request):
    start = time.perf_counter()
    mode = request.headers.get("x-lab-mode", "unknown")
    metadata = from_proxy_headers(request.headers)
    reasons = rule_reasons(metadata)
    score = None
    ml_bad = False
    error = None
    if mode in {"ml", "hybrid"}:
        try:
            if app.state.bundle is None:
                raise RuntimeError("model unavailable")
            score, ml_bad = score_request(app.state.bundle, metadata)
        except Exception:
            error = "model-unavailable"
    if mode not in {"observe", "rule", "ml", "hybrid"}:
        error = "invalid-mode"
    bypass = bool(error or (mode in {"rule", "hybrid"} and reasons) or ml_bad)
    reason = error or ("rule:" + ",".join(reasons) if mode in {"rule", "hybrid"} and reasons
                       else "ml" if ml_bad else "normal")
    # Raw synthetic lab traffic only. Production deployment would need redaction.
    with LOCK, sqlite3.connect(DB, timeout=10) as db:
        if mode == "observe":
            record_id = request.headers.get("x-lab-record-id", "")
            if record_id:
                db.execute("INSERT OR REPLACE INTO observations VALUES (?,?)",
                           (record_id, json.dumps(metadata)))
        db.execute("INSERT INTO decisions VALUES (?,?,?,?,?)",
                   (time.time(), mode, score, int(bypass), reason))
    return Response(status_code=204, headers={
        "X-Bypass": str(int(bypass)), "X-Decision": reason,
        "X-Anomaly-Score": "NA" if score is None else f"{score:.6f}",
        "X-Detector-Ms": f"{(time.perf_counter()-start)*1000:.3f}",
    })
