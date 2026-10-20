"""Internal API boundary for route-aware candidate inference."""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import OrderedDict, defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Literal

try:
    import fcntl
except ImportError:  # Windows unit tests; production image is Linux.
    fcntl = None

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ml.route_detector import (
    REGISTRY_PATH,
    extract_route_features,
    load_registry,
    route_for_request,
    score_route_feature_batch,
)

MODEL_REGISTRY = Path(os.getenv("MODEL_REGISTRY_PATH", str(REGISTRY_PATH)))
ROUTES = ("query", "xfh", "utm", "fatget")
LOGGER = logging.getLogger(__name__)
EVENT_LOG = Path(os.getenv("ML_SHADOW_EVENT_LOG", "data/events/ml-shadow-events.jsonl"))
EVENT_LOG_MAX_BYTES = int(os.getenv("ML_SHADOW_EVENT_LOG_MAX_BYTES", str(10 * 1024 * 1024)))
EVENT_LOG_BACKUPS = int(os.getenv("ML_SHADOW_EVENT_LOG_BACKUPS", "5"))
EVENT_LOG_LOCK = threading.Lock()
QUEUE_SIZE = int(os.getenv("ML_SHADOW_QUEUE_SIZE", "512"))
BATCH_SIZE = int(os.getenv("ML_SHADOW_BATCH_SIZE", "16"))
BATCH_WAIT_MS = float(os.getenv("ML_SHADOW_BATCH_WAIT_MS", "5"))
MAX_JOB_AGE_MS = float(os.getenv("ML_SHADOW_MAX_JOB_AGE_MS", "30000"))
RESULT_CACHE_SIZE = int(os.getenv("ML_SHADOW_RESULT_CACHE_SIZE", "2048"))
if min(QUEUE_SIZE, BATCH_SIZE, RESULT_CACHE_SIZE) < 1:
    raise ValueError("ML shadow queue, batch and result sizes must be positive")
if not 0 <= BATCH_WAIT_MS <= 100 or not 100 <= MAX_JOB_AGE_MS <= 300_000:
    raise ValueError("invalid ML shadow batch wait or job age")
if EVENT_LOG_MAX_BYTES < 1024 or not 1 <= EVENT_LOG_BACKUPS <= 20:
    raise ValueError("invalid ML shadow event log rotation configuration")


# Xoay vòng file event khi đạt ngưỡng dung lượng.
def _rotate_event_log(incoming_bytes: int):
    if not EVENT_LOG.exists() or EVENT_LOG.stat().st_size + incoming_bytes <= EVENT_LOG_MAX_BYTES:
        return
    oldest = EVENT_LOG.with_name(f"{EVENT_LOG.name}.{EVENT_LOG_BACKUPS}")
    if oldest.exists():
        oldest.unlink()
    for index in range(EVENT_LOG_BACKUPS - 1, 0, -1):
        source = EVENT_LOG.with_name(f"{EVENT_LOG.name}.{index}")
        if source.exists():
            os.replace(source, EVENT_LOG.with_name(f"{EVENT_LOG.name}.{index + 1}"))
    os.replace(EVENT_LOG, EVENT_LOG.with_name(f"{EVENT_LOG.name}.1"))


# Ghi lifecycle/assessment Shadow vào JSONL đã sanitize.
def write_ml_shadow_event(result: dict):
    """Write one bounded lifecycle event without request metadata or cache controls."""
    allowed = {
        "request_id", "route", "status", "mode", "candidate_id", "model_version",
        "feature_schema_version", "component_scores", "thresholds",
        "if_anomaly", "profile_anomaly", "profile_reasons", "final_anomaly",
        "monitor_closely", "queue_wait_ms", "inference_ms",
        "shadow_latency_ms", "batch_size", "queue_depth", "fallback_reason",
    }
    status_value = result["status"]
    event = {
        "schema": "fusion-ml-shadow-event-v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "shadow_failed" if status_value == "dropped" else f"shadow_{status_value}",
        # Keep the common observability field name used by Alloy. The canonical
        # route remains present for consumers of the ML-specific schema.
        "scenario": result.get("route"),
        **{name: result[name] for name in allowed if name in result},
    }
    payload = (json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        with EVENT_LOG_LOCK:
            EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
            _rotate_event_log(len(payload))
            descriptor = os.open(EVENT_LOG, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o640)
            try:
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                if os.write(descriptor, payload) != len(payload):
                    raise OSError("short ML shadow JSONL append")
            finally:
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
    except OSError as exc:
        LOGGER.warning("ml shadow event log unavailable: %s", type(exc).__name__)
    return event


# Quy lỗi nạp registry về mã telemetry ổn định.
def registry_error_code(exc: Exception) -> str:
    message = str(exc).lower()
    if isinstance(exc, FileNotFoundError):
        return "registry_file_missing"
    if "checksum" in message:
        return "registry_checksum_mismatch"
    if "schema" in message:
        return "registry_schema_mismatch"
    if isinstance(exc, ValueError):
        return "registry_validation_error"
    return "registry_load_error"


class ShadowMetadata(BaseModel):
    """Allowlisted request-time fields; arbitrary headers/body are forbidden."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    method: Literal["GET", "HEAD", "POST"]
    uri: str = Field(min_length=1, max_length=4096)
    host: str = Field(min_length=1, max_length=255)
    user_agent: str = Field(default="", max_length=1024)
    accept: str = Field(default="", max_length=1024)
    accept_language: str = Field(default="", max_length=512)
    x_forwarded_host: str = Field(default="", max_length=255)
    content_length: int = Field(default=0, ge=0, le=10_000_000)

    @field_validator("uri")
    @classmethod
    # Chỉ chấp nhận URI tương đối để giới hạn metadata gửi vào Shadow.
    def relative_uri_only(cls, value: str) -> str:
        if not value.startswith("/") or value.startswith("//"):
            raise ValueError("uri must be an origin-form path")
        return value

    # Chiếu schema event thành metadata cho route detector.
    def runtime_metadata(self) -> dict[str, object]:
        headers = {
            "host": self.host,
            "user-agent": self.user_agent,
            "accept": self.accept,
            "accept-language": self.accept_language,
            "x-forwarded-host": self.x_forwarded_host,
            "content-length": str(self.content_length),
        }
        return {"method": self.method, "uri": self.uri, "headers": headers}


class ShadowEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    request_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    route: Literal["query", "xfh", "utm", "fatget"]
    metadata: ShadowMetadata

    @field_validator("metadata")
    @classmethod
    # Từ chối event khai route không khớp URI.
    def route_must_match_uri(cls, metadata: ShadowMetadata, info):
        route = info.data.get("route")
        if route and route_for_request(metadata.runtime_metadata()) != route:
            raise ValueError("route does not match request URI")
        return metadata


@dataclass(frozen=True)
class ShadowJob:
    request_id: str
    route: str
    metadata: dict[str, object]
    accepted_at: float


# Quy lỗi inference về mã telemetry ổn định.
def inference_error_code(exc: Exception) -> str:
    message = str(exc).lower()
    if "nan" in message or "infinity" in message or "finite" in message:
        return "non_finite_score_or_feature"
    if "route" in message:
        return "route_validation_error"
    return "feature_extraction_or_inference_error"


class ShadowMicrobatchWorker:
    """One bounded queue shared by the single ml-shadow API process."""

    # Khởi tạo queue hữu hạn, cache kết quả và worker microbatch.
    def __init__(self, registry, queue_size=QUEUE_SIZE, batch_size=BATCH_SIZE,
                 batch_wait_ms=BATCH_WAIT_MS, max_job_age_ms=MAX_JOB_AGE_MS,
                 result_cache_size=RESULT_CACHE_SIZE):
        self.registry = registry
        self.queue = Queue(maxsize=queue_size)
        self.batch_size = batch_size
        self.batch_wait_s = batch_wait_ms / 1000.0
        self.max_job_age_s = max_job_age_ms / 1000.0
        self.result_cache_size = result_cache_size
        self.results = OrderedDict()
        self.results_lock = threading.Lock()
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self._run, name="ml-shadow-microbatch", daemon=True)
        self.thread.start()

    # Lưu kết quả gần đây theo request_id để tra cứu.
    def _store(self, request_id, value):
        with self.results_lock:
            self.results[request_id] = value
            self.results.move_to_end(request_id)
            while len(self.results) > self.result_cache_size:
                self.results.popitem(last=False)

    # Ghi kết quả và phát lifecycle event tương ứng.
    def _record(self, request_id, value):
        self._store(request_id, value)
        write_ml_shadow_event(value)

    # Trả kết quả Shadow gần đây của request_id.
    def get(self, request_id):
        with self.results_lock:
            value = self.results.get(request_id)
            return dict(value) if value else None

    # Nhận job vào central inference queue và báo overflow nếu đầy.
    def submit(self, event: ShadowEvent):
        job = ShadowJob(
            request_id=event.request_id,
            route=event.route,
            metadata=event.metadata.runtime_metadata(),
            accepted_at=time.perf_counter(),
        )
        try:
            self.queue.put_nowait(job)
        except Full:
            self._record(event.request_id, {
                "request_id": event.request_id, "route": event.route,
                "status": "failed", "fallback_reason": "queue_overflow",
            })
            return False
        self._record(event.request_id, {
            "request_id": event.request_id, "route": event.route,
            "status": "accepted", "queue_depth": self.queue.qsize(),
            "fallback_reason": None,
        })
        return True

    # Dừng worker microbatch có kiểm soát.
    def close(self):
        self.stopping.set()
        self.thread.join(timeout=10)
        while True:
            try:
                job = self.queue.get_nowait()
            except Empty:
                break
            self._record(job.request_id, {
                "request_id": job.request_id, "route": job.route,
                "status": "dropped", "fallback_reason": "shutdown_dropped",
            })
            self.queue.task_done()

    # Gom job theo batch size/thời gian chờ rồi chuyển sang xử lý.
    def _run(self):
        while not self.stopping.is_set() or not self.queue.empty():
            try:
                first = self.queue.get(timeout=0.1)
            except Empty:
                continue
            batch = [first]
            deadline = time.perf_counter() + self.batch_wait_s
            while len(batch) < self.batch_size:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    break
                try:
                    batch.append(self.queue.get(timeout=remaining))
                except Empty:
                    break
            self._process(batch)
            for _ in batch:
                self.queue.task_done()

    # Nhóm job theo route, chấm model tương ứng và ghi completion/failure.
    def _process(self, batch):
        now = time.perf_counter()
        grouped = defaultdict(list)
        for job in batch:
            age = now - job.accepted_at
            if age > self.max_job_age_s:
                self._record(job.request_id, {
                    "request_id": job.request_id, "route": job.route,
                    "status": "failed", "fallback_reason": "job_expired",
                    "queue_wait_ms": round(age * 1000, 3), "batch_size": 0,
                })
            else:
                grouped[job.route].append(job)
        for route, jobs in grouped.items():
            valid_jobs, rows = [], []
            extraction_started = time.perf_counter()
            for job in jobs:
                try:
                    rows.append(extract_route_features(route, job.metadata, self.registry))
                    valid_jobs.append(job)
                except Exception as exc:
                    finished = time.perf_counter()
                    self._record(job.request_id, {
                        "request_id": job.request_id, "route": route,
                        "status": "failed", "fallback_reason": inference_error_code(exc),
                        "queue_wait_ms": round((extraction_started - job.accepted_at) * 1000, 3),
                        "inference_ms": round((finished - extraction_started) * 1000, 3),
                        "shadow_latency_ms": round((finished - job.accepted_at) * 1000, 3),
                        "batch_size": len(jobs),
                    })
            if not valid_jobs:
                continue
            inference_started = time.perf_counter()
            try:
                scored = score_route_feature_batch(route, rows, self.registry)
                finished = time.perf_counter()
                component = self.registry[route]
                for job, result in zip(valid_jobs, scored, strict=True):
                    self._record(job.request_id, {
                        "request_id": job.request_id, "route": route,
                        "status": "completed", "processing": True, "mode": "shadow",
                        "candidate_id": result["candidate_id"],
                        "model_version": result["candidate_id"],
                        "feature_schema_version": component["feature_schema"]["schema_version"],
                        "component_scores": result["component_scores"],
                        "thresholds": result["thresholds"],
                        "if_anomaly": result["if_anomaly"],
                        "profile_anomaly": result["profile_anomaly"],
                        "profile_reasons": result["profile_reasons"],
                        "final_anomaly": result["final_anomaly"],
                        "monitor_closely": result["monitor_closely"],
                        "queue_wait_ms": round((inference_started - job.accepted_at) * 1000, 3),
                        "inference_ms": round((finished - inference_started) * 1000, 3),
                        "shadow_latency_ms": round((finished - job.accepted_at) * 1000, 3),
                        "batch_size": len(valid_jobs), "fallback_reason": None,
                    })
            except Exception as exc:
                finished = time.perf_counter()
                for job in valid_jobs:
                    self._record(job.request_id, {
                        "request_id": job.request_id, "route": route,
                        "status": "failed", "fallback_reason": inference_error_code(exc),
                        "queue_wait_ms": round((inference_started - job.accepted_at) * 1000, 3),
                        "inference_ms": round((finished - inference_started) * 1000, 3),
                        "shadow_latency_ms": round((finished - job.accepted_at) * 1000, 3),
                        "batch_size": len(valid_jobs),
                    })


@asynccontextmanager
# Nạp registry và quản lý vòng đời worker Shadow.
async def lifespan(app: FastAPI):
    try:
        app.state.registry = load_registry(MODEL_REGISTRY)
        app.state.registry_error = None
    except Exception as exc:
        app.state.registry = None
        app.state.registry_error = registry_error_code(exc)
        write_ml_shadow_event({
            "request_id": "registry-startup",
            "route": "registry",
            "status": "failed",
            "fallback_reason": app.state.registry_error,
        })
    app.state.worker = ShadowMicrobatchWorker(app.state.registry) if app.state.registry else None
    yield
    if app.state.worker:
        app.state.worker.close()


app = FastAPI(
    title="Route-aware ML Shadow Inference Service",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


@app.get("/health")
# Báo trạng thái registry, worker và queue cho health check.
def health():
    registry = app.state.registry
    route_status = {
        route: {
            "ready": bool(registry and route in registry),
            "candidate_id": registry[route]["candidate_id"] if registry and route in registry else None,
            "mode": registry[route]["mode"] if registry and route in registry else "shadow",
        }
        for route in ROUTES
    }
    ready = registry is not None and all(item["ready"] for item in route_status.values())
    return {
        "ok": ready,
        "service": "ml-shadow",
        "registry_ready": ready,
        "registry_error": app.state.registry_error,
        "queue_ready": app.state.worker is not None,
        "queue_depth": app.state.worker.queue.qsize() if app.state.worker else None,
        "queue_capacity": QUEUE_SIZE,
        "batch_size": BATCH_SIZE,
        "batch_wait_ms": BATCH_WAIT_MS,
        "max_job_age_ms": MAX_JOB_AGE_MS,
        "routes": route_status,
    }


@app.post("/internal/v1/shadow/events", status_code=status.HTTP_202_ACCEPTED)
# Nhận event nội bộ từ Detection API và xếp hàng inference.
def ingest(event: ShadowEvent):
    """Accept one job into the centralized bounded inference queue."""
    if app.state.registry is None:
        raise HTTPException(
            status_code=503,
            detail={"error": app.state.registry_error or "registry_unavailable"},
        )
    if not app.state.worker.submit(event):
        raise HTTPException(status_code=429, detail={"error": "queue_overflow"})
    return {
        "request_id": event.request_id,
        "route": event.route,
        "status": "accepted",
        "processing": False,
        "mode": "shadow",
        "queue_depth": app.state.worker.queue.qsize(),
    }


@app.get("/internal/v1/shadow/results/{request_id}")
# Tra kết quả Shadow theo request_id.
def result(request_id: str):
    if app.state.worker is None:
        raise HTTPException(status_code=503, detail={"error": "registry_unavailable"})
    item = app.state.worker.get(request_id)
    if item is None:
        raise HTTPException(status_code=404, detail={"error": "result_not_found"})
    return item
