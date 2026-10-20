import json
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from ml_shadow import app as module
from ml.route_detector import detect

GOLDEN = Path(__file__).parent / "golden" / "route_detection_v1.json"


@pytest.fixture(autouse=True)
def isolated_ml_event_log(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "EVENT_LOG", tmp_path / "ml-shadow-events.jsonl")


def _event(route="query"):
    paths = {
        "query": "/labs/query/?page=1&view=grid",
        "xfh": "/labs/xfh/shop",
        "utm": "/labs/utm/js/geolocate.js?callback=ready",
        "fatget": "/labs/fatget/js/geolocate.js?callback=ready",
    }
    return {
        "request_id": "section1-contract-1",
        "route": route,
        "metadata": {"method": "GET", "uri": paths[route], "host": "fusion.local:8090"},
    }


def _completed(client, request_id, timeout=3):
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        response = client.get(f"/internal/v1/shadow/results/{request_id}")
        if response.status_code == 200 and response.json()["status"] != "accepted":
            return response.json()
        time.sleep(0.01)
    raise AssertionError(f"shadow result did not complete: {request_id}")


def test_health_reports_all_four_frozen_candidates():
    with TestClient(module.app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is True
        assert body["registry_ready"] is True
        assert set(body["routes"]) == {"query", "xfh", "utm", "fatget"}
        assert all(item["ready"] and item["mode"] == "shadow" for item in body["routes"].values())


@pytest.mark.parametrize("route", ["query", "xfh", "utm", "fatget"])
def test_ingestion_runs_the_correct_frozen_candidate(route):
    with TestClient(module.app) as client:
        response = client.post("/internal/v1/shadow/events", json=_event(route))
        assert response.status_code == 202
        assert response.json()["status"] == "accepted"
        body = _completed(client, "section1-contract-1")
    assert body["request_id"] == "section1-contract-1"
    assert body["route"] == route
    assert body["status"] == "completed"
    assert body["processing"] is True
    assert body["mode"] == "shadow"
    assert body["candidate_id"]
    assert body["feature_schema_version"]
    assert isinstance(body["component_scores"], dict)
    assert isinstance(body["thresholds"], dict)
    assert isinstance(body["if_anomaly"], bool)
    assert isinstance(body["profile_anomaly"], bool)
    assert isinstance(body["final_anomaly"], bool)
    assert body["inference_ms"] >= 0
    assert body["queue_wait_ms"] >= 0
    assert body["shadow_latency_ms"] >= body["inference_ms"]
    assert body["batch_size"] >= 1
    assert {"action", "cache_bypass", "recommended_cache_action"}.isdisjoint(body)


def test_ingestion_rejects_route_mismatch_and_unallowlisted_content():
    mismatch = _event("query")
    mismatch["route"] = "xfh"
    raw_content = _event("query")
    raw_content["metadata"]["cookie"] = "must-not-be-accepted"
    fixed = _event("query")
    fixed["metadata"]["uri"] = "/labs/query/fixed/"
    unknown = _event("query")
    unknown["route"] = "unknown"
    with TestClient(module.app) as client:
        assert client.post("/internal/v1/shadow/events", json=mismatch).status_code == 422
        assert client.post("/internal/v1/shadow/events", json=raw_content).status_code == 422
        assert client.post("/internal/v1/shadow/events", json=fixed).status_code == 422
        assert client.post("/internal/v1/shadow/events", json=unknown).status_code == 422


@pytest.mark.parametrize("mutation", [
    lambda event: event["metadata"].update({"uri": "https://invalid.example/path"}),
    lambda event: event["metadata"].update({"method": "TRACE"}),
    lambda event: event["metadata"].update({"content_length": -1}),
    lambda event: event.update({"request_id": "contains whitespace"}),
])
def test_ingestion_rejects_malformed_metadata(mutation):
    event = _event("query")
    mutation(event)
    with TestClient(module.app) as client:
        assert client.post("/internal/v1/shadow/events", json=event).status_code == 422


@pytest.mark.parametrize("route", ["query", "xfh", "utm", "fatget"])
def test_service_output_matches_direct_runtime_and_golden_vector(route):
    vector = json.loads(GOLDEN.read_text(encoding="utf-8"))["vectors"][route]
    request = vector["request"]
    headers = {name.lower(): value for name, value in request["headers"].items()}
    payload = {
        "request_id": f"golden-{route}",
        "route": route,
        "metadata": {
            "method": request["method"],
            "uri": request["uri"],
            "host": headers["host"],
            "user_agent": headers.get("user-agent", ""),
            "accept": headers.get("accept", ""),
            "accept_language": headers.get("accept-language", ""),
            "x_forwarded_host": headers.get("x-forwarded-host", ""),
            "content_length": int(headers.get("content-length", "0")),
        },
    }
    with TestClient(module.app) as client:
        response = client.post("/internal/v1/shadow/events", json=payload)
        direct = detect(route, request, module.app.state.registry)
        assert response.status_code == 202
        body = _completed(client, f"golden-{route}")
    assert body["candidate_id"] == direct["candidate_id"]
    assert body["component_scores"] == pytest.approx(direct["component_scores"], abs=1e-12)
    assert body["thresholds"] == direct["thresholds"]
    for name in ("if_anomaly", "profile_anomaly", "final_anomaly", "monitor_closely"):
        assert body[name] is direct[name]


def test_health_and_ingestion_fail_closed_when_registry_is_unavailable(monkeypatch):
    def failed_registry(*args, **kwargs):
        raise ValueError("checksum mismatch")

    monkeypatch.setattr(module, "load_registry", failed_registry)
    with TestClient(module.app) as client:
        health = client.get("/health").json()
        response = client.post("/internal/v1/shadow/events", json=_event("query"))
    assert health["ok"] is False
    assert health["registry_error"] == "registry_checksum_mismatch"
    assert response.status_code == 503
    assert response.json()["detail"]["error"] == "registry_checksum_mismatch"


def test_central_microbatch_groups_by_route_without_schema_mixing():
    registry = module.load_registry()
    worker = module.ShadowMicrobatchWorker(
        registry, queue_size=32, batch_size=16, batch_wait_ms=50,
        max_job_age_ms=30_000, result_cache_size=32,
    )
    try:
        events = []
        for route in ("query", "xfh", "utm", "fatget"):
            for index in range(2):
                raw = _event(route)
                raw["request_id"] = f"batch-{route}-{index}"
                event = module.ShadowEvent.model_validate(raw)
                events.append(event)
                assert worker.submit(event) is True
        deadline = time.perf_counter() + 5
        while time.perf_counter() < deadline and any(
            not worker.get(event.request_id)
            or worker.get(event.request_id)["status"] == "accepted"
            for event in events
        ):
            time.sleep(0.01)
        for event in events:
            result = worker.get(event.request_id)
            assert result["status"] == "completed"
            assert result["route"] == event.route
            assert result["candidate_id"] == registry[event.route]["candidate_id"]
            assert result["feature_schema_version"] == registry[event.route]["feature_schema"]["schema_version"]
            assert result["batch_size"] == 2
    finally:
        worker.close()


def test_result_cache_is_bounded_and_expired_job_is_explicit():
    registry = module.load_registry()
    worker = module.ShadowMicrobatchWorker(
        registry, queue_size=2, batch_size=1, batch_wait_ms=0,
        max_job_age_ms=100, result_cache_size=2,
    )
    try:
        for index in range(3):
            worker._store(f"bounded-{index}", {"status": "completed"})
        assert list(worker.results) == ["bounded-1", "bounded-2"]
        job = module.ShadowJob(
            request_id="expired-1", route="query",
            metadata=module.ShadowEvent.model_validate(_event("query")).metadata.runtime_metadata(),
            accepted_at=time.perf_counter() - 1,
        )
        worker._process([job])
        assert worker.get("expired-1")["fallback_reason"] == "job_expired"
    finally:
        worker.close()


def test_shutdown_drains_pending_jobs_and_queue_overflow_is_explicit():
    registry = module.load_registry()
    worker = module.ShadowMicrobatchWorker(
        registry, queue_size=8, batch_size=8, batch_wait_ms=50,
        max_job_age_ms=30_000, result_cache_size=16,
    )
    events = []
    for index in range(4):
        raw = _event("xfh")
        raw["request_id"] = f"drain-{index}"
        event = module.ShadowEvent.model_validate(raw)
        events.append(event)
        assert worker.submit(event) is True
    worker.close()
    assert all(worker.get(event.request_id)["status"] == "completed" for event in events)

    stopped = module.ShadowMicrobatchWorker(
        registry, queue_size=1, batch_size=1, batch_wait_ms=0,
        max_job_age_ms=30_000, result_cache_size=4,
    )
    stopped.close()
    filler = module.ShadowJob("filler", "xfh", _event("xfh")["metadata"], time.perf_counter())
    stopped.queue.put_nowait(filler)
    overflow = module.ShadowEvent.model_validate({**_event("xfh"), "request_id": "overflow-central"})
    assert stopped.submit(overflow) is False
    assert stopped.get("overflow-central")["fallback_reason"] == "queue_overflow"
    stopped.queue.get_nowait()
    stopped.queue.task_done()


def test_worker_can_restart_after_clean_shutdown():
    registry = module.load_registry()
    first = module.ShadowMicrobatchWorker(registry, queue_size=4, batch_size=1, batch_wait_ms=0)
    first.close()
    second = module.ShadowMicrobatchWorker(registry, queue_size=4, batch_size=1, batch_wait_ms=0)
    try:
        raw = _event("utm")
        raw["request_id"] = "worker-restart-utm"
        assert second.submit(module.ShadowEvent.model_validate(raw)) is True
        deadline = time.perf_counter() + 5
        result = None
        while time.perf_counter() < deadline:
            result = second.get(raw["request_id"])
            if result and result["status"] == "completed":
                break
            time.sleep(0.01)
        assert result["status"] == "completed"
        assert result["route"] == "utm"
    finally:
        second.close()


def test_jsonl_lifecycle_is_complete_sanitized_and_correlated():
    event = _event("query")
    event["request_id"] = "lifecycle-query-1"
    event["metadata"].update({
        "uri": "/labs/query/?secret=must-not-be-logged",
        "host": "sensitive-host.invalid",
        "user_agent": "sensitive-agent",
    })
    with TestClient(module.app) as client:
        assert client.post("/internal/v1/shadow/events", json=event).status_code == 202
        result = _completed(client, event["request_id"])
    rows = [json.loads(line) for line in module.EVENT_LOG.read_text(encoding="utf-8").splitlines()]
    correlated = [row for row in rows if row["request_id"] == event["request_id"]]
    assert [row["event_type"] for row in correlated] == ["shadow_accepted", "shadow_completed"]
    assert all(row["schema"] == "fusion-ml-shadow-event-v1" for row in correlated)
    completed = correlated[-1]
    for field in (
        "candidate_id", "feature_schema_version", "component_scores", "thresholds",
        "if_anomaly", "profile_anomaly", "final_anomaly", "queue_wait_ms",
        "inference_ms", "shadow_latency_ms", "batch_size", "fallback_reason",
    ):
        assert field in completed
    assert completed["component_scores"] == result["component_scores"]
    serialized = json.dumps(correlated)
    for secret in ("must-not-be-logged", "sensitive-host.invalid", "sensitive-agent", "/labs/query/"):
        assert secret not in serialized
    assert {"action", "cache_bypass", "cache_key", "cookie", "headers", "uri"}.isdisjoint(completed)


def test_concurrent_jsonl_writes_are_valid_and_rotation_is_bounded(monkeypatch):
    threads = []
    for index in range(50):
        thread = threading.Thread(target=module.write_ml_shadow_event, args=({
            "request_id": f"concurrent-{index}", "route": "xfh",
            "status": "accepted", "fallback_reason": None,
        },))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    rows = [json.loads(line) for line in module.EVENT_LOG.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 50
    assert len({row["request_id"] for row in rows}) == 50

    monkeypatch.setattr(module, "EVENT_LOG_MAX_BYTES", 1024)
    monkeypatch.setattr(module, "EVENT_LOG_BACKUPS", 2)
    for index in range(50, 100):
        module.write_ml_shadow_event({
            "request_id": f"rotate-{index}", "route": "utm",
            "status": "accepted", "fallback_reason": None,
        })
    files = list(module.EVENT_LOG.parent.glob("ml-shadow-events.jsonl*"))
    assert module.EVENT_LOG.with_name("ml-shadow-events.jsonl.1") in files
    assert len(files) <= 3
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            json.loads(line)
