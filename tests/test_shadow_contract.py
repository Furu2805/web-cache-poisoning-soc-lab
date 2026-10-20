import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from detector import app as detector_module


def _request(route="query"):
    paths = {
        "query": "/labs/query/?cb=shadow&page=1&view=grid&utm_content=summer",
        "xfh": "/labs/xfh/shop",
        "utm": "/labs/utm/js/geolocate.js?callback=ready&locale=vi",
        "fatget": "/labs/fatget/js/geolocate.js?callback=ready&locale=vi",
    }
    return {"method": "GET", "uri": paths[route], "headers": {"host": "fusion.local:8086"}}


def test_inspect_queues_external_shadow_and_stays_non_enforcing(tmp_path, monkeypatch):
    monkeypatch.setattr(detector_module, "DB", tmp_path / "detector.sqlite3")
    monkeypatch.setattr(detector_module, "EVENT_LOG", tmp_path / "events.jsonl")
    headers = {
        "X-Request-ID": "shadow-api-1",
        "X-Meta-Method": "GET",
        "X-Meta-URI": "/labs/query/?cb=shadow&page=1&view=grid&utm_content=summer",
        "X-Meta-Host": "fusion.local:8086",
        "X-Meta-User-Agent": "pytest",
    }
    with TestClient(detector_module.app) as client:
        response = client.get("/inspect", headers=headers)
        assert response.status_code == 200
        body = response.json()
        shadow = body["shadow_candidate"]
        assert shadow["request_id"] == "shadow-api-1"
        assert shadow["route"] == "query"
        assert shadow["model_version"] is None
        assert shadow["status"] == "queued"
        assert shadow["fallback_reason"] is None
        assert body["action"] == "observe"
        assert response.headers["x-fusion-cache-bypass"] == "0"
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    request_events = [event for event in events if event["schema"] == "fusion-detector-event-v2"]
    candidate_events = [event for event in events if event["schema"] == "fusion-shadow-candidate-event-v1"]
    assert len(request_events) == 1
    assert candidate_events == []
    assert request_events[-1]["request_id"] == "shadow-api-1"
    assert request_events[-1]["fallback_reason"] is None
    serialized = json.dumps(request_events[-1])
    assert headers["X-Meta-URI"] not in serialized
    assert "pytest" not in serialized


def test_delivery_payload_is_allowlisted_and_excludes_sensitive_content():
    metadata = {
        "method": "GET",
        "uri": "/labs/xfh/shop",
        "headers": {
            "host": "fusion.local:8090",
            "user-agent": "pytest",
            "x-forwarded-host": "edge.invalid",
            "cookie": "secret-cookie",
            "authorization": "secret-token",
            "content-type": "text/plain",
            "content-length": "12",
        },
    }
    payload = detector_module.shadow_delivery_payload("allowlist-1", "xfh", metadata)
    serialized = json.dumps(payload)
    assert payload["metadata"]["content_length"] == 12
    assert payload["metadata"]["x_forwarded_host"] == "edge.invalid"
    assert "cookie" not in serialized.lower()
    assert "authorization" not in serialized.lower()
    assert "secret" not in serialized


def test_queue_overflow_is_structured_and_never_changes_cache_fields():
    class FullDelivery:
        def submit(self, payload):
            return False

        def close(self):
            pass

    status = detector_module.enqueue_external_shadow(
        "overflow-1", _request("fatget"), FullDelivery()
    )
    assert status["status"] == "not_queued"
    assert status["fallback_reason"] == "queue_overflow"
    assert status["final_anomaly"] is None
    assert {"action", "cache_bypass", "recommended_cache_action"}.isdisjoint(status)


def test_delivery_failure_does_not_change_detection_or_cache_action(tmp_path, monkeypatch):
    monkeypatch.setattr(detector_module, "DB", tmp_path / "detector.sqlite3")
    monkeypatch.setattr(detector_module, "EVENT_LOG", tmp_path / "events.jsonl")
    headers = {
        "X-Request-ID": "delivery-failure-1",
        "X-Meta-Method": "GET",
        "X-Meta-URI": "/labs/xfh/shop",
        "X-Meta-Host": "fusion.local:8090",
        "X-Meta-X-Forwarded-Host": "edge.invalid",
    }

    class FullDelivery:
        def __init__(self, *args, **kwargs):
            pass

        def submit(self, payload):
            return False

        def close(self):
            pass

    monkeypatch.setattr(detector_module, "ShadowDeliveryClient", FullDelivery)
    with TestClient(detector_module.app) as client:
        response = client.get("/inspect", headers=headers)
    body = response.json()
    assert response.status_code == 200
    assert body["shadow_candidate"]["fallback_reason"] == "queue_overflow"
    assert body["action"] == "observe"
    assert response.headers["x-fusion-cache-bypass"] == "0"
