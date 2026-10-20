import json

from fastapi.testclient import TestClient

from tests.test_triage import _detector_event, _nginx_event, _shadow_event


def _incident_nginx_event(request_id):
    event = _nginx_event(request_id)
    event.update({"client_ip": "127.0.0.1", "method": "GET"})
    return event


def test_incident_report_is_sanitized_stable_and_retrievable(tmp_path, monkeypatch):
    from triage import app as module

    request_id = "fusion-incident-xfh"
    nginx_event = _incident_nginx_event(request_id)
    detector_event = _detector_event(request_id)
    shadow_event = _shadow_event(request_id)
    monkeypatch.setenv("TRIAGE_LLM_PROVIDER", "rules")
    monkeypatch.setattr(module, "REPORT_DIR", tmp_path / "reports")
    monkeypatch.setattr(module, "INCIDENT_EVENT_LOG", tmp_path / "incident-report-events.jsonl")
    monkeypatch.setattr(
        module,
        "get_loki_events",
        lambda job, value: {
            "fusion-nginx": [nginx_event],
            "fusion-detector": [detector_event],
            "fusion-ml-shadow": [shadow_event],
        }[job],
    )

    with TestClient(module.app) as client:
        created = client.post(f"/incidents/{request_id}")
        assert created.status_code == 201
        payload = created.json()
        assert payload["created"] is True
        report = payload["report"]
        incident_id = report["incident_id"]

        assert report["schema"] == "fusion-incident-report-v1"
        assert report["request"] == {
            "request_id": request_id,
            "client_ip": "127.0.0.1",
            "method": "GET",
            "uri_path": "/labs/xfh/shop",
            "scenario": "xfh",
        }
        assert report["suspicious_input"]["input_class"].startswith("X-Forwarded-Host")
        assert report["suspicious_input"]["raw_values_available"] is False
        assert report["detection"]["prediction"] == "anomaly"
        assert report["detection"]["authoritative_for_cache"] is True
        assert report["candidate_assessment"]["authoritative_for_cache"] is False
        assert report["candidate_assessment"]["model_version"] == "xfh-candidate-test"
        assert report["cache"]["status"] == "MISS"
        assert report["suspected_technique"]["id"] == "unkeyed-x-forwarded-host"
        assert report["system_action"]["recommended_cache_action"] == "bypass-no-cache"
        assert report["llm_narration"]["generative_model_used"] is False

        repeated = client.post(f"/incidents/{request_id}")
        assert repeated.status_code == 200
        assert repeated.json()["created"] is False
        assert repeated.json()["report"]["incident_id"] == incident_id

        fetched = client.get(f"/incidents/{incident_id}")
        assert fetched.status_code == 200
        assert fetched.json()["incident_id"] == incident_id

        listing = client.get("/incidents?limit=10")
        assert listing.status_code == 200
        assert listing.json()[0]["incident_id"] == incident_id

    serialized = json.dumps(report)
    assert "do-not-expose.invalid" not in serialized
    assert "do-not-expose-cookie" not in serialized
    assert "raw_values_available" in serialized

    audit_lines = (tmp_path / "incident-report-events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(audit_lines) == 1
    audit_event = json.loads(audit_lines[0])
    assert audit_event["schema"] == "fusion-incident-report-event-v1"
    assert audit_event["incident_id"] == incident_id
    assert "client_ip" not in audit_event


def test_incident_report_rejects_invalid_identifiers_and_missing_reports(tmp_path, monkeypatch):
    from triage import app as module

    monkeypatch.setattr(module, "REPORT_DIR", tmp_path / "reports")
    with TestClient(module.app) as client:
        assert client.post("/incidents/not valid").status_code == 422
        assert client.get("/incidents/not-an-incident").status_code == 422
        missing = client.get("/incidents/INC-20260922T153520Z-0123456789ab")
        assert missing.status_code == 404
        assert client.get("/incidents?limit=0").status_code == 422
