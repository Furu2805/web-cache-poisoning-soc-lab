import json

from fastapi.testclient import TestClient


def _nginx_event(request_id, *, status="MISS", scenario="xfh", uri_path=None):
    return {
        "schema": "fusion-nginx-access-v1",
        "timestamp": "2026-09-22T15:35:20+00:00",
        "request_id": request_id,
        "scenario": scenario,
        "uri_path": uri_path or f"/labs/{scenario}/shop",
        "cache_status": status,
        # Unknown/raw-looking fields must never be copied to triage output.
        "x_forwarded_host": "do-not-expose.invalid",
        "cookie": "do-not-expose-cookie",
    }


def _detector_event(request_id, *, classification="anomaly", scenario="xfh", uri_path=None):
    return {
        "schema": "fusion-detector-event-v1",
        "timestamp": "2026-09-22T15:35:20.574487+00:00",
        "request_id": request_id,
        "detector_mode": "observe",
        "scenario": scenario,
        "uri_path": uri_path or f"/labs/{scenario}/shop",
        "classification": classification,
        "anomaly_score": 0.5945,
        "action": "observe",
        "recommended_cache_action": "bypass-no-cache",
        "cache_bypass": False,
        "model_version": f"{scenario}-candidate-test",
        "component_scores": {"relationship": 0.61},
        "thresholds": {"relationship": 0.58},
        "if_anomaly": True,
        "profile_anomaly": True,
        "indicators": {
            "isolation_forest_anomaly": False,
            "normal_profile_deviations": ["has_x_forwarded_host", "host_mismatch", "query_length"],
            "shadow_candidate": {"route": scenario, "profile_reasons": ["host_mismatch"]},
        },
    }


def _shadow_event(request_id, *, scenario="xfh"):
    return {
        "schema": "fusion-ml-shadow-event-v1",
        "timestamp": "2026-09-22T15:35:20.650000+00:00",
        "event_type": "shadow_completed",
        "request_id": request_id,
        "status": "completed",
        "mode": "shadow",
        "route": scenario,
        "candidate_id": f"{scenario}-candidate-test",
        "model_version": f"{scenario}-candidate-test",
        "component_scores": {"relationship": 0.61},
        "thresholds": {"relationship": 0.58},
        "if_anomaly": True,
        "profile_anomaly": True,
        "final_anomaly": True,
        "profile_reasons": ["host_mismatch"],
        "monitor_closely": scenario == "fatget",
        "shadow_latency_ms": 12.5,
        "fallback_reason": None,
    }


def test_triage_correlates_sanitized_evidence_and_writes_audit_event(tmp_path, monkeypatch):
    from triage import app as module

    request_id = "fusion-triage-xfh"
    monkeypatch.setattr(module, "EVENT_LOG", tmp_path / "triage-events.jsonl")
    monkeypatch.setattr(
        module,
        "get_loki_events",
        lambda job, value: {
            "fusion-nginx": [_nginx_event(value)],
            "fusion-detector": [_detector_event(value)],
            "fusion-ml-shadow": [_shadow_event(value)],
        }[job],
    )
    with TestClient(module.app) as client:
        response = client.post(f"/triage/{request_id}")

    assert response.status_code == 200
    result = response.json()
    assert result["request_id"] == request_id
    assert result["verdict"] == "suspected"
    assert result["severity"] == "medium"
    assert result["possible_technique"]["id"] == "unkeyed-x-forwarded-host"
    assert result["cache_assessment"]["recommended_cache_action"] == "bypass-no-cache"
    assert "has_x_forwarded_host" in result["suspicious_indicators"]
    assert result["triage_engine"]["generative_model_used"] is False
    assert result["model_evidence"]["route"] == "xfh"
    assert result["model_evidence"]["component_scores"] == {"relationship": 0.61}
    assert result["model_evidence"]["profile_reasons"] == ["host_mismatch"]
    assert result["baseline_detection"]["authoritative_for_cache"] is True
    assert result["candidate_assessment"]["authoritative_for_cache"] is False
    serialized = json.dumps(result)
    assert "do-not-expose.invalid" not in serialized
    assert "do-not-expose-cookie" not in serialized

    audit_event = json.loads(module.EVENT_LOG.read_text(encoding="utf-8"))
    assert audit_event["schema"] == "fusion-triage-event-v1"
    assert audit_event["request_id"] == request_id
    assert audit_event["possible_technique"]["id"] == "unkeyed-x-forwarded-host"
    assert "do-not-expose.invalid" not in json.dumps(audit_event)


def test_triage_normal_is_a_control_not_a_security_claim(tmp_path, monkeypatch):
    from triage import app as module

    request_id = "fusion-triage-normal"
    monkeypatch.setattr(module, "EVENT_LOG", tmp_path / "triage-events.jsonl")
    monkeypatch.setattr(
        module,
        "get_loki_events",
        lambda job, value: {
            "fusion-nginx": [_nginx_event(value)],
            "fusion-detector": [_detector_event(value, classification="normal")],
            "fusion-ml-shadow": [_shadow_event(value)],
        }[job],
    )
    with TestClient(module.app) as client:
        response = client.post(f"/triage/{request_id}")

    assert response.status_code == 200
    result = response.json()
    assert result["verdict"] == "not-suspicious"
    assert result["possible_technique"] is None
    assert "not evidence that the lab is secure" in result["lab_impact"]


def test_triage_maps_all_four_fusion_lab_families():
    from triage import app as module

    expected = {
        "xfh": "unkeyed-x-forwarded-host",
        "query": "unkeyed-query-parameter",
        "utm": "parameter-cloaking",
        "fatget": "fat-get-request",
    }
    for scenario, technique in expected.items():
        request_id = f"fusion-triage-{scenario}"
        result = module.build_triage(
            request_id,
            _nginx_event(request_id, scenario=scenario),
            _detector_event(request_id, scenario=scenario),
            _shadow_event(request_id, scenario=scenario),
        )
        assert result["verdict"] == "suspected"
        assert result["possible_technique"]["id"] == technique


def test_triage_rejects_invalid_and_incomplete_evidence(monkeypatch):
    from triage import app as module

    with TestClient(module.app) as client:
        invalid = client.post("/triage/not valid")
        assert invalid.status_code == 422

        monkeypatch.setattr(module, "get_loki_events", lambda job, value: [_nginx_event(value)] if job == "fusion-nginx" else [])
        incomplete = client.post("/triage/fusion-triage-incomplete")
        assert incomplete.status_code == 409
        assert incomplete.json()["detail"]["error"] == "triage-evidence-incomplete"
        assert incomplete.json()["detail"]["decision"] == "không đủ dữ liệu"


def test_zai_llm_enrichment_receives_only_sanitized_evidence(monkeypatch):
    from triage import app as triage
    from triage import llm

    request_id = "fusion-triage-zai"
    result = triage.build_triage(
        request_id, _nginx_event(request_id), _detector_event(request_id), _shadow_event(request_id)
    )
    monkeypatch.setenv("TRIAGE_LLM_PROVIDER", "zai-chat-completions")
    monkeypatch.setenv("TRIAGE_ZAI_MODEL", "glm-5.3-flash")
    monkeypatch.setenv("ZAI_API_KEY", "test-key-not-a-real-secret")
    seen = {}

    def fake_zai(evidence, config):
        seen["evidence"] = evidence
        seen["config"] = config
        return ({
            "summary": "The evidence supports a cautious X-Forwarded-Host triage.",
            "confidence": "medium",
            "evidence_points": ["Detector marked the event anomalous."],
            "mitigation_rationale": "Apply the deterministic mitigation controls.",
            "limitations": ["Local lab evidence only."],
        }, "zai-response-test")

    monkeypatch.setattr(llm, "request_zai_assessment", fake_zai)
    output = llm.enrich(result)
    assert output["provider"] == "zai-chat-completions"
    assert output["status"] == "used"
    assert output["generative_model_used"] is True
    assert output["model"] == "glm-5.3-flash"
    assert output["assessment"]["confidence"] == "medium"
    serialized = json.dumps(seen["evidence"])
    assert "do-not-expose.invalid" not in serialized
    assert "do-not-expose-cookie" not in serialized
    assert seen["config"]["endpoint"].endswith("/chat/completions")
    assert seen["evidence"]["if_component_scores"] == {"relationship": 0.61}
    assert seen["evidence"]["profile_reason_codes"] == ["host_mismatch"]


def test_triage_exposes_no_block_or_cache_configuration_endpoint():
    from triage.app import app

    mutation_paths = {
        route.path.lower() for route in app.routes
        if set(getattr(route, "methods", set())) & {"POST", "PUT", "PATCH", "DELETE"}
    }
    assert not any("block" in path or "cache-config" in path or "enforce" in path for path in mutation_paths)


def test_zai_payload_uses_json_mode_and_bounded_thinking_budget(monkeypatch):
    from triage import llm

    monkeypatch.setenv("TRIAGE_ZAI_MAX_TOKENS", "99999")
    config = llm.provider_config()
    payload = llm.zai_payload({"scenario": "xfh"}, "glm-5.3-flash", config["zai_max_tokens"])

    assert config["zai_max_tokens"] == 4096
    assert payload["response_format"] == {"type": "json_object"}
    assert payload["max_tokens"] == 4096
    assert payload["reasoning_effort"] == "low"
    assert payload["do_sample"] is False


def test_zai_fast_profile_defaults_to_short_bounded_triage(monkeypatch):
    from triage import llm

    for name in ("TRIAGE_LLM_TIMEOUT_SECONDS", "TRIAGE_ZAI_MAX_TOKENS", "TRIAGE_ZAI_REASONING_EFFORT"):
        monkeypatch.delenv(name, raising=False)

    config = llm.provider_config()
    assert config["timeout_seconds"] == 30
    assert config["zai_max_tokens"] == 2048
    assert config["zai_reasoning_effort"] == "low"


def test_llm_parser_accepts_a_json_code_fence():
    from triage.llm import _validated_assessment

    assessment = _validated_assessment(
        "```json\n"
        '{"summary":"Local lab triage.","confidence":"low","evidence_points":["code"],'
        '"mitigation_rationale":"Review controls.","limitations":["Lab only."]}\n```'
    )
    assert assessment["confidence"] == "low"


def test_triage_uses_late_completed_candidate_within_lookback(monkeypatch):
    from triage import app as module

    request_id = "fusion-triage-late-shadow"
    accepted = {"schema": "fusion-ml-shadow-event-v1", "event_type": "shadow_accepted",
                "request_id": request_id, "route": "xfh", "status": "accepted"}
    completed = _shadow_event(request_id)
    monkeypatch.setattr(
        module,
        "get_loki_events",
        lambda job, value: {
            "fusion-nginx": [_nginx_event(value)],
            "fusion-detector": [_detector_event(value)],
            "fusion-ml-shadow": [accepted, completed],
        }[job],
    )
    nginx, detector, shadow = module.correlated_event_bundle(request_id)
    assert nginx["request_id"] == detector["request_id"] == shadow["request_id"] == request_id
    assert shadow["event_type"] == "shadow_completed"
