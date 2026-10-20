import json

import pytest

from traffic import fusion_benchmark
from traffic import fusion_e2e_demo as stage15
from traffic import verify_cache_poisoning as poisoning_proof
from traffic.fusion_scenarios import attack_case


def _response(request_id, *, status=200, cache_status="BYPASS", classification="anomaly", bypass="1"):
    return {
        "status": status,
        "latency_ms": 10.0,
        "request_id": request_id,
        "cache_status": cache_status,
        "detector_mode": "enforce",
        "classification": classification,
        "detector_action": "bypass-no-cache" if bypass == "1" else "cache-normal",
        "recommended_cache_action": "bypass-no-cache" if bypass == "1" else "cache-normal",
        "cache_bypass": bypass,
        "detector_ms": "2.000",
        "_body": "internal-only-body",
    }


def test_stage15_clean_follow_up_removes_every_attack_primitive():
    for lab in ("xfh", "query", "utm", "fatget"):
        case = attack_case(lab, "a" * 24, "UA", "en")
        uri, headers, body, marker = stage15.clean_follow_up(case)

        assert body == ""
        assert marker
        assert all(name.lower() not in {"x-forwarded-host", "content-type", "content-length"} for name in headers)
        if lab == "query":
            assert "utm_content" not in uri
            assert "page=1" in uri and "view=grid" in uri
        elif lab == "utm":
            assert "utm_content" not in uri
            assert "locale=vi" in uri
        else:
            assert uri == case.uri


def test_stage15_summary_is_redacted_and_requires_the_full_pipeline():
    attacker = _response("request-attack")
    clean = _response("request-clean", cache_status="MISS", classification="normal", bypass="0")
    triage = {
        "request_id": "request-attack",
        "triage_engine": {"name": "evidence-rules-v1"},
        "verdict": "suspected",
        "severity": "medium",
        "possible_technique": {"id": "unkeyed-x-forwarded-host"},
        "incident_summary": "sanitized summary",
        "mitigation_suggestions": ["sanitize forwarding header"],
        "llm": {"provider": "rules", "status": "disabled", "model": None, "generative_model_used": False},
    }
    incident = {
        "created": True,
        "report": {
            "incident_id": "INC-20260923T000000Z-0123456789ab",
            "schema": "fusion-incident-report-v1",
            "suspicious_input": {"raw_values_available": False},
        },
    }
    observability = {
        "loki_nginx": {"delivered": True},
        "loki_detector": {"delivered": True},
        "loki_triage": {"delivered": True},
        "loki_incident": {"delivered": True},
        "grafana_health": {"ok": True},
    }

    summary = stage15.build_summary("run-a", "xfh", attacker, clean, True, False, triage, incident, observability)

    assert summary["passed"] is True
    assert summary["incident_report"]["raw_values_available"] is False
    serialized = json.dumps(summary)
    assert "internal-only-body" not in serialized
    assert "127.0.0.1:8087" not in serialized


def test_stage15_loki_helper_allows_only_bounded_correlation_fields():
    with pytest.raises(ValueError):
        fusion_benchmark._loki_has_field("http://loki:3100", "fusion-nginx", "uri_path", "/labs/xfh")


def test_poisoning_proof_cache_basis_removes_only_the_intentional_input():
    for lab in ("xfh", "query", "utm", "fatget"):
        case = attack_case(lab, "a" * 24, "UA", "en")
        clean_uri, clean_headers, _, _ = stage15.clean_follow_up(case)
        assert poisoning_proof.cache_basis(lab, case.uri, case.headers) == poisoning_proof.cache_basis(
            lab, clean_uri, clean_headers
        )
