import json
import sqlite3
import numpy as np
from fastapi.testclient import TestClient
from sklearn.ensemble import IsolationForest

from common.features import (
    FEATURE_NAMES, STRUCTURAL_FEATURE_NAMES, build_feature_profile, extract_features, from_proxy_headers,
    normal_profile_reasons, project_request, rule_reasons,
)


def req(uri="/lab/query?id=1",headers=None,method="GET"):
    return project_request(method,uri,headers or {"Host":"lab.test"})


def test_hashed_lexical_features_distinguish_request_syntax_without_changing_structural_schema():
    safe = extract_features(req("/lab/query?id=1&message=SAFE"))
    evil = extract_features(req("/lab/query?id=1&message=EVIL"))
    assert {name: safe[name] for name in STRUCTURAL_FEATURE_NAMES} == {
        name: evil[name] for name in STRUCTURAL_FEATURE_NAMES
    }
    assert any(safe[name] != evil[name] for name in FEATURE_NAMES if name.startswith("lexical_hash_"))


def test_proxy_projection_and_no_label_leakage():
    r=from_proxy_headers({"X-Meta-Method":"GET","X-Meta-Uri":"/lab/fatget?id=1",
                          "X-Meta-Host":"lab.test","X-Meta-Content-Length":"12",
                          "X-Lab-Mode":"ml","X-Lab-Record-ID":"attack", "label":"1"})
    f=extract_features(r)
    assert tuple(f)==FEATURE_NAMES
    assert f["has_body_on_get"]==1
    assert "label" not in f and "attack" not in json.dumps(r)


def test_fixed_rules_and_documented_blind_spot():
    assert "host_mismatch" in rule_reasons(req(headers={"Host":"lab.test","X-Forwarded-Host":"evil.test"}))
    assert not rule_reasons(req("/lab/query?id=1&message=POISON"))
    assert "semicolon_count" in rule_reasons(req("/lab/cloaking?id=1&utm_content=x;message=POISON"))


def test_rare_header_profile_is_fit_on_normal_requests_only():
    normal = [req(headers={"Host":"lab.test", "User-Agent":"Browser"}) for _ in range(20)]
    profile = build_feature_profile(normal)
    attack = req(headers={"Host":"lab.test", "User-Agent":"Browser", "X-Forwarded-Host":"evil.test"})
    assert "x-forwarded-host" in profile["rare_headers"]
    assert extract_features(attack, profile)["rare_header_count"] == 1
    assert "has_x_forwarded_host" in normal_profile_reasons(attack, profile)


def test_constant_feature_is_not_a_magic_novelty_detector():
    # Same nonconstant coordinate, unseen constant coordinate: same score.
    x=np.column_stack([np.linspace(0,1,100),np.zeros(100)])
    m=IsolationForest(random_state=42,n_estimators=20).fit(x)
    assert np.isclose(m.score_samples([[.5,0]])[0],m.score_samples([[.5,1]])[0])


def test_backend_gadgets(tmp_path,monkeypatch):
    from backend import app as module
    monkeypatch.setattr(module,"DB",tmp_path/"backend.sqlite3")
    with TestClient(module.app) as c:
        assert c.get("/lab/xfh",headers={"X-Forwarded-Host":"poison.test"}).json()["value"]=="poison.test"
        html = c.get("/lab/xfh-page",headers={"X-Forwarded-Host":"attacker.com"}).text
        assert '<script src="https://attacker.com/resources/js/tracking.js"></script>' in html
        shop = c.get("/lab/shop/xfh?id=demo",headers={"X-Forwarded-Host":"attacker.com"}).text
        assert "Flaskr Store" in shop and '<script src="https://attacker.com/resources/js/tracking.js"></script>' in shop
        assert c.get("/lab/query?message=POISON").json()["value"]=="POISON"
        assert c.get("/lab/cloaking?id=1&utm_content=x;message=POISON").json()["value"]=="POISON"
        assert c.request("GET","/lab/fatget",content="message=POISON").json()["value"]=="POISON"
        assert c.get("/lab/fatget").json()["value"]=="NORMAL"


def test_missing_model_bypasses_and_observation_is_exact(tmp_path,monkeypatch):
    from detector import app as module
    monkeypatch.setattr(module,"DB",tmp_path/"detector.sqlite3")
    monkeypatch.setattr(module,"MODEL",tmp_path/"missing.joblib")
    monkeypatch.setattr(module,"EVENT_LOG",tmp_path/"detector-events.jsonl")
    h={"X-Lab-Mode":"ml","X-Meta-Method":"GET","X-Meta-Uri":"/lab/query?id=1","X-Meta-Host":"lab.test"}
    with TestClient(module.app) as c:
        r=c.get("/check",headers=h)
        assert r.status_code==204 and r.headers["x-bypass"]=="1"
        assert r.headers["x-decision"]=="model-unavailable"
        inspect = c.get("/inspect", headers={
            "X-Request-ID": "fusion-model-missing",
            "X-Meta-Method": "GET",
            "X-Meta-URI": "/labs/query/?cb=missing-model",
            "X-Meta-Host": "127.0.0.1:8086",
        })
        assert inspect.status_code == 503
        assert inspect.json()["detail"]["error"] == "model-unavailable"
        assert inspect.json()["detail"]["request_id"] == "fusion-model-missing"
        h.update({"X-Lab-Mode":"observe","X-Lab-Record-ID":"record-1"})
        assert c.get("/check",headers=h).headers["x-bypass"]=="0"
    with sqlite3.connect(module.DB) as db:
        observed=json.loads(db.execute("SELECT request_json FROM observations").fetchone()[0])
    assert observed==from_proxy_headers(h)


def test_fusion_inspect_api_is_observe_only_and_correlates_request_id(tmp_path, monkeypatch):
    from detector import app as module
    monkeypatch.setattr(module, "EVENT_LOG", tmp_path / "detector-events.jsonl")

    normal_headers = {
        "X-Request-ID": "fusion-stage7-normal",
        "X-Meta-Method": "GET",
        # A held-out normal Fusion shape, not an invented convenience row.
        "X-Meta-URI": "/labs/xfh/shop?cb=2b81971380ca321515d9990d&category=featured&page=1",
        "X-Meta-Host": "127.0.0.1:8086",
        "X-Meta-User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0",
        "X-Meta-Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "X-Meta-Accept-Language": "vi,en;q=0.8",
        "X-Meta-Cookie": "fusion_session=synthetic-2b81971380ca",
    }
    with TestClient(module.app) as client:
        normal = client.get("/inspect", headers=normal_headers)
        assert normal.status_code == 200
        body = normal.json()
        assert body["request_id"] == "fusion-stage7-normal"
        assert body["classification"] == "normal"
        assert body["detector_mode"] == "observe"
        assert body["action"] == "observe"
        assert body["recommended_cache_action"] == "cache-normal"
        assert isinstance(body["anomaly_score"], float)
        assert "probability" in body["score_convention"]
        assert normal.headers["x-fusion-cache-bypass"] == "0"
        assert normal.headers["cache-control"] == "no-store"

        attack = client.get("/inspect", headers={
            **normal_headers,
            "X-Request-ID": "fusion-stage7-xfh",
            "X-Meta-URI": "/labs/xfh/shop",
            "X-Meta-X-Forwarded-Host": "127.0.0.1:8087",
        })
        assert attack.status_code == 200
        attack_body = attack.json()
        assert attack_body["request_id"] == "fusion-stage7-xfh"
        assert attack_body["classification"] == "anomaly"
        assert attack_body["detector_mode"] == "observe"
        assert attack_body["action"] == "observe"
        assert attack_body["recommended_cache_action"] == "bypass-no-cache"
        assert attack.headers["x-fusion-cache-bypass"] == "0"
        assert "has_x_forwarded_host" in attack_body["components"]["normal_profile_deviations"]

        enforced = client.get("/inspect", headers={
            **normal_headers,
            "X-Request-ID": "fusion-stage8-enforced-xfh",
            "X-Meta-URI": "/labs/xfh/shop",
            "X-Meta-X-Forwarded-Host": "127.0.0.1:8087",
            "X-Fusion-Detector-Mode": "enforce",
        })
        assert enforced.status_code == 200
        enforced_body = enforced.json()
        assert enforced_body["classification"] == "anomaly"
        assert enforced_body["detector_mode"] == "enforce"
        assert enforced_body["action"] == "bypass-no-cache"
        assert enforced.headers["x-fusion-cache-bypass"] == "1"


def test_fusion_inspect_writes_sanitized_correlated_event(tmp_path, monkeypatch):
    from detector import app as module

    event_log = tmp_path / "detector-events.jsonl"
    monkeypatch.setattr(module, "EVENT_LOG", event_log)
    headers = {
        "X-Request-ID": "fusion-stage9-query",
        "X-Meta-Method": "GET",
        "X-Meta-URI": "/labs/query/?cb=0123456789abcdef01234567&utm_content='/><script>alert(1)</script>",
        "X-Meta-Host": "127.0.0.1:8086",
        "X-Meta-User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0",
        "X-Meta-Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "X-Meta-Accept-Language": "vi,en;q=0.8",
        "X-Meta-Cookie": "fusion_session=do-not-log-this-cookie",
    }
    with TestClient(module.app) as client:
        response = client.get("/inspect", headers=headers)
    assert response.status_code == 200
    events = [json.loads(line) for line in event_log.read_text(encoding="utf-8").splitlines()]
    event = next(row for row in events if row["schema"] == "fusion-detector-event-v2")
    assert event["schema"] == "fusion-detector-event-v2"
    assert event["request_id"] == "fusion-stage9-query"
    assert event["scenario"] == "query"
    assert event["uri_path"] == "/labs/query/"
    assert event["classification"] == response.json()["classification"]
    assert event["anomaly_score"] == response.json()["anomaly_score"]
    assert event["action"] == "observe"
    assert event["model_version"] is None
    assert event["feature_schema_version"] is None
    assert event["shadow_status"] == "queued"
    assert event["component_scores"] is None
    assert event["fallback_reason"] is None
    serialized = json.dumps(event)
    assert "alert(1)" not in serialized
    assert "do-not-log-this-cookie" not in serialized


def test_fusion_inspect_rejects_incomplete_or_invalid_metadata():
    from detector import app as module

    with TestClient(module.app) as client:
        missing = client.get("/inspect")
        assert missing.status_code == 422
        assert missing.json()["detail"]["error"] == "missing-fusion-metadata"

        invalid_uri = client.get("/inspect", headers={
            "X-Request-ID": "fusion-stage7-invalid-uri",
            "X-Meta-Method": "GET",
            "X-Meta-URI": "https://not-nginx-contract.example/",
            "X-Meta-Host": "127.0.0.1:8086",
        })
        assert invalid_uri.status_code == 422
        assert invalid_uri.json()["detail"]["error"] == "invalid-fusion-uri"
        assert invalid_uri.json()["detail"]["request_id"] == "fusion-stage7-invalid-uri"

        invalid_mode = client.get("/inspect", headers={
            "X-Request-ID": "fusion-stage8-invalid-mode",
            "X-Meta-Method": "GET",
            "X-Meta-URI": "/labs/query/",
            "X-Meta-Host": "127.0.0.1:8086",
            "X-Fusion-Detector-Mode": "off",
        })
        assert invalid_mode.status_code == 422
        assert invalid_mode.json()["detail"]["error"] == "invalid-detector-mode"
