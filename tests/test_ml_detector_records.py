import json

from traffic.fusion_collect import build_row, load_route_registry
from traffic.fusion_scenarios import attack_case, normal_case


def _observation(*, effect=False):
    return {
        "status": 200,
        "cache_status": "MISS",
        "request_id": "record-test-request-id",
        "cache_key": "sensitive-cache-key-material",
        "lab_scenario": "xfh",
        "content_type": "text/html",
        "content_length": 123,
        "effect_observed": effect,
    }


def test_route_registry_is_canonical_for_the_four_ml_routes():
    registry = load_route_registry()
    assert registry["schema_version"] == "wcp-route-registry-v1"
    assert set(registry["routes"]) == {"xfh", "query", "utm", "fatget"}
    assert "cloaking" in registry["routes"]["utm"]["ui_aliases"]


def test_attack_record_separates_safe_request_features_from_evidence():
    case = attack_case("query", "0123456789abcdef01234567", "TestBrowser", "vi", 0)
    row = build_row("collection", "group", "test", case, _observation(effect=True), load_route_registry()["routes"])

    assert row["schema_version"] == "wcp-request-record-v1"
    assert row["route"] == {"id": "query", "scenario": "query", "variant": "vulnerable"}
    assert row["annotation"]["attack_type"] == "query-unkeyed-parameter"
    assert row["evidence"]["effect"]["verified"] is True
    assert row["evidence"]["cache"]["key_hash"]
    assert len(row["request_features"]["structural"]) == 25
    assert len(row["request_features"]["lexical_hash"]) == 96

    serialized = json.dumps(row)
    assert "alert(1)" not in serialized
    assert "sensitive-cache-key-material" not in serialized
    assert "Cookie" not in serialized


def test_normal_record_keeps_cache_evidence_outside_the_feature_object():
    case = normal_case("xfh", "0123456789abcdef01234567", "TestBrowser", "vi", 0)
    row = build_row("collection", "group", "train", case, _observation(), load_route_registry()["routes"])

    assert row["annotation"]["label"] == "normal"
    assert row["annotation"]["attack_type"] == "normal"
    assert row["evidence"]["cache"]["unkeyed_input"] is None
    assert "cache" not in row["request_features"]
    assert "evidence" not in row["request_features"]
