import copy
import hashlib
import json
from pathlib import Path

import pytest

from ml.route_detector import REGISTRY_PATH, detect, load_registry


def request(route):
    paths = {"query": "/labs/query/", "xfh": "/labs/xfh/shop", "utm": "/labs/utm/js/geolocate.js", "fatget": "/labs/fatget/js/geolocate.js"}
    return {"method": "GET", "uri": paths[route], "headers": {"host": "localhost", "user-agent": "pytest", "accept-language": "en"}}


def test_registry_loads_all_routes_and_detects_without_fallback():
    registry = load_registry()
    assert set(registry) == {"query", "xfh", "utm", "fatget"}
    for route in registry:
        result = detect(route, request(route), registry)
        assert result["route"] == route
        assert result["candidate_id"] == registry[route]["candidate_id"]
        assert result["mode"] == "shadow"


def test_unknown_route_is_rejected():
    with pytest.raises(ValueError, match="unsupported model route"):
        detect("unknown", request("query"), load_registry())


def test_cross_route_invocation_is_rejected():
    registry = load_registry()
    registry["query"] = copy.copy(registry["xfh"])
    with pytest.raises(ValueError, match="cross-route"):
        detect("query", request("query"), registry)


def test_registry_rejects_schema_tampering(tmp_path):
    raw = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    raw["routes"]["query"]["feature_schema_path"] = "ml-detector/artifacts/candidates/xfh_phase1_v3/feature_schema.json"
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    approval = {
        "schema_version": "wcp-model-registry-approval-v1",
        "registry_path": "registry.json",
        "registry_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "decision": "approved-shadow-only",
        "routes": ["query", "xfh", "utm", "fatget"],
        "automatic_enforcement": False,
        "evidence": ["docs/CHUONG_5_KET_QUA_THUC_NGHIEM.md"],
    }
    (tmp_path / "registry.approval.json").write_text(json.dumps(approval), encoding="utf-8")
    with pytest.raises(ValueError):
        load_registry(path)


def test_registry_rejects_unapproved_byte_change(tmp_path):
    registry = tmp_path / "registry.json"
    registry.write_bytes(REGISTRY_PATH.read_bytes())
    approval = json.loads(REGISTRY_PATH.with_name("model_registry.approval.json").read_text(encoding="utf-8"))
    approval["registry_path"] = registry.name
    approval["registry_sha256"] = hashlib.sha256(registry.read_bytes()).hexdigest()
    (tmp_path / "registry.approval.json").write_text(json.dumps(approval), encoding="utf-8")
    registry.write_text(registry.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="approval checksum mismatch"):
        load_registry(registry)
