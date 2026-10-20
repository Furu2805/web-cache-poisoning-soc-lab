"""Fail-closed loader and unified inference for frozen route candidates."""
from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np

from common.features import extract_features

ROOT = Path(__file__).resolve().parents[1]
FEATURE_SOURCE = ROOT / "ml-detector" / "src"
if str(FEATURE_SOURCE) not in sys.path:
    sys.path.insert(0, str(FEATURE_SOURCE))

from fatget_features import extract_fatget_features  # noqa: E402
from query_v7_features import extract_query_v7_features  # noqa: E402
from utm_features import extract_utm_features  # noqa: E402
from xfh_features import extract_xfh_v2  # noqa: E402

REGISTRY_PATH = ROOT / "ml-detector" / "config" / "model_registry.json"
APPROVAL_SCHEMA = "wcp-model-registry-approval-v1"
ROUTES = {"query", "xfh", "utm", "fatget"}
EXTRACTORS = {
    "query": extract_query_v7_features,
    "xfh": extract_xfh_v2,
    "utm": extract_utm_features,
    "fatget": extract_fatget_features,
}


# Chỉ nhận diện bốn vulnerable route; fixed/unknown route không dùng candidate.
def route_for_request(request_metadata: dict[str, object]) -> str:
    parts = [part for part in urlsplit(str(request_metadata["uri"])).path.split("/") if part]
    if len(parts) < 2 or parts[0] != "labs" or parts[1] not in ROUTES:
        raise ValueError("unsupported model route")
    if len(parts) > 2 and parts[2] == "fixed":
        raise ValueError("fixed route is not a candidate model route")
    return parts[1]


# Đọc một tài liệu JSON của registry hoặc artifact.
def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


# Tính SHA-256 để đối chiếu tính toàn vẹn artifact.
def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# Giải đường dẫn artifact trong phạm vi cấu hình của project.
def _resolve(value: str) -> Path:
    path = (ROOT / value).resolve()
    if ROOT.resolve() not in path.parents:
        raise ValueError("registry path escapes project root")
    return path


# Kiểm tra manifest và checksum của artifact được đóng băng.
def _verify_manifest(path: Path) -> dict[str, str]:
    expected = {}
    for line in path.read_text(encoding="ascii").splitlines():
        checksum, name = line.split("  ", 1)
        target = (path.parent / name).resolve()
        if path.parent.resolve() not in target.parents or not target.is_file():
            raise ValueError(f"invalid checksum target: {name}")
        if _sha256(target) != checksum:
            raise ValueError(f"checksum mismatch: {name}")
        expected[name] = checksum
    return expected


# Lấy tên feature đúng thứ tự và kiểm tra schema.
def _schema_feature_names(schema: dict) -> tuple[list[str], list[str]]:
    structural = list(schema.get("structural_if", []))
    relationship = list(schema.get("relationship_if", schema.get("if_features", [])))
    if not relationship:
        raise ValueError("feature schema has no IF features")
    return structural, relationship


# Xác thực approval cho registry chỉ được load ở shadow mode.
def _verify_registry_approval(path: Path) -> dict:
    """Require operator evidence for the exact registry bytes being loaded."""
    approval_path = path.with_name(f"{path.stem}.approval.json")
    if not approval_path.is_file():
        raise ValueError("model registry approval manifest is missing")
    approval = _json(approval_path)
    if approval.get("schema_version") != APPROVAL_SCHEMA:
        raise ValueError("unsupported model registry approval schema")
    if approval.get("registry_path") != path.name:
        raise ValueError("model registry approval path mismatch")
    if approval.get("registry_sha256") != _sha256(path):
        raise ValueError("model registry approval checksum mismatch")
    if approval.get("decision") != "approved-shadow-only":
        raise ValueError("model registry is not approved for shadow runtime")
    if set(approval.get("routes", [])) != ROUTES or approval.get("automatic_enforcement") is not False:
        raise ValueError("model registry approval scope mismatch")
    evidence = approval.get("evidence", [])
    if not evidence or not all((_resolve(item)).is_file() for item in evidence):
        raise ValueError("model registry approval evidence is missing")
    return approval


# Nạp registry và kiểm tra model, profile, threshold, schema, checksum.
def load_registry(path: Path = REGISTRY_PATH) -> dict:
    _verify_registry_approval(path)
    raw = _json(path)
    if raw.get("schema_version") != "wcp-model-registry-v1":
        raise ValueError("unsupported model registry schema")
    routes = raw.get("routes")
    if not isinstance(routes, dict) or set(routes) != ROUTES:
        raise ValueError("registry must contain exactly the four supported routes")
    loaded = {}
    for route, entry in routes.items():
        if entry.get("route_id") != route or entry.get("mode") != "shadow":
            raise ValueError(f"registry route/mode mismatch: {route}")
        paths = {key: _resolve(entry[key]) for key in (
            "model_path", "threshold_path", "feature_schema_path", "feature_profile_path",
            "profile_guard_path", "checksum_manifest",
        )}
        manifest = _verify_manifest(paths["checksum_manifest"])
        for key in ("model_path", "threshold_path", "feature_schema_path", "feature_profile_path", "profile_guard_path"):
            if paths[key].name not in manifest:
                raise ValueError(f"{route} registry file is not covered by checksum manifest: {key}")
        artifact = joblib.load(paths["model_path"])
        thresholds = _json(paths["threshold_path"])
        schema = _json(paths["feature_schema_path"])
        if artifact.get("route") != route:
            raise ValueError(f"cross-route artifact rejected for {route}")
        if artifact.get("candidate_id") != entry.get("candidate_id"):
            raise ValueError(f"candidate ID mismatch for {route}")
        structural, relationship = _schema_feature_names(schema)
        if structural != list(artifact.get("structural_feature_names", [])):
            raise ValueError(f"structural feature schema mismatch for {route}")
        if relationship != list(artifact.get("relationship_feature_names", [])):
            raise ValueError(f"relationship feature schema mismatch for {route}")
        if thresholds != artifact.get("thresholds"):
            raise ValueError(f"threshold mismatch for {route}")
        loaded[route] = {
            **entry, **paths, "artifact": artifact, "thresholds": thresholds,
            "feature_schema": schema, "feature_profile": _json(paths["feature_profile_path"]),
            "profile_guard": _json(paths["profile_guard_path"]),
        }
    return loaded


# Sắp feature theo schema, từ chối thiếu/sai chiều hoặc giá trị không hữu hạn.
def _vector(features: dict[str, float], names: list[str]) -> np.ndarray:
    values = [float(features[name]) for name in names]
    if not all(math.isfinite(value) for value in values):
        raise ValueError("feature vector contains NaN or Infinity")
    return np.asarray([values], dtype=float)


# Gọi extractor riêng của route để tạo feature từ metadata request.
def extract_route_features(route: str, request_metadata: dict[str, object], registry: dict) -> dict[str, float]:
    if route not in registry:
        raise ValueError(f"unsupported model route: {route}")
    resolved = route_for_request(request_metadata)
    if resolved != route:
        raise ValueError(f"request route mismatch: expected {route}, got {resolved}")
    component = registry[route]
    specialized = EXTRACTORS[route](request_metadata, component["feature_profile"])
    features = {**extract_features(request_metadata), **specialized}
    required = (
        list(component["artifact"].get("structural_feature_names", []))
        + list(component["artifact"]["relationship_feature_names"])
        + list(component["profile_guard"].get("bounds", {}))
    )
    if component["profile_guard"].get("feature"):
        required.append(component["profile_guard"]["feature"])
    _vector(features, required)
    return {name: float(value) for name, value in features.items()}


# Đánh giá các guard theo profile và thu indicator vi phạm.
def _profile_anomaly(guard: dict, features: dict[str, float]) -> tuple[bool, list[str]]:
    if guard.get("type") == "explicit primitive":
        name = guard["feature"]
        bad = float(features[name]) != float(guard["normal_value"])
        return bad, [name] if bad else []
    reasons = []
    for name, bounds in guard.get("bounds", {}).items():
        value = float(features[name])
        if value < float(bounds["min"]) or value > float(bounds["max"]):
            reasons.append(name)
    return bool(reasons), reasons


# Chấm một batch cùng route bằng IF rồi kết hợp profile guard.
def score_route_feature_batch(route: str, feature_rows: list[dict[str, float]], registry: dict) -> list[dict]:
    """Score vectors with the same validated logic used by online inference."""
    if route not in registry:
        raise ValueError(f"unsupported model route: {route}")
    component = registry[route]
    if component["route_id"] != route or component["artifact"]["route"] != route:
        raise ValueError("cross-route model invocation rejected")
    artifact = component["artifact"]
    if not feature_rows:
        return []
    component_scores: dict[str, list[float]] = {}
    component_decisions: list[list[bool]] = []
    if artifact.get("structural_model") is not None:
        names = list(artifact["structural_feature_names"])
        matrix = np.vstack([_vector(features, names) for features in feature_rows])
        scores = [-float(value) for value in artifact["structural_model"].score_samples(matrix)]
        if not all(math.isfinite(value) for value in scores):
            raise ValueError("model score contains NaN or Infinity")
        component_scores["structural"] = scores
        component_decisions.append([value > float(component["thresholds"]["structural"]) for value in scores])
    names = list(artifact["relationship_feature_names"])
    matrix = np.vstack([_vector(features, names) for features in feature_rows])
    scores = [-float(value) for value in artifact["relationship_model"].score_samples(matrix)]
    if not all(math.isfinite(value) for value in scores):
        raise ValueError("model score contains NaN or Infinity")
    component_scores["relationship"] = scores
    component_decisions.append([value > float(component["thresholds"]["relationship"]) for value in scores])
    results = []
    for index, features in enumerate(feature_rows):
        profile_anomaly, profile_reasons = _profile_anomaly(component["profile_guard"], features)
        if_anomaly = any(decisions[index] for decisions in component_decisions)
        results.append({
            "route": route, "candidate_id": component["candidate_id"], "mode": "shadow",
            "component_scores": {name: values[index] for name, values in component_scores.items()},
            "thresholds": component["thresholds"], "if_anomaly": if_anomaly,
            "profile_anomaly": profile_anomaly, "profile_reasons": profile_reasons,
            "final_anomaly": bool(if_anomaly or profile_anomaly),
            "monitor_closely": bool(component.get("monitor_closely", False)),
        })
    return results


# Chấm một vector feature qua đường batch dùng chung.
def score_route_features(route: str, features: dict[str, float], registry: dict) -> dict:
    """Score one persisted or freshly extracted vector through the runtime path."""
    return score_route_feature_batch(route, [features], registry)[0]


# Giải route, trích feature và trả assessment của candidate.
def detect(route: str, request_metadata: dict[str, object], registry: dict) -> dict:
    if route not in registry:
        raise ValueError(f"unsupported model route: {route}")
    component = registry[route]
    if component["route_id"] != route or component["artifact"]["route"] != route:
        raise ValueError("cross-route model invocation rejected")
    features = extract_route_features(route, request_metadata, registry)
    return score_route_features(route, features, registry)
