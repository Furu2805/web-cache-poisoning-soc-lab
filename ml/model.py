"""Shared inference helpers for legacy and route-aware IF bundles."""
from __future__ import annotations

from urllib.parse import urlsplit

import joblib
import numpy as np

from common.features import (
    FEATURE_NAMES,
    LEGACY_SCHEMA_VERSION,
    SCHEMA_VERSION,
    STRUCTURAL_FEATURE_NAMES,
    extract_features,
    normal_profile_reasons,
    validate_feature_profile,
)

FUSION_ROUTES = ("xfh", "query", "utm", "fatget")
SCORE_CONVENTION = "minus_score_samples; larger is more anomalous; not an attack probability"


# Phân loại request vào nhóm route của mô hình Baseline.
def route_for_request(request: dict[str, object]) -> str:
    """Select a vulnerable Fusion namespace without routing or endpoint changes."""
    parts = [part for part in urlsplit(str(request["uri"])).path.split("/") if part]
    if len(parts) < 2 or parts[0] != "labs" or parts[1] not in FUSION_ROUTES:
        raise ValueError("unsupported Fusion model route")
    if len(parts) > 2 and parts[2] == "fixed":
        raise ValueError("fixed route is not an ML model route")
    return parts[1]


# Chuyển các request thành ma trận feature cùng thứ tự cột.
def matrix(rows, feature_profile=None, feature_names=FEATURE_NAMES):
    return np.asarray([
        [extract_features(row["request"], feature_profile)[name] for name in feature_names]
        for row in rows
    ], dtype=float)


# Kiểm tra thành phần model và schema feature trong bundle.
def _validate_component(component: dict[str, object], feature_names) -> None:
    required = {"model", "threshold", "feature_profile", "score_convention"}
    missing = required - set(component)
    if missing:
        raise ValueError(f"Model component is incomplete: {sorted(missing)}")
    validate_feature_profile(component["feature_profile"])
    if component["score_convention"] != SCORE_CONVENTION:
        raise ValueError("Model score convention mismatch; retrain with this version")
    if not isinstance(component["threshold"], (float, int)):
        raise ValueError("Model threshold must be numeric")
    if list(feature_names) not in (list(STRUCTURAL_FEATURE_NAMES), list(FEATURE_NAMES)):
        raise ValueError("Unsupported model feature schema")


# Nạp bundle Baseline đã lưu và xác thực cấu trúc cần thiết.
def load_bundle(path):
    # Load only artifacts generated locally by this project, never untrusted joblib files.
    bundle = joblib.load(path)
    if bundle.get("schema") == LEGACY_SCHEMA_VERSION:
        if bundle.get("features") != list(STRUCTURAL_FEATURE_NAMES):
            raise ValueError("Legacy model/feature schema mismatch")
        _validate_component(bundle, STRUCTURAL_FEATURE_NAMES)
        bundle["bundle_kind"] = "legacy-global"
        return bundle

    if bundle.get("schema") != SCHEMA_VERSION or bundle.get("features") != list(FEATURE_NAMES):
        raise ValueError("Model/feature schema mismatch; retrain with this version")
    required = {"route_bundles", "dataset_sha256", "score_convention", "model_type"}
    missing = required - set(bundle)
    if missing:
        raise ValueError(f"Model metadata is incomplete: {sorted(missing)}")
    if bundle["score_convention"] != SCORE_CONVENTION:
        raise ValueError("Model score convention mismatch; retrain with this version")
    routes = bundle["route_bundles"]
    if set(routes) != set(FUSION_ROUTES):
        raise ValueError("Route-aware model must contain exactly the Fusion vulnerable routes")
    for route, component in routes.items():
        if component.get("route") != route:
            raise ValueError("Route bundle metadata mismatch")
        _validate_component(component, FEATURE_NAMES)
    bundle["bundle_kind"] = "route-aware"
    return bundle


# Chọn thành phần Baseline phù hợp với route request.
def select_component(bundle, request: dict[str, object]):
    if bundle.get("bundle_kind") == "legacy-global":
        return "legacy-global", bundle, STRUCTURAL_FEATURE_NAMES
    route = route_for_request(request)
    return route, bundle["route_bundles"][route], FEATURE_NAMES


# Kết hợp score IF và profile/rule guard thành assessment Baseline.
def inspect_request(bundle, request):
    """Return score, IF decision and structural-profile deviations."""
    _, component, feature_names = select_component(bundle, request)
    x = matrix([{"request": request}], component["feature_profile"], feature_names)
    score = float(-component["model"].score_samples(x)[0])
    profile_reasons = normal_profile_reasons(request, component["feature_profile"])
    return score, score > component["threshold"], profile_reasons


# Trả về điểm và kết luận Baseline cho một request.
def score_request(bundle, request):
    score, iforest_anomaly, profile_reasons = inspect_request(bundle, request)
    return score, bool(iforest_anomaly or profile_reasons)
