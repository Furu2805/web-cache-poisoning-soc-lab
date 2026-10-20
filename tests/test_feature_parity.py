import hashlib
import json
import math
import copy
from pathlib import Path

import numpy as np
import pytest

from common.features import extract_features
from ml.route_detector import EXTRACTORS, _vector, detect, extract_route_features, load_registry, score_route_feature_batch

GOLDEN = Path(__file__).parent / "golden" / "route_detection_v1.json"


def _digest(features):
    payload = json.dumps(
        {name: features[name] for name in sorted(features)},
        sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture(scope="module")
def registry():
    return load_registry()


@pytest.mark.parametrize("route", ["query", "xfh", "utm", "fatget"])
def test_runtime_matches_collector_and_golden_vector(route, registry):
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))["vectors"][route]
    request = golden["request"]
    runtime = extract_route_features(route, request, registry)
    collector = {
        **extract_features(request),
        **EXTRACTORS[route](request, registry[route]["feature_profile"]),
    }
    assert runtime == collector
    assert all(isinstance(value, (int, float)) and math.isfinite(value) for value in runtime.values())
    assert _digest(runtime) == golden["feature_sha256"]

    decision = detect(route, request, registry)
    assert decision["component_scores"] == pytest.approx(golden["component_scores"], abs=1e-12)
    for name in ("if_anomaly", "profile_anomaly", "final_anomaly"):
        assert decision[name] is golden[name]


@pytest.mark.parametrize("route", ["query", "xfh", "utm", "fatget"])
def test_header_names_are_case_insensitive(route, registry):
    request = json.loads(GOLDEN.read_text(encoding="utf-8"))["vectors"][route]["request"]
    lowercase = {**request, "headers": {name.lower(): value for name, value in request["headers"].items()}}
    assert extract_route_features(route, request, registry) == extract_route_features(route, lowercase, registry)


def test_route_path_is_canonical_and_cross_route_or_fixed_is_rejected(registry):
    query = json.loads(GOLDEN.read_text(encoding="utf-8"))["vectors"]["query"]["request"]
    with pytest.raises(ValueError, match="request route mismatch"):
        detect("xfh", query, registry)
    fixed = {**query, "uri": "/labs/query/fixed/"}
    with pytest.raises(ValueError, match="fixed route"):
        detect("query", fixed, registry)


def test_invalid_content_length_has_deterministic_zero_behavior(registry):
    request = json.loads(GOLDEN.read_text(encoding="utf-8"))["vectors"]["fatget"]["request"]
    invalid = {**request, "headers": {**request["headers"], "Content-Length": "invalid"}}
    first = extract_route_features("fatget", invalid, registry)
    second = extract_route_features("fatget", invalid, registry)
    assert first == second
    assert first["declared_body_bytes"] == 0
    assert first["has_body_on_get"] == 0


def test_vector_rejects_missing_non_numeric_nan_and_infinity():
    with pytest.raises(KeyError):
        _vector({}, ["missing"])
    with pytest.raises((TypeError, ValueError)):
        _vector({"x": "not-numeric"}, ["x"])
    for value in (np.nan, np.inf, -np.inf):
        with pytest.raises(ValueError, match="NaN or Infinity"):
            _vector({"x": value}, ["x"])


def test_batch_scorer_rejects_non_finite_model_scores(registry):
    class NonFiniteModel:
        def score_samples(self, matrix):
            return np.full(len(matrix), np.nan)

    isolated = dict(registry)
    isolated["xfh"] = dict(registry["xfh"])
    isolated["xfh"]["artifact"] = copy.copy(registry["xfh"]["artifact"])
    isolated["xfh"]["artifact"]["relationship_model"] = NonFiniteModel()
    features = extract_route_features("xfh", {
        "method": "GET", "uri": "/labs/xfh/shop", "headers": {"host": "localhost"},
    }, isolated)
    with pytest.raises(ValueError, match="model score contains NaN or Infinity"):
        score_route_feature_batch("xfh", [features], isolated)


def test_detection_output_does_not_echo_request_content(registry):
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))["vectors"]
    for route, vector in golden.items():
        serialized = json.dumps(detect(route, vector["request"], registry))
        assert vector["request"]["uri"] not in serialized
        assert "headers" not in serialized.lower()
