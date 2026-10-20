"""Collect and score an independent blind test against frozen route candidates.

No fitting, feature selection, or threshold calibration occurs in this file.
All requests are collected before any held-out feature vector is scored.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
import sys
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import joblib
import numpy as np


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fatget_features import extract_fatget_features  # noqa: E402
from query_features import extract_query_v3  # noqa: E402
from traffic.fusion_collect import add_benign_cookie, load_route_registry, observe  # noqa: E402
from traffic.fusion_scenarios import FusionCase, base_headers  # noqa: E402
from utm_features import extract_utm_features  # noqa: E402
from xfh_features import extract_xfh_v2  # noqa: E402


FREEZE_MANIFEST = ROOT / "ml-detector" / "artifacts" / "evidence_freeze_v1" / "freeze_manifest.json"
OUTPUT = ROOT / "ml-detector" / "data" / "blind" / "blind_v1"
ARTIFACT_OUTPUT = ROOT / "ml-detector" / "artifacts" / "blind_test_v1"
RUNTIME_MODEL = ROOT / "models" / "isolation_forest.joblib"
SEED = 20261101
NORMAL_PER_ROUTE = 1000
ATTACK_PER_ROUTE = 1000
SESSION_SIZE = 10
ROUTES = ("query", "xfh", "utm", "fatget")
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 Version/19.1 Safari/605.1.15",
    "curl/8.16.0",
)
LANGUAGES = ("vi-VN,vi;q=0.8,en;q=0.6", "en-GB,en;q=0.8", "ja-JP,ja;q=0.8,en;q=0.5")


@dataclass(frozen=True)
class RouteRuntime:
    model: dict[str, object]
    profile: dict[str, object]
    extractor: object
    secondary_model_key: str
    secondary_names_key: str
    secondary_threshold_key: str


# Tính checksum SHA-256 để ràng buộc dữ liệu hoặc artifact với evidence.
def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# Chiếu lab case thành metadata đầu vào của model.
def _request(case: FusionCase) -> dict[str, object]:
    return {"method": case.method, "uri": case.uri, "headers": case.headers}


# Sinh Query normal case cho blind test.
def _normal_query(token: str, ua: str, language: str, index: int, method: str) -> FusionCase:
    headers = base_headers(ua, language)
    variants: tuple[list[tuple[str, str]], ...] = (
        [("cb", token), ("page", "5"), ("view", "gallery"), ("utm_content", "winter catalogue")],
        [("view", "table"), ("cb", token), ("page", "6"), ("utm_content", "partner referral")],
        [("cb", token), ("locale", "en-GB"), ("campaign", "boxing day"), ("utm_content", "email digest")],
        [("cb", token), ("q", "mechanical keyboard"), ("category", "accessories"), ("page", "2")],
        [("cb", token), ("page", "1"), ("sort", "rating"), ("currency", "USD")],
        [("cb", token), ("page", "3"), ("tag", "wireless"), ("tag", "office")],
        [("utm_content", "comparison guide"), ("cb", token), ("view", "cards"), ("page", "2")],
        [("cb", token), ("campaign", "spring preview"), ("source", "mobile app"), ("limit", "36")],
        [("cb", token), ("note", "staff pick"), ("ref", "weekly digest"), ("page", "1")],
        [("cb", token), ("locale", "ja-JP"), ("view", "compact"), ("utm_content", "regional launch")],
        [("cb", token), ("page", "7"), ("layout", "dense cards"), ("theme", "light")],
        [("cb", token), ("category", "networking"), ("q", "wifi adapter"), ("utm_content", "search result")],
    )
    return FusionCase(
        "query", "normal", "normal", f"blind-query-benign-{index % len(variants):02d}",
        method, "/labs/query/?" + urlencode(variants[index % len(variants)]), headers, "",
    )


# Sinh Query attack case cho blind test.
def _attack_query(token: str, ua: str, language: str, index: int) -> FusionCase:
    headers = base_headers(ua, language)
    variants = (
        ("javascript-confirm-context", "javascript:alert(71)"),
        ("globalthis-string-breakout", "';globalThis.alert(72);//"),
        ("svg-animation-context", "</script><svg><animate onbegin=alert(73) attributeName=x>"),
        ("details-toggle-context", "</script><details open ontoggle=alert(74)>"),
        ("data-url-context", "data:text/html,<svg onload=alert(75)>")
    )
    name, payload = variants[index % len(variants)]
    keyed = urlencode([("cb", token), ("page", "2"), ("view", "gallery")])
    return FusionCase(
        "query", "attack", "query-unkeyed-parameter", name, "GET",
        "/labs/query/?" + keyed + "&utm_content=" + payload.replace(" ", "%20"), headers, "",
    )


# Sinh XFH normal case cho blind test.
def _normal_xfh(token: str, ua: str, language: str, index: int, method: str) -> FusionCase:
    headers = base_headers(ua, language)
    hosts = (
        "127.0.0.1:8086", "localhost:8086", "fusion.local:8086",
        "shop.fusion.local:8086", "edge-a.fusion.local:8086",
        "edge-b.fusion.local:8086", "catalog.fusion.local:8086",
    )
    host = hosts[index % len(hosts)]
    headers["Host"] = host
    if index % 10 >= 3:
        headers["X-Forwarded-Host"] = host
    params = (
        [("cb", token), ("category", "networking"), ("page", "5")],
        [("cb", token), ("category", "audio"), ("view", "gallery")],
        [("category", "storage"), ("cb", token), ("sort", "rating")],
        [("cb", token), ("q", "power bank"), ("currency", "USD")],
        [("cb", token), ("campaign", "winter preview"), ("limit", "36")],
        [("cb", token), ("tag", "office"), ("tag", "wireless")],
    )[index % 6]
    return FusionCase(
        "xfh", "normal", "normal", f"blind-xfh-benign-{index % 42:02d}", method,
        "/labs/xfh/shop?" + urlencode(params), headers, "",
    )


# Sinh XFH attack case cho blind test.
def _attack_xfh(token: str, ua: str, language: str, index: int) -> FusionCase:
    headers = base_headers(ua, language)
    hosts = (
        "edge-b.fusion.local:8086", "catalog.fusion.local:8086", "fusion.local:8086",
        "shop.fusion.local:8086", "localhost:8086",
    )
    names = (
        "blind-edge-host-mismatch", "blind-catalog-host-mismatch", "blind-forwarded-with-proto",
        "blind-shop-host-mismatch", "blind-localhost-mismatch",
    )
    headers["Host"] = hosts[index % len(hosts)]
    headers["X-Forwarded-Host"] = "127.0.0.1:8087"
    if index % 5 == 2:
        headers["X-Forwarded-Proto"] = "http"
    uri = "/labs/xfh/shop?" + urlencode({"cb": token, "category": "networking", "page": str(6 + index % 3)})
    return FusionCase("xfh", "attack", "xfh-unkeyed-header", names[index % 5], "GET", uri, headers, "")


# Sinh UTM normal case cho blind test.
def _normal_utm(token: str, ua: str, language: str, index: int, method: str) -> FusionCase:
    headers = base_headers(ua, language)
    callback = ("countryReady", "locationHook", "regionCallback")[index % 3] + token[:8]
    locale = ("en-GB", "ja", "vi-VN", "en-US")[index % 4]
    variants: tuple[list[tuple[str, str]], ...] = (
        [("callback", callback), ("locale", locale)],
        [("callback", callback), ("locale", locale), ("view", "gallery")],
        [("callback", callback), ("locale", locale), ("utm_content", "winter newsletter")],
        [("callback", callback), ("locale", locale), ("utm_content", "regional guide"), ("theme", "light")],
        [("locale", locale), ("callback", callback), ("utm_content", "partner release"), ("campaign", "winter")],
        [("callback", callback), ("locale", locale), ("utm_content", "digest-" + token[:8] + ";locale=ja")],
        [("callback", callback), ("locale", locale), ("utm_content", "mobile-" + token[:8] + ";source=app")],
        [("callback", callback), ("locale", locale), ("utm_content", "preview-" + token[:8] + ";campaign=spring")],
        [("callback", callback), ("locale", locale), ("utm_content", "comparison page"), ("region", "eu")],
        [("callback", callback), ("locale", locale), ("utm_content", "weekly digest"), ("format", "jsonp")],
        [("callback", callback), ("locale", locale), ("tag", "regional"), ("tag", "featured")],
        [("callback", callback), ("locale", locale), ("utm_content", "mobile banner"), ("ref", "catalogue")],
    )
    return FusionCase(
        "utm", "normal", "normal", f"blind-utm-benign-{index % len(variants):02d}", method,
        "/labs/utm/js/geolocate.js?" + urlencode(variants[index % len(variants)]), headers, "",
    )


# Sinh UTM attack case cho blind test.
def _attack_utm(token: str, ua: str, language: str, index: int) -> FusionCase:
    headers = base_headers(ua, language)
    callback = ("countryReady", "locationHook", "regionCallback")[index % 3] + token[:8]
    number = 11 + index % 5
    prefixes = ("digest-", "mobile-", "preview-", "partner-", "regional-")
    uri = (
        "/labs/utm/js/geolocate.js?callback=" + callback + "&locale=en-GB&utm_content="
        + prefixes[index % 5] + token[:8] + ";callback=alert(" + str(number) + ")"
    )
    return FusionCase(
        "utm", "attack", "utm-parameter-cloaking", f"blind-semicolon-callback-{number}",
        "GET", uri, headers, "",
    )


# Sinh Fat GET normal case cho blind test.
def _normal_fatget(token: str, ua: str, language: str, index: int, method: str) -> FusionCase:
    headers = base_headers(ua, language)
    callback = ("countryReady", "locationHook", "regionCallback")[index % 3] + token[:8]
    locale = ("en-GB", "ja", "vi-VN", "en-US")[index % 4]
    variants: tuple[list[tuple[str, str]], ...] = (
        [("callback", callback), ("locale", locale)],
        [("callback", callback), ("locale", locale), ("view", "gallery")],
        [("locale", locale), ("callback", callback), ("region", "eu")],
        [("callback", callback), ("locale", locale), ("campaign", "winter preview")],
        [("callback", callback), ("locale", locale), ("theme", "light")],
        [("callback", callback), ("locale", locale), ("source", "mobile app")],
        [("callback", callback), ("locale", locale), ("tag", "regional"), ("tag", "featured")],
        [("callback", callback), ("locale", locale), ("format", "jsonp")],
        [("callback", callback), ("locale", locale), ("currency", "USD")],
        [("callback", callback), ("locale", locale), ("ref", "catalogue")],
        [("callback", callback), ("locale", locale), ("limit", "36")],
        [("callback", callback), ("locale", locale), ("view", "dense cards"), ("region", "eu")],
    )
    return FusionCase(
        "fatget", "normal", "normal", f"blind-fatget-benign-{index % len(variants):02d}", method,
        "/labs/fatget/js/geolocate.js?" + urlencode(variants[index % len(variants)]), headers, "",
    )


# Sinh Fat GET attack case cho blind test.
def _attack_fatget(token: str, ua: str, language: str, index: int) -> FusionCase:
    headers = base_headers(ua, language)
    callback = ("countryReady", "locationHook", "regionCallback")[index % 3] + token[:8]
    number = 11 + index % 5
    bodies = (
        f"callback=alert%28{number}%29&locale=en",
        f"source=mobile&callback=alert%28{number}%29&locale=en",
        f"locale=en&campaign=winter&callback=alert%28{number}%29",
        f"callback=alert%28{number}%29&note=regional+preview",
        f"ref=catalogue&callback=alert%28{number}%29&source=body",
    )
    body = bodies[index % 5]
    headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
    headers["Content-Length"] = str(len(body.encode("utf-8")))
    uri = "/labs/fatget/js/geolocate.js?" + urlencode({"callback": callback, "locale": "en-GB"})
    return FusionCase(
        "fatget", "attack", "fat-get-body", f"blind-body-callback-{number}",
        "GET", uri, headers, body,
    )


NORMAL_FACTORIES = {
    "query": _normal_query, "xfh": _normal_xfh, "utm": _normal_utm, "fatget": _normal_fatget,
}
ATTACK_FACTORIES = {
    "query": _attack_query, "xfh": _attack_xfh, "utm": _attack_utm, "fatget": _attack_fatget,
}


# Nạp model/profile frozen của từng route để chấm blind set.
def _load_frozen_runtimes(freeze: dict[str, object]) -> dict[str, RouteRuntime]:
    specs = {
        "query": ("query_v4_feature_profile.json", extract_query_v3,
                  "lexical_density_model", "lexical_density_feature_names", "lexical_density"),
        "xfh": ("xfh_v2_feature_profile.json", extract_xfh_v2,
                "relationship_model", "relationship_feature_names", "relationship"),
        "utm": ("utm_feature_profile.json", extract_utm_features,
                "relationship_model", "relationship_feature_names", "relationship"),
        "fatget": ("fatget_feature_profile.json", extract_fatget_features,
                   "relationship_model", "relationship_feature_names", "relationship"),
    }
    runtimes = {}
    for route, spec in specs.items():
        evidence = freeze["routes"][route]
        directory = ROOT / evidence["candidate_directory"]
        model_path = directory / "model.joblib"
        expected_model_hash = evidence["package"]["files"]["model.joblib"]
        if sha256(model_path) != expected_model_hash:
            raise ValueError(f"frozen {route} model hash mismatch")
        model = joblib.load(model_path)
        profile_path = directory / spec[0]
        runtimes[route] = RouteRuntime(
            model=model, profile=json.loads(profile_path.read_text(encoding="utf-8")), extractor=spec[1],
            secondary_model_key=spec[2], secondary_names_key=spec[3], secondary_threshold_key=spec[4],
        )
    return runtimes


# Kiểm tra freeze manifest và checksum trước blind test.
def _verify_freeze(freeze: dict[str, object]) -> None:
    if freeze.get("freeze_id") != "route-if-evidence-freeze-v1":
        raise ValueError("unexpected evidence freeze")
    if not freeze["policy"]["further_retuning_on_frozen_test_forbidden"]:
        raise ValueError("freeze policy does not forbid retuning")
    if sha256(RUNTIME_MODEL) != freeze["runtime_model"]["sha256"]:
        raise ValueError("runtime model changed since evidence freeze")
    for path_text, expected in freeze["source_sha256"].items():
        if sha256(ROOT / path_text) != expected:
            raise ValueError(f"frozen source changed: {path_text}")


# Tính confusion matrix và các metric của candidate.
def _metric(prediction: np.ndarray, labels: np.ndarray) -> dict[str, object]:
    tp = int(np.sum((prediction == 1) & (labels == 1)))
    fp = int(np.sum((prediction == 1) & (labels == 0)))
    tn = int(np.sum((prediction == 0) & (labels == 0)))
    fn = int(np.sum((prediction == 0) & (labels == 1)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "confusion_matrix": [[tn, fp], [fn, tp]], "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "false_discovery_rate": fp / (tp + fp) if tp + fp else 0.0,
    }


# Chuyển feature rows thành ma trận theo đúng thứ tự schema.
def _matrix(rows: list[dict[str, object]], names: list[str]) -> np.ndarray:
    return np.asarray([[float(row["features"][name]) for name in names] for row in rows], dtype=float)


# Đọc tham số CLI và chạy sealed blind test của run_blind_test_v1.
def main() -> None:
    if OUTPUT.exists() or ARTIFACT_OUTPUT.exists():
        raise FileExistsError("refusing to overwrite blind-test v1 evidence")
    freeze = json.loads(FREEZE_MANIFEST.read_text(encoding="utf-8"))
    _verify_freeze(freeze)
    runtimes = _load_frozen_runtimes(freeze)
    registry = load_route_registry()
    origin = "http://127.0.0.1:8086"
    if origin not in set(registry["allowed_targets"]):
        raise ValueError("blind target is not allowlisted")
    rng = random.Random(SEED)
    collection_id = "blind-v1-" + uuid.uuid4().hex[:12]
    captured: dict[str, list[tuple[str, FusionCase, dict[str, object]]]] = {route: [] for route in ROUTES}

    # Collection completes for all routes before any model score is calculated.
    for route in ROUTES:
        for label, count in (("normal", NORMAL_PER_ROUTE), ("attack", ATTACK_PER_ROUTE)):
            for index in range(count):
                token = f"{rng.getrandbits(96):024x}"
                ua, language = rng.choice(USER_AGENTS), rng.choice(LANGUAGES)
                if label == "normal":
                    method = "HEAD" if index / count < 0.20 else "GET"
                    case = NORMAL_FACTORIES[route](token, ua, language, index, method)
                else:
                    case = ATTACK_FACTORIES[route](token, ua, language, index)
                add_benign_cookie(case, token, rng, 0.60)
                observation = observe(origin, case)
                if observation["status"] != 200 or not observation["request_id"]:
                    raise RuntimeError(f"blind {route}/{label} collection failed")
                if label == "attack" and not observation["effect_observed"]:
                    raise RuntimeError(f"blind effect failed: {route}/{case.payload_variant}")
                group_id = f"{collection_id}-{route}-{label}-session-{index // SESSION_SIZE:05d}"
                captured[route].append((group_id, case, observation))
            print(f"Collected {count} blind {route} {label} records", flush=True)

    records_by_route: dict[str, list[dict[str, object]]] = {}
    for route in ROUTES:
        runtime = runtimes[route]
        rows = []
        for group_id, case, observation in captured[route]:
            features = runtime.extractor(_request(case), runtime.profile)
            rows.append({
                "schema_version": "wcp-blind-feature-record-v1",
                "record_id": uuid.uuid4().hex, "collection_id": collection_id,
                "group_id": group_id, "route": route, "split": "blind_test",
                "label": int(case.label == "attack"), "label_name": case.label,
                "attack_type": case.attack_type, "payload_variant": case.payload_variant,
                "features": {name: float(value) for name, value in features.items()},
                "evidence": {
                    "request_id": str(observation["request_id"]),
                    "http_status": int(observation["status"]),
                    "cache_status": str(observation["cache_status"]),
                    "cache_key_hash": hashlib.sha256(str(observation["cache_key"]).encode()).hexdigest(),
                    "effect_verified": bool(observation["effect_observed"]) if case.label == "attack" else None,
                },
                "privacy": {"raw_payload_stored": False, "raw_body_stored": False,
                            "raw_cookie_stored": False, "evidence_excluded_from_features": True},
            })
        records_by_route[route] = rows

    evaluations, decisions = {}, []
    for route in ROUTES:
        runtime = runtimes[route]
        model = runtime.model
        rows = records_by_route[route]
        labels = np.asarray([int(row["label"]) for row in rows], dtype=int)
        structural_scores = -model["structural_model"].score_samples(
            _matrix(rows, model["structural_feature_names"])
        )
        secondary_scores = -model[runtime.secondary_model_key].score_samples(
            _matrix(rows, model[runtime.secondary_names_key])
        )
        structural = structural_scores > float(model["thresholds"]["structural"])
        secondary = secondary_scores > float(model["thresholds"][runtime.secondary_threshold_key])
        if_prediction = (structural | secondary).astype(int)
        bounds = model["normal_profile_guard"]["bounds"]
        profile_prediction = np.asarray([
            int(any(float(row["features"][name]) < float(limit["min"]) or
                    float(row["features"][name]) > float(limit["max"])
                    for name, limit in bounds.items()))
            for row in rows
        ], dtype=int)
        hybrid_prediction = np.maximum(if_prediction, profile_prediction)
        if_unique = (if_prediction == 1) & (profile_prediction == 0)
        overlap = (if_prediction == 1) & (profile_prediction == 1)
        profile_unique = (if_prediction == 0) & (profile_prediction == 1)
        variant_metrics = {}
        for variant in sorted({row["payload_variant"] for row in rows if int(row["label"]) == 1}):
            mask = np.asarray([int(row["label"]) == 1 and row["payload_variant"] == variant for row in rows])
            variant_metrics[variant] = {
                "count": int(np.sum(mask)), "if_recall": float(np.mean(if_prediction[mask])),
                "profile_recall": float(np.mean(profile_prediction[mask])),
                "hybrid_recall": float(np.mean(hybrid_prediction[mask])),
            }
        metric = {
            "structural_if": _metric(structural.astype(int), labels),
            "secondary_if": _metric(secondary.astype(int), labels),
            "if_only": _metric(if_prediction, labels),
            "profile_only": _metric(profile_prediction, labels),
            "hybrid_or": _metric(hybrid_prediction, labels),
        }
        evaluations[route] = {
            "candidate_id": model["candidate_id"], "counts": {"normal": 1000, "attack": 1000},
            "metrics": metric,
            "contribution": {
                "if_unique_tp": int(np.sum(if_unique & (labels == 1))),
                "if_unique_fp": int(np.sum(if_unique & (labels == 0))),
                "profile_unique_tp": int(np.sum(profile_unique & (labels == 1))),
                "profile_unique_fp": int(np.sum(profile_unique & (labels == 0))),
                "overlap_tp": int(np.sum(overlap & (labels == 1))),
                "overlap_fp": int(np.sum(overlap & (labels == 0)),),
            },
            "variant_metrics": variant_metrics,
            "gate": {
                "recall_at_least_90_percent": metric["if_only"]["recall"] >= 0.90,
                "fpr_at_most_2_percent": metric["if_only"]["false_positive_rate"] <= 0.02,
            },
        }
        for index, row in enumerate(rows):
            decisions.append({
                "record_id": row["record_id"], "route": route, "label": int(labels[index]),
                "payload_variant": row["payload_variant"],
                "structural_score": float(structural_scores[index]),
                "secondary_score": float(secondary_scores[index]),
                "structural_anomaly": bool(structural[index]),
                "secondary_anomaly": bool(secondary[index]),
                "if_anomaly": bool(if_prediction[index]),
                "profile_anomaly": bool(profile_prediction[index]),
                "final_anomaly": bool(hybrid_prediction[index]),
            })

    OUTPUT.mkdir(parents=True)
    records_path = OUTPUT / "feature_records.jsonl"
    with records_path.open("w", encoding="utf-8") as handle:
        for route in ROUTES:
            for row in records_by_route[route]:
                handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    ARTIFACT_OUTPUT.mkdir(parents=True)
    decisions_path = ARTIFACT_OUTPUT / "decisions.jsonl"
    with decisions_path.open("w", encoding="utf-8") as handle:
        for row in decisions:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    evaluation_path = ARTIFACT_OUTPUT / "evaluation.json"
    evaluation = {
        "schema_version": "wcp-independent-blind-test-v1",
        "blind_test_id": collection_id, "created_at_epoch": round(time.time(), 3),
        "seed": SEED, "session_size": SESSION_SIZE,
        "policy": {
            "models_profiles_thresholds_frozen": True,
            "fit_or_calibration_performed": False,
            "all_collection_completed_before_scoring": True,
            "source_freeze_manifest": str(FREEZE_MANIFEST.relative_to(ROOT)).replace("\\", "/"),
            "source_freeze_manifest_sha256": sha256(FREEZE_MANIFEST),
        },
        "routes": evaluations,
        "overall_gate": {
            "all_routes_recall_at_least_90_percent": all(
                item["gate"]["recall_at_least_90_percent"] for item in evaluations.values()
            ),
            "all_routes_fpr_at_most_2_percent": all(
                item["gate"]["fpr_at_most_2_percent"] for item in evaluations.values()
            ),
        },
        "runtime_model_sha256": sha256(RUNTIME_MODEL),
        "runtime_model_unchanged_from_freeze": sha256(RUNTIME_MODEL) == freeze["runtime_model"]["sha256"],
    }
    evaluation_path.write_text(json.dumps(evaluation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest_path = ARTIFACT_OUTPUT / "manifest.json"
    manifest = {
        "schema_version": "wcp-blind-test-package-v1", "blind_test_id": collection_id,
        "counts": {"routes": 4, "normal_per_route": 1000, "attack_per_route": 1000, "total": 8000},
        "privacy": {"raw_payload_stored": False, "raw_body_stored": False, "raw_cookie_stored": False},
        "outputs": {
            "feature_records": str(records_path.relative_to(ROOT)).replace("\\", "/"),
            "decisions": str(decisions_path.relative_to(ROOT)).replace("\\", "/"),
            "evaluation": str(evaluation_path.relative_to(ROOT)).replace("\\", "/"),
        },
        "sha256": {
            "feature_records": sha256(records_path), "decisions": sha256(decisions_path),
            "evaluation": sha256(evaluation_path), "freeze_manifest": sha256(FREEZE_MANIFEST),
        },
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report_path = ARTIFACT_OUTPUT / "BLIND_TEST_REPORT.md"
    lines = [
        "# Independent Blind Test v1", "",
        "All four frozen candidates were scored without fitting or threshold changes.", "",
        "| Route | IF Recall | IF FPR | Precision | FDR | IF-only TP |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for route, item in evaluations.items():
        metric = item["metrics"]["if_only"]
        lines.append(
            f"| {route} | {metric['recall']:.2%} | {metric['false_positive_rate']:.2%} | "
            f"{metric['precision']:.2%} | {metric['false_discovery_rate']:.2%} | "
            f"{item['contribution']['if_unique_tp']} |"
        )
    lines += [
        "", "The blind set uses new collection/session IDs, user agents, normal values and attack variants.",
        "No candidate is automatically promoted by this result.", "",
    ]
    report_path.write_text("\n".join(lines), encoding="utf-8")
    checksum_path = ARTIFACT_OUTPUT / "CHECKSUMS.sha256"
    files = sorted(path for path in ARTIFACT_OUTPUT.iterdir() if path.is_file() and path.name != checksum_path.name)
    checksum_path.write_text("".join(f"{sha256(path)}  {path.name}\n" for path in files), encoding="ascii")
    print(json.dumps(evaluation, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
