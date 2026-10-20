"""Collect and score Query blind-v2 using the locked Query v5 candidate."""
from __future__ import annotations

import hashlib
import json
import random
import sys
import time
import uuid
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlencode

import joblib
import numpy as np


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from query_generalized_features import extract_query_general_features  # noqa: E402
from traffic.fusion_collect import add_benign_cookie, load_route_registry, observe  # noqa: E402
from traffic.fusion_scenarios import FusionCase, base_headers  # noqa: E402


FREEZE = ROOT / "ml-detector/artifacts/query_v5_freeze/freeze_manifest.json"
OUTPUT = ROOT / "ml-detector/data/blind/query_blind_v2"
ARTIFACT = ROOT / "ml-detector/artifacts/query_blind_test_v2"
RUNTIME_MODEL = ROOT / "models/isolation_forest.joblib"
SEED = 20261217
NORMAL_COUNT = 1000
ATTACK_COUNT = 1000
SESSION_SIZE = 10
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 Chrome/156.0 Safari/537.36",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 16_1) AppleWebKit/620.2 Version/20.0 Safari/620.2",
    "HTTPie/3.3.0",
)
LANGUAGES = ("fr-FR,fr;q=0.9,en;q=0.5", "de-DE,de;q=0.8", "ko-KR,ko;q=0.9,en;q=0.4")


# Tính checksum SHA-256 để ràng buộc dữ liệu hoặc artifact với evidence.
def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# Chiếu lab case thành metadata đầu vào của model.
def request(case: FusionCase) -> dict[str, object]:
    return {"method": case.method, "uri": case.uri, "headers": case.headers}


# Sinh request normal cho blind test của route.
def normal_case(token: str, ua: str, language: str, index: int) -> FusionCase:
    headers = base_headers(ua, language)
    variants: tuple[list[tuple[str, str]], ...] = (
        [("cb", token), ("offset", "24"), ("filter", "available now"), ("channel", "desktop web")],
        [("cb", token), ("q", "ergonomic mouse"), ("sort", "price ascending"), ("currency", "EUR")],
        [("locale", "fr-FR"), ("cb", token), ("category", "smart home"), ("ref", "monthly bulletin")],
        [("cb", token), ("layout", "list view"), ("theme", "system default"), ("page", "8")],
        [("cb", token), ("campaign", "autumn collection"), ("source", "tablet client"), ("limit", "48")],
        [("cb", token), ("tag", "energy saving"), ("tag", "home office"), ("region", "apac")],
        [("utm_content", "editor choice"), ("cb", token), ("view", "comparison"), ("page", "4")],
        [("cb", token), ("note", "new arrival"), ("category", "wearables"), ("format", "html")],
        [("cb", token), ("q", "usb c dock"), ("filter", "ships today"), ("offset", "12")],
        [("cb", token), ("locale", "de-DE"), ("channel", "web portal"), ("theme", "high contrast")],
        [("cb", token), ("ref", "support article"), ("campaign", "member preview"), ("page", "9")],
        [("cb", token), ("category", "photography"), ("sort", "newest first"), ("limit", "60")],
        [("view", "grid compact"), ("cb", token), ("currency", "KRW"), ("region", "kr")],
        [("cb", token), ("source", "desktop app"), ("utm_content", "product roundup"), ("page", "10")],
        [("cb", token), ("filter", "refurbished"), ("category", "monitors"), ("layout", "wide")],
        [("cb", token), ("tag", "travel"), ("tag", "compact"), ("sort", "popularity")],
        [("cb", token), ("note", "limited stock"), ("locale", "ko-KR"), ("format", "html")],
        [("campaign", "holiday guide"), ("cb", token), ("ref", "community post"), ("offset", "36")],
        [("cb", token), ("q", "noise cancelling headset"), ("region", "eu"), ("page", "11")],
        [("cb", token), ("channel", "browser extension"), ("theme", "dark mode"), ("limit", "72")],
    )
    method = "HEAD" if index % 10 in (0, 1) else "GET"
    return FusionCase("query", "normal", "normal", f"blind-v2-query-benign-{index % len(variants):02d}",
                      method, "/labs/query/?" + urlencode(variants[index % len(variants)]), headers, "")


# Sinh request attack cho blind test của route.
def attack_case(token: str, ua: str, language: str, index: int) -> FusionCase:
    headers = base_headers(ua, language)
    variants = (
        ("iframe-source-context-v2", "</script><iframe srcdoc=<svg/onload=alert(81)>>"),
        ("javascript-confirm-context-v2", "javascript:alert(82)"),
        ("quote-window-context-v2", "\";window.alert(83);//"),
        ("math-event-context-v2", "</script><math><mtext onmouseover=alert(84)>x"),
        ("svg-load-context-v2", "</script><svg onload=alert(85)>") ,
    )
    name, payload = variants[index % len(variants)]
    keyed = urlencode([("cb", token), ("page", "4"), ("view", "comparison")])
    return FusionCase("query", "attack", "query-unkeyed-parameter", name, "GET",
                      "/labs/query/?" + keyed + "&utm_content=" + payload.replace(" ", "%20"), headers, "")


# Chuyển feature rows thành ma trận theo đúng thứ tự schema.
def matrix(rows: list[dict[str, object]], names: list[str]) -> np.ndarray:
    return np.asarray([[float(row["features"][name]) for name in names] for row in rows], dtype=float)


# Tính confusion matrix và các metric của candidate.
def metrics(pred: np.ndarray, labels: np.ndarray) -> dict[str, object]:
    tp = int(np.sum((pred == 1) & (labels == 1))); fp = int(np.sum((pred == 1) & (labels == 0)))
    tn = int(np.sum((pred == 0) & (labels == 0))); fn = int(np.sum((pred == 0) & (labels == 1)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"confusion_matrix": [[tn, fp], [fn, tp]], "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": precision, "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
            "false_discovery_rate": fp / (tp + fp) if tp + fp else 0.0}


# Đọc tham số CLI và chạy sealed blind test của run_query_blind_test_v2.
def main() -> None:
    if OUTPUT.exists() or ARTIFACT.exists():
        raise FileExistsError("refusing to overwrite Query blind-v2 evidence")
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    if freeze["freeze_id"] != "query-v5-pre-blind-v2-freeze":
        raise ValueError("unexpected freeze")
    if sha256(RUNTIME_MODEL) != freeze["runtime_model"]["sha256"]:
        raise ValueError("runtime model changed after freeze")
    for path_text, expected in freeze["source_sha256"].items():
        if sha256(ROOT / path_text) != expected:
            raise ValueError(f"frozen source changed: {path_text}")
    candidate = ROOT / freeze["candidate_directory"]
    for name, expected in freeze["candidate_package"]["files"].items():
        if sha256(candidate / name) != expected:
            raise ValueError(f"frozen candidate changed: {name}")
    model = joblib.load(candidate / "model.joblib")
    profile = json.loads((candidate / "query_v5_feature_profile.json").read_text(encoding="utf-8"))
    registry = load_route_registry()
    origin = "http://127.0.0.1:8086"
    if origin not in set(registry["allowed_targets"]):
        raise ValueError("target not allowlisted")

    rng = random.Random(SEED)
    collection_id = "query-blind-v2-" + uuid.uuid4().hex[:12]
    captured = []
    for label, count, factory in (("normal", NORMAL_COUNT, normal_case), ("attack", ATTACK_COUNT, attack_case)):
        for index in range(count):
            token = f"{rng.getrandbits(96):024x}"
            case = factory(token, rng.choice(USER_AGENTS), rng.choice(LANGUAGES), index)
            add_benign_cookie(case, token, rng, 0.60)
            observation = observe(origin, case)
            if observation["status"] != 200 or not observation["request_id"]:
                raise RuntimeError(f"blind-v2 collection failed: {label}/{case.payload_variant}")
            if label == "attack" and not observation["effect_observed"]:
                raise RuntimeError(f"blind-v2 effect failed: {case.payload_variant}")
            captured.append((label, index, case, observation))
        print(f"Collected {count} Query blind-v2 {label} records", flush=True)

    # Scoring starts only after both labels have been completely collected.
    rows = []
    for label, index, case, observation in captured:
        feature = extract_query_general_features(request(case), profile)
        rows.append({
            "schema_version": "wcp-query-blind-v2-feature-record-v1", "record_id": uuid.uuid4().hex,
            "collection_id": collection_id, "group_id": f"{collection_id}-{label}-session-{index // SESSION_SIZE:05d}",
            "route": "query", "split": "blind_test_v2", "label": int(label == "attack"),
            "label_name": label, "attack_type": case.attack_type, "payload_variant": case.payload_variant,
            "features": {name: float(value) for name, value in feature.items()},
            "evidence": {"request_id": str(observation["request_id"]), "http_status": int(observation["status"]),
                         "cache_status": str(observation["cache_status"]),
                         "cache_key_hash": hashlib.sha256(str(observation["cache_key"]).encode()).hexdigest(),
                         "effect_verified": bool(observation["effect_observed"]) if label == "attack" else None},
            "privacy": {"raw_payload_stored": False, "raw_cookie_stored": False,
                        "evidence_excluded_from_features": True},
        })

    labels = np.asarray([row["label"] for row in rows], dtype=int)
    structural_score = -model["structural_model"].score_samples(matrix(rows, model["structural_feature_names"]))
    relationship_score = -model["relationship_model"].score_samples(matrix(rows, model["relationship_feature_names"]))
    structural = structural_score > float(model["thresholds"]["structural"])
    relationship = relationship_score > float(model["thresholds"]["relationship"])
    if_pred = (structural | relationship).astype(int)
    bounds = model["normal_profile_guard"]["bounds"]
    profile_pred = np.asarray([int(any(float(row["features"][name]) < float(limit["min"]) or
                                      float(row["features"][name]) > float(limit["max"])
                                      for name, limit in bounds.items())) for row in rows], dtype=int)
    hybrid = np.maximum(if_pred, profile_pred)
    if_unique = (if_pred == 1) & (profile_pred == 0)

    variant = defaultdict(lambda: {"count": 0, "if_detected": 0, "profile_detected": 0, "hybrid_detected": 0})
    decisions = []
    for i, row in enumerate(rows):
        item = variant[row["payload_variant"]]
        item["count"] += 1; item["if_detected"] += int(if_pred[i])
        item["profile_detected"] += int(profile_pred[i]); item["hybrid_detected"] += int(hybrid[i])
        decisions.append({"record_id": row["record_id"], "label": int(labels[i]),
                          "payload_variant": row["payload_variant"],
                          "structural_score": float(structural_score[i]),
                          "relationship_score": float(relationship_score[i]),
                          "if_anomaly": bool(if_pred[i]), "profile_anomaly": bool(profile_pred[i]),
                          "final_anomaly": bool(hybrid[i])})
    variant_metrics = {name: {**item, "if_rate": item["if_detected"] / item["count"],
                              "profile_rate": item["profile_detected"] / item["count"],
                              "hybrid_rate": item["hybrid_detected"] / item["count"]}
                       for name, item in sorted(variant.items())}
    evaluation = {
        "schema_version": "wcp-query-independent-blind-test-v2", "blind_test_id": collection_id,
        "created_at_epoch": round(time.time(), 3), "seed": SEED, "session_size": SESSION_SIZE,
        "candidate_id": model["candidate_id"],
        "policy": {"candidate_frozen_before_collection": True, "fit_or_calibration_performed": False,
                   "all_collection_completed_before_scoring": True,
                   "freeze_manifest_sha256": sha256(FREEZE), "retuning_on_this_set_forbidden": True},
        "counts": {"normal": NORMAL_COUNT, "attack": ATTACK_COUNT},
        "metrics": {"structural_if": metrics(structural.astype(int), labels),
                    "relationship_if": metrics(relationship.astype(int), labels),
                    "if_only": metrics(if_pred, labels), "profile_only": metrics(profile_pred, labels),
                    "hybrid_or": metrics(hybrid, labels)},
        "contribution": {"if_unique_tp": int(np.sum(if_unique & (labels == 1))),
                         "if_unique_fp": int(np.sum(if_unique & (labels == 0)))},
        "variant_metrics": variant_metrics,
        "gate": {"recall_at_least_90_percent": metrics(if_pred, labels)["recall"] >= 0.90,
                 "fpr_at_most_2_percent": metrics(if_pred, labels)["false_positive_rate"] <= 0.02,
                 "if_unique_tp_at_least_one": int(np.sum(if_unique & (labels == 1))) >= 1},
        "runtime_model_sha256": sha256(RUNTIME_MODEL),
        "runtime_model_unchanged_from_freeze": sha256(RUNTIME_MODEL) == freeze["runtime_model"]["sha256"],
    }

    OUTPUT.mkdir(parents=True)
    records_path = OUTPUT / "feature_records.jsonl"
    records_path.write_text("".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows), encoding="utf-8")
    ARTIFACT.mkdir(parents=True)
    decisions_path = ARTIFACT / "decisions.jsonl"
    decisions_path.write_text("".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in decisions), encoding="utf-8")
    evaluation_path = ARTIFACT / "evaluation.json"
    evaluation_path.write_text(json.dumps(evaluation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report_path = ARTIFACT / "BLIND_TEST_REPORT.md"
    report_path.write_text(
        "# Query independent blind test v2\n\n"
        "Candidate, profile and thresholds were frozen before collection. No fitting or calibration occurred.\n\n"
        "| Detector | Recall | FPR | Precision | FDR |\n| --- | ---: | ---: | ---: | ---: |\n" +
        "\n".join(f"| {name} | {value['recall']:.2%} | {value['false_positive_rate']:.2%} | "
                  f"{value['precision']:.2%} | {value['false_discovery_rate']:.2%} |"
                  for name, value in evaluation["metrics"].items()) +
        "\n\nBlind-v2 is opened evidence. Retuning this candidate on these records is forbidden.\n", encoding="utf-8")
    manifest_path = ARTIFACT / "manifest.json"
    manifest = {"schema_version": "wcp-query-blind-v2-package-v1", "blind_test_id": collection_id,
                "status": "sealed_opened_blind_evidence", "retuning_on_this_blind_set_forbidden": True,
                "outputs": {"feature_records": str(records_path.relative_to(ROOT)).replace("\\", "/"),
                            "decisions": str(decisions_path.relative_to(ROOT)).replace("\\", "/"),
                            "evaluation": str(evaluation_path.relative_to(ROOT)).replace("\\", "/"),
                            "report": str(report_path.relative_to(ROOT)).replace("\\", "/")},
                "sha256": {"feature_records": sha256(records_path), "decisions": sha256(decisions_path),
                           "evaluation": sha256(evaluation_path), "report": sha256(report_path),
                           "freeze_manifest": sha256(FREEZE)}}
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    files = sorted(path for path in ARTIFACT.iterdir() if path.is_file() and path.name != "CHECKSUMS.sha256")
    (ARTIFACT / "CHECKSUMS.sha256").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in files), encoding="ascii")
    print(json.dumps(evaluation, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
