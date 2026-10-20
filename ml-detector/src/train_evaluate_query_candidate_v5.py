"""Train/evaluate generalized Query candidate v5 on a new development set."""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

import joblib
import numpy as np


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common.features import STRUCTURAL_FEATURE_NAMES  # noqa: E402
from query_generalized_features import QUERY_GENERAL_DITHER_FEATURE_NAMES  # noqa: E402
from train_evaluate_utm import _fit, _matrix, _metrics, _variant_metrics  # noqa: E402


INPUT = ROOT / "ml-detector" / "data" / "processed" / "query_v5" / "feature_records.jsonl"
AUDIT = ROOT / "ml-detector" / "data" / "manifests" / "query_v5" / "train_normal_variance_audit.json"
DATASET_MANIFEST = ROOT / "ml-detector" / "data" / "manifests" / "query_v5" / "dataset_manifest.json"
FEATURE_PROFILE = ROOT / "ml-detector" / "artifacts" / "candidates" / "query_v5_feature_profile.json"
OUTPUT = ROOT / "ml-detector" / "artifacts" / "candidates" / "query_phase2_v5"
RUNTIME_MODEL = ROOT / "models" / "isolation_forest.joblib"
BLIND_V1_EVALUATION = ROOT / "ml-detector" / "artifacts" / "blind_test_v1" / "evaluation.json"
PROFILE_FEATURES = ("raw_angle_bracket_count", "single_quote_count", "semicolon_count")


# Tính checksum SHA-256 để ràng buộc dữ liệu hoặc artifact với evidence.
def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Nạp train normal và validation normal cho bước fit/threshold.
def _load_fit_rows() -> tuple[list[dict[str, object]], list[dict[str, object]], Counter[str]]:
    train, validation = [], []
    excluded: Counter[str] = Counter()
    with INPUT.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("route") != "query":
                raise ValueError("Query-v5 input must contain only route=query")
            split, label = str(row["split"]), int(row["label"])
            if split == "train":
                if label:
                    raise ValueError("Query-v5 train must be normal-only")
                train.append(row)
            elif split == "validation":
                if label:
                    raise ValueError("Query-v5 validation must be normal-only")
                validation.append(row)
            else:
                excluded[f"test_{'attack' if label else 'normal'}"] += 1
    if len(train) != 8000 or len(validation) != 2000:
        raise ValueError("unexpected Query-v5 train/validation counts")
    return train, validation, excluded


# Nạp development test chỉ dùng cho đánh giá.
def _load_test() -> list[dict[str, object]]:
    rows = []
    with INPUT.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                if row.get("route") == "query" and row.get("split") == "test":
                    rows.append(row)
    if Counter(int(row["label"]) for row in rows) != Counter({0: 1000, 1: 1000}):
        raise ValueError("Query-v5 development test must contain 1000 normal and 1000 attack")
    return rows


# Học giới hạn profile guard từ normal train.
def _profile_bounds(train: list[dict[str, object]]) -> dict[str, dict[str, float]]:
    return {
        name: {"min": min(float(row["features"][name]) for row in train),
               "max": max(float(row["features"][name]) for row in train)}
        for name in PROFILE_FEATURES
    }


# Áp dụng profile guard để dự báo anomaly.
def _profile_predict(rows: list[dict[str, object]], bounds: dict[str, dict[str, float]]) -> np.ndarray:
    return np.asarray([
        int(any(float(row["features"][name]) < limit["min"] or
                float(row["features"][name]) > limit["max"]
                for name, limit in bounds.items()))
        for row in rows
    ], dtype=int)


# Ghi metric, cấu hình và checksum của lần chạy.
def _write_evidence(path: Path, evidence: dict[str, object]) -> None:
    lines = [
        "# Query candidate v5 — Development Evidence", "",
        "This is post-blind-v1 development evidence, not a new blind-test claim.", "",
        "| Detector | TP | FP | TN | FN | Precision | Recall | F1 | FPR | FDR |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for key, label in (("if_only", "Dual Isolation Forest"),
                       ("profile_only", "Normal-profile guard"),
                       ("hybrid_or", "Hybrid OR")):
        metric = evidence["metrics"][key]
        lines.append(
            f"| {label} | {metric['tp']} | {metric['fp']} | {metric['tn']} | {metric['fn']} | "
            f"{metric['precision']:.4f} | {metric['recall']:.4f} | {metric['f1']:.4f} | "
            f"{metric['false_positive_rate']:.4f} | {metric['false_discovery_rate']:.4f} |"
        )
    lines += [
        "", "Candidate v5 does not use blind-v1 records for training or calibration.",
        "A completely new blind-v2 collection is required before any promotion decision.", "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


# Huấn luyện và đánh giá candidate train_evaluate_query_candidate_v5; lưu metric/evidence.
def run(fpr_each: float = 0.0025, seed: int = 510) -> dict[str, object]:
    if OUTPUT.exists():
        raise FileExistsError(f"refusing to overwrite Query-v5 candidate: {OUTPUT}")
    runtime_before = _sha256(RUNTIME_MODEL)
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    if audit["input_sha256"] != _sha256(INPUT):
        raise ValueError("Query-v5 variance audit and input hash differ")
    dataset_manifest = json.loads(DATASET_MANIFEST.read_text(encoding="utf-8"))
    if dataset_manifest.get("blind_v1_records_used_for_training") is not False:
        raise ValueError("Query-v5 provenance does not exclude blind-v1 records")
    variable = set(audit["variable_features"])
    structural_names = tuple(name for name in STRUCTURAL_FEATURE_NAMES if name in variable)
    relationship_names = tuple(name for name in QUERY_GENERAL_DITHER_FEATURE_NAMES if name in variable)
    hash_names = tuple(name for name in audit["variable_features"] if name.startswith("query_general_hash_"))
    if not structural_names or len(relationship_names) != 3 or len(hash_names) < 100:
        raise ValueError("unexpected Query-v5 feature views")

    train, validation, excluded = _load_fit_rows()
    structural_model, structural_threshold, structural_val_fpr = _fit(
        train, validation, structural_names, 512, seed, fpr_each
    )
    relationship_model, relationship_threshold, relationship_val_fpr = _fit(
        train, validation, relationship_names, 1024, seed + 1, fpr_each
    )
    bounds = _profile_bounds(train)
    val_structural = -structural_model.score_samples(_matrix(validation, structural_names)) > structural_threshold
    val_relationship = -relationship_model.score_samples(_matrix(validation, relationship_names)) > relationship_threshold
    validation_or_fpr = float(np.mean(val_structural | val_relationship))

    OUTPUT.mkdir(parents=True)
    artifact = {
        "schema_version": "query-v5-dual-if-candidate-v1",
        "candidate_id": "query-phase2-v5-generalized-syntax", "route": "query",
        "candidate_only": True, "status": "frozen_development_unevaluated",
        "model_type": "DualIsolationForestOR",
        "structural_model": structural_model, "relationship_model": relationship_model,
        "structural_feature_names": list(structural_names),
        "relationship_feature_names": list(relationship_names),
        "audited_hash_feature_names": list(hash_names),
        "thresholds": {"structural": structural_threshold, "relationship": relationship_threshold},
        "validation_fpr": {"target_each": fpr_each, "structural": structural_val_fpr,
                           "relationship": relationship_val_fpr, "combined_or": validation_or_fpr},
        "normal_profile_guard": {"type": "train-normal primitive min/max", "bounds": bounds},
        "decision": "structural_if OR generalized_relationship_if; final=if_anomaly OR profile_anomaly",
        "provenance": {
            "development_after_blind_v1": True,
            "blind_v1_records_used_for_training": False,
            "blind_v1_evaluation_sha256": _sha256(BLIND_V1_EVALUATION),
            "new_blind_v2_required": True,
        },
        "input_sha256": _sha256(INPUT), "audit_sha256": _sha256(AUDIT),
        "runtime_model_sha256_before": runtime_before,
    }
    model_path = OUTPUT / "model.joblib"
    joblib.dump(artifact, model_path)
    (OUTPUT / "threshold.json").write_text(json.dumps(artifact["thresholds"], indent=2) + "\n", encoding="utf-8")
    (OUTPUT / "feature_schema.json").write_text(json.dumps({
        "schema_version": "query-generalized-request-features-v1", "total_persisted_features": 552,
        "structural_if": list(structural_names), "relationship_if": list(relationship_names),
        "audited_signed_hash": list(hash_names), "normal_profile_guard": list(PROFILE_FEATURES),
    }, indent=2) + "\n", encoding="utf-8")
    shutil.copy2(FEATURE_PROFILE, OUTPUT / FEATURE_PROFILE.name)
    shutil.copy2(DATASET_MANIFEST, OUTPUT / "dataset_manifest.json")
    shutil.copy2(AUDIT, OUTPUT / "train_normal_variance_audit.json")
    (OUTPUT / "normal_profile_guard.json").write_text(
        json.dumps(artifact["normal_profile_guard"], indent=2) + "\n", encoding="utf-8"
    )

    test = _load_test()
    labels = np.asarray([int(row["label"]) for row in test], dtype=int)
    structural_prediction = (
        -structural_model.score_samples(_matrix(test, structural_names)) > structural_threshold
    ).astype(int)
    relationship_prediction = (
        -relationship_model.score_samples(_matrix(test, relationship_names)) > relationship_threshold
    ).astype(int)
    if_prediction = np.maximum(structural_prediction, relationship_prediction)
    profile_prediction = _profile_predict(test, bounds)
    hybrid_prediction = np.maximum(if_prediction, profile_prediction)
    metrics = {
        "structural_if": _metrics(structural_prediction, labels),
        "relationship_if": _metrics(relationship_prediction, labels),
        "if_only": _metrics(if_prediction, labels),
        "profile_only": _metrics(profile_prediction, labels),
        "hybrid_or": _metrics(hybrid_prediction, labels),
    }
    if_unique = (if_prediction == 1) & (profile_prediction == 0)
    overlap = (if_prediction == 1) & (profile_prediction == 1)
    profile_unique = (if_prediction == 0) & (profile_prediction == 1)
    contribution = {
        "if_unique_tp": int(np.sum(if_unique & (labels == 1))),
        "if_unique_fp": int(np.sum(if_unique & (labels == 0))),
        "profile_unique_tp": int(np.sum(profile_unique & (labels == 1))),
        "profile_unique_fp": int(np.sum(profile_unique & (labels == 0))),
        "overlap_tp": int(np.sum(overlap & (labels == 1))),
        "overlap_fp": int(np.sum(overlap & (labels == 0))),
    }
    accepted = (
        metrics["if_only"]["recall"] >= 0.90
        and metrics["if_only"]["false_positive_rate"] <= 0.02
        and contribution["if_unique_tp"] >= 1
    )
    evidence = {
        "schema_version": "query-v5-development-evidence-v1",
        "candidate_id": artifact["candidate_id"],
        "evaluation_scope": "new development hold-out; not blind v1 and not blind v2",
        "pre_test_excluded_counts": dict(excluded), "test_counts": {"normal": 1000, "attack": 1000},
        "validation_fpr": artifact["validation_fpr"], "metrics": metrics,
        "contribution": contribution,
        "attack_variant_metrics": _variant_metrics(test, {
            "if_only": if_prediction, "profile_only": profile_prediction, "hybrid_or": hybrid_prediction,
        }),
        "acceptance": {
            "development_recall_at_least_90_percent": metrics["if_only"]["recall"] >= 0.90,
            "development_fpr_at_most_2_percent": metrics["if_only"]["false_positive_rate"] <= 0.02,
            "if_unique_true_positive_at_least_one": contribution["if_unique_tp"] >= 1,
            "eligible_for_blind_v2": accepted,
            "eligible_for_runtime_promotion": False,
            "automatic_promotion": False,
        },
        "runtime_model_unchanged": _sha256(RUNTIME_MODEL) == runtime_before,
    }
    evaluation_path = OUTPUT / "evaluation.json"
    evaluation_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _write_evidence(OUTPUT / "EVIDENCE.md", evidence)
    manifest = {
        "schema_version": "wcp-candidate-package-v2", "candidate_id": artifact["candidate_id"],
        "route": "query", "candidate_only": True, "status": "development_evaluated_not_promoted",
        "promotable": False, "automatic_promotion": False,
        "eligible_for_blind_v2": accepted,
        "reason_not_promotable": "new blind-v2 evaluation is mandatory after blind-v1-informed development",
        "input_sha256": artifact["input_sha256"], "model_sha256": _sha256(model_path),
        "evaluation_sha256": _sha256(evaluation_path), "runtime_model_sha256": _sha256(RUNTIME_MODEL),
    }
    (OUTPUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    files = sorted(path for path in OUTPUT.iterdir() if path.is_file() and path.name != "CHECKSUMS.sha256")
    (OUTPUT / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in files), encoding="ascii"
    )
    if _sha256(RUNTIME_MODEL) != runtime_before:
        raise RuntimeError("runtime model changed during Query-v5 evaluation")
    return evidence


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
