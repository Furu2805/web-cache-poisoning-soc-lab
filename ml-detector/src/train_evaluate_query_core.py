"""Shared trainer/evaluator for the retained Query dual Isolation Forest.

Training is normal-only.  The two component thresholds are calibrated from
Query validation-normal at one percent each.  Held-out test feature values are
loaded only after models, features, thresholds, and the profile guard have
been persisted in a frozen candidate artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / "ml-detector" / "data" / "processed" / "query_v4" / "feature_records.jsonl"
AUDIT = ROOT / "ml-detector" / "data" / "manifests" / "query_v4" / "train_normal_variance_audit.json"
DATASET_MANIFEST = ROOT / "ml-detector" / "data" / "manifests" / "query_v4" / "dataset_manifest.json"
FEATURE_PROFILE = ROOT / "ml-detector" / "artifacts" / "candidates" / "query_v4_feature_profile.json"
OUTPUT = ROOT / "ml-detector" / "artifacts" / "candidates" / "query_phase2_v4"
RUNTIME_MODEL = ROOT / "models" / "isolation_forest.joblib"
STRUCTURAL_PREFIXES = {
    "query_length", "query_count", "duplicate_param_count", "query_special_ratio",
    "percent_count", "selected_header_count", "selected_header_bytes",
    "max_selected_value_bytes", "cookie_bytes", "user_agent_bytes",
}
PROFILE_FEATURES = ("raw_angle_bracket_count", "single_quote_count", "semicolon_count")


# Tính checksum SHA-256 để ràng buộc dữ liệu hoặc artifact với evidence.
def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Chuyển feature rows thành ma trận theo đúng thứ tự schema.
def _matrix(rows: list[dict[str, object]], names: tuple[str, ...]) -> np.ndarray:
    return np.asarray([[float(row["features"][name]) for name in names] for row in rows], dtype=float)


# Tính confusion matrix và các metric của candidate.
def _metrics(prediction: np.ndarray, labels: np.ndarray) -> dict[str, object]:
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
    }


# Nạp train normal và validation normal cho bước fit/threshold.
def _load_fit_rows(path: Path) -> tuple[list[dict[str, object]], list[dict[str, object]], Counter[str]]:
    train, validation = [], []
    excluded: Counter[str] = Counter()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("route") != "query":
                raise ValueError("Query-v2 input must contain only route=query")
            split = str(row["split"])
            label = int(row["label"])
            if split == "train":
                if label:
                    raise ValueError("train must be normal-only")
                train.append(row)
            elif split == "validation":
                if label:
                    raise ValueError("validation must be normal-only")
                validation.append(row)
            else:
                excluded[f"test_{'attack' if label else 'normal'}"] += 1
    if len(train) != 5000 or len(validation) != 1000:
        raise ValueError("unexpected Query-v2 train/validation counts")
    return train, validation, excluded


# Nạp development test chỉ dùng cho đánh giá.
def _load_test(path: Path) -> list[dict[str, object]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                if row.get("route") == "query" and row.get("split") == "test":
                    rows.append(row)
    counts = Counter(int(row["label"]) for row in rows)
    if counts != Counter({0: 1000, 1: 1000}):
        raise ValueError(f"unexpected held-out counts: {dict(counts)}")
    return rows


# Fit IF trên normal train và chọn threshold trên validation normal.
def _fit(train: list[dict[str, object]], validation: list[dict[str, object]],
         names: tuple[str, ...], max_samples: int, seed: int,
         fpr_target: float) -> tuple[IsolationForest, float, float]:
    model = IsolationForest(
        n_estimators=500, max_samples=max_samples, contamination="auto",
        max_features=1.0, bootstrap=False, random_state=seed, n_jobs=1,
    ).fit(_matrix(train, names))
    scores = -model.score_samples(_matrix(validation, names))
    threshold = float(np.quantile(scores, 1 - fpr_target, method="higher"))
    return model, threshold, float(np.mean(scores > threshold))


# Học giới hạn profile guard từ normal train.
def _profile_bounds(train: list[dict[str, object]]) -> dict[str, dict[str, float]]:
    return {
        name: {
            "min": min(float(row["features"][name]) for row in train),
            "max": max(float(row["features"][name]) for row in train),
        }
        for name in PROFILE_FEATURES
    }


# Áp dụng profile guard để dự báo anomaly.
def _profile_prediction(rows: list[dict[str, object]], bounds: dict[str, dict[str, float]]) -> np.ndarray:
    return np.asarray([
        int(any(float(row["features"][name]) < limit["min"] or
                float(row["features"][name]) > limit["max"]
                for name, limit in bounds.items()))
        for row in rows
    ], dtype=int)


# So sánh kết quả IF-only, profile-only và hybrid.
def _variant_metrics(rows: list[dict[str, object]], predictions: dict[str, np.ndarray]) -> dict[str, object]:
    output = {}
    for variant in sorted({str(row["payload_variant"]) for row in rows if int(row["label"]) == 1}):
        mask = np.asarray([int(row["label"]) == 1 and row["payload_variant"] == variant for row in rows])
        output[variant] = {
            "count": int(np.sum(mask)),
            **{name: {"detected": int(np.sum(pred[mask])), "recall": float(np.mean(pred[mask]))}
               for name, pred in predictions.items()},
        }
    return output


# Ghi metric, cấu hình và checksum của lần chạy.
def _write_evidence(path: Path, evidence: dict[str, object]) -> None:
    lines = [
        f"# {evidence['candidate_id']} - Held-out Evidence", "",
        "Models and thresholds were frozen from train-normal/validation-normal before the held-out test was opened.", "",
        "| Detector | TP | FP | TN | FN | Precision | Recall | F1 | FPR |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for key, label in (("if_only", "Dual Isolation Forest"), ("profile_only", "Normal-profile"),
                       ("hybrid_or", "Hybrid OR")):
        metric = evidence["metrics"][key]
        lines.append(
            f"| {label} | {metric['tp']} | {metric['fp']} | {metric['tn']} | {metric['fn']} | "
            f"{metric['precision']:.4f} | {metric['recall']:.4f} | {metric['f1']:.4f} | "
            f"{metric['false_positive_rate']:.4f} |"
        )
    lines += ["", "## Component ablation", "", "| Component | Recall | FPR |", "| --- | ---: | ---: |"]
    for key, label in (("structural_if", "Structural IF"), ("lexical_density_if", "Lexical-density IF")):
        metric = evidence["metrics"][key]
        lines.append(f"| {label} | {metric['recall']:.4f} | {metric['false_positive_rate']:.4f} |")
    lines += ["", "Candidate-only artifact. Automatic runtime promotion is forbidden.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


# Huấn luyện và đánh giá candidate train_evaluate_query_core; lưu metric/evidence.
def run(input_path: Path = INPUT, audit_path: Path = AUDIT,
        output: Path = OUTPUT, fpr_each: float = 0.01, seed: int = 42,
        candidate_id: str = "query-phase2-v2-dual-if",
        expected_total_features: int = 553,
        density_mode: str = "all_density",
        feature_profile_path: Path = FEATURE_PROFILE,
        dataset_manifest_path: Path = DATASET_MANIFEST) -> dict[str, object]:
    input_path, audit_path, output = input_path.resolve(), audit_path.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to reopen/overwrite evaluated candidate: {output}")
    if not 0 < fpr_each <= 0.01:
        raise ValueError("each component FPR budget must be in (0, 0.01]")
    runtime_before = _sha256(RUNTIME_MODEL)
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    if audit["input_sha256"] != _sha256(input_path):
        raise ValueError("variance audit and Query-v2 input hash differ")
    variable = set(audit["variable_features"])
    structural_names = tuple(name for name in audit["variable_features"] if name in STRUCTURAL_PREFIXES)
    if density_mode == "dithered_only":
        density_names = tuple(name for name in audit["variable_features"] if name.endswith("_dithered"))
        expected_density_count = 3
    elif density_mode == "all_density":
        density_names = tuple(name for name in audit["variable_features"] if name.startswith("query_") and
                              not name.startswith("query_v2_hash_") and name not in STRUCTURAL_PREFIXES)
        expected_density_count = 13
    else:
        raise ValueError("unknown density feature mode")
    hash_names = tuple(name for name in audit["variable_features"] if name.startswith("query_v2_hash_"))
    if len(structural_names) != 10 or len(density_names) != expected_density_count or len(hash_names) < 400:
        raise ValueError("unexpected frozen Query-v2 feature views")

    train, validation, excluded = _load_fit_rows(input_path)
    structural_model, structural_threshold, structural_val_fpr = _fit(
        train, validation, structural_names, 512, seed, fpr_each
    )
    density_model, density_threshold, density_val_fpr = _fit(
        train, validation, density_names, 1024, seed + 1, fpr_each
    )
    bounds = _profile_bounds(train)
    val_structural = (-structural_model.score_samples(_matrix(validation, structural_names)) > structural_threshold)
    val_density = (-density_model.score_samples(_matrix(validation, density_names)) > density_threshold)
    validation_or_fpr = float(np.mean(val_structural | val_density))

    output.mkdir(parents=True)
    artifact = {
        "schema_version": "query-phase2-v2-dual-if-candidate-v1",
        "candidate_id": candidate_id,
        "route": "query", "candidate_only": True, "status": "frozen_unevaluated",
        "model_type": "DualIsolationForestOR",
        "structural_model": structural_model, "lexical_density_model": density_model,
        "structural_feature_names": list(structural_names),
        "lexical_density_feature_names": list(density_names),
        "audited_hash_feature_names": list(hash_names),
        "hash_usage_note": (
            "The 512-dimensional signed n-gram vector is persisted and variance-audited. "
            f"The final lexical IF consumes {len(density_names)} normal-only lexical density/novelty "
            "features to avoid high-dimensional hash dilution; no attack label selected them."
        ),
        "thresholds": {"structural": structural_threshold, "lexical_density": density_threshold},
        "validation_fpr": {"target_each": fpr_each, "structural": structural_val_fpr,
                           "lexical_density": density_val_fpr, "combined_or": validation_or_fpr},
        "normal_profile_guard": {"type": "train-normal primitive min/max", "bounds": bounds},
        "input_sha256": _sha256(input_path), "audit_sha256": _sha256(audit_path),
        "runtime_model_sha256_before": runtime_before,
        "decision": "structural_if OR lexical_density_if; final=if_anomaly OR normal_profile_anomaly",
    }
    model_path = output / "model.joblib"
    joblib.dump(artifact, model_path)
    (output / "threshold.json").write_text(json.dumps(artifact["thresholds"], indent=2) + "\n", encoding="utf-8")
    (output / "feature_schema.json").write_text(json.dumps({
        "schema_version": "query-request-features-candidate-v1", "total_persisted_features": expected_total_features,
        "structural_if": list(structural_names), "lexical_density_if": list(density_names),
        "audited_signed_hash": list(hash_names), "normal_profile_guard": list(PROFILE_FEATURES),
    }, indent=2) + "\n", encoding="utf-8")
    shutil.copy2(feature_profile_path, output / feature_profile_path.name)
    shutil.copy2(dataset_manifest_path, output / "dataset_manifest.json")
    shutil.copy2(audit_path, output / "train_normal_variance_audit.json")
    (output / "normal_profile_guard.json").write_text(json.dumps(artifact["normal_profile_guard"], indent=2) + "\n", encoding="utf-8")

    # Design is now immutable.  This is the sole held-out opening for v2.
    test = _load_test(input_path)
    labels = np.asarray([int(row["label"]) for row in test], dtype=int)
    structural_prediction = (-structural_model.score_samples(_matrix(test, structural_names)) > structural_threshold).astype(int)
    density_prediction = (-density_model.score_samples(_matrix(test, density_names)) > density_threshold).astype(int)
    if_prediction = np.maximum(structural_prediction, density_prediction)
    profile_prediction = _profile_prediction(test, bounds)
    hybrid_prediction = np.maximum(if_prediction, profile_prediction)
    predictions = {"if_only": if_prediction, "profile_only": profile_prediction, "hybrid_or": hybrid_prediction}
    metrics = {
        "structural_if": _metrics(structural_prediction, labels),
        "lexical_density_if": _metrics(density_prediction, labels),
        "if_only": _metrics(if_prediction, labels),
        "profile_only": _metrics(profile_prediction, labels),
        "hybrid_or": _metrics(hybrid_prediction, labels),
    }
    if_unique = (if_prediction == 1) & (profile_prediction == 0)
    profile_unique = (profile_prediction == 1) & (if_prediction == 0)
    overlap = (if_prediction == 1) & (profile_prediction == 1)
    contribution = {
        "if_unique_tp": int(np.sum(if_unique & (labels == 1))),
        "if_unique_fp": int(np.sum(if_unique & (labels == 0))),
        "profile_unique_tp": int(np.sum(profile_unique & (labels == 1))),
        "profile_unique_fp": int(np.sum(profile_unique & (labels == 0))),
        "overlap_tp": int(np.sum(overlap & (labels == 1))),
        "overlap_fp": int(np.sum(overlap & (labels == 0))),
    }
    accepted = (metrics["if_only"]["recall"] >= 0.90 and
                metrics["if_only"]["false_positive_rate"] <= 0.02 and
                contribution["if_unique_tp"] >= 1)
    evidence = {
        "schema_version": "query-phase2-held-out-evidence-v2", "candidate_id": artifact["candidate_id"],
        "evaluation_policy": "fit=train-normal; thresholds=validation-normal; final metrics=held-out test opened once",
        "pre_test_excluded_counts": dict(excluded), "test_counts": {"normal": 1000, "attack": 1000},
        "validation_fpr": artifact["validation_fpr"], "metrics": metrics, "contribution": contribution,
        "attack_variant_metrics": _variant_metrics(test, predictions),
        "acceptance": {
            "if_recall_at_least_90_percent": metrics["if_only"]["recall"] >= 0.90,
            "if_fpr_at_most_2_percent": metrics["if_only"]["false_positive_rate"] <= 0.02,
            "if_unique_true_positive_at_least_one": contribution["if_unique_tp"] >= 1,
            "eligible_for_manual_promotion_review": accepted,
            "automatic_promotion": False,
        },
        "runtime_model_unchanged": _sha256(RUNTIME_MODEL) == runtime_before,
    }
    evidence_path = output / "evaluation.json"
    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _write_evidence(output / "EVIDENCE.md", evidence)
    manifest = {
        "schema_version": "wcp-candidate-package-v2", "candidate_id": artifact["candidate_id"],
        "route": "query", "candidate_only": True, "status": "evaluated_not_promoted",
        "promotable": False, "automatic_promotion": False,
        "eligible_for_manual_promotion_review": accepted,
        "reason_not_promotable": "manual review is required even when acceptance criteria pass",
        "input_sha256": artifact["input_sha256"], "model_sha256": _sha256(model_path),
        "evaluation_sha256": _sha256(evidence_path), "runtime_model_sha256": _sha256(RUNTIME_MODEL),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    checksum_files = sorted(path for path in output.iterdir() if path.is_file() and path.name != "CHECKSUMS.sha256")
    (output / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in checksum_files), encoding="ascii"
    )
    if _sha256(RUNTIME_MODEL) != runtime_before:
        raise RuntimeError("runtime model changed during Query-v2 evaluation")
    return evidence


# Đọc tham số CLI và chạy huấn luyện/đánh giá candidate của train_evaluate_query_core.
def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze/evaluate Query-v2 dual IF candidate once")
    parser.add_argument("--input", type=Path, default=INPUT)
    parser.add_argument("--audit", type=Path, default=AUDIT)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--fpr-each", type=float, default=0.01)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    print(json.dumps(run(args.input, args.audit, args.output, args.fpr_each, args.seed), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
