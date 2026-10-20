"""Train and evaluate a non-promoted route-aware IF candidate.

The input is the safe processed dataset. Fitting uses train-normal only,
threshold calibration uses validation-normal only, and test attack rows are
read only after both choices are fixed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT / "ml-detector" / "data" / "processed" / "feature_records.jsonl"
DEFAULT_MODEL = ROOT / "ml-detector" / "artifacts" / "candidates" / "route_if_smoke.joblib"
ROUTES = ("xfh", "query", "utm", "fatget")


# Đọc các record JSONL phục vụ huấn luyện hoặc đánh giá.
def _read_jsonl(path: Path) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


# Chuyển feature rows thành ma trận theo đúng thứ tự schema.
def _matrix(rows: list[dict[str, object]], feature_names: tuple[str, ...]) -> np.ndarray:
    return np.asarray([[float(row["features"][name]) for name in feature_names] for row in rows], dtype=float)


# Tính confusion matrix và các metric của candidate.
def _metrics(prediction: np.ndarray, labels: np.ndarray) -> dict[str, float | int]:
    tp = int(np.sum((prediction == 1) & (labels == 1)))
    fp = int(np.sum((prediction == 1) & (labels == 0)))
    tn = int(np.sum((prediction == 0) & (labels == 0)))
    fn = int(np.sum((prediction == 0) & (labels == 1)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
    }


# Fit IF trên normal, hiệu chỉnh threshold và đánh giá theo split.
def train_evaluate(input_path: Path = DEFAULT_INPUT, model_path: Path = DEFAULT_MODEL,
                   fpr_target: float = 0.02, n_estimators: int = 200, random_state: int = 42) -> dict[str, object]:
    if not 0 < fpr_target < 1:
        raise ValueError("fpr_target must be in (0, 1)")
    rows = _read_jsonl(input_path)
    if not rows or {str(row["route"]) for row in rows} != set(ROUTES):
        raise ValueError("processed dataset must contain all four canonical routes")
    feature_names = tuple(rows[0]["features"])
    if len(feature_names) != 121 or any(set(row["features"]) != set(feature_names) for row in rows):
        raise ValueError("processed feature schema mismatch")
    bundles = {}
    route_metrics = {}
    for route in ROUTES:
        route_rows = [row for row in rows if row["route"] == route]
        train = [row for row in route_rows if row["split"] == "train"]
        validation = [row for row in route_rows if row["split"] == "validation"]
        test = [row for row in route_rows if row["split"] == "test"]
        if len(train) < 20 or len(validation) < 20:
            raise ValueError(f"{route} needs at least 20 train and validation normal rows")
        if any(row["label"] != 0 for row in train + validation):
            raise ValueError("train and validation must be normal-only")
        if not any(row["label"] == 0 for row in test) or not any(row["label"] == 1 for row in test):
            raise ValueError(f"{route} needs held-out normal and attack test rows")
        model = IsolationForest(
            n_estimators=n_estimators, contamination="auto", random_state=random_state, n_jobs=1
        ).fit(_matrix(train, feature_names))
        validation_scores = -model.score_samples(_matrix(validation, feature_names))
        threshold = float(np.quantile(validation_scores, 1 - fpr_target, method="higher"))
        test_scores = -model.score_samples(_matrix(test, feature_names))
        prediction = (test_scores > threshold).astype(int)
        labels = np.asarray([int(row["label"]) for row in test], dtype=int)
        route_metrics[route] = {
            **_metrics(prediction, labels),
            "threshold": threshold,
            "validation_observed_fpr": float(np.mean(validation_scores > threshold)),
            "train_normal_count": len(train),
            "validation_normal_count": len(validation),
            "test_count": len(test),
        }
        bundles[route] = {"model": model, "threshold": threshold}
    metadata = {
        "schema_version": "wcp-route-if-candidate-v1",
        "model_type": "RouteAwareIsolationForest",
        "candidate_only": True,
        "runtime_promotion": "forbidden without review",
        "input": str(input_path.relative_to(ROOT)).replace("\\", "/"),
        "feature_count": len(feature_names),
        "feature_names": list(feature_names),
        "fpr_target": fpr_target,
        "n_estimators": n_estimators,
        "random_state": random_state,
        "split_policy": "fit=train normal only; threshold=validation normal only; attacks=held-out test only",
        "csic_policy": "CSIC shared-normal corpus not mixed into route model or threshold calibration",
        "route_metrics": route_metrics,
    }
    bundle = {**metadata, "route_bundles": bundles}
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)
    metrics_path = model_path.with_suffix(".metrics.json")
    metrics_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return metadata


# Đọc tham số CLI và chạy huấn luyện/đánh giá candidate của train_evaluate_route_if.
def main() -> None:
    parser = argparse.ArgumentParser(description="Train a local route-aware IF candidate")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--fpr-target", type=float, default=0.02)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    print(json.dumps(train_evaluate(args.input, args.model, args.fpr_target, args.n_estimators, args.random_state), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
