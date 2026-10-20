"""Train the reproducible normal-only Isolation Forest baseline for Fusion.

The adapter in :mod:`traffic.fusion_features` is the only supported input. It
keeps attacks in the held-out test split, so neither fitting nor threshold
calibration can learn from test attacks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from common.features import FEATURE_NAMES, SCHEMA_VERSION, build_feature_profile, validate_feature_profile
from common.io import read_jsonl
from ml.model import FUSION_ROUTES, SCORE_CONVENTION, matrix


# The validated detector collection is the default. The earlier 400-record
# dataset remains a development snapshot and is intentionally not selected by
# an unqualified production-style training command.
DEFAULT_DATASET = Path("data/fusion/processed_detector_v2/ml_dataset.jsonl")
DEFAULT_PROFILE = Path("data/fusion/processed_detector_v2/feature_profile.json")
DEFAULT_MODEL = Path("models/isolation_forest.joblib")
FUSION_SOURCE = "synthetic-local-fusion-nginx-correlated"


# Tính checksum cho artifact và dữ liệu đầu vào.
def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Nạp và kiểm tra normal profile dùng khi train Baseline.
def _load_profile(path: Path) -> dict[str, object]:
    profile = json.loads(path.read_text(encoding="utf-8"))
    validate_feature_profile(profile)
    return profile


# Tách/kiểm tra các hàng normal train và validation, tránh dùng label làm feature.
def _validate_rows(rows: list[dict[str, object]]) -> tuple[list[dict], list[dict]]:
    if not rows:
        raise ValueError("Fusion dataset is empty")
    required = {"record_id", "request_id", "group", "split", "label", "source", "request"}
    for index, row in enumerate(rows):
        missing = required - set(row)
        if missing:
            raise ValueError(f"row {index} is missing fields: {sorted(missing)}")
        if row["source"] != FUSION_SOURCE:
            raise ValueError("Training requires the Fusion adapter dataset, not a legacy dataset")
        if "observation" in row or "response" in row:
            raise ValueError("Model input must not contain response-side fields")
    ids = [str(row["request_id"]) for row in rows]
    if "" in ids or len(ids) != len(set(ids)):
        raise ValueError("request_id must be non-empty and unique")

    groups = {split: {str(row["group"]) for row in rows if row["split"] == split}
              for split in ("train", "validation", "test")}
    if groups["train"] & groups["validation"] or groups["train"] & groups["test"] or groups["validation"] & groups["test"]:
        raise ValueError("Group leakage between splits")

    train = [row for row in rows if row["split"] == "train"]
    validation = [row for row in rows if row["split"] == "validation"]
    test = [row for row in rows if row["split"] == "test"]
    if len(train) < 20 or len(validation) < 20:
        raise ValueError("Need at least 20 training and 20 validation normal records")
    if any(row["label"] != 0 for row in train + validation):
        raise ValueError("Train and validation splits must contain normal requests only")
    if not test or not any(row["label"] == 0 for row in test) or not any(row["label"] == 1 for row in test):
        raise ValueError("Held-out test split must contain normal and attack records")
    if {str(row.get("lab", "")) for row in rows} != set(FUSION_ROUTES):
        raise ValueError("Route-aware training requires exactly the four vulnerable Fusion routes")
    for route in FUSION_ROUTES:
        route_train = [row for row in train if row["lab"] == route]
        route_validation = [row for row in validation if row["lab"] == route]
        if len(route_train) < 20 or len(route_validation) < 20:
            raise ValueError(f"Route {route} needs at least 20 train-normal and 20 validation-normal records")
    return train, validation


# Fit Isolation Forest trên normal train, chọn threshold từ validation normal và lưu bundle.
def train(dataset=DEFAULT_DATASET, profile_path=DEFAULT_PROFILE, model_path=DEFAULT_MODEL,
          fpr_target=.02, n_estimators=200, contamination="auto", random_state=42):
    """Fit train-normal and calibrate exclusively on validation-normal.

    ``contamination`` is only an Isolation Forest fitting setting. The stored
    operational threshold always comes from validation-normal scores instead.
    """
    dataset, profile_path, model_path = map(Path, (dataset, profile_path, model_path))
    if not 0 < fpr_target < 1:
        raise ValueError("fpr_target must be between 0 and 1")
    if n_estimators < 1:
        raise ValueError("n_estimators must be positive")
    if not dataset.is_file() or not profile_path.is_file():
        raise FileNotFoundError("Run `python -m traffic.fusion_features` before training")

    rows = read_jsonl(dataset)
    train_rows, validation_rows = _validate_rows(rows)
    profile = _load_profile(profile_path)
    if profile.get("sample_count") != len(train_rows):
        raise ValueError("Feature profile sample count does not match normal training split")
    expected_profile = build_feature_profile([row["request"] for row in train_rows], profile["rare_threshold"])
    if profile != expected_profile:
        raise ValueError("Feature profile is not derived exactly from normal training requests")

    route_bundles = {}
    route_metadata = {}
    for route in FUSION_ROUTES:
        route_train = [row for row in train_rows if row["lab"] == route]
        route_validation = [row for row in validation_rows if row["lab"] == route]
        # The profile remains a transparent structural guard. The IF receives
        # the 25 structural features plus bounded lexical hash features.
        route_profile = build_feature_profile([row["request"] for row in route_train], profile["rare_threshold"])
        x_train = matrix(route_train, route_profile, FEATURE_NAMES)
        model = IsolationForest(
            n_estimators=n_estimators, max_samples="auto", contamination=contamination,
            random_state=random_state, n_jobs=1,
        ).fit(x_train)
        validation_scores = -model.score_samples(matrix(route_validation, route_profile, FEATURE_NAMES))
        # Inference uses ``score > threshold``. ``higher`` guarantees
        # calibration is based only on validation-normal for this route.
        threshold = float(np.quantile(validation_scores, 1 - fpr_target, method="higher"))
        validation_fpr = float(np.mean(validation_scores > threshold))
        component = {
            "route": route,
            "model": model,
            "threshold": threshold,
            "feature_profile": route_profile,
            "score_convention": SCORE_CONVENTION,
            "train_count": len(route_train),
            "validation_normal_count": len(route_validation),
            "validation_observed_fpr": validation_fpr,
            "constant_features": [name for i, name in enumerate(FEATURE_NAMES) if np.ptp(x_train[:, i]) == 0],
        }
        route_bundles[route] = component
        route_metadata[route] = {name: value for name, value in component.items() if name not in {"model", "feature_profile"}}
    metadata = {
        "schema": SCHEMA_VERSION,
        "features": list(FEATURE_NAMES),
        "dataset": str(dataset).replace("\\", "/"),
        "dataset_sha256": _sha256(dataset),
        "training_source": FUSION_SOURCE,
        "split_policy": "per-route fit=train normal only; per-route threshold=validation normal only; attacks=held-out test only",
        "model_type": "RouteAwareIsolationForest",
        "n_estimators": n_estimators,
        "contamination": contamination,
        "random_state": random_state,
        "fpr_target": fpr_target,
        "score_convention": SCORE_CONVENTION,
        "sklearn_version": sklearn.__version__,
        "train_count": len(train_rows),
        "validation_normal_count": len(validation_rows),
        "route_metadata": route_metadata,
        "feature_profile_sha256": _sha256(profile_path),
    }
    bundle = {**metadata, "route_bundles": route_bundles}
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)
    metadata_path = model_path.with_name("model_metadata.json")
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, ensure_ascii=False, indent=2))
    print(f"Model: {model_path}")
    return metadata


# Đọc CLI rồi chạy huấn luyện Baseline.
def main() -> None:
    parser = argparse.ArgumentParser(description="Train Fusion normal-only Isolation Forest")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--fpr-target", type=float, default=.02)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--contamination", default="auto")
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    contamination = args.contamination if args.contamination == "auto" else float(args.contamination)
    train(args.dataset, args.profile, args.model, args.fpr_target, args.n_estimators, contamination, args.random_state)


if __name__ == "__main__":
    main()
