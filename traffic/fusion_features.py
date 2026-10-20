"""Prepare leak-free request features from the labelled Fusion dataset.

The raw collector output is preserved. This adapter creates a model-facing
JSONL dataset, a CSV feature matrix, a normal-only header profile, and a
manifest under ``data/fusion/processed``.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from common.features import FEATURE_NAMES, SCHEMA_VERSION, build_feature_profile, extract_features
from common.io import read_jsonl, write_jsonl


DEFAULT_INPUT = Path("data/fusion/raw/fusion_dataset.jsonl")
DEFAULT_OUTPUT_DIR = Path("data/fusion/processed")
LABELS = {"normal": 0, "attack": 1}
METADATA_COLUMNS = (
    "record_id", "request_id", "group", "split", "label", "label_name",
    "lab", "attack_type", "payload_variant",
)


# Kiểm tra raw record và các trường bắt buộc trước khi xử lý.
def _validate_raw(rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError("Fusion dataset is empty")
    required = {"record_id", "request_id", "group_id", "split", "label", "lab", "request"}
    for index, row in enumerate(rows):
        missing = required - set(row)
        if missing:
            raise ValueError(f"row {index} is missing fields: {sorted(missing)}")
        if row["label"] not in LABELS:
            raise ValueError(f"row {index} has unsupported label: {row['label']!r}")
        request = row["request"]
        if not isinstance(request, dict) or not {"method", "uri", "headers"} <= set(request):
            raise ValueError(f"row {index} has an invalid request object")
    request_ids = [str(row["request_id"]) for row in rows]
    record_ids = [str(row["record_id"]) for row in rows]
    if "" in request_ids or len(request_ids) != len(set(request_ids)):
        raise ValueError("request_id must be non-empty and unique")
    if len(record_ids) != len(set(record_ids)):
        raise ValueError("record_id must be unique")


# Chuyển raw request record sang dạng metadata cho extractor.
def _adapt(row: dict[str, object]) -> dict[str, object]:
    label_name = str(row["label"])
    # Isolation Forest never sees attack rows during fit or threshold
    # calibration. All attacks become held-out test cases.
    split = str(row["split"]) if label_name == "normal" else "test"
    if split not in {"train", "validation", "test"}:
        raise ValueError(f"unsupported split: {split!r}")
    return {
        "record_id": str(row["record_id"]),
        "request_id": str(row["request_id"]),
        "group": str(row["group_id"]),
        "split": split,
        "label": LABELS[label_name],
        "label_name": label_name,
        "lab": str(row["lab"]),
        "attack_type": str(row.get("attack_type", "normal")),
        "payload_variant": str(row.get("payload_variant", "")),
        "source": "synthetic-local-fusion-nginx-correlated",
        "request": row["request"],
    }


# Kiểm tra các split và group không gây leakage.
def _validate_splits(rows: list[dict[str, object]]) -> None:
    train = [row for row in rows if row["split"] == "train"]
    validation = [row for row in rows if row["split"] == "validation"]
    test = [row for row in rows if row["split"] == "test"]
    if not train or not validation or not test:
        raise ValueError("train, validation and test must all be non-empty")
    if any(row["label"] != 0 for row in train + validation):
        raise ValueError("Isolation Forest train/validation splits must contain normal rows only")
    if not any(row["label"] == 0 for row in test) or not any(row["label"] == 1 for row in test):
        raise ValueError("test split must contain both normal and attack rows")
    groups = {name: {row["group"] for row in rows if row["split"] == name}
              for name in ("train", "validation", "test")}
    if groups["train"] & groups["validation"] or groups["train"] & groups["test"] or groups["validation"] & groups["test"]:
        raise ValueError("group leakage detected between splits")


# Tạo processed feature records theo route, tách feature khỏi label/evidence.
def prepare_features(input_path=DEFAULT_INPUT, output_dir=DEFAULT_OUTPUT_DIR,
                     rare_threshold=0.05) -> dict[str, object]:
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    raw = read_jsonl(input_path)
    _validate_raw(raw)
    rows = [_adapt(row) for row in raw]
    _validate_splits(rows)

    train_normal_requests = [row["request"] for row in rows if row["split"] == "train"]
    profile = build_feature_profile(train_normal_requests, rare_threshold)
    feature_rows = []
    for row in rows:
        features = extract_features(row["request"], profile)
        if set(features) != set(FEATURE_NAMES):
            raise ValueError("feature extractor returned an unexpected schema")
        feature_rows.append({**{name: row[name] for name in METADATA_COLUMNS}, **features})

    output_dir.mkdir(parents=True, exist_ok=True)
    dataset_path = output_dir / "ml_dataset.jsonl"
    csv_path = output_dir / "features.csv"
    profile_path = output_dir / "feature_profile.json"
    manifest_path = output_dir / "feature_manifest.json"
    write_jsonl(dataset_path, rows)
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*METADATA_COLUMNS, *FEATURE_NAMES])
        writer.writeheader()
        writer.writerows(feature_rows)
    profile_path.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    split_counts = Counter(str(row["split"]) for row in rows)
    split_label_counts = Counter(f"{row['split']}:{row['label_name']}" for row in rows)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source_dataset": str(input_path).replace("\\", "/"),
        "source_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "rows": len(rows),
        "split_counts": dict(split_counts),
        "split_label_counts": dict(split_label_counts),
        "feature_count": len(FEATURE_NAMES),
        "feature_names": list(FEATURE_NAMES),
        "metadata_columns_not_used_as_features": list(METADATA_COLUMNS),
        "feature_profile": str(profile_path).replace("\\", "/"),
        "outputs": {
            "ml_dataset": str(dataset_path).replace("\\", "/"),
            "features_csv": str(csv_path).replace("\\", "/"),
        },
        "policy": {
            "train_validation": "normal-only",
            "attack_usage": "held-out test only",
            "request_only_features": True,
            "response_fields_used": False,
            "request_id_used_as_feature": False,
        },
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Prepared {len(rows)} Fusion records with {len(FEATURE_NAMES)} request-only features")
    print(f"Splits: {dict(split_counts)}")
    print(f"Feature CSV: {csv_path}")
    return manifest


# Đọc tham số CLI và chạy bước chuẩn bị feature.
def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare Fusion request features for ML")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--rare-threshold", type=float, default=0.05)
    args = parser.parse_args()
    prepare_features(args.input, args.output_dir, args.rare_threshold)


if __name__ == "__main__":
    main()
