"""Audit numeric feature variance using train-normal rows only.

This is a pre-training diagnostic, not an attack-driven feature selector.
Validation and test rows are counted for exclusion evidence but their feature
values are never included in any statistic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT / "ml-detector" / "data" / "processed" / "query" / "feature_records.jsonl"
DEFAULT_OUTPUT = ROOT / "ml-detector" / "data" / "manifests" / "query" / "train_normal_variance_audit.json"


# Đọc các record JSONL phục vụ huấn luyện hoặc đánh giá.
def _read_jsonl(path: Path) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


# Kiểm tra độ biến thiên feature trong normal train để phát hiện feature hằng hoặc lỗi dữ liệu.
def audit(input_path: Path = DEFAULT_INPUT, output_path: Path = DEFAULT_OUTPUT,
          route: str = "query", near_constant_ratio: float = 0.99) -> dict[str, object]:
    if not 0.5 < near_constant_ratio <= 1:
        raise ValueError("near-constant-ratio must be in (0.5, 1]")
    input_path = input_path.resolve()
    output_path = output_path.resolve()
    rows = _read_jsonl(input_path)
    if not rows:
        raise ValueError("processed dataset is empty")
    route_rows = [row for row in rows if row.get("route") == route]
    if len(route_rows) != len(rows):
        raise ValueError("variance audit input must contain exactly one requested route")
    train = [row for row in route_rows if row.get("split") == "train" and int(row.get("label", -1)) == 0]
    excluded = [row for row in route_rows if row not in train]
    if not train:
        raise ValueError("no train-normal rows found")
    if any(row.get("split") == "train" and int(row.get("label", -1)) != 0 for row in route_rows):
        raise ValueError("train split contains a non-normal row")

    feature_names = tuple(train[0]["features"])
    if any(set(row["features"]) != set(feature_names) for row in train):
        raise ValueError("train-normal feature schema mismatch")
    matrix = np.asarray([
        [float(row["features"][name]) for name in feature_names]
        for row in train
    ], dtype=float)

    details: dict[str, dict[str, float | int | bool]] = {}
    constant = []
    near_constant = []
    variable = []
    for index, name in enumerate(feature_names):
        values = matrix[:, index]
        counts = Counter(values.tolist())
        unique_count = len(counts)
        dominant_count = max(counts.values())
        dominant_ratio = dominant_count / len(values)
        is_constant = unique_count == 1
        is_near_constant = not is_constant and dominant_ratio >= near_constant_ratio
        details[name] = {
            "min": float(np.min(values)),
            "max": float(np.max(values)),
            "mean": float(np.mean(values)),
            "variance_population": float(np.var(values)),
            "std_population": float(np.std(values)),
            "unique_count": unique_count,
            "dominant_count": dominant_count,
            "dominant_ratio": dominant_ratio,
            "zero_ratio": float(np.mean(values == 0)),
            "constant": is_constant,
            "near_constant": is_near_constant,
        }
        if is_constant:
            constant.append(name)
        elif is_near_constant:
            near_constant.append(name)
        else:
            variable.append(name)

    group_ids = {str(row["group_id"]) for row in train}
    report = {
        "schema_version": "wcp-train-normal-variance-audit-v1",
        "route": route,
        "input": str(input_path.relative_to(ROOT)).replace("\\", "/"),
        "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "policy": "statistics computed from train-normal only; validation and test feature values excluded",
        "train_normal_rows": len(train),
        "train_group_count": len(group_ids),
        "excluded_row_counts": dict(sorted(Counter(
            f"{row['split']}_{'attack' if int(row['label']) else 'normal'}" for row in excluded
        ).items())),
        "feature_count": len(feature_names),
        "near_constant_ratio_threshold": near_constant_ratio,
        "summary": {
            "constant_count": len(constant),
            "near_constant_count": len(near_constant),
            "variable_count": len(variable),
        },
        "constant_features": constant,
        "near_constant_features": near_constant,
        "variable_features": variable,
        "features": details,
        "interpretation": {
            "constant": "cannot create an Isolation Forest split on this training sample",
            "near_constant": "may create unstable or low-support splits; review before modeling",
            "variance_scale_warning": "raw variance is not comparable across differently scaled features; use unique and dominant ratios too",
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


# Đọc tham số CLI và chạy huấn luyện/đánh giá candidate của audit_train_variance.
def main() -> None:
    parser = argparse.ArgumentParser(description="Audit feature variance on train-normal only")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--route", default="query")
    parser.add_argument("--near-constant-ratio", type=float, default=0.99)
    args = parser.parse_args()
    print(json.dumps(audit(args.input, args.output, args.route, args.near_constant_ratio), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
