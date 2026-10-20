"""Validation-only calibration experiment for the Fusion Isolation Forest.

This is deliberately not a search for the highest test recall. It demonstrates
how the declared FPR target maps to a validation threshold and records that
``contamination`` is not used as the live decision threshold.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

from ml.model import matrix
from ml.train import DEFAULT_DATASET, DEFAULT_PROFILE, _load_profile, _validate_rows
from common.io import read_jsonl


DEFAULT_FPR_TARGETS = (0.01, 0.02, 0.05)
DEFAULT_CONTAMINATIONS = ("auto", 0.01, 0.05)


# Thử cấu hình Baseline trên development data và lưu evidence hiệu chỉnh.
def calibrate(dataset=DEFAULT_DATASET, profile_path=DEFAULT_PROFILE, output_dir="results",
              fpr_targets=DEFAULT_FPR_TARGETS, contaminations=DEFAULT_CONTAMINATIONS,
              n_estimators=200, random_state=42):
    dataset, profile_path, output_dir = map(Path, (dataset, profile_path, output_dir))
    rows = read_jsonl(dataset)
    train_rows, validation_rows = _validate_rows(rows)
    profile = _load_profile(profile_path)
    # Only these two normal-only splits are converted into feature vectors.
    x_train = matrix(train_rows, profile)
    x_validation = matrix(validation_rows, profile)
    reports = []
    for contamination in contaminations:
        model = IsolationForest(
            n_estimators=n_estimators, max_samples="auto", contamination=contamination,
            random_state=random_state, n_jobs=1,
        ).fit(x_train)
        scores = -model.score_samples(x_validation)
        for target in fpr_targets:
            if not 0 < target < 1:
                raise ValueError("FPR targets must be in (0, 1)")
            threshold = float(np.quantile(scores, 1 - target, method="higher"))
            reports.append({
                "contamination": contamination,
                "fpr_target": target,
                "threshold": threshold,
                "validation_observed_fpr": float(np.mean(scores > threshold)),
                "validation_score_min": float(scores.min()),
                "validation_score_mean": float(scores.mean()),
                "validation_score_max": float(scores.max()),
                "selected_for_stage6": contamination == "auto" and target == 0.02,
            })
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "tuning_validation.csv"
    with report_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(reports[0]))
        writer.writeheader()
        writer.writerows(reports)
    context = {
        "purpose": "validation-only threshold calibration; test attacks were not used",
        "selection_rule": "predeclared contamination=auto and fpr_target=0.02",
        "threshold_rule": "score > quantile(validation-normal, 1 - fpr_target, method='higher')",
        "note": "contamination is fitted-model configuration, not the operational threshold",
        "train_normal_count": len(train_rows),
        "validation_normal_count": len(validation_rows),
    }
    (output_dir / "tuning_context.json").write_text(json.dumps(context, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(reports, ensure_ascii=False, indent=2))
    return reports


# Đọc CLI rồi chạy calibration.
def main() -> None:
    parser = argparse.ArgumentParser(description="Run Fusion validation-only threshold calibration")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    args = parser.parse_args()
    calibrate(args.dataset, args.profile, args.output_dir)


if __name__ == "__main__":
    main()
