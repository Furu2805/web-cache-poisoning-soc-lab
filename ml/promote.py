"""Promote an Isolation Forest candidate only after a contribution ablation.

The runtime model is intentionally not replaced merely because the combined
detector has a good score. A candidate must add at least one held-out true
positive beyond normal-profile and add no IF-only false positive. This is a
small integrity gate for the educational Fusion lab, not a production MLOps
approval workflow.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from ml.model import load_bundle


# Tính checksum cho model candidate trước khi promote.
def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Kiểm tra evidence rồi sao chép artifact được duyệt vào runtime Baseline.
def promote(candidate_model: Path, evaluation_dir: Path, target_model: Path) -> dict[str, object]:
    candidate_model, evaluation_dir, target_model = map(Path, (candidate_model, evaluation_dir, target_model))
    contribution_path = evaluation_dir / "iforest_contribution.json"
    context_path = evaluation_dir / "evaluation_context.json"
    if not candidate_model.is_file() or not contribution_path.is_file() or not context_path.is_file():
        raise FileNotFoundError("Candidate model and its evaluation context/contribution files are required")

    bundle = load_bundle(candidate_model)
    contribution = json.loads(contribution_path.read_text(encoding="utf-8"))
    context = json.loads(context_path.read_text(encoding="utf-8"))
    if context.get("model_training_dataset_sha256") != bundle.get("dataset_sha256"):
        raise ValueError("Evaluation context does not match candidate training dataset")
    if not contribution.get("iforest_has_measured_incremental_value"):
        raise ValueError("Refusing promotion: IF has no held-out incremental true positive beyond normal-profile")
    if int(contribution.get("iforest_only_false_positives", -1)) != 0:
        raise ValueError("Refusing promotion: review IF-only false positives before promotion")

    target_model.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(candidate_model, target_model)
    candidate_metadata = candidate_model.with_name("model_metadata.json")
    target_metadata = target_model.with_name("model_metadata.json")
    if candidate_metadata.is_file():
        shutil.copy2(candidate_metadata, target_metadata)
    receipt = {
        "schema": "fusion-iforest-promotion-v1",
        "candidate_model": str(candidate_model).replace("\\", "/"),
        "candidate_sha256": _sha256(candidate_model),
        "target_model": str(target_model).replace("\\", "/"),
        "dataset_sha256": bundle["dataset_sha256"],
        "iforest_only_true_positives": contribution["iforest_only_true_positives"],
        "iforest_only_false_positives": contribution["iforest_only_false_positives"],
        "status": "promoted",
    }
    receipt_path = target_model.with_name("iforest_promotion_receipt.json")
    receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return receipt


# Đọc CLI và chạy quy trình promote thủ công.
def main() -> None:
    parser = argparse.ArgumentParser(description="Promote a Fusion IF candidate after contribution validation")
    parser.add_argument("--candidate-model", type=Path, required=True)
    parser.add_argument("--evaluation-dir", type=Path, required=True)
    parser.add_argument("--target-model", type=Path, default=Path("models/isolation_forest.joblib"))
    args = parser.parse_args()
    print(json.dumps(promote(args.candidate_model, args.evaluation_dir, args.target_model), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
