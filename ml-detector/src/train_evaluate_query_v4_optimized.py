"""Train/evaluate a v4-derived candidate on fresh core-schema development data."""
from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from train_evaluate_query_v4_optimized_core import run  # noqa: E402


# Đọc tham số CLI và chạy huấn luyện/đánh giá candidate của train_evaluate_query_v4_optimized.
def main() -> None:
    base = ROOT / "ml-detector"
    evidence = run(
        base / "data/processed/query_v4_optimized/feature_records.jsonl",
        base / "data/manifests/query_v4_optimized/train_normal_variance_audit.json",
        base / "artifacts/candidates/query_phase2_v4_optimized",
        fpr_each=0.0025,
        seed=146,
        candidate_id="query-phase2-v4-optimized-core-schema",
        expected_total_features=556,
        density_mode="dithered_only",
        feature_profile_path=base / "artifacts/candidates/query_v4_optimized_feature_profile.json",
        dataset_manifest_path=base / "data/manifests/query_v4_optimized/dataset_manifest.json",
    )
    print(json.dumps(evidence, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
