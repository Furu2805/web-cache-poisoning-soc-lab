"""Collect a fresh core-schema dataset for the v4-derived optimized candidate."""
from __future__ import annotations

import json
from pathlib import Path

from collect_query_candidate_v6 import normal_case
from collect_query_dataset import _attack_case_v4
from collect_query_dataset_core import collect
from query_features import (
    QUERY_V3_DENSITY_FEATURE_NAMES,
    QUERY_V3_FEATURE_NAMES,
    build_profile_v3,
    extract_query_v3,
)


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "ml-detector"


# Đọc tham số CLI và chạy thu dataset của collect_query_v4_optimized.
def main() -> None:
    manifest_path = BASE / "data/manifests/query_v4_optimized/dataset_manifest.json"
    result = collect(
        "http://127.0.0.1:8086",
        BASE / "data/raw/query_v4_optimized/requests.jsonl",
        BASE / "data/processed/query_v4_optimized/feature_records.jsonl",
        BASE / "artifacts/candidates/query_v4_optimized_feature_profile.json",
        manifest_path,
        train_normal=5000, validation_normal=1000,
        test_normal=1000, test_attack=1000,
        seed=20270311, dataset_version="v4-optimized",
        profile_builder=build_profile_v3,
        feature_extractor=extract_query_v3,
        feature_names=QUERY_V3_FEATURE_NAMES,
        density_names=QUERY_V3_DENSITY_FEATURE_NAMES,
        normal_factory=normal_case,
        attack_factory=_attack_case_v4,
    )
    result.update({
        "allowed_query_parameter_names": ["cb", "page", "utm_content", "view"],
        "derived_from_candidate": "query-phase2-v4-dual-if-conservative",
        "blind_v1_or_v2_records_used_for_training_or_calibration": False,
        "requires_new_blind_test": True,
    })
    manifest_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
