"""Collect a fresh core-schema development dataset for Query v6.1."""
from __future__ import annotations

import json
from pathlib import Path

import collect_query_candidate_v5 as base
from collect_query_candidate_v6 import attack_case, normal_case
from query_v61_density_features import (
    QUERY_V61_DENSITY_FEATURE_NAMES,
    QUERY_V61_FEATURE_NAMES,
    build_query_v61_profile,
    extract_query_v61_features,
)


ROOT = Path(__file__).resolve().parents[2]


# Sinh request theo scenario, thu response evidence và ghi dataset theo split.
def collect() -> dict[str, object]:
    base.RAW = ROOT / "ml-detector/data/raw/query_v61/requests.jsonl"
    base.PROCESSED = ROOT / "ml-detector/data/processed/query_v61/feature_records.jsonl"
    base.PROFILE = ROOT / "ml-detector/artifacts/candidates/query_v61_feature_profile.json"
    base.MANIFEST = ROOT / "ml-detector/data/manifests/query_v61/dataset_manifest.json"
    base.normal_case, base.attack_case = normal_case, attack_case
    base.build_query_general_profile = build_query_v61_profile
    base.extract_query_general_features = extract_query_v61_features
    base.QUERY_GENERAL_FEATURE_NAMES = QUERY_V61_FEATURE_NAMES
    base.QUERY_GENERAL_DENSITY_FEATURE_NAMES = tuple(base.QUERY_GENERAL_DENSITY_FEATURE_NAMES) + QUERY_V61_DENSITY_FEATURE_NAMES
    manifest = base.collect(seed=20270223)
    manifest.update({
        "schema_version": "query-v61-dataset-manifest-v1",
        "candidate_generation": "v6.1-core-schema-low-dimensional-density",
        "allowed_query_parameter_names": ["cb", "page", "utm_content", "view"],
        "blind_v2_records_used_for_training_or_calibration": False,
        "requires_new_blind_v3": True,
        "v61_density_summary_features": len(QUERY_V61_DENSITY_FEATURE_NAMES),
    })
    base.MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    print(json.dumps(collect(), ensure_ascii=False, indent=2))
