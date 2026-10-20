"""Collect fresh Query-v8 data for full-sample one-dimensional novelty IF."""
from __future__ import annotations

import json
from pathlib import Path

import collect_query_candidate_v7 as v7
import collect_query_candidate_v5 as base


ROOT = Path(__file__).resolve().parents[2]


# Sinh request theo scenario, thu response evidence và ghi dataset theo split.
def collect() -> dict[str, object]:
    # v7.collect configures the same extractor; redirect its base outputs and use a fresh seed directly.
    from collect_query_candidate_v6 import attack_case, normal_case
    from query_v7_features import QUERY_V7_FEATURE_NAMES, QUERY_V7_NOVELTY_FEATURE, build_query_v7_profile, extract_query_v7_features
    base.RAW=ROOT/"ml-detector/data/raw/query_v8/requests.jsonl"; base.PROCESSED=ROOT/"ml-detector/data/processed/query_v8/feature_records.jsonl"
    base.PROFILE=ROOT/"ml-detector/artifacts/candidates/query_v8_feature_profile.json"; base.MANIFEST=ROOT/"ml-detector/data/manifests/query_v8/dataset_manifest.json"
    base.normal_case,base.attack_case=normal_case,attack_case; base.build_query_general_profile=build_query_v7_profile
    base.extract_query_general_features=extract_query_v7_features; base.QUERY_GENERAL_FEATURE_NAMES=QUERY_V7_FEATURE_NAMES
    base.QUERY_GENERAL_DENSITY_FEATURE_NAMES=tuple(base.QUERY_GENERAL_DENSITY_FEATURE_NAMES)+(QUERY_V7_NOVELTY_FEATURE,)
    manifest=base.collect(seed=20270629)
    manifest.update({"schema_version":"query-v8-dataset-manifest-v1","allowed_query_parameter_names":["cb","page","utm_content","view"],
                     "blind_evidence_records_used_for_training_or_calibration":False,"requires_new_blind_test":True,
                     "candidate_generation":"full-sample-one-dimensional-generalized-novelty-if"})
    base.MANIFEST.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    return manifest


if __name__=="__main__": print(json.dumps(collect(),ensure_ascii=False,indent=2))
