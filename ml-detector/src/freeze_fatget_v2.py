"""Seal Fat GET v2 before independent blind-v2 collection."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT=Path(__file__).resolve().parents[2]
CANDIDATE=ROOT/"ml-detector/artifacts/candidates/fatget_phase4_v2"
DATASET=ROOT/"ml-detector/data/manifests/fatget_v2/dataset_manifest.json"
OUTPUT=ROOT/"ml-detector/artifacts/fatget_v2_freeze"
RUNTIME=ROOT/"models/isolation_forest.joblib"
SOURCES=("ml-detector/src/fatget_features.py","ml-detector/src/collect_fatget_dataset.py",
         "ml-detector/src/collect_fatget_candidate_v2.py","ml-detector/src/train_evaluate_fatget_v2.py",
         "common/features.py","traffic/fusion_collect.py","traffic/fusion_scenarios.py",
         "ml-detector/config/route_registry.json")


# Tính checksum artifact Fat GET v2.
def sha256(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()


# Đóng băng artifact, schema, profile và checksum Fat GET v2.
def main()->None:
    if OUTPUT.exists(): raise FileExistsError(f"refusing to overwrite {OUTPUT}")
    files={}
    for line in (CANDIDATE/"CHECKSUMS.sha256").read_text(encoding="ascii").splitlines():
        expected,name=line.split("  ",1)
        if sha256(CANDIDATE/name)!=expected: raise ValueError(f"candidate checksum mismatch: {name}")
        files[name]=expected
    evaluation=json.loads((CANDIDATE/"evaluation.json").read_text(encoding="utf-8")); metric=evaluation["metrics"]["if_only"]
    if metric["recall"]<.90 or metric["false_positive_rate"]>.02 or metric["false_discovery_rate"]>=.02: raise ValueError("development gate failed")
    dataset=json.loads(DATASET.read_text(encoding="utf-8"))
    for key,path_text in dataset["outputs"].items():
        if sha256(ROOT/path_text)!=dataset["sha256"][key]: raise ValueError(f"dataset mismatch: {key}")
    freeze={"schema_version":"fatget-v2-freeze-v1","freeze_id":"fatget-v2-pre-blind-v2-freeze",
            "frozen_at_utc":datetime.now(timezone.utc).isoformat(),"candidate_id":evaluation["candidate_id"],
            "candidate_directory":"ml-detector/artifacts/candidates/fatget_phase4_v2",
            "candidate_package":{"checksums_sha256":sha256(CANDIDATE/"CHECKSUMS.sha256"),"files":files},
            "dataset_manifest":{"path":"ml-detector/data/manifests/fatget_v2/dataset_manifest.json","sha256":sha256(DATASET)},
            "source_sha256":{name:sha256(ROOT/name) for name in SOURCES},
            "runtime_model":{"path":"models/isolation_forest.joblib","sha256":sha256(RUNTIME),"changed":False},
            "policy":{"candidate_locked_before_blind":True,"fit_or_calibration_in_blind_forbidden":True,
                      "retuning_on_blind_forbidden":True,"profile_is_primary_fatget_guard":True,
                      "if_mode_if_blind_passes":"shadow_monitoring_only","automatic_runtime_promotion":False}}
    OUTPUT.mkdir(parents=True); manifest=OUTPUT/"freeze_manifest.json"
    manifest.write_text(json.dumps(freeze,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    readme=OUTPUT/"README.md"; readme.write_text("# Fat GET v2 pre-blind freeze\n\nCandidate-only; runtime unchanged.\n",encoding="utf-8")
    (OUTPUT/"CHECKSUMS.sha256").write_text(f"{sha256(manifest)}  freeze_manifest.json\n{sha256(readme)}  README.md\n",encoding="ascii")
    print(json.dumps({"freeze_id":freeze["freeze_id"],"manifest_sha256":sha256(manifest)},indent=2))


if __name__=="__main__": main()
