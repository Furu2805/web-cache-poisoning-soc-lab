"""Train/evaluate the XFH-v3 relationship-only normal Isolation Forest."""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

import joblib
import numpy as np


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(Path(__file__).resolve().parent))
from train_evaluate_utm import _fit, _matrix, _metrics, _variant_metrics  # noqa: E402


INPUT = ROOT / "ml-detector/data/processed/xfh_v3/feature_records.jsonl"
AUDIT = ROOT / "ml-detector/data/manifests/xfh_v3/train_normal_variance_audit.json"
DATASET_MANIFEST = ROOT / "ml-detector/data/manifests/xfh_v3/dataset_manifest.json"
PROFILE = ROOT / "ml-detector/artifacts/candidates/xfh_v3_feature_profile.json"
OUTPUT = ROOT / "ml-detector/artifacts/candidates/xfh_phase1_v3"
RUNTIME = ROOT / "models/isolation_forest.joblib"
RELATIONSHIP_NAMES = ("xfh_relation_distance_dithered",)


# Tính checksum của dữ liệu/artifact XFH v3.
def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Nạp và tách train, validation, development test cho XFH.
def load_rows() -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    train, validation, test = [], [], []
    with INPUT.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row["route"] != "xfh": raise ValueError("route must be xfh")
            if row["split"] == "train": train.append(row)
            elif row["split"] == "validation": validation.append(row)
            elif row["split"] == "test": test.append(row)
    if len(train) != 8000 or any(int(row["label"]) for row in train): raise ValueError("invalid train")
    if len(validation) != 2000 or any(int(row["label"]) for row in validation): raise ValueError("invalid validation")
    if Counter(int(row["label"]) for row in test) != Counter({0:1000,1:1000}): raise ValueError("invalid test")
    return train, validation, test


# Fit/đánh giá XFH v3 và lưu metric cùng artifact.
def main() -> None:
    if OUTPUT.exists(): raise FileExistsError(f"refusing to overwrite {OUTPUT}")
    runtime_before=sha256(RUNTIME); audit=json.loads(AUDIT.read_text(encoding="utf-8"))
    if audit["input_sha256"] != sha256(INPUT): raise ValueError("audit/input mismatch")
    if not set(RELATIONSHIP_NAMES).issubset(set(audit["variable_features"])): raise ValueError("relationship feature has no variance")
    dataset=json.loads(DATASET_MANIFEST.read_text(encoding="utf-8"))
    if dataset.get("blind_v1_records_used_for_training_or_calibration") is not False: raise ValueError("blind leakage")
    train,validation,test=load_rows()
    model,threshold,val_fpr=_fit(train,validation,RELATIONSHIP_NAMES,len(train),310,0.01)
    val_scores=-model.score_samples(_matrix(validation,RELATIONSHIP_NAMES))
    OUTPUT.mkdir(parents=True)
    artifact={"schema_version":"xfh-v3-relationship-if-candidate-v1","candidate_id":"xfh-phase1-v3-relation-distance",
              "route":"xfh","candidate_only":True,"status":"development_evaluated_not_promoted",
              "model_type":"IsolationForest","relationship_model":model,"relationship_feature_names":list(RELATIONSHIP_NAMES),
              "thresholds":{"relationship":threshold},"validation_fpr":{"target":.01,"actual":val_fpr},
              "normal_profile_guard":{"type":"explicit primitive","feature":"host_mismatch","normal_value":0.0},
              "decision":"if_anomaly=relationship_if; final=if_anomaly OR host_mismatch_profile",
              "input_sha256":sha256(INPUT),"audit_sha256":sha256(AUDIT),"runtime_model_sha256_before":runtime_before,
              "provenance":{"blind_v1_records_used_for_training_or_calibration":False,"new_blind_v2_required":True}}
    model_path=OUTPUT/"model.joblib"; joblib.dump(artifact,model_path)
    labels=np.asarray([int(row["label"]) for row in test]); scores=-model.score_samples(_matrix(test,RELATIONSHIP_NAMES))
    if_pred=(scores>threshold).astype(int)
    profile_pred=np.asarray([int(float(row["features"]["host_mismatch"])!=0.0) for row in test])
    hybrid=np.maximum(if_pred,profile_pred); unique=(if_pred==1)&(profile_pred==0); overlap=(if_pred==1)&(profile_pred==1)
    metrics={"if_only":_metrics(if_pred,labels),"profile_only":_metrics(profile_pred,labels),"hybrid_or":_metrics(hybrid,labels)}
    contribution={"if_unique_tp":int(np.sum(unique&(labels==1))),"if_unique_fp":int(np.sum(unique&(labels==0))),
                  "overlap_tp":int(np.sum(overlap&(labels==1))),"overlap_fp":int(np.sum(overlap&(labels==0)))}
    metric=metrics["if_only"]; accepted=metric["recall"]>=.90 and metric["false_positive_rate"]<=.02 and metric["false_discovery_rate"]<.02
    evidence={"schema_version":"xfh-v3-development-evidence-v1","candidate_id":artifact["candidate_id"],
              "evaluation_scope":"fresh development hold-out; blind-v1 excluded","counts":{"normal":1000,"attack":1000},
              "validation_fpr":artifact["validation_fpr"],"metrics":metrics,"contribution":contribution,
              "attack_variant_metrics":_variant_metrics(test,{"if_only":if_pred,"profile_only":profile_pred,"hybrid_or":hybrid}),
              "acceptance":{"recall_at_least_90_percent":metric["recall"]>=.90,"fpr_at_most_2_percent":metric["false_positive_rate"]<=.02,
                            "fdr_below_2_percent":metric["false_discovery_rate"]<.02,"eligible_for_blind_v2":accepted,
                            "eligible_for_runtime_promotion":False,"automatic_promotion":False},
              "interpretation":"host_mismatch remains the primary guard; IF is evaluated for shadow monitoring",
              "runtime_model_unchanged":sha256(RUNTIME)==runtime_before}
    (OUTPUT/"evaluation.json").write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    (OUTPUT/"threshold.json").write_text(json.dumps(artifact["thresholds"],indent=2)+"\n",encoding="utf-8")
    (OUTPUT/"feature_schema.json").write_text(json.dumps({"schema_version":"xfh-v3-runtime-features-v1","if_features":list(RELATIONSHIP_NAMES),
                                                          "profile_guard":["host_mismatch"]},indent=2)+"\n",encoding="utf-8")
    (OUTPUT/"normal_profile_guard.json").write_text(json.dumps(artifact["normal_profile_guard"],indent=2)+"\n",encoding="utf-8")
    shutil.copy2(PROFILE,OUTPUT/PROFILE.name); shutil.copy2(DATASET_MANIFEST,OUTPUT/"dataset_manifest.json"); shutil.copy2(AUDIT,OUTPUT/"train_normal_variance_audit.json")
    (OUTPUT/"EVIDENCE.md").write_text(f"# XFH v3 development evidence\n\nIF recall: {metric['recall']:.2%}; FPR: {metric['false_positive_rate']:.2%}; FDR: {metric['false_discovery_rate']:.2%}.\n",encoding="utf-8")
    manifest={"schema_version":"wcp-candidate-package-v3","candidate_id":artifact["candidate_id"],"route":"xfh","candidate_only":True,
              "eligible_for_blind_v2":accepted,"promotable":False,"automatic_promotion":False,"model_sha256":sha256(model_path),
              "evaluation_sha256":sha256(OUTPUT/"evaluation.json"),"runtime_model_sha256":sha256(RUNTIME)}
    (OUTPUT/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    files=sorted(path for path in OUTPUT.iterdir() if path.is_file() and path.name!="CHECKSUMS.sha256")
    (OUTPUT/"CHECKSUMS.sha256").write_text("".join(f"{sha256(path)}  {path.name}\n" for path in files),encoding="ascii")
    print(json.dumps(evidence,ensure_ascii=False,indent=2))


if __name__=="__main__": main()
