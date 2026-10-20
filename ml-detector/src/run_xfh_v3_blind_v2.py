"""Independent blind-v2 test for the frozen XFH-v3 candidate."""
from __future__ import annotations

import hashlib
import json
import random
import sys
import time
import uuid
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlencode

import joblib
import numpy as np


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(Path(__file__).resolve().parent))
from traffic.fusion_collect import add_benign_cookie, load_route_registry, observe  # noqa: E402
from traffic.fusion_scenarios import FusionCase, base_headers  # noqa: E402
from xfh_features import extract_xfh_v2  # noqa: E402


FREEZE = ROOT / "ml-detector/artifacts/xfh_v3_freeze/freeze_manifest.json"
OUTPUT = ROOT / "ml-detector/data/blind/xfh_blind_v2"
ARTIFACT = ROOT / "ml-detector/artifacts/xfh_blind_test_v2"
RUNTIME = ROOT / "models/isolation_forest.joblib"
SEED = 20270911
COUNT = 1000
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 Chrome/159.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:158.0) Gecko/20100101 Firefox/158.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 16_3) AppleWebKit/622.1 Version/20.3 Safari/622.1",
    "curl/8.20.0",
)
LANGUAGES = ("vi-VN,vi;q=0.9,en;q=0.4", "en-GB,en;q=0.8", "ja-JP,ja;q=0.8,en;q=0.3")


# Tính checksum SHA-256 để ràng buộc dữ liệu hoặc artifact với evidence.
def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# Sinh request normal cho blind test của route.
def normal_case(token: str, ua: str, language: str, index: int) -> FusionCase:
    headers = base_headers(ua, language)
    hosts = (
        "cdn-a.fusion.local:8086", "cdn-b.fusion.local:8086",
        "static.fusion.local:8086", "media.fusion.local:8086",
        "catalog-v2.fusion.local:8086", "store-v2.fusion.local:8086",
    )
    host = hosts[index % len(hosts)]
    headers["Host"] = host
    if index % 10 >= 3:
        headers["X-Forwarded-Host"] = host
    if index % 9 in (2, 6):
        headers["X-Forwarded-Proto"] = "https" if index % 2 else "http"
    variants = (
        (("cb", token), ("category", "audio"), ("page", "6")),
        (("cb", token), ("q", "wireless charger"), ("view", "cards")),
        (("category", "accessories"), ("cb", token), ("sort", "newest")),
        (("cb", token), ("campaign", "weekend offer"), ("limit", "36")),
        (("cb", token), ("tag", "popular"), ("tag", "portable")),
    )
    method = "HEAD" if index % 10 in (0, 1) else "GET"
    return FusionCase("xfh", "normal", "normal", f"blind-v2-benign-{index % 30:02d}", method,
                      "/labs/xfh/shop?" + urlencode(variants[index % len(variants)]), headers, "")


# Sinh request attack cho blind test của route.
def attack_case(token: str, ua: str, language: str, index: int) -> FusionCase:
    headers = base_headers(ua, language)
    hosts = (
        "cdn-a.fusion.local:8086", "cdn-b.fusion.local:8086",
        "static.fusion.local:8086", "media.fusion.local:8086",
        "catalog-v2.fusion.local:8086",
    )
    headers["Host"] = hosts[index % len(hosts)]
    headers["X-Forwarded-Host"] = "127.0.0.1:8087"
    if index % 5 in (1, 3):
        headers["X-Forwarded-Proto"] = "https"
    params = (("cb", token), ("category", ("audio", "accessories", "featured")[index % 3]),
              ("page", str(1 + index % 7)))
    return FusionCase("xfh", "attack", "xfh-unkeyed-header", f"blind-v2-mismatch-{index % 5}", "GET",
                      "/labs/xfh/shop?" + urlencode(params), headers, "")


# Chuyển feature rows thành ma trận theo đúng thứ tự schema.
def matrix(rows: list[dict[str, object]], names: list[str]) -> np.ndarray:
    return np.asarray([[float(row["features"][name]) for name in names] for row in rows])


# Tính confusion matrix và các metric của candidate.
def metric(pred: np.ndarray, labels: np.ndarray) -> dict[str, object]:
    tp=int(np.sum((pred==1)&(labels==1))); fp=int(np.sum((pred==1)&(labels==0)))
    tn=int(np.sum((pred==0)&(labels==0))); fn=int(np.sum((pred==0)&(labels==1)))
    precision=tp/(tp+fp) if tp+fp else 0.; recall=tp/(tp+fn) if tp+fn else 0.
    return {"confusion_matrix":[[tn,fp],[fn,tp]],"tp":tp,"fp":fp,"tn":tn,"fn":fn,
            "precision":precision,"recall":recall,"f1":2*precision*recall/(precision+recall) if precision+recall else 0.,
            "false_positive_rate":fp/(fp+tn) if fp+tn else 0.,"false_discovery_rate":fp/(tp+fp) if tp+fp else 0.}


# Đọc tham số CLI và chạy sealed blind test của run_xfh_v3_blind_v2.
def main() -> None:
    if OUTPUT.exists() or ARTIFACT.exists():
        raise FileExistsError("refusing to overwrite blind-v2 evidence")
    freeze=json.loads(FREEZE.read_text(encoding="utf-8"))
    if sha256(RUNTIME)!=freeze["runtime_model"]["sha256"]: raise ValueError("runtime changed")
    for name,expected in freeze["source_sha256"].items():
        if sha256(ROOT/name)!=expected: raise ValueError(f"frozen source changed: {name}")
    candidate=ROOT/freeze["candidate_directory"]
    for name,expected in freeze["candidate_package"]["files"].items():
        if sha256(candidate/name)!=expected: raise ValueError(f"candidate changed: {name}")
    package=joblib.load(candidate/"model.joblib")
    profile=json.loads((candidate/"xfh_v3_feature_profile.json").read_text(encoding="utf-8"))
    origin="http://127.0.0.1:8086"
    if origin not in set(load_route_registry()["allowed_targets"]): raise ValueError("target not allowlisted")
    rng=random.Random(SEED); collection_id="xfh-blind-v2-"+uuid.uuid4().hex[:12]; captured=[]
    for label,factory in (("normal",normal_case),("attack",attack_case)):
        for index in range(COUNT):
            token=f"{rng.getrandbits(96):024x}"; case=factory(token,rng.choice(USER_AGENTS),rng.choice(LANGUAGES),index)
            add_benign_cookie(case,token,rng,.60); observation=observe(origin,case)
            if observation["status"]!=200 or not observation["request_id"]: raise RuntimeError("blind collection failed")
            if label=="attack" and not observation["effect_observed"]: raise RuntimeError(f"effect failed: {case.payload_variant}")
            captured.append((label,index,case,observation))
        print(f"Collected {COUNT} XFH blind-v2 {label} records",flush=True)
    rows=[]
    for label,index,case,observation in captured:
        features=extract_xfh_v2({"method":case.method,"uri":case.uri,"headers":case.headers},profile)
        rows.append({"schema_version":"xfh-v3-blind-v2-feature-v1","record_id":uuid.uuid4().hex,
                     "collection_id":collection_id,"group_id":f"{collection_id}-{label}-{index//10:05d}",
                     "route":"xfh","split":"blind_test","label":int(label=="attack"),"label_name":label,
                     "attack_type":case.attack_type,"payload_variant":case.payload_variant,
                     "features":{k:float(v) for k,v in features.items()},
                     "evidence":{"request_id":observation["request_id"],"http_status":observation["status"],
                                 "cache_key_hash":hashlib.sha256(str(observation["cache_key"]).encode()).hexdigest(),
                                 "effect_verified":bool(observation["effect_observed"]) if label=="attack" else None},
                     "privacy":{"raw_host_stored":False,"raw_xfh_stored":False,"raw_cookie_stored":False}})
    labels=np.asarray([r["label"] for r in rows]); scores=-package["relationship_model"].score_samples(matrix(rows,package["relationship_feature_names"]))
    if_pred=(scores>package["thresholds"]["relationship"]).astype(int)
    profile_pred=np.asarray([int(float(r["features"]["host_mismatch"])!=0.0) for r in rows])
    hybrid=np.maximum(if_pred,profile_pred); unique=(if_pred==1)&(profile_pred==0); overlap=(if_pred==1)&(profile_pred==1)
    variants=defaultdict(lambda:{"count":0,"if_detected":0,"profile_detected":0}); decisions=[]
    for index,row in enumerate(rows):
        variants[row["payload_variant"]]["count"]+=1; variants[row["payload_variant"]]["if_detected"]+=int(if_pred[index]); variants[row["payload_variant"]]["profile_detected"]+=int(profile_pred[index])
        decisions.append({"record_id":row["record_id"],"label":int(labels[index]),"payload_variant":row["payload_variant"],
                          "if_score":float(scores[index]),"if_anomaly":bool(if_pred[index]),"profile_anomaly":bool(profile_pred[index]),"final_anomaly":bool(hybrid[index])})
    metrics={"if_only":metric(if_pred,labels),"profile_only":metric(profile_pred,labels),"hybrid_or":metric(hybrid,labels)}
    im=metrics["if_only"]; passed=im["recall"]>=.90 and im["false_positive_rate"]<=.02 and im["false_discovery_rate"]<.02
    contribution={"if_unique_tp":int(np.sum(unique&(labels==1))),"if_unique_fp":int(np.sum(unique&(labels==0))),
                  "overlap_tp":int(np.sum(overlap&(labels==1))),"overlap_fp":int(np.sum(overlap&(labels==0)))}
    evaluation={"schema_version":"xfh-v3-independent-blind-v2","blind_test_id":collection_id,"created_at_epoch":round(time.time(),3),
                "seed":SEED,"counts":{"normal":COUNT,"attack":COUNT},"candidate_id":package["candidate_id"],
                "policy":{"frozen_before_collection":True,"fit_or_calibration_performed":False,
                          "all_collection_completed_before_scoring":True,"retuning_on_this_set_forbidden":True,
                          "freeze_manifest_sha256":sha256(FREEZE)},"metrics":metrics,"contribution":contribution,
                "variant_counts":dict(variants),"gate":{"recall_at_least_90_percent":im["recall"]>=.90,
                "fpr_at_most_2_percent":im["false_positive_rate"]<=.02,"fdr_below_2_percent":im["false_discovery_rate"]<.02,
                "eligible_for_runtime_shadow_monitoring":passed,"eligible_for_runtime_enforcement":False,
                "if_unique_tp_required":False},"runtime_model_sha256":sha256(RUNTIME),
                "runtime_unchanged":sha256(RUNTIME)==freeze["runtime_model"]["sha256"]}
    OUTPUT.mkdir(parents=True); records=OUTPUT/"feature_records.jsonl"
    records.write_text("".join(json.dumps(r,separators=(",",":"))+"\n" for r in rows),encoding="utf-8")
    ARTIFACT.mkdir(parents=True); decision_path=ARTIFACT/"decisions.jsonl"
    decision_path.write_text("".join(json.dumps(r,separators=(",",":"))+"\n" for r in decisions),encoding="utf-8")
    evaluation_path=ARTIFACT/"evaluation.json"; evaluation_path.write_text(json.dumps(evaluation,indent=2)+"\n",encoding="utf-8")
    report=ARTIFACT/"BLIND_TEST_REPORT.md"; report.write_text(
        f"# XFH v3 blind-v2\n\nIF recall: {im['recall']:.2%}; IF FPR: {im['false_positive_rate']:.2%}; IF FDR: {im['false_discovery_rate']:.2%}; IF-only TP: {contribution['if_unique_tp']}.\n\nRuntime mode: shadow monitoring only; profile remains the primary guard.\n",encoding="utf-8")
    manifest=ARTIFACT/"manifest.json"; payload={"schema_version":"xfh-v3-blind-v2-package-v1","status":"sealed_opened_blind_evidence",
             "retuning_forbidden":True,"outputs":{"records":str(records.relative_to(ROOT)).replace("\\","/"),"decisions":str(decision_path.relative_to(ROOT)).replace("\\","/"),"evaluation":str(evaluation_path.relative_to(ROOT)).replace("\\","/"),"report":str(report.relative_to(ROOT)).replace("\\","/")},
             "sha256":{"records":sha256(records),"decisions":sha256(decision_path),"evaluation":sha256(evaluation_path),"report":sha256(report),"freeze":sha256(FREEZE)}}
    manifest.write_text(json.dumps(payload,indent=2)+"\n",encoding="utf-8")
    files=sorted(p for p in ARTIFACT.iterdir() if p.is_file() and p.name!="CHECKSUMS.sha256")
    (ARTIFACT/"CHECKSUMS.sha256").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in files),encoding="ascii")
    print(json.dumps(evaluation,indent=2))


if __name__ == "__main__":
    main()
