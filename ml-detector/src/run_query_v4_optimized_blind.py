"""Independent near-distribution blind test for frozen Query v4-optimized."""
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
from query_features import extract_query_v3  # noqa: E402
from traffic.fusion_collect import add_benign_cookie, load_route_registry, observe  # noqa: E402
from traffic.fusion_scenarios import FusionCase, base_headers  # noqa: E402


FREEZE = ROOT / "ml-detector/artifacts/query_v4_optimized_freeze/freeze_manifest.json"
OUTPUT = ROOT / "ml-detector/data/blind/query_v4_optimized_blind_v1"
ARTIFACT = ROOT / "ml-detector/artifacts/query_v4_optimized_blind_v1"
RUNTIME = ROOT / "models/isolation_forest.joblib"
SEED = 20270419
COUNT = 1000
SESSION_SIZE = 10
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 Chrome/158.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 16_2) AppleWebKit/621.1 Version/20.2 Safari/621.1",
    "curl/8.19.0",
)
LANGUAGES = ("vi-VN,vi;q=0.9,en;q=0.5", "en-US,en;q=0.8", "ko-KR,ko;q=0.8,en;q=0.4")


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
    pages = ("1", "2", "3", "4", "5", "7", "9", "12")
    views = ("grid", "list", "compact", "gallery", "cards", "mosaic", "table", "detail")
    content = ("spring launch", "customer newsletter", "frontpage banner", "shopping guide",
               "monthly catalogue", "subscriber preview", "affiliate bulletin", "summer collection",
               "editor digest", "phone promotion", "comparison article", "recent arrivals")
    values = {"cb": token, "page": pages[index % 8], "view": views[(index // 2) % 8],
              "utm_content": content[(index // 3) % 12]}
    orders = (("cb", "page", "view", "utm_content"), ("cb", "view", "page", "utm_content"),
              ("page", "cb", "view", "utm_content"), ("utm_content", "cb", "page", "view"),
              ("cb", "page", "utm_content", "view"), ("cb", "view", "utm_content", "page"))
    pairs = [(name, values[name]) for name in orders[index % len(orders)]]
    method = "HEAD" if index % 10 in (0, 1) else "GET"
    return FusionCase("query", "normal", "normal", f"blind-core-{index % len(orders):02d}", method,
                      "/labs/query/?" + urlencode(pairs), headers, "")


# Sinh request attack cho blind test của route.
def attack_case(token: str, ua: str, language: str, index: int) -> FusionCase:
    headers = base_headers(ua, language)
    variants = (("blind-javascript-url", "javascript:alert(101)"),
                ("blind-svg-event", "'></script><svg onload=alert(102)>"),
                ("blind-details-event", "'></script><details open ontoggle=alert(103)>"),
                ("blind-video-event", "'></script><video onerror=alert(104)>"),
                ("blind-quote-breakout", "';window.alert(105);//"))
    name, payload = variants[index % len(variants)]
    keyed = urlencode((("cb", token), ("page", str(1 + index % 5)),
                       ("view", ("grid", "list", "cards")[index % 3])))
    return FusionCase("query", "attack", "query-unkeyed-parameter", name, "GET",
                      "/labs/query/?" + keyed + "&utm_content=" + payload.replace(" ", "%20"), headers, "")


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


# Đọc tham số CLI và chạy sealed blind test của run_query_v4_optimized_blind.
def main() -> None:
    if OUTPUT.exists() or ARTIFACT.exists():
        raise FileExistsError("refusing to overwrite blind evidence")
    freeze=json.loads(FREEZE.read_text(encoding="utf-8"))
    if sha256(RUNTIME)!=freeze["runtime_model"]["sha256"]: raise ValueError("runtime changed")
    for name, expected in freeze["source_sha256"].items():
        if sha256(ROOT/name)!=expected: raise ValueError(f"frozen source changed: {name}")
    candidate=ROOT/freeze["candidate_directory"]
    for name, expected in freeze["candidate_package"]["files"].items():
        if sha256(candidate/name)!=expected: raise ValueError(f"candidate changed: {name}")
    model=joblib.load(candidate/"model.joblib")
    profile=json.loads((candidate/"query_v4_optimized_feature_profile.json").read_text(encoding="utf-8"))
    origin="http://127.0.0.1:8086"
    if origin not in set(load_route_registry()["allowed_targets"]): raise ValueError("target not allowlisted")
    rng=random.Random(SEED); collection_id="query-v4opt-blind-"+uuid.uuid4().hex[:12]; captured=[]
    for label, factory in (("normal",normal_case),("attack",attack_case)):
        for index in range(COUNT):
            token=f"{rng.getrandbits(96):024x}"; case=factory(token,rng.choice(USER_AGENTS),rng.choice(LANGUAGES),index)
            add_benign_cookie(case,token,rng,.60); observation=observe(origin,case)
            if observation["status"]!=200 or not observation["request_id"]: raise RuntimeError("collection failed")
            if label=="attack" and not observation["effect_observed"]: raise RuntimeError(f"effect failed: {case.payload_variant}")
            captured.append((label,index,case,observation))
        print(f"Collected {COUNT} blind {label} records",flush=True)
    rows=[]
    for label,index,case,observation in captured:
        features=extract_query_v3({"method":case.method,"uri":case.uri,"headers":case.headers},profile)
        rows.append({"schema_version":"query-v4opt-blind-feature-v1","record_id":uuid.uuid4().hex,
                     "collection_id":collection_id,"group_id":f"{collection_id}-{label}-{index//SESSION_SIZE:05d}",
                     "route":"query","split":"blind_test","label":int(label=="attack"),"label_name":label,
                     "attack_type":case.attack_type,"payload_variant":case.payload_variant,
                     "features":{k:float(v) for k,v in features.items()},
                     "evidence":{"request_id":observation["request_id"],"http_status":observation["status"],
                                 "cache_key_hash":hashlib.sha256(str(observation["cache_key"]).encode()).hexdigest(),
                                 "effect_verified":bool(observation["effect_observed"]) if label=="attack" else None},
                     "privacy":{"raw_payload_stored":False,"raw_cookie_stored":False}})
    labels=np.asarray([r["label"] for r in rows]); ss=-model["structural_model"].score_samples(matrix(rows,model["structural_feature_names"]))
    ls=-model["lexical_density_model"].score_samples(matrix(rows,model["lexical_density_feature_names"]))
    structural=ss>model["thresholds"]["structural"]; lexical=ls>model["thresholds"]["lexical_density"]
    if_pred=(structural|lexical).astype(int); bounds=model["normal_profile_guard"]["bounds"]
    profile_pred=np.asarray([int(any(float(r["features"][n])<b["min"] or float(r["features"][n])>b["max"] for n,b in bounds.items())) for r in rows])
    hybrid=np.maximum(if_pred,profile_pred); unique=(if_pred==1)&(profile_pred==0)
    decisions=[]; variants=defaultdict(lambda:{"count":0,"if_detected":0,"profile_detected":0})
    for i,row in enumerate(rows):
        variants[row["payload_variant"]]["count"]+=1; variants[row["payload_variant"]]["if_detected"]+=int(if_pred[i]); variants[row["payload_variant"]]["profile_detected"]+=int(profile_pred[i])
        decisions.append({"record_id":row["record_id"],"label":int(labels[i]),"payload_variant":row["payload_variant"],
                          "structural_score":float(ss[i]),"lexical_score":float(ls[i]),"if_anomaly":bool(if_pred[i]),
                          "profile_anomaly":bool(profile_pred[i]),"final_anomaly":bool(hybrid[i])})
    metrics={"structural_if":metric(structural.astype(int),labels),"lexical_density_if":metric(lexical.astype(int),labels),
             "if_only":metric(if_pred,labels),"profile_only":metric(profile_pred,labels),"hybrid_or":metric(hybrid,labels)}
    evaluation={"schema_version":"query-v4opt-independent-blind-v1","blind_test_id":collection_id,
                "created_at_epoch":round(time.time(),3),"seed":SEED,"counts":{"normal":COUNT,"attack":COUNT},
                "candidate_id":model["candidate_id"],"policy":{"frozen_before_collection":True,
                "fit_or_calibration_performed":False,"all_collection_completed_before_scoring":True,
                "freeze_manifest_sha256":sha256(FREEZE),"retuning_on_this_set_forbidden":True},
                "metrics":metrics,"contribution":{"if_unique_tp":int(np.sum(unique&(labels==1))),"if_unique_fp":int(np.sum(unique&(labels==0)))},
                "variant_counts":dict(variants),"gate":{"recall_at_least_90_percent":metrics["if_only"]["recall"]>=.90,
                "fpr_at_most_2_percent":metrics["if_only"]["false_positive_rate"]<=.02,
                "if_unique_tp_at_least_one":int(np.sum(unique&(labels==1)))>=1},
                "runtime_model_sha256":sha256(RUNTIME),"runtime_unchanged":sha256(RUNTIME)==freeze["runtime_model"]["sha256"]}
    OUTPUT.mkdir(parents=True); records=OUTPUT/"feature_records.jsonl"
    records.write_text("".join(json.dumps(r,separators=(",",":"))+"\n" for r in rows),encoding="utf-8")
    ARTIFACT.mkdir(parents=True); decision_path=ARTIFACT/"decisions.jsonl"
    decision_path.write_text("".join(json.dumps(r,separators=(",",":"))+"\n" for r in decisions),encoding="utf-8")
    evaluation_path=ARTIFACT/"evaluation.json"; evaluation_path.write_text(json.dumps(evaluation,indent=2)+"\n",encoding="utf-8")
    report=ARTIFACT/"BLIND_TEST_REPORT.md"; m=metrics["if_only"]
    report.write_text(f"# Query v4-optimized blind test\n\nIF recall: {m['recall']:.2%}; IF FPR: {m['false_positive_rate']:.2%}; IF-only TP: {evaluation['contribution']['if_unique_tp']}.\n",encoding="utf-8")
    manifest=ARTIFACT/"manifest.json"; payload={"schema_version":"query-v4opt-blind-package-v1","status":"sealed_opened_blind_evidence",
             "retuning_forbidden":True,"outputs":{"records":str(records.relative_to(ROOT)).replace("\\","/"),"decisions":str(decision_path.relative_to(ROOT)).replace("\\","/"),"evaluation":str(evaluation_path.relative_to(ROOT)).replace("\\","/"),"report":str(report.relative_to(ROOT)).replace("\\","/")},
             "sha256":{"records":sha256(records),"decisions":sha256(decision_path),"evaluation":sha256(evaluation_path),"report":sha256(report),"freeze":sha256(FREEZE)}}
    manifest.write_text(json.dumps(payload,indent=2)+"\n",encoding="utf-8")
    files=sorted(p for p in ARTIFACT.iterdir() if p.is_file() and p.name!="CHECKSUMS.sha256")
    (ARTIFACT/"CHECKSUMS.sha256").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in files),encoding="ascii")
    print(json.dumps(evaluation,indent=2))


if __name__ == "__main__": main()
