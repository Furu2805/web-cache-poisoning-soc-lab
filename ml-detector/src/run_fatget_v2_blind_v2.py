"""Independent blind-v2 test of the frozen Fat GET v2 candidate."""
from __future__ import annotations

import hashlib,json,random,sys,time,uuid
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlencode
import joblib
import numpy as np

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(Path(__file__).resolve().parent))
from fatget_features import extract_fatget_features  # noqa: E402
from traffic.fusion_collect import add_benign_cookie,load_route_registry,observe  # noqa: E402
from traffic.fusion_scenarios import FusionCase,base_headers  # noqa: E402

FREEZE=ROOT/"ml-detector/artifacts/fatget_v2_freeze/freeze_manifest.json"
OUTPUT=ROOT/"ml-detector/data/blind/fatget_blind_v2"
ARTIFACT=ROOT/"ml-detector/artifacts/fatget_blind_test_v2"
RUNTIME=ROOT/"models/isolation_forest.joblib"
SEED=20271004; COUNT=1000
USER_AGENTS=("Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 Chrome/160.0 Safari/537.36",
             "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0",
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 16_4) AppleWebKit/623.1 Version/20.4 Safari/623.1","curl/8.21.0")
LANGUAGES=("vi-VN,vi;q=0.9,en;q=0.3","en-AU,en;q=0.8","zh-SG,zh;q=0.8,en;q=0.3")

# Tính checksum SHA-256 để ràng buộc dữ liệu hoặc artifact với evidence.
def sha256(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()

# Sinh request normal cho blind test của route.
def normal_case(token:str,ua:str,lang:str,index:int)->FusionCase:
    headers=base_headers(ua,lang); callback=("geoComplete","countryReady","localeHook")[index%3]+token[:7]
    variants=((("callback",callback),("locale","fr-FR"),("channel","mobile")),
              (("locale","de-DE"),("callback",callback),("view","tiles")),
              (("callback",callback),("locale","en-AU"),("region","oceania"),("limit","48")),
              (("callback",callback),("locale","zh-SG"),("campaign","holiday guide")),
              (("callback",callback),("locale","vi"),("tag","weekly"),("tag","featured")),
              (("callback",callback),("locale","en"),("format","javascript"),("preview","false")))
    headers["Accept"]=("application/javascript,*/*;q=0.7","text/javascript,*/*;q=0.6","*/*")[index%3]
    method="HEAD" if index%10 in (0,1) else "GET"
    return FusionCase("fatget","normal","normal",f"blind-v2-benign-{index%24:02d}",method,
                      "/labs/fatget/js/geolocate.js?"+urlencode(variants[index%len(variants)]),headers,"")

# Sinh request attack cho blind test của route.
def attack_case(token:str,ua:str,lang:str,index:int)->FusionCase:
    headers=base_headers(ua,lang); callback=("geoComplete","countryReady","localeHook")[index%3]+token[:7]
    number=201+index%5
    bodies=(f"callback=alert%28{number}%29",f"locale=en&callback=alert%28{number}%29",
            f"source=mobile&callback=alert%28{number}%29",f"callback=alert%28{number}%29&region=sea",
            f"note=blindv2&callback=alert%28{number}%29")
    body=bodies[index%len(bodies)]; headers["Content-Type"]="application/x-www-form-urlencoded; charset=UTF-8"
    headers["Content-Length"]=str(len(body.encode("utf-8")))
    uri="/labs/fatget/js/geolocate.js?"+urlencode({"callback":callback,"locale":("fr-FR","de-DE","en-AU")[index%3]})
    return FusionCase("fatget","attack","fat-get-body",f"blind-v2-body-override-{index%5}","GET",uri,headers,body)

# Chuyển feature rows thành ma trận theo đúng thứ tự schema.
def matrix(rows,names): return np.asarray([[float(row["features"][name]) for name in names] for row in rows])
# Tính confusion matrix và các metric của candidate.
def metric(pred,labels):
    tp=int(np.sum((pred==1)&(labels==1))); fp=int(np.sum((pred==1)&(labels==0))); tn=int(np.sum((pred==0)&(labels==0))); fn=int(np.sum((pred==0)&(labels==1)))
    precision=tp/(tp+fp) if tp+fp else 0.; recall=tp/(tp+fn) if tp+fn else 0.
    return {"confusion_matrix":[[tn,fp],[fn,tp]],"tp":tp,"fp":fp,"tn":tn,"fn":fn,"precision":precision,"recall":recall,
            "f1":2*precision*recall/(precision+recall) if precision+recall else 0.,"false_positive_rate":fp/(fp+tn) if fp+tn else 0.,"false_discovery_rate":fp/(tp+fp) if tp+fp else 0.}

# Đọc tham số CLI và chạy sealed blind test của run_fatget_v2_blind_v2.
def main()->None:
    if OUTPUT.exists() or ARTIFACT.exists(): raise FileExistsError("refusing to overwrite blind-v2")
    freeze=json.loads(FREEZE.read_text(encoding="utf-8"))
    if sha256(RUNTIME)!=freeze["runtime_model"]["sha256"]: raise ValueError("runtime changed")
    for name,expected in freeze["source_sha256"].items():
        if sha256(ROOT/name)!=expected: raise ValueError(f"frozen source changed: {name}")
    candidate=ROOT/freeze["candidate_directory"]
    for name,expected in freeze["candidate_package"]["files"].items():
        if sha256(candidate/name)!=expected: raise ValueError(f"candidate changed: {name}")
    package=joblib.load(candidate/"model.joblib"); profile=json.loads((candidate/"fatget_v2_feature_profile.json").read_text(encoding="utf-8"))
    origin="http://127.0.0.1:8086"
    if origin not in set(load_route_registry()["allowed_targets"]): raise ValueError("target not allowlisted")
    rng=random.Random(SEED); collection_id="fatget-blind-v2-"+uuid.uuid4().hex[:12]; captured=[]
    for label,factory in (("normal",normal_case),("attack",attack_case)):
        for index in range(COUNT):
            token=f"{rng.getrandbits(96):024x}"; case=factory(token,rng.choice(USER_AGENTS),rng.choice(LANGUAGES),index)
            add_benign_cookie(case,token,rng,.60); observation=observe(origin,case)
            if observation["status"]!=200 or not observation["request_id"]: raise RuntimeError("blind collection failed")
            if label=="attack" and not observation["effect_observed"]: raise RuntimeError(f"effect failed: {case.payload_variant}")
            captured.append((label,index,case,observation))
        print(f"Collected {COUNT} Fat GET blind-v2 {label} records",flush=True)
    rows=[]
    for label,index,case,observation in captured:
        features=extract_fatget_features({"method":case.method,"uri":case.uri,"headers":case.headers},profile)
        rows.append({"schema_version":"fatget-v2-blind-v2-feature-v1","record_id":uuid.uuid4().hex,"collection_id":collection_id,
                     "group_id":f"{collection_id}-{label}-{index//10:05d}","route":"fatget","split":"blind_test","label":int(label=="attack"),
                     "label_name":label,"attack_type":case.attack_type,"payload_variant":case.payload_variant,
                     "features":{k:float(v) for k,v in features.items()},"evidence":{"request_id":observation["request_id"],"http_status":observation["status"],
                     "cache_key_hash":hashlib.sha256(str(observation["cache_key"]).encode()).hexdigest(),"effect_verified":bool(observation["effect_observed"]) if label=="attack" else None},
                     "privacy":{"raw_body_stored":False,"raw_content_headers_stored":False,"raw_cookie_stored":False}})
    labels=np.asarray([r["label"] for r in rows]); scores=-package["relationship_model"].score_samples(matrix(rows,package["relationship_feature_names"]))
    if_pred=(scores>package["thresholds"]["relationship"]).astype(int); profile_pred=np.asarray([int(float(r["features"]["has_body_on_get"])!=0.0) for r in rows])
    hybrid=np.maximum(if_pred,profile_pred); unique=(if_pred==1)&(profile_pred==0); overlap=(if_pred==1)&(profile_pred==1)
    variants=defaultdict(lambda:{"count":0,"if_detected":0,"profile_detected":0}); decisions=[]
    for i,row in enumerate(rows):
        variants[row["payload_variant"]]["count"]+=1; variants[row["payload_variant"]]["if_detected"]+=int(if_pred[i]); variants[row["payload_variant"]]["profile_detected"]+=int(profile_pred[i])
        decisions.append({"record_id":row["record_id"],"label":int(labels[i]),"payload_variant":row["payload_variant"],"if_score":float(scores[i]),"if_anomaly":bool(if_pred[i]),"profile_anomaly":bool(profile_pred[i]),"final_anomaly":bool(hybrid[i])})
    metrics={"if_only":metric(if_pred,labels),"profile_only":metric(profile_pred,labels),"hybrid_or":metric(hybrid,labels)}; im=metrics["if_only"]
    contribution={"if_unique_tp":int(np.sum(unique&(labels==1))),"if_unique_fp":int(np.sum(unique&(labels==0))),"overlap_tp":int(np.sum(overlap&(labels==1))),"overlap_fp":int(np.sum(overlap&(labels==0)))}
    passed=im["recall"]>=.90 and im["false_positive_rate"]<=.02 and im["false_discovery_rate"]<.02
    evaluation={"schema_version":"fatget-v2-independent-blind-v2","blind_test_id":collection_id,"created_at_epoch":round(time.time(),3),"seed":SEED,
                "counts":{"normal":COUNT,"attack":COUNT},"candidate_id":package["candidate_id"],"policy":{"frozen_before_collection":True,
                "fit_or_calibration_performed":False,"all_collection_completed_before_scoring":True,"retuning_on_this_set_forbidden":True,"freeze_manifest_sha256":sha256(FREEZE)},
                "metrics":metrics,"contribution":contribution,"variant_counts":dict(variants),"gate":{"recall_at_least_90_percent":im["recall"]>=.90,
                "fpr_at_most_2_percent":im["false_positive_rate"]<=.02,"fdr_below_2_percent":im["false_discovery_rate"]<.02,
                "eligible_for_runtime_shadow_monitoring":passed,"eligible_for_runtime_enforcement":False,"if_unique_tp_required":False},
                "runtime_model_sha256":sha256(RUNTIME),"runtime_unchanged":sha256(RUNTIME)==freeze["runtime_model"]["sha256"]}
    OUTPUT.mkdir(parents=True); records=OUTPUT/"feature_records.jsonl"; records.write_text("".join(json.dumps(r,separators=(",",":"))+"\n" for r in rows),encoding="utf-8")
    ARTIFACT.mkdir(parents=True); decision_path=ARTIFACT/"decisions.jsonl"; decision_path.write_text("".join(json.dumps(r,separators=(",",":"))+"\n" for r in decisions),encoding="utf-8")
    evaluation_path=ARTIFACT/"evaluation.json"; evaluation_path.write_text(json.dumps(evaluation,indent=2)+"\n",encoding="utf-8")
    report=ARTIFACT/"BLIND_TEST_REPORT.md"; report.write_text(f"# Fat GET v2 blind-v2\n\nIF recall: {im['recall']:.2%}; IF FPR: {im['false_positive_rate']:.2%}; IF FDR: {im['false_discovery_rate']:.2%}; IF-only TP: {contribution['if_unique_tp']}.\n\nRuntime mode: shadow monitoring only.\n",encoding="utf-8")
    manifest=ARTIFACT/"manifest.json"; payload={"schema_version":"fatget-v2-blind-v2-package-v1","status":"sealed_opened_blind_evidence","retuning_forbidden":True,
             "outputs":{"records":str(records.relative_to(ROOT)).replace("\\","/"),"decisions":str(decision_path.relative_to(ROOT)).replace("\\","/"),"evaluation":str(evaluation_path.relative_to(ROOT)).replace("\\","/"),"report":str(report.relative_to(ROOT)).replace("\\","/")},
             "sha256":{"records":sha256(records),"decisions":sha256(decision_path),"evaluation":sha256(evaluation_path),"report":sha256(report),"freeze":sha256(FREEZE)}}
    manifest.write_text(json.dumps(payload,indent=2)+"\n",encoding="utf-8"); files=sorted(p for p in ARTIFACT.iterdir() if p.is_file() and p.name!="CHECKSUMS.sha256")
    (ARTIFACT/"CHECKSUMS.sha256").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in files),encoding="ascii")
    print(json.dumps(evaluation,indent=2))

if __name__=="__main__": main()
