"""Collect actual metadata observed by Nginx, then join client-side labels by ID."""
import argparse
import json
import random
import sqlite3
import uuid
from pathlib import Path
from urllib.parse import urlencode

import httpx
from common.io import write_jsonl
from common.features import extract_features
from traffic.scenarios import SCENARIOS, attack_case, base_headers, send, verify_case


def normal_case(rng, split, index):
    scenario = rng.choice(SCENARIOS)
    headers = base_headers()
    headers["User-Agent"] = rng.choice(["Mozilla/5.0 Chrome/128.0", "Mozilla/5.0 Firefox/130.0",
                                         "Mozilla/5.0 Mobile Safari/17.0", "curl/8.0"])
    headers["Accept-Language"] = rng.choice(["vi", "en", "vi,en;q=0.8"])
    if rng.random() < .35:
        headers["Cookie"] = "session=" + "a" * rng.randint(16, 200)
    if rng.random() < .20:
        headers["X-Forwarded-Host"] = "lab.test"
    if rng.random() < .20:
        headers["X-Forwarded-Proto"] = rng.choice(["http", "https"])
    # Disjoint batches, with legitimate variation and rare but benign queries.
    params = {"id": uuid.uuid4().hex}
    if rng.random() < .6:
        params["q"] = rng.choice(["sensor", "led", "esp32", "cam bien nhiet do"]) * rng.randint(1, 5)
    if rng.random() < .5:
        params["page"] = str(rng.randint(1, 99))
    if rng.random() < .2:
        params["utm_content"] = "spring;summer"  # encoded ';', benign marketing value
    return {"scenario": scenario, "method": "GET", "uri": f"/lab/{scenario}?" + urlencode(params),
            "headers": headers, "body": ""}


def collect(train=2000, normal_eval=400, attacks_per_type=40):
    rng = random.Random(2026)
    run = uuid.uuid4().hex[:12]
    labels, evidence = [], []
    with httpx.Client(timeout=10, trust_env=False) as client:
        for split, count in [("train", train), ("validation", normal_eval), ("test", normal_eval)]:
            for i in range(count):
                case = normal_case(rng, split, i)
                rid = f"{run}-{split}-normal-{i}"
                response = send(client, "observe", case, rid)
                response.raise_for_status()
                labels.append({"record_id": rid, "split": split, "label": 0,
                               "attack_type": "normal", "group": f"{run}-{split}-normal",
                               "baseline_verified": False})
            print(f"Collected {count} normal: {split}", flush=True)
        for split, variant in [("validation", "plain"), ("test", "encoded")]:
            for scenario in SCENARIOS:
                for i in range(attacks_per_type):
                    case = attack_case(scenario, variant)
                    proof = verify_case(client, "none", case)
                    if not proof["poisoning_success"]:
                        raise RuntimeError(f"Baseline poisoning NOT verified: {scenario}. Check Nginx before labeling.")
                    rid = f"{run}-{split}-{scenario}-{i}"
                    response = send(client, "observe", case, rid)
                    response.raise_for_status()
                    labels.append({"record_id": rid, "split": split, "label": 1,
                                   "attack_type": scenario, "group": f"{run}-{scenario}-{variant}",
                                   "baseline_verified": True})
                    proof["record_id"] = rid
                    evidence.append(proof)
                print(f"Verified {attacks_per_type} attacks: {split}/{scenario}", flush=True)
    rows = []
    with sqlite3.connect("data/detector.sqlite3") as db:
        for label in labels:
            observed = db.execute("SELECT request_json FROM observations WHERE record_id=?",
                                  (label["record_id"],)).fetchone()
            if observed is None:
                raise RuntimeError("Missing proxy observation; verify shared data volume")
            rows.append({**label, "source": "nginx-observed", "request": json.loads(observed[0])})
    write_jsonl("data/raw/dataset.jsonl", rows)
    write_jsonl("data/raw/attack_evidence.jsonl", evidence)
    import pandas as pd
    Path("data/processed").mkdir(parents=True, exist_ok=True)
    pd.DataFrame([{**extract_features(r["request"]), **{k:r[k] for k in
                 ["record_id", "split", "label", "attack_type", "group"]}} for r in rows]).to_csv(
                     "data/processed/features.csv", index=False)
    print(f"Saved {len(rows)} observed requests. Dataset is synthetic local-lab traffic.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--train", type=int, default=2000)
    p.add_argument("--normal-eval", type=int, default=400)
    p.add_argument("--attacks-per-type", type=int, default=40)
    a = p.parse_args()
    collect(a.train, a.normal_eval, a.attacks_per_type)
