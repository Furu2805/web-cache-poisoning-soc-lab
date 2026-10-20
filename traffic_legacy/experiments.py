import argparse
from pathlib import Path

import httpx
import pandas as pd

from common.io import write_jsonl
from traffic.scenarios import SCENARIOS, attack_case, verify_case


def experiments(repeats=5):
    rows=[]
    with httpx.Client(timeout=10,trust_env=False) as client:
        for mode in ["none","rule","ml","hybrid","hardened"]:
            for scenario in SCENARIOS:
                for i in range(repeats):
                    case=attack_case(scenario,"plain" if i%2==0 else "encoded")
                    row=verify_case(client,mode,case)
                    if mode in {"ml","hybrid"} and (row["score"] in {"", "NA"} or "unavailable" in row["decision"]):
                        raise RuntimeError("ML model is unavailable. Restart detector after training.")
                    if mode == "none" and not row["poisoning_success"]:
                        raise AssertionError(f"Vulnerable baseline failed: {scenario}")
                    if mode == "hardened" and row["victim_received_marker"]:
                        raise AssertionError(f"Hardened control failed: {scenario}")
                    rows.append(row)
    write_jsonl("results/http_evidence.jsonl",rows)
    columns=["mode","scenario","variant","attack_cache","victim_first_cache","victim_cache",
             "decision","score","victim_received_marker","poisoning_success","same_origin_response"]
    frame=pd.DataFrame([{k:r[k] for k in columns} for r in rows])
    frame.to_csv("results/poisoning_trials.csv",index=False)
    summary=frame.groupby(["mode","scenario"])["poisoning_success"].agg(["count","sum","mean"]).reset_index()
    summary.columns=["mode","scenario","trials","successful_poisonings","poisoning_success_rate"]
    summary.to_csv("results/poisoning_summary.csv",index=False)
    print(summary.to_string(index=False))
    return frame


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--repeats",type=int,default=5)
    experiments(p.parse_args().repeats)
