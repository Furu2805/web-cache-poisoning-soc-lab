"""Sequential, paired warm/cold benchmark, not a capacity/load test."""
import argparse
import random
import time
import uuid
from pathlib import Path

import httpx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from traffic.scenarios import PORTS, base_headers, base_url


def benchmark(count=200, repeats=3):
    if count < 20 or repeats < 1:
        raise ValueError("count >= 20, repeats >= 1")
    modes=["none","rule","ml","hybrid","hardened"]
    rows=[]
    for run in range(repeats):
        token=uuid.uuid4().hex
        rng=random.Random(42+run)
        paths=[f"/lab/query?id={token}-"+(f"hot{rng.randrange(10)}" if rng.random()<.8 else f"cold{i}")
               for i in range(count)]
        order=modes.copy(); rng.shuffle(order)
        for mode in order:
            with httpx.Client(timeout=10,trust_env=False) as client:
                for i in range(10):
                    r=client.get(base_url(mode)+f"/lab/query?id={token}-hot{i}",headers=base_headers())
                    r.raise_for_status()
                    if mode in {"ml","hybrid"} and r.headers.get("x-anomaly-score", "NA") == "NA":
                        raise RuntimeError("Benchmark requires loaded model")
                for path in paths:
                    start=time.perf_counter()
                    r=client.get(base_url(mode)+path,headers=base_headers())
                    elapsed=(time.perf_counter()-start)*1000
                    r.raise_for_status()
                    rows.append({"run":run,"mode":mode,"latency_ms":elapsed,
                                 "cache":r.headers.get("x-cache-status", ""),
                                 "decision":r.headers.get("x-decision", ""),"status":r.status_code})
            print(f"Bench run {run+1}/{repeats}: {mode}",flush=True)
    frame=pd.DataFrame(rows)
    frame.to_csv("results/latency_samples.csv",index=False)
    summaries=[]
    for mode,g in frame.groupby("mode",sort=False):
        summaries.append({"mode":mode,"requests":len(g),"mean_ms":g.latency_ms.mean(),
                          "p50_ms":g.latency_ms.quantile(.5),"p95_ms":g.latency_ms.quantile(.95),
                          "p99_ms":g.latency_ms.quantile(.99),"cache_hit_ratio":(g.cache=="HIT").mean(),
                          "origin_fetches":int((g.cache!="HIT").sum())})
    summary=pd.DataFrame(summaries)
    summary.to_csv("results/latency_summary.csv",index=False)
    fig,axs=plt.subplots(1,2,figsize=(10,4))
    summary.plot.bar(x="mode",y=["p50_ms","p95_ms"],ax=axs[0]); axs[0].set_ylabel("Milliseconds")
    summary.plot.bar(x="mode",y="cache_hit_ratio",ax=axs[1],legend=False); axs[1].set_ylim(0,1)
    fig.tight_layout(); fig.savefig("results/latency_and_cache.png",dpi=160); plt.close(fig)
    print(summary.to_string(index=False))


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--count",type=int,default=200)
    p.add_argument("--repeats",type=int,default=3)
    a=p.parse_args(); benchmark(a.count,a.repeats)
