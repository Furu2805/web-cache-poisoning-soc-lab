"""Compare warm-cache behavior with detector off and in observe mode."""
from __future__ import annotations

import argparse
import json
import time
import urllib.request
from pathlib import Path

ROUTES = ("query/?cb=cache&page=1&view=grid", "xfh/shop?cb=cache&category=electronics",
          "utm/js/geolocate.js?callback=ready&locale=vi", "fatget/js/geolocate.js?callback=ready&locale=vi")


# Gửi request đo cache status.
def fetch(base, path, token, index):
    separator = "&" if "?" in path else "?"
    request = urllib.request.Request(f"{base}/labs/{path}{separator}probe={token}-{index}", headers={"User-Agent": "section10-cache/1"})
    with urllib.request.urlopen(request, timeout=5) as response:
        response.read()
        return response.headers.get("X-Cache-Status") or "none"


# Tính HIT ratio cho một chế độ chạy.
def probe(name, base, count):
    token = f"{name}-{time.time_ns()}"
    paths = [ROUTES[index % len(ROUTES)] for index in range(count)]
    cold = [fetch(base, path, token, index) for index, path in enumerate(paths)]
    warm = [fetch(base, path, token, index) for index, path in enumerate(paths)]
    counts = lambda rows: {key: rows.count(key) for key in sorted(set(rows))}
    return {"requests_per_pass": count, "cold": counts(cold), "warm": counts(warm),
            "warm_hit_ratio": warm.count("HIT") / count}


# So sánh warm cache ratio khi Shadow tắt/bật.
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=40)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema_version": "section10-cache-ratio-v1",
              "detector_off": probe("off", "http://127.0.0.1:8086", args.requests),
              "shadow_observe": probe("shadow", "http://127.0.0.1:8090", args.requests)}
    report["warm_hit_ratio_delta"] = report["shadow_observe"]["warm_hit_ratio"] - report["detector_off"]["warm_hit_ratio"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
