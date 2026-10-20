"""Collect XFH-v3 data with broad benign Host/XFH pair coverage."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlencode

import collect_xfh_dataset as base
from traffic.fusion_scenarios import FusionCase, base_headers


ROOT = Path(__file__).resolve().parents[2]


# Sinh normal case phiên bản v3 cho route.
def normal_case_v3(token: str, user_agent: str, language: str, index: int, method: str) -> FusionCase:
    headers = base_headers(user_agent, language)
    hosts = (
        "127.0.0.1:8086", "localhost:8086", "fusion.local:8086",
        "shop.fusion.local:8086", "edge-a.fusion.local:8086",
        "edge-b.fusion.local:8086", "catalog.fusion.local:8086",
        "assets.fusion.local:8086", "store.fusion.local:8086",
        "web.fusion.local:8086",
    )
    host = hosts[index % len(hosts)]
    headers["Host"] = host
    relation_variant = index % 10
    if relation_variant >= 3:
        headers["X-Forwarded-Host"] = host
    if index % 8 in (2, 5):
        headers["X-Forwarded-Proto"] = "https" if index % 2 else "http"
    headers["Accept"] = (
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "text/html,application/xhtml+xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "text/html;q=0.9,application/json;q=0.7,*/*;q=0.5",
        "text/html,*/*;q=0.6",
    )[index % 4]
    variants = (
        [("cb", token), ("category", "electronics"), ("page", "1")],
        [("cb", token), ("category", "computers"), ("page", "2"), ("view", "compact")],
        [("category", "featured"), ("cb", token), ("page", "3"), ("sort", "price")],
        [("cb", token), ("q", "usb hub"), ("currency", "VND"), ("page", "1")],
        [("cb", token), ("campaign", "seasonal sale"), ("limit", "24")],
        [("cb", token), ("category", "electronics"), ("tag", "new"), ("tag", "sale")],
        [("cb", token), ("category", "networking"), ("page", "4"), ("view", "grid")],
        [("cb", token), ("q", "power adapter"), ("page", "5"), ("sort", "rating")],
    )
    return FusionCase(
        "xfh", "normal", "normal", f"xfh-v3-benign-{index % 80:02d}", method,
        "/labs/xfh/shop?" + urlencode(variants[index % len(variants)]), headers, "",
    )


# Sinh request theo scenario, thu response evidence và ghi dataset theo split.
def collect() -> dict[str, object]:
    base.RAW = ROOT / "ml-detector/data/raw/xfh_v3/requests.jsonl"
    base.PROCESSED = ROOT / "ml-detector/data/processed/xfh_v3/feature_records.jsonl"
    base.PROFILE = ROOT / "ml-detector/artifacts/candidates/xfh_v3_feature_profile.json"
    base.MANIFEST = ROOT / "ml-detector/data/manifests/xfh_v3/dataset_manifest.json"
    base.normal_case_v2 = normal_case_v3
    manifest = base.collect(seed=20270817, train_normal=8000, validation_normal=2000)
    manifest.update({
        "schema_version": "xfh-v3-dataset-manifest-v1",
        "candidate_generation": "relation-distance-only-full-sample-if",
        "blind_v1_records_used_for_training_or_calibration": False,
        "normal_policy": "XFH absent or exactly equal to Host; mismatch forbidden",
        "requires_new_blind_v2": True,
    })
    base.MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    print(json.dumps(collect(), ensure_ascii=False, indent=2))
