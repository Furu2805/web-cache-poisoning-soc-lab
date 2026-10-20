"""Collect Fat GET v2 data with broader benign request-shape coverage."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlencode

import collect_fatget_dataset as base
from traffic.fusion_scenarios import FusionCase, base_headers


ROOT = Path(__file__).resolve().parents[2]


# Sinh normal case phiên bản v2 cho route.
def normal_case_v2(token: str, user_agent: str, language: str, index: int, method: str) -> FusionCase:
    headers = base_headers(user_agent, language)
    callback = ("setCountryCookie", "geoReady" + token[:7], "regionHook" + token[:6],
                "storeLocale" + token[:5])[index % 4]
    locale = ("vi", "en", "vi-VN", "en-US", "ja-JP", "ko-KR")[index % 6]
    variants = (
        (("callback", callback), ("locale", locale)),
        (("locale", locale), ("callback", callback), ("view", "grid")),
        (("callback", callback), ("locale", locale), ("region", "sea")),
        (("callback", callback), ("locale", locale), ("campaign", "weekend offer")),
        (("callback", callback), ("locale", locale), ("theme", "light")),
        (("callback", callback), ("locale", locale), ("source", "catalog")),
        (("callback", callback), ("locale", locale), ("tag", "popular"), ("tag", "portable")),
        (("callback", callback), ("locale", locale), ("format", "jsonp")),
        (("callback", callback), ("locale", locale), ("currency", "USD")),
        (("callback", callback), ("locale", locale), ("ref", "navigation")),
        (("callback", callback), ("locale", locale), ("limit", "36")),
        (("locale", locale), ("callback", callback), ("view", "cards"), ("region", "apac")),
        (("callback", callback), ("locale", locale), ("page", "2"), ("sort", "newest")),
        (("callback", callback), ("locale", locale), ("device", "desktop")),
        (("callback", callback), ("locale", locale), ("channel", "web")),
        (("callback", callback), ("locale", locale), ("preview", "false")),
    )
    if index % 9 in (2, 7):
        headers["X-Forwarded-Proto"] = "https"
    headers["Accept"] = (
        "application/javascript,*/*;q=0.8",
        "text/javascript,application/javascript;q=0.9,*/*;q=0.5",
        "*/*",
        "application/json,text/javascript;q=0.8,*/*;q=0.4",
    )[index % 4]
    return FusionCase(
        "fatget", "normal", "normal", f"fatget-v2-benign-{index % 64:02d}", method,
        "/labs/fatget/js/geolocate.js?" + urlencode(variants[index % len(variants)]), headers, "",
    )


# Sinh request theo scenario, thu response evidence và ghi dataset theo split.
def collect() -> dict[str, object]:
    base.RAW = ROOT / "ml-detector/data/raw/fatget_v2/requests.jsonl"
    base.PROCESSED = ROOT / "ml-detector/data/processed/fatget_v2/feature_records.jsonl"
    base.PROFILE = ROOT / "ml-detector/artifacts/candidates/fatget_v2_feature_profile.json"
    base.MANIFEST = ROOT / "ml-detector/data/manifests/fatget_v2/dataset_manifest.json"
    base.normal_case = normal_case_v2
    manifest = base.collect(seed=20270921, train_normal=8000, validation_normal=2000)
    manifest.update({
        "schema_version": "fatget-v2-dataset-manifest-v1",
        "candidate_generation": "body-presence-relation-full-sample-if",
        "blind_v1_records_used_for_training_or_calibration": False,
        "normal_policy": "GET/HEAD without body; vulnerable GET-body primitive excluded from normal",
        "requires_new_blind_v2": True,
    })
    base.MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    print(json.dumps(collect(), ensure_ascii=False, indent=2))
