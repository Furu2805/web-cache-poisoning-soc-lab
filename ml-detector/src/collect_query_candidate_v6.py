"""Collect Query-v6 development data using only the lab's core query schema."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlencode

import collect_query_candidate_v5 as base
from traffic.fusion_scenarios import FusionCase, base_headers


ROOT = Path(__file__).resolve().parents[2]
CORE_NAMES = {"cb", "page", "view", "utm_content"}


# Sinh request normal cho blind test của route.
def normal_case(token: str, user_agent: str, language: str, index: int, method: str) -> FusionCase:
    headers = base_headers(user_agent, language)
    pages = ("1", "2", "3", "4", "5", "6", "8", "10")
    views = ("grid", "list", "compact", "gallery", "cards", "mosaic", "table", "detail")
    content = (
        "autumn launch", "email campaign", "homepage banner", "product guide",
        "weekly catalogue", "member preview", "partner bulletin", "seasonal collection",
        "editorial digest", "mobile promotion", "comparison page", "new arrivals",
    )
    cb, page, view, utm = token, pages[index % len(pages)], views[(index // 2) % len(views)], content[(index // 3) % len(content)]
    variants = (
        [("cb", cb), ("page", page), ("view", view), ("utm_content", utm)],
        [("cb", cb), ("view", view), ("page", page), ("utm_content", utm)],
        [("page", page), ("cb", cb), ("view", view), ("utm_content", utm)],
        [("utm_content", utm), ("cb", cb), ("page", page), ("view", view)],
        [("cb", cb), ("page", page), ("utm_content", utm), ("view", view)],
        [("cb", cb), ("view", view), ("utm_content", utm), ("page", page)],
    )
    pairs = variants[index % len(variants)]
    if {name for name, _ in pairs} != CORE_NAMES:
        raise AssertionError("Query-v6 normal schema drift")
    return FusionCase("query", "normal", "normal", f"query-v6-core-{index % len(variants):02d}",
                      method, "/labs/query/?" + urlencode(pairs), headers, "")


# Sinh request attack cho blind test của route.
def attack_case(token: str, user_agent: str, language: str, index: int) -> FusionCase:
    headers = base_headers(user_agent, language)
    variants = (
        ("query-v6-js-scheme", "javascript:alert(91)"),
        ("query-v6-script-breakout", "</script><script>alert(92)</script>"),
        ("query-v6-image-event", "</script><img src=x onerror=alert(93)>"),
        ("query-v6-object-data", "</script><object data=javascript:alert(94)>"),
        ("query-v6-quote-breakout", "';window.alert(95);//"),
    )
    name, payload = variants[index % len(variants)]
    pairs = [("cb", token), ("page", str(1 + index % 6)), ("view", ("grid", "list", "cards")[index % 3])]
    return FusionCase("query", "attack", "query-unkeyed-parameter", name, "GET",
                      "/labs/query/?" + urlencode(pairs) + "&utm_content=" + payload.replace(" ", "%20"), headers, "")


# Sinh request theo scenario, thu response evidence và ghi dataset theo split.
def collect() -> dict[str, object]:
    base.RAW = ROOT / "ml-detector/data/raw/query_v6/requests.jsonl"
    base.PROCESSED = ROOT / "ml-detector/data/processed/query_v6/feature_records.jsonl"
    base.PROFILE = ROOT / "ml-detector/artifacts/candidates/query_v6_feature_profile.json"
    base.MANIFEST = ROOT / "ml-detector/data/manifests/query_v6/dataset_manifest.json"
    base.normal_case = normal_case
    base.attack_case = attack_case
    manifest = base.collect(seed=20270119)
    manifest.update({
        "schema_version": "query-v6-dataset-manifest-v1",
        "candidate_generation": "v6-core-schema-stable-density",
        "allowed_query_parameter_names": sorted(CORE_NAMES),
        "blind_v2_records_used_for_training_or_calibration": False,
        "blind_v2_role": "diagnostic family-level evidence only",
        "requires_new_blind_v3": True,
    })
    base.MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    print(json.dumps(collect(), ensure_ascii=False, indent=2))
