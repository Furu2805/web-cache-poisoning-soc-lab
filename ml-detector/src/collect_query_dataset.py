"""Collect fresh Query-v4 evidence for conservative FPR calibration."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from collect_query_dataset_core import collect  # noqa: E402
from query_features import (  # noqa: E402
    QUERY_V3_DENSITY_FEATURE_NAMES, QUERY_V3_FEATURE_NAMES,
    build_profile_v3, extract_query_v3,
)
from traffic.fusion_scenarios import FusionCase, base_headers  # noqa: E402


RAW = ROOT / "ml-detector" / "data" / "raw" / "query_v4" / "requests.jsonl"
PROCESSED = ROOT / "ml-detector" / "data" / "processed" / "query_v4" / "feature_records.jsonl"
PROFILE = ROOT / "ml-detector" / "artifacts" / "candidates" / "query_v4_feature_profile.json"
MANIFEST = ROOT / "ml-detector" / "data" / "manifests" / "query_v4" / "dataset_manifest.json"


# Sinh Query attack case theo biến thể v4.
def _attack_case_v4(token: str, user_agent: str, language: str, index: int) -> FusionCase:
    headers = base_headers(user_agent, language)
    variants = (
        ("math-image-onerror", "'><math><mtext></math><img src=x onerror=alert(9)>"),
        ("body-onpageshow", "'><body onpageshow=alert(9)>"),
        ("video-source-onerror", "'><video><source onerror=alert(9)>"),
        ("input-onfocus", '\"><input autofocus onfocus=alert(9)>'),
        ("javascript-url-v4", "javascript:alert(9)"),
    )
    name, payload = variants[index % len(variants)]
    payload = payload.replace(" ", "%20")
    query = urlencode([("cb", token), ("page", "1"), ("view", "grid")])
    return FusionCase(
        "query", "attack", "query-unkeyed-parameter", name, "GET",
        "/labs/query/?" + query + "&utm_content=" + payload, headers, "",
    )


# Đọc tham số CLI và chạy thu dataset của collect_query_dataset.
def main() -> None:
    result = collect(
        "http://127.0.0.1:8086", RAW, PROCESSED, PROFILE, MANIFEST,
        seed=20261003, dataset_version="v4", profile_builder=build_profile_v3,
        feature_extractor=extract_query_v3, feature_names=QUERY_V3_FEATURE_NAMES,
        density_names=QUERY_V3_DENSITY_FEATURE_NAMES, attack_factory=_attack_case_v4,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
