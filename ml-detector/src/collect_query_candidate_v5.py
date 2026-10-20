"""Collect a broader development dataset for generalized Query candidate v5."""
from __future__ import annotations

import hashlib
import json
import random
import sys
import uuid
from collections import Counter
from pathlib import Path
from urllib.parse import urlencode, urlsplit


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common.features import STRUCTURAL_FEATURE_NAMES  # noqa: E402
from common.io import write_jsonl  # noqa: E402
from query_generalized_features import (  # noqa: E402
    QUERY_GENERAL_DENSITY_FEATURE_NAMES, QUERY_GENERAL_FEATURE_NAMES,
    QUERY_GENERAL_HASH_FEATURE_NAMES, build_query_general_profile,
    extract_query_general_features,
)
from traffic.fusion_collect import add_benign_cookie, build_row, load_route_registry, observe  # noqa: E402
from traffic.fusion_scenarios import FusionCase, base_headers  # noqa: E402


RAW = ROOT / "ml-detector" / "data" / "raw" / "query_v5" / "requests.jsonl"
PROCESSED = ROOT / "ml-detector" / "data" / "processed" / "query_v5" / "feature_records.jsonl"
PROFILE = ROOT / "ml-detector" / "artifacts" / "candidates" / "query_v5_feature_profile.json"
MANIFEST = ROOT / "ml-detector" / "data" / "manifests" / "query_v5" / "dataset_manifest.json"
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/149.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/605.1.15 Version/19.0 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 16) AppleWebKit/537.36 Chrome/149.0 Mobile Safari/537.36",
    "curl/8.15.0",
)
LANGUAGES = ("vi-VN,vi;q=0.8,en;q=0.6", "en-GB,en;q=0.8", "ko-KR,ko;q=0.8,en;q=0.5")


# Sinh request normal cho blind test của route.
def normal_case(token: str, user_agent: str, language: str, index: int, method: str) -> FusionCase:
    headers = base_headers(user_agent, language)
    views = ("mosaic", "detailed", "tiles", "summary", "rows")
    campaigns = ("summer roadmap", "partner bulletin", "editorial digest", "member preview", "seasonal catalogue")
    searches = ("ergonomic keyboard", "portable monitor", "mesh router", "noise cancelling headset", "usb charger")
    categories = ("office", "networking", "audio", "mobile", "storage")
    locales = ("en-CA", "ko-KR", "vi-VN", "fr-FR", "de-DE")
    view = views[index % len(views)]
    campaign = campaigns[(index // 2) % len(campaigns)]
    q = searches[(index // 3) % len(searches)]
    category = categories[(index // 5) % len(categories)]
    locale = locales[(index // 7) % len(locales)]
    variants: tuple[list[tuple[str, str]], ...] = (
        [("cb", token), ("page", "8"), ("view", view), ("utm_content", campaign)],
        [("view", view), ("cb", token), ("page", "9"), ("utm_content", campaign)],
        [("cb", token), ("locale", locale), ("campaign", campaign), ("utm_content", "member bulletin")],
        [("cb", token), ("q", q), ("category", category), ("page", "3")],
        [("cb", token), ("page", "4"), ("sort", "popularity"), ("currency", "EUR")],
        [("cb", token), ("page", "5"), ("tag", "portable"), ("tag", "recommended")],
        [("utm_content", campaign), ("cb", token), ("view", view), ("page", "6")],
        [("cb", token), ("campaign", campaign), ("source", "desktop client"), ("limit", "48")],
        [("cb", token), ("note", "editor recommendation"), ("ref", "monthly bulletin"), ("page", "2")],
        [("cb", token), ("locale", locale), ("view", view), ("utm_content", "international release")],
        [("cb", token), ("page", "10"), ("layout", "wide panels"), ("theme", "system")],
        [("cb", token), ("category", category), ("q", q), ("utm_content", "search campaign")],
        [("cb", token), ("filter", "in stock"), ("channel", "web catalogue"), ("page", "2")],
        [("channel", "partner portal"), ("cb", token), ("locale", locale), ("view", view)],
        [("cb", token), ("offset", "24"), ("limit", "24"), ("sort", "newest")],
        [("cb", token), ("category", category), ("filter", "free shipping"), ("currency", "EUR")],
        [("cb", token), ("page", "2"), ("format", "html"), ("layout", "compact rows")],
        [("cb", token), ("region", "emea"), ("source", "partner app"), ("utm_content", campaign)],
    )
    uri = "/labs/query/?" + urlencode(variants[index % len(variants)])
    return FusionCase("query", "normal", "normal", f"query-v5-benign-{index % len(variants):02d}", method, uri, headers, "")


# Sinh request attack cho blind test của route.
def attack_case(token: str, user_agent: str, language: str, index: int) -> FusionCase:
    headers = base_headers(user_agent, language)
    variants = (
        ("javascript-scheme-v5", "javascript:alert(81)"),
        ("self-string-breakout-v5", "';self.alert(82);//"),
        ("object-data-context-v5", "</script><object data=javascript:alert(83)>") ,
        ("marquee-event-context-v5", "</script><marquee onstart=alert(84)>") ,
        ("image-error-context-v5", "</script><img src=x onerror=alert(85)>") ,
    )
    name, payload = variants[index % len(variants)]
    keyed = urlencode([("cb", token), ("page", "4"), ("view", "mosaic")])
    return FusionCase(
        "query", "attack", "query-unkeyed-parameter", name, "GET",
        "/labs/query/?" + keyed + "&utm_content=" + payload.replace(" ", "%20"), headers, "",
    )


# Chiếu lab case thành metadata đầu vào của model.
def _request(case: FusionCase) -> dict[str, object]:
    return {"method": case.method, "uri": case.uri, "headers": case.headers}


# Sinh request theo scenario, thu response evidence và ghi dataset theo split.
def collect(origin: str = "http://127.0.0.1:8086", seed: int = 20261110,
            train_normal: int = 8000, validation_normal: int = 2000,
            test_normal: int = 1000, test_attack: int = 1000,
            session_size: int = 10, cookie_ratio: float = 0.60,
            head_ratio: float = 0.20) -> dict[str, object]:
    counts = (train_normal, validation_normal, test_normal, test_attack)
    if any(count < 1 or count % session_size for count in counts):
        raise ValueError("all counts must be positive and divisible by session-size")
    registry = load_route_registry()
    normalized_origin = origin.rstrip("/")
    if normalized_origin not in set(registry["allowed_targets"]):
        raise ValueError("Query-v5 target must be an allowlisted local origin")
    routes = registry["routes"]
    rng = random.Random(seed)
    collection_id = "query-v5-" + uuid.uuid4().hex[:12]
    captured: list[tuple[str, str, FusionCase, dict[str, object]]] = []
    normal_index = 0

    for split, count in (("train", train_normal), ("validation", validation_normal), ("test", test_normal)):
        for index in range(count):
            token = f"{rng.getrandbits(96):024x}"
            method = "HEAD" if index / count < head_ratio else "GET"
            case = normal_case(token, rng.choice(USER_AGENTS), rng.choice(LANGUAGES), normal_index, method)
            add_benign_cookie(case, token, rng, cookie_ratio)
            observation = observe(normalized_origin, case)
            if observation["status"] != 200 or not observation["request_id"]:
                raise RuntimeError("Query-v5 normal collection failed")
            group_id = f"{collection_id}-normal-{split}-session-{index // session_size:05d}"
            captured.append((split, group_id, case, observation))
            normal_index += 1
        print(f"Collected {count} Query-v5 {split}-normal records", flush=True)

    for index in range(test_attack):
        token = f"{rng.getrandbits(96):024x}"
        case = attack_case(token, rng.choice(USER_AGENTS), rng.choice(LANGUAGES), index)
        add_benign_cookie(case, token, rng, cookie_ratio)
        observation = observe(normalized_origin, case)
        if observation["status"] != 200 or not observation["request_id"] or not observation["effect_observed"]:
            raise RuntimeError(f"Query-v5 attack effect failed for {case.payload_variant}")
        group_id = f"{collection_id}-attack-test-session-{index // session_size:05d}"
        captured.append(("test", group_id, case, observation))
    print(f"Collected {test_attack} Query-v5 test-attack records", flush=True)

    profile = build_query_general_profile([_request(item[2]) for item in captured[:train_normal]])
    raw_rows, processed_rows = [], []
    for split, group_id, case, observation in captured:
        features = extract_query_general_features(_request(case), profile)
        row = build_row(collection_id, group_id, split, case, observation, routes)
        row["schema_version"] = "wcp-query-v5-record-v1"
        row["request_features"] = {
            "feature_schema_version": "query-generalized-request-features-v1",
            "method": case.method, "uri_path": urlsplit(case.uri).path,
            "structural": {name: features[name] for name in STRUCTURAL_FEATURE_NAMES},
            "generalized_hash": {name: features[name] for name in QUERY_GENERAL_HASH_FEATURE_NAMES},
            "generalized_density": {name: features[name] for name in QUERY_GENERAL_DENSITY_FEATURE_NAMES},
        }
        row["feature_policy"].update({
            "raw_query_stored": False, "raw_value_stored": False,
            "abstract_syntax_fingerprints_only": True,
        })
        raw_rows.append(row)
        annotation = row["annotation"]
        processed_rows.append({
            "schema_version": "wcp-query-v5-features-v1",
            "record_id": row["record_id"], "group_id": group_id,
            "route": "query", "split": split,
            "label": int(annotation["label"] == "attack"),
            "label_name": annotation["label"], "attack_type": annotation["attack_type"],
            "payload_variant": annotation["payload_variant"],
            "features": {name: float(features[name]) for name in QUERY_GENERAL_FEATURE_NAMES},
        })

    normal_rows = [row for row in raw_rows if row["annotation"]["label"] == "normal"]
    attack_rows = [row for row in raw_rows if row["annotation"]["label"] == "attack"]
    fixed_count = sum("/fixed/" in row["request_features"]["uri_path"] for row in raw_rows)
    if fixed_count or not all(row["evidence"]["effect"]["verified"] for row in attack_rows):
        raise RuntimeError("Query-v5 dataset invariant failed")

    write_jsonl(RAW, raw_rows)
    write_jsonl(PROCESSED, processed_rows)
    PROFILE.parent.mkdir(parents=True, exist_ok=True)
    PROFILE.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "schema_version": "query-v5-dataset-manifest-v1", "collection_id": collection_id,
        "route": "query", "origin": normalized_origin,
        "vulnerable_target": routes["query"]["vulnerable_target"], "fixed_route_included": False,
        "development_after_blind_v1": True,
        "blind_v1_records_used_for_training": False,
        "requires_new_blind_v2": True,
        "seed": seed, "session_size": session_size, "cookie_ratio": cookie_ratio, "head_ratio": head_ratio,
        "counts": {"train_normal": train_normal, "validation_normal": validation_normal,
                   "test_normal": test_normal, "test_attack": test_attack},
        "feature_count": len(QUERY_GENERAL_FEATURE_NAMES),
        "feature_groups": {"structural": len(STRUCTURAL_FEATURE_NAMES),
                           "generalized_signed_hash": len(QUERY_GENERAL_HASH_FEATURE_NAMES),
                           "generalized_density": len(QUERY_GENERAL_DENSITY_FEATURE_NAMES)},
        "normal_variant_counts": dict(Counter(row["annotation"]["payload_variant"] for row in normal_rows)),
        "attack_variant_counts": dict(Counter(row["annotation"]["payload_variant"] for row in attack_rows)),
        "invariants": {"fixed_route_count": fixed_count,
                       "attack_effect_verified_count": sum(row["evidence"]["effect"]["verified"] for row in attack_rows),
                       "unique_request_id_count": len({row["evidence"]["request_id"] for row in raw_rows})},
        "privacy": {"raw_query_stored": False, "raw_value_stored": False,
                    "raw_cookie_stored": False, "evidence_excluded_from_ml": True},
        "outputs": {"raw": str(RAW.relative_to(ROOT)).replace("\\", "/"),
                    "processed": str(PROCESSED.relative_to(ROOT)).replace("\\", "/"),
                    "feature_profile": str(PROFILE.relative_to(ROOT)).replace("\\", "/")},
    }
    manifest["sha256"] = {"raw": hashlib.sha256(RAW.read_bytes()).hexdigest(),
                          "processed": hashlib.sha256(PROCESSED.read_bytes()).hexdigest(),
                          "feature_profile": hashlib.sha256(PROFILE.read_bytes()).hexdigest()}
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    print(json.dumps(collect(), ensure_ascii=False, indent=2))
