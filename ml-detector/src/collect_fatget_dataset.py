"""Collect the Fat GET normal-only/held-out dataset from the unchanged local lab."""
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
from fatget_features import (  # noqa: E402
    FATGET_DENSITY_FEATURE_NAMES, FATGET_FEATURE_NAMES, FATGET_HASH_FEATURE_NAMES,
    build_fatget_profile, extract_fatget_features,
)
from traffic.fusion_collect import (  # noqa: E402
    LANGUAGES, USER_AGENTS, add_benign_cookie, build_row, load_route_registry, observe,
)
from traffic.fusion_scenarios import FusionCase, base_headers  # noqa: E402


RAW = ROOT / "ml-detector" / "data" / "raw" / "fatget" / "requests.jsonl"
PROCESSED = ROOT / "ml-detector" / "data" / "processed" / "fatget" / "feature_records.jsonl"
PROFILE = ROOT / "ml-detector" / "artifacts" / "candidates" / "fatget_feature_profile.json"
MANIFEST = ROOT / "ml-detector" / "data" / "manifests" / "fatget" / "dataset_manifest.json"


# Sinh request normal cho blind test của route.
def normal_case(token: str, user_agent: str, language: str, index: int, method: str) -> FusionCase:
    headers = base_headers(user_agent, language)
    callback = ("setCountryCookie", "fusionCallback" + token[:8], "geoReady" + token[:6])[index % 3]
    locale = ("vi", "en", "vi-VN", "en-US")[index % 4]
    variants: tuple[list[tuple[str, str]], ...] = (
        [("callback", callback), ("locale", locale)],
        [("callback", callback), ("locale", locale), ("view", "compact")],
        [("locale", locale), ("callback", callback), ("region", "apac")],
        [("callback", callback), ("locale", locale), ("campaign", "autumn sale")],
        [("callback", callback), ("locale", locale), ("theme", "dark")],
        [("callback", callback), ("locale", locale), ("source", "storefront")],
        [("callback", callback), ("locale", locale), ("tag", "new"), ("tag", "sale")],
        [("callback", callback), ("locale", locale), ("format", "jsonp")],
        [("callback", callback), ("locale", locale), ("currency", "VND")],
        [("callback", callback), ("locale", locale), ("ref", "homepage")],
        [("callback", callback), ("locale", locale), ("limit", "24")],
        [("callback", callback), ("locale", locale), ("view", "compact cards"), ("region", "sea")],
    )
    uri = "/labs/fatget/js/geolocate.js?" + urlencode(variants[index % len(variants)])
    return FusionCase("fatget", "normal", "normal", f"fatget-benign-{index % len(variants):02d}", method, uri, headers, "")


# Sinh request attack cho blind test của route.
def attack_case(token: str, user_agent: str, language: str, index: int) -> FusionCase:
    headers = base_headers(user_agent, language)
    # Keep the request-line callback unique so collection validates a fresh
    # poisoning response instead of accidentally reusing a clean cached object.
    callback = ("fusionCallback", "geoReady", "countryHook")[index % 3] + token[:8]
    locale = ("vi", "en", "vi-VN")[index % 3]
    number = 1 + index % 5
    body_variants = (
        f"callback=alert%28{number}%29",
        f"locale=vi&callback=alert%28{number}%29",
        f"callback=alert%28{number}%29&source=body",
        f"source=body&callback=alert%28{number}%29",
        f"callback=alert%28{number}%29&note=campaign",
    )
    body = body_variants[index % len(body_variants)]
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["Content-Length"] = str(len(body.encode("utf-8")))
    uri = "/labs/fatget/js/geolocate.js?" + urlencode({"callback": callback, "locale": locale})
    return FusionCase(
        "fatget", "attack", "fat-get-body", f"body-callback-override-{number}",
        "GET", uri, headers, body,
    )


# Chiếu lab case thành metadata đầu vào của model.
def _request(case: FusionCase) -> dict[str, object]:
    return {"method": case.method, "uri": case.uri, "headers": case.headers}


# Sinh request theo scenario, thu response evidence và ghi dataset theo split.
def collect(origin: str = "http://127.0.0.1:8086", seed: int = 20261006,
            train_normal: int = 5000, validation_normal: int = 1000,
            test_normal: int = 1000, test_attack: int = 1000,
            session_size: int = 10, cookie_ratio: float = 0.60,
            head_ratio: float = 0.20) -> dict[str, object]:
    counts = (train_normal, validation_normal, test_normal, test_attack)
    if any(count < 1 or count % session_size for count in counts):
        raise ValueError("all counts must be positive and divisible by session-size")
    registry = load_route_registry()
    normalized_origin = origin.rstrip("/")
    if normalized_origin not in set(registry["allowed_targets"]):
        raise ValueError("Fat GET target must be an allowlisted local origin")
    routes = registry["routes"]
    rng = random.Random(seed)
    collection_id = "fatget-" + uuid.uuid4().hex[:12]
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
                raise RuntimeError("Fat GET normal collection failed")
            group_id = f"{collection_id}-normal-{split}-session-{index // session_size:05d}"
            captured.append((split, group_id, case, observation))
            normal_index += 1
        print(f"Collected {count} Fat GET {split}-normal records", flush=True)

    for index in range(test_attack):
        token = f"{rng.getrandbits(96):024x}"
        case = attack_case(token, rng.choice(USER_AGENTS), rng.choice(LANGUAGES), index)
        add_benign_cookie(case, token, rng, cookie_ratio)
        observation = observe(normalized_origin, case)
        if observation["status"] != 200 or not observation["request_id"] or not observation["effect_observed"]:
            raise RuntimeError(f"Fat GET attack effect failed for {case.payload_variant}")
        group_id = f"{collection_id}-attack-test-session-{index // session_size:05d}"
        captured.append(("test", group_id, case, observation))
    print(f"Collected {test_attack} Fat GET test-attack records", flush=True)

    profile = build_fatget_profile([_request(item[2]) for item in captured[:train_normal]])
    raw_rows, processed_rows = [], []
    for split, group_id, case, observation in captured:
        features = extract_fatget_features(_request(case), profile)
        row = build_row(collection_id, group_id, split, case, observation, routes)
        row["schema_version"] = "wcp-fatget-record-v1"
        row["request_features"] = {
            "feature_schema_version": "fatget-request-features-v1",
            "method": case.method,
            "uri_path": urlsplit(case.uri).path,
            "structural": {name: features[name] for name in STRUCTURAL_FEATURE_NAMES},
            "fatget_hash": {name: features[name] for name in FATGET_HASH_FEATURE_NAMES},
            "fatget_density": {name: features[name] for name in FATGET_DENSITY_FEATURE_NAMES},
        }
        row["feature_policy"].update({
            "request_body_stored": False, "raw_content_headers_stored": False,
            "numeric_fingerprints_only": True,
        })
        raw_rows.append(row)
        annotation = row["annotation"]
        processed_rows.append({
            "schema_version": "wcp-fatget-features-v1",
            "record_id": row["record_id"], "group_id": group_id,
            "route": "fatget", "split": split,
            "label": int(annotation["label"] == "attack"),
            "label_name": annotation["label"], "attack_type": annotation["attack_type"],
            "payload_variant": annotation["payload_variant"],
            "features": {name: float(features[name]) for name in FATGET_FEATURE_NAMES},
        })

    normal_rows = [row for row in raw_rows if row["annotation"]["label"] == "normal"]
    attack_rows = [row for row in raw_rows if row["annotation"]["label"] == "attack"]
    fixed_count = sum("/fixed/" in row["request_features"]["uri_path"] for row in raw_rows)
    normal_body = sum(row["request_features"]["structural"]["has_body_on_get"] != 0 for row in normal_rows)
    attack_body = sum(row["request_features"]["structural"]["has_body_on_get"] == 1 for row in attack_rows)
    if fixed_count or normal_body or attack_body != len(attack_rows) or not all(
        row["evidence"]["effect"]["verified"] for row in attack_rows
    ):
        raise RuntimeError("Fat GET dataset invariant failed")

    write_jsonl(RAW, raw_rows)
    write_jsonl(PROCESSED, processed_rows)
    PROFILE.parent.mkdir(parents=True, exist_ok=True)
    PROFILE.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "schema_version": "fatget-dataset-manifest-v1", "collection_id": collection_id,
        "route": "fatget", "origin": normalized_origin,
        "vulnerable_target": routes["fatget"]["vulnerable_target"], "fixed_route_included": False,
        "design_frozen_before_final_test": True, "seed": seed, "session_size": session_size,
        "cookie_ratio": cookie_ratio, "head_ratio": head_ratio,
        "counts": {"train_normal": train_normal, "validation_normal": validation_normal,
                   "test_normal": test_normal, "test_attack": test_attack},
        "feature_count": len(FATGET_FEATURE_NAMES),
        "feature_groups": {"structural": len(STRUCTURAL_FEATURE_NAMES),
                           "signed_relationship_hash": len(FATGET_HASH_FEATURE_NAMES),
                           "fatget_density": len(FATGET_DENSITY_FEATURE_NAMES)},
        "normal_variant_counts": dict(Counter(row["annotation"]["payload_variant"] for row in normal_rows)),
        "attack_variant_counts": dict(Counter(row["annotation"]["payload_variant"] for row in attack_rows)),
        "invariants": {
            "fixed_route_count": fixed_count, "normal_get_body_count": normal_body,
            "attack_get_body_count": attack_body,
            "attack_effect_verified_count": sum(row["evidence"]["effect"]["verified"] for row in attack_rows),
            "unique_request_id_count": len({row["evidence"]["request_id"] for row in raw_rows}),
        },
        "privacy": {"request_body_stored": False, "raw_content_headers_stored": False,
                    "raw_cookie_stored": False, "evidence_excluded_from_ml": True},
        "outputs": {"raw": str(RAW.relative_to(ROOT)).replace("\\", "/"),
                    "processed": str(PROCESSED.relative_to(ROOT)).replace("\\", "/"),
                    "feature_profile": str(PROFILE.relative_to(ROOT)).replace("\\", "/")},
    }
    manifest["sha256"] = {
        "raw": hashlib.sha256(RAW.read_bytes()).hexdigest(),
        "processed": hashlib.sha256(PROCESSED.read_bytes()).hexdigest(),
        "feature_profile": hashlib.sha256(PROFILE.read_bytes()).hexdigest(),
    }
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    print(json.dumps(collect(), ensure_ascii=False, indent=2))
