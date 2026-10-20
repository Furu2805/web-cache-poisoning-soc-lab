"""Shared collector for the retained Query normal-only/held-out dataset.

The vulnerable lab is not modified. Attack variants change only request
encoding and preserve an ordinary keyed query shape; every attack label still
requires the vulnerable response effect to be observed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import uuid
from collections import Counter
from pathlib import Path
from collections.abc import Callable
from urllib.parse import urlencode, urlsplit


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from common.features import STRUCTURAL_FEATURE_NAMES  # noqa: E402
from common.io import write_jsonl  # noqa: E402
from query_feature_base import (  # noqa: E402
    QUERY_DENSITY_FEATURE_NAMES,
    QUERY_HASH_FEATURE_NAMES,
    QUERY_V2_FEATURE_NAMES,
    build_profile,
    extract_query_v2,
)
from traffic.fusion_collect import (  # noqa: E402
    LANGUAGES, USER_AGENTS, add_benign_cookie,
    build_row, load_route_registry, observe,
)
from traffic.fusion_scenarios import FusionCase, base_headers  # noqa: E402


DEFAULT_RAW = ROOT / "ml-detector" / "data" / "raw" / "query_v4" / "requests.jsonl"
DEFAULT_PROCESSED = ROOT / "ml-detector" / "data" / "processed" / "query_v4" / "feature_records.jsonl"
DEFAULT_PROFILE = ROOT / "ml-detector" / "artifacts" / "candidates" / "query_v4_feature_profile.json"
DEFAULT_MANIFEST = ROOT / "ml-detector" / "data" / "manifests" / "query_v4" / "dataset_manifest.json"


# Sinh normal case có group/split cho dataset.
def _normal_case(token: str, user_agent: str, language: str,
                 variant_index: int, method: str) -> FusionCase:
    headers = base_headers(user_agent, language)
    variants: tuple[list[tuple[str, str]], ...] = (
        [("cb", token), ("page", "1"), ("view", "grid"), ("utm_content", "autumn-launch")],
        [("cb", token), ("view", "list"), ("page", "2"), ("utm_content", "email campaign")],
        [("page", "3"), ("cb", token), ("view", "compact"), ("utm_content", "product-guide")],
        [("utm_content", "homepage banner"), ("cb", token), ("page", "1"), ("view", "grid")],
        [("cb", token), ("page", "4"), ("view", "cards")],
        [("cb", token), ("q", "wireless mouse"), ("category", "computers"), ("page", "1"), ("utm_content", "search ad")],
        [("cb", token), ("page", "1"), ("view", "grid"), ("tag", "computer"), ("tag", "accessory"), ("utm_content", "tag campaign")],
        [("cb", token), ("locale", "vi-VN"), ("ref", "email"), ("campaign", "new arrivals"), ("utm_content", "newsletter")],
        [("cb", token), ("page", "2"), ("sort", "price"), ("currency", "VND"), ("utm_content", "price-comparison")],
        [("cb", token), ("q", "buyer's guide"), ("note", "editor's choice"), ("utm_content", "content hub")],
        [("cb", token), ("page", "1"), ("view", "grid"), ("layout", "cards compact"), ("theme", "dark"), ("utm_content", "design test")],
        [("cb", token), ("category", "featured"), ("limit", "24"), ("campaign", "autumn sale"), ("source", "storefront"), ("utm_content", "featured-products")],
    )
    pairs = variants[variant_index % len(variants)]
    return FusionCase(
        "query", "normal", "normal", f"query-v2-benign-{variant_index % len(variants):02d}",
        method, "/labs/query/?" + urlencode(pairs), headers, "",
    )


# Sinh attack case có group/split cho dataset.
def _attack_case(token: str, user_agent: str, language: str,
                 variant_index: int) -> FusionCase:
    headers = base_headers(user_agent, language)
    raw_script = "'/><script>alert(1)</script>"
    raw_javascript = "';alert(1);//"
    variants = (
        ("raw-script-context", raw_script),
        ("raw-javascript-context", raw_javascript),
        ("raw-svg-context", "'/><svg/onload=alert(1)>") ,
        ("mixed-case-script-context", "'/><ScRiPt>alert(1)</ScRiPt>"),
        # A poisoned canonical URL that becomes script-bearing when followed.
        # It deliberately has none of the three clear profile primitives, so
        # it measures IF contribution instead of the normal-profile guard.
        ("javascript-url-context", "javascript:alert(1)"),
    )
    name, payload = variants[variant_index % len(variants)]
    # Keep all keyed parameters identical to the most common benign shape.
    # utm_content remains last so the existing vulnerable cache normalization
    # is exercised exactly as implemented by the lab.
    query = urlencode([("cb", token), ("page", "1"), ("view", "grid")])
    uri = "/labs/query/?" + query + "&utm_content=" + payload
    return FusionCase("query", "attack", "query-unkeyed-parameter", name, "GET", uri, headers, "")


# Chiếu lab case thành metadata đầu vào của model.
def _request(case: FusionCase) -> dict[str, object]:
    return {"method": case.method, "uri": case.uri, "headers": case.headers}


# Sinh request theo scenario, thu response evidence và ghi dataset theo split.
def collect(origin: str, raw_path: Path = DEFAULT_RAW,
            processed_path: Path = DEFAULT_PROCESSED,
            profile_path: Path = DEFAULT_PROFILE,
            manifest_path: Path = DEFAULT_MANIFEST,
            train_normal: int = 5000, validation_normal: int = 1000,
            test_normal: int = 1000, test_attack: int = 1000,
            session_size: int = 10, seed: int = 20261001,
            cookie_ratio: float = 0.60, head_ratio: float = 0.20,
            dataset_version: str = "v2",
            profile_builder: Callable[[list[dict[str, object]]], dict[str, object]] = build_profile,
            feature_extractor: Callable[[dict[str, object], dict[str, object]], dict[str, float]] = extract_query_v2,
            feature_names: tuple[str, ...] = QUERY_V2_FEATURE_NAMES,
            density_names: tuple[str, ...] = QUERY_DENSITY_FEATURE_NAMES,
            normal_factory: Callable[[str, str, str, int, str], FusionCase] = _normal_case,
            attack_factory: Callable[[str, str, str, int], FusionCase] = _attack_case) -> dict[str, object]:
    counts = (train_normal, validation_normal, test_normal, test_attack)
    if any(count < 1 or count % session_size for count in counts):
        raise ValueError("all counts must be positive and divisible by session-size")
    registry = load_route_registry()
    normalized_origin = origin.rstrip("/")
    if normalized_origin not in set(registry["allowed_targets"]):
        raise ValueError("Query-v2 target must be an allowlisted local origin")
    routes = registry["routes"]
    rng = random.Random(seed)
    collection_id = f"query-{dataset_version}-" + uuid.uuid4().hex[:12]
    captured: list[tuple[str, str, FusionCase, dict[str, object]]] = []
    global_normal_index = 0

    for split, count in (("train", train_normal), ("validation", validation_normal), ("test", test_normal)):
        for index in range(count):
            token = f"{rng.getrandbits(96):024x}"
            method = "HEAD" if index / count < head_ratio else "GET"
            case = normal_factory(token, rng.choice(USER_AGENTS), rng.choice(LANGUAGES), global_normal_index, method)
            add_benign_cookie(case, token, rng, cookie_ratio)
            observation = observe(normalized_origin, case)
            if observation["status"] != 200 or not observation["request_id"]:
                raise RuntimeError("Query-v2 normal collection failed")
            group_id = f"{collection_id}-normal-{split}-session-{index // session_size:05d}"
            captured.append((split, group_id, case, observation))
            global_normal_index += 1
        print(f"Collected {count} Query-{dataset_version} {split}-normal records", flush=True)

    for index in range(test_attack):
        token = f"{rng.getrandbits(96):024x}"
        case = attack_factory(token, rng.choice(USER_AGENTS), rng.choice(LANGUAGES), index)
        add_benign_cookie(case, token, rng, cookie_ratio)
        observation = observe(normalized_origin, case)
        if observation["status"] != 200 or not observation["request_id"] or not observation["effect_observed"]:
            raise RuntimeError(f"Query-v2 attack effect failed for {case.payload_variant}")
        group_id = f"{collection_id}-attack-test-session-{index // session_size:05d}"
        captured.append(("test", group_id, case, observation))
    print(f"Collected {test_attack} Query-{dataset_version} test-attack records", flush=True)

    train_requests = [_request(item[2]) for item in captured[:train_normal]]
    profile = profile_builder(train_requests)
    raw_rows, processed_rows = [], []
    for split, group_id, case, observation in captured:
        features = feature_extractor(_request(case), profile)
        row = build_row(collection_id, group_id, split, case, observation, routes)
        row["schema_version"] = f"wcp-query-{dataset_version}-record-v1"
        row["request_features"] = {
            "feature_schema_version": f"query-{dataset_version}-request-features-v1",
            "method": case.method,
            "uri_path": urlsplit(case.uri).path,
            "structural": {name: features[name] for name in STRUCTURAL_FEATURE_NAMES},
            "query_hash": {name: features[name] for name in QUERY_HASH_FEATURE_NAMES},
            "query_density": {name: features[name] for name in density_names},
        }
        row["feature_policy"].update({
            "raw_query_stored": False,
            "decoded_query_stored": False,
            "numeric_fingerprints_only": True,
        })
        raw_rows.append(row)
        annotation = row["annotation"]
        processed_rows.append({
            "schema_version": f"wcp-query-{dataset_version}-features-v1",
            "record_id": row["record_id"],
            "group_id": group_id,
            "route": "query",
            "split": split,
            "label": int(annotation["label"] == "attack"),
            "label_name": annotation["label"],
            "attack_type": annotation["attack_type"],
            "payload_variant": annotation["payload_variant"],
            "features": {name: float(features[name]) for name in feature_names},
        })

    normal_rows = [row for row in raw_rows if row["annotation"]["label"] == "normal"]
    attack_rows = [row for row in raw_rows if row["annotation"]["label"] == "attack"]
    fixed_count = sum("/fixed/" in row["request_features"]["uri_path"] for row in raw_rows)
    normal_clear_primitive = sum(
        any(row["request_features"]["structural"][name] > 0 for name in (
            "raw_angle_bracket_count", "single_quote_count", "semicolon_count"
        )) for row in normal_rows
    )
    if fixed_count or normal_clear_primitive or not all(row["evidence"]["effect"]["verified"] for row in attack_rows):
        raise RuntimeError("Query-v2 dataset invariant failed")

    write_jsonl(raw_path, raw_rows)
    write_jsonl(processed_path, processed_rows)
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "schema_version": f"query-{dataset_version}-dataset-manifest-v1",
        "collection_id": collection_id,
        "route": "query",
        "origin": normalized_origin,
        "vulnerable_target": routes["query"]["vulnerable_target"],
        "fixed_route_included": False,
        "design_frozen_before_final_test": True,
        "seed": seed,
        "session_size": session_size,
        "cookie_ratio": cookie_ratio,
        "head_ratio": head_ratio,
        "counts": {
            "train_normal": train_normal, "validation_normal": validation_normal,
            "test_normal": test_normal, "test_attack": test_attack,
        },
        "feature_count": len(feature_names),
        "feature_groups": {
            "structural": len(STRUCTURAL_FEATURE_NAMES),
            "signed_query_hash": len(QUERY_HASH_FEATURE_NAMES),
            "query_density": len(density_names),
        },
        "normal_variant_counts": dict(Counter(row["annotation"]["payload_variant"] for row in normal_rows)),
        "attack_variant_counts": dict(Counter(row["annotation"]["payload_variant"] for row in attack_rows)),
        "encoded_attack_count": 0,
        "attack_encoding_note": (
            "Fully percent-encoded payloads were excluded because this lab reflects percent escapes "
            "without decoding them and the browser-visible alert effect cannot be verified."
        ),
        "invariants": {
            "fixed_route_count": fixed_count,
            "normal_clear_primitive_count": normal_clear_primitive,
            "attack_effect_verified_count": sum(row["evidence"]["effect"]["verified"] for row in attack_rows),
            "unique_request_id_count": len({row["evidence"]["request_id"] for row in raw_rows}),
        },
        "privacy": {
            "raw_query_stored": False, "decoded_query_stored": False,
            "raw_payload_stored": False, "raw_cookie_stored": False,
            "evidence_excluded_from_ml": True,
        },
        "outputs": {
            "raw": str(raw_path.relative_to(ROOT)).replace("\\", "/"),
            "processed": str(processed_path.relative_to(ROOT)).replace("\\", "/"),
            "feature_profile": str(profile_path.relative_to(ROOT)).replace("\\", "/"),
        },
    }
    manifest["sha256"] = {
        "raw": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        "processed": hashlib.sha256(processed_path.read_bytes()).hexdigest(),
        "feature_profile": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


# Đọc tham số CLI và chạy thu dataset của collect_query_dataset_core.
def main() -> None:
    parser = argparse.ArgumentParser(description="Collect Query-v2 dataset from local vulnerable lab")
    parser.add_argument("--origin", default="http://127.0.0.1:8086")
    parser.add_argument("--raw", type=Path, default=DEFAULT_RAW)
    parser.add_argument("--processed", type=Path, default=DEFAULT_PROCESSED)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--seed", type=int, default=20261001)
    args = parser.parse_args()
    print(json.dumps(collect(
        args.origin, args.raw, args.processed, args.profile, args.manifest, seed=args.seed
    ), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
