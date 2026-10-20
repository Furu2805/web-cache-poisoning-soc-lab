"""Collect a fresh XFH-v2 dataset from the unchanged local vulnerable lab."""
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
from traffic.fusion_collect import (  # noqa: E402
    LANGUAGES, USER_AGENTS, add_benign_cookie, build_row,
    load_route_registry, observe,
)
from traffic.fusion_scenarios import FusionCase, base_headers  # noqa: E402
from xfh_features import (  # noqa: E402
    XFH_DENSITY_FEATURE_NAMES, XFH_HASH_FEATURE_NAMES, XFH_V2_FEATURE_NAMES,
    build_xfh_v2_profile, extract_xfh_v2,
)


RAW = ROOT / "ml-detector" / "data" / "raw" / "xfh_v2" / "requests.jsonl"
PROCESSED = ROOT / "ml-detector" / "data" / "processed" / "xfh_v2" / "feature_records.jsonl"
PROFILE = ROOT / "ml-detector" / "artifacts" / "candidates" / "xfh_v2_feature_profile.json"
MANIFEST = ROOT / "ml-detector" / "data" / "manifests" / "xfh_v2" / "dataset_manifest.json"


# Sinh normal case phiên bản v2 cho route.
def normal_case_v2(token: str, user_agent: str, language: str,
                   index: int, method: str) -> FusionCase:
    headers = base_headers(user_agent, language)
    hosts = (
        "127.0.0.1:8086", "localhost:8086", "fusion.local:8086",
        "shop.fusion.local:8086", "edge-a.fusion.local:8086",
    )
    host = hosts[index % len(hosts)]
    headers["Host"] = host
    if index % 10 >= 4:
        headers["X-Forwarded-Host"] = host
    accepts = (
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "text/html,application/xhtml+xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "text/html;q=0.9,application/json;q=0.7,*/*;q=0.5",
    )
    headers["Accept"] = accepts[index % len(accepts)]
    variants = (
        [("cb", token), ("category", "electronics"), ("page", "1")],
        [("cb", token), ("category", "computers"), ("page", "2"), ("view", "compact")],
        [("category", "featured"), ("cb", token), ("page", "3"), ("sort", "price")],
        [("cb", token), ("q", "usb hub"), ("currency", "VND"), ("page", "1")],
        [("cb", token), ("campaign", "autumn sale"), ("limit", "24")],
        [("cb", token), ("category", "electronics"), ("tag", "new"), ("tag", "sale")],
    )
    uri = "/labs/xfh/shop?" + urlencode(variants[index % len(variants)])
    return FusionCase("xfh", "normal", "normal", f"xfh-v2-benign-{index % 30:02d}", method, uri, headers, "")


# Sinh attack case phiên bản v2 cho route.
def attack_case_v2(token: str, user_agent: str, language: str, index: int) -> FusionCase:
    headers = base_headers(user_agent, language)
    hosts = (
        "127.0.0.1:8086", "localhost:8086", "fusion.local:8086",
        "shop.fusion.local:8086", "edge-a.fusion.local:8086",
    )
    names = (
        "loopback-host-mismatch", "localhost-with-proto", "fusion-host-mismatch",
        "shop-host-with-proto", "edge-host-mismatch",
    )
    headers["Host"] = hosts[index % len(hosts)]
    headers["X-Forwarded-Host"] = "127.0.0.1:8087"
    if index % 5 in {1, 3}:
        headers["X-Forwarded-Proto"] = "https"
    params = [("cb", token), ("category", ("electronics", "computers", "featured")[index % 3]),
              ("page", str(1 + index % 5))]
    if index % 2:
        params.append(("view", "compact"))
    return FusionCase(
        "xfh", "attack", "xfh-unkeyed-header", names[index % len(names)],
        "GET", "/labs/xfh/shop?" + urlencode(params), headers, "",
    )


# Chiếu lab case thành metadata đầu vào của model.
def _request(case: FusionCase) -> dict[str, object]:
    return {"method": case.method, "uri": case.uri, "headers": case.headers}


# Sinh request theo scenario, thu response evidence và ghi dataset theo split.
def collect(origin: str = "http://127.0.0.1:8086", seed: int = 20261004,
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
        raise ValueError("XFH-v2 target must be an allowlisted local origin")
    routes = registry["routes"]
    rng = random.Random(seed)
    collection_id = "xfh-v2-" + uuid.uuid4().hex[:12]
    captured: list[tuple[str, str, FusionCase, dict[str, object]]] = []
    normal_index = 0

    for split, count in (("train", train_normal), ("validation", validation_normal), ("test", test_normal)):
        for index in range(count):
            token = f"{rng.getrandbits(96):024x}"
            method = "HEAD" if index / count < head_ratio else "GET"
            case = normal_case_v2(token, rng.choice(USER_AGENTS), rng.choice(LANGUAGES), normal_index, method)
            add_benign_cookie(case, token, rng, cookie_ratio)
            observation = observe(normalized_origin, case)
            if observation["status"] != 200 or not observation["request_id"]:
                raise RuntimeError("XFH-v2 normal collection failed")
            group_id = f"{collection_id}-normal-{split}-session-{index // session_size:05d}"
            captured.append((split, group_id, case, observation))
            normal_index += 1
        print(f"Collected {count} XFH-v2 {split}-normal records", flush=True)

    for index in range(test_attack):
        token = f"{rng.getrandbits(96):024x}"
        case = attack_case_v2(token, rng.choice(USER_AGENTS), rng.choice(LANGUAGES), index)
        add_benign_cookie(case, token, rng, cookie_ratio)
        observation = observe(normalized_origin, case)
        if observation["status"] != 200 or not observation["request_id"] or not observation["effect_observed"]:
            raise RuntimeError(f"XFH-v2 attack effect failed for {case.payload_variant}")
        group_id = f"{collection_id}-attack-test-session-{index // session_size:05d}"
        captured.append(("test", group_id, case, observation))
    print(f"Collected {test_attack} XFH-v2 test-attack records", flush=True)

    profile = build_xfh_v2_profile([_request(item[2]) for item in captured[:train_normal]])
    raw_rows, processed_rows = [], []
    for split, group_id, case, observation in captured:
        features = extract_xfh_v2(_request(case), profile)
        row = build_row(collection_id, group_id, split, case, observation, routes)
        row["schema_version"] = "wcp-xfh-v2-record-v1"
        row["request_features"] = {
            "feature_schema_version": "xfh-v2-request-features-v1",
            "method": case.method,
            "uri_path": urlsplit(case.uri).path,
            "structural": {name: features[name] for name in STRUCTURAL_FEATURE_NAMES},
            "xfh_hash": {name: features[name] for name in XFH_HASH_FEATURE_NAMES},
            "xfh_density": {name: features[name] for name in XFH_DENSITY_FEATURE_NAMES},
        }
        row["feature_policy"].update({
            "raw_host_stored": False, "raw_xfh_stored": False,
            "numeric_fingerprints_only": True,
        })
        raw_rows.append(row)
        annotation = row["annotation"]
        processed_rows.append({
            "schema_version": "wcp-xfh-v2-features-v1",
            "record_id": row["record_id"], "group_id": group_id,
            "route": "xfh", "split": split,
            "label": int(annotation["label"] == "attack"),
            "label_name": annotation["label"], "attack_type": annotation["attack_type"],
            "payload_variant": annotation["payload_variant"],
            "features": {name: float(features[name]) for name in XFH_V2_FEATURE_NAMES},
        })

    normal_rows = [row for row in raw_rows if row["annotation"]["label"] == "normal"]
    attack_rows = [row for row in raw_rows if row["annotation"]["label"] == "attack"]
    fixed_count = sum("/fixed/" in row["request_features"]["uri_path"] for row in raw_rows)
    normal_mismatch = sum(row["request_features"]["structural"]["host_mismatch"] != 0 for row in normal_rows)
    attack_mismatch = sum(row["request_features"]["structural"]["host_mismatch"] == 1 for row in attack_rows)
    if fixed_count or normal_mismatch or attack_mismatch != len(attack_rows) or not all(
        row["evidence"]["effect"]["verified"] for row in attack_rows
    ):
        raise RuntimeError("XFH-v2 dataset invariant failed")

    write_jsonl(RAW, raw_rows)
    write_jsonl(PROCESSED, processed_rows)
    PROFILE.parent.mkdir(parents=True, exist_ok=True)
    PROFILE.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "schema_version": "xfh-v2-dataset-manifest-v1", "collection_id": collection_id,
        "route": "xfh", "origin": normalized_origin,
        "vulnerable_target": routes["xfh"]["vulnerable_target"], "fixed_route_included": False,
        "design_frozen_before_final_test": True, "seed": seed, "session_size": session_size,
        "cookie_ratio": cookie_ratio, "head_ratio": head_ratio,
        "counts": {"train_normal": train_normal, "validation_normal": validation_normal,
                   "test_normal": test_normal, "test_attack": test_attack},
        "feature_count": len(XFH_V2_FEATURE_NAMES),
        "feature_groups": {"structural": len(STRUCTURAL_FEATURE_NAMES),
                           "signed_xfh_hash": len(XFH_HASH_FEATURE_NAMES),
                           "xfh_density": len(XFH_DENSITY_FEATURE_NAMES)},
        "normal_variant_counts": dict(Counter(row["annotation"]["payload_variant"] for row in normal_rows)),
        "attack_variant_counts": dict(Counter(row["annotation"]["payload_variant"] for row in attack_rows)),
        "invariants": {"fixed_route_count": fixed_count,
                       "normal_host_mismatch_count": normal_mismatch,
                       "attack_host_mismatch_count": attack_mismatch,
                       "attack_effect_verified_count": sum(row["evidence"]["effect"]["verified"] for row in attack_rows),
                       "unique_request_id_count": len({row["evidence"]["request_id"] for row in raw_rows})},
        "privacy": {"raw_host_stored": False, "raw_xfh_stored": False,
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
