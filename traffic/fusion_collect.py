"""Collect a labelled, synthetic local dataset from the Fusion four-labs.

Examples
--------
    python -m traffic.fusion_collect
    python -m traffic.fusion_collect --normal-per-lab 50 --attack-per-lab 50

The collector never opens a browser or sends traffic outside the local lab.
It saves privacy-preserving request-time features in
``ml-detector/data/raw/requests.jsonl`` and a reproducibility manifest under
``ml-detector/data/manifests``. Response/cache observations are kept in the
separate ``evidence`` object and must not be used as ML features.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import random
import time
import uuid
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from common.features import (
    LEXICAL_FEATURE_NAMES,
    LEXICAL_PAIR_FEATURE_NAMES,
    SCHEMA_VERSION as FEATURE_SCHEMA_VERSION,
    STRUCTURAL_FEATURE_NAMES,
    extract_features,
)
from common.io import write_jsonl
from traffic.fusion_scenarios import LABS, FusionCase, attack_case, normal_case


ROOT = Path(__file__).resolve().parents[1]
ROUTE_REGISTRY_PATH = ROOT / "ml-detector" / "config" / "route_registry.json"
DEFAULT_OUTPUT = Path("ml-detector/data/raw/requests.jsonl")
DEFAULT_MANIFEST_DIR = Path("ml-detector/data/manifests")
USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/146.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 Version/18.6 Safari/605.1.15",
)
LANGUAGES = ("vi-VN,vi;q=0.9,en-US;q=0.8", "en-US,en;q=0.9", "vi,en;q=0.8")


# Đọc registry route để gắn metadata dataset đúng candidate.
def load_route_registry(path: Path = ROUTE_REGISTRY_PATH) -> dict[str, object]:
    """Load and minimally validate the one canonical local-lab route map."""
    registry = json.loads(path.read_text(encoding="utf-8"))
    routes = registry.get("routes")
    if registry.get("schema_version") != "wcp-route-registry-v1" or not isinstance(routes, dict):
        raise ValueError("invalid WCP route registry")
    if set(routes) != set(LABS):
        raise ValueError("route registry must define exactly the four Fusion labs")
    for lab in LABS:
        route = routes[lab]
        if not isinstance(route, dict) or route.get("scenario") != lab:
            raise ValueError(f"route registry has an invalid scenario for {lab}")
        if not str(route.get("vulnerable_target", "")).startswith(f"/labs/{lab}/"):
            raise ValueError(f"route registry has an invalid vulnerable target for {lab}")
    return registry


# Chỉ giữ feature request được phép đưa vào dữ liệu huấn luyện.
def _safe_request_features(case: FusionCase) -> dict[str, object]:
    """Derive numeric request-time features without persisting raw request data."""
    request = {"method": case.method, "uri": case.uri, "headers": case.headers}
    features = extract_features(request)
    return {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "method": case.method,
        "uri_path": urlsplit(case.uri).path,
        "structural": {name: features[name] for name in STRUCTURAL_FEATURE_NAMES},
        "lexical_hash": {
            name: features[name]
            for name in (*LEXICAL_FEATURE_NAMES, *LEXICAL_PAIR_FEATURE_NAMES)
        },
    }


# Hash giá trị nhạy cảm hoặc trả rỗng khi không có dữ liệu.
def _hash_or_empty(value: object) -> str:
    text = str(value or "")
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest() if text else ""


# Gán group vào train/validation/test theo chỉ số xác định.
def split_for(index: int, total: int) -> str:
    """Deterministic 60/20/20 split assigned by case group, not response."""
    ratio = index / max(1, total)
    if ratio < 0.60:
        return "train"
    if ratio < 0.80:
        return "validation"
    return "test"


# Tạo biến thiên cookie lành tính cho normal traffic.
def add_benign_cookie(case: FusionCase, token: str, rng: random.Random, ratio: float) -> None:
    if rng.random() >= ratio:
        return
    values = (
        "fusion_country=Vietnam",
        "fusion_theme=dark; fusion_country=Vietnam",
        "fusion_session=synthetic-" + token[:12],
    )
    case.headers["Cookie"] = rng.choice(values)


# Gửi case tới lab và thu outcome/cache evidence riêng với feature.
def observe(origin: str, case: FusionCase) -> dict[str, object]:
    """Send the request target unchanged, including raw Query-lab payloads."""
    parsed = urlsplit(origin)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("origin must be an http URL with a hostname")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=15)
    try:
        connection.request(case.method, case.uri, body=case.body.encode("utf-8") if case.body else None,
                           headers=case.headers)
        response = connection.getresponse()
        body = response.read()
        headers = {name.lower(): value for name, value in response.getheaders()}
    finally:
        connection.close()
    effect_observed = None
    if case.label == "attack":
        text = body.decode("utf-8", "replace")
        if case.lab == "xfh":
            effect_observed = "127.0.0.1:8087/resources/js/tracking.js" in text
        else:
            effect_observed = "alert(" in text
    return {
        "status": response.status,
        "cache_status": headers.get("x-cache-status", ""),
        "request_id": headers.get("x-request-id", ""),
        "cache_key": headers.get("x-cache-key", ""),
        "lab_scenario": headers.get("x-lab-scenario", ""),
        "content_type": headers.get("content-type", ""),
        "content_length": len(body),
        "effect_observed": effect_observed,
    }


# Đóng gói case, group, split, label và evidence thành raw record.
def build_row(collection_id: str, group_id: str, split: str, case: FusionCase,
              observation: dict[str, object], routes: dict[str, object]) -> dict[str, object]:
    """Build a record that separates numeric request features from evidence.

    Raw query values, request bodies, cookies, response bodies and cache keys
    are intentionally used only transiently while collecting. They are never
    written to the dataset record.
    """
    route = routes[case.lab]
    if not isinstance(route, dict):
        raise ValueError(f"missing route registry entry for {case.lab}")
    target = str(route["vulnerable_target"])
    if not urlsplit(case.uri).path.startswith(target):
        raise ValueError(f"{case.lab} request does not target its canonical vulnerable route")
    expected_attack_type = "normal" if case.label == "normal" else str(route["attack_type"])
    if case.attack_type != expected_attack_type:
        raise ValueError(f"unexpected attack type for {case.lab}: {case.attack_type}")
    effect_observed = bool(observation["effect_observed"])
    return {
        "schema_version": "wcp-request-record-v1",
        "record_id": uuid.uuid4().hex,
        "collected_at_epoch": round(time.time(), 3),
        "collection": {
            "collection_id": collection_id,
            "group_id": group_id,
            "source": "synthetic-local-fusion-lab",
        },
        "route": {"id": case.lab, "scenario": str(route["scenario"]), "variant": "vulnerable"},
        "annotation": {
            "split": split,
            "label": case.label,
            "attack_type": case.attack_type,
            "payload_variant": case.payload_variant,
        },
        "request_features": _safe_request_features(case),
        "evidence": {
            "request_id": str(observation["request_id"]),
            "http_status": int(observation["status"]),
            "cache": {
                "status": str(observation["cache_status"]),
                "key_hash": _hash_or_empty(observation["cache_key"]),
                "unkeyed_input": str(route["unkeyed_input"]) if case.label == "attack" else None,
            },
            "response": {
                "content_type": str(observation["content_type"]),
                "content_length": int(observation["content_length"]),
                "size_delta": None,
            },
            "effect": {
                "expected": case.label == "attack",
                "observed": effect_observed,
                "verified": case.label == "attack" and effect_observed,
            },
        },
        "feature_policy": {
            "request_time_only": True,
            "evidence_excluded_from_ml": True,
            "raw_payload_stored": False,
            "raw_cookie_stored": False,
        },
    }


# Sinh và thu bộ case cho bốn lab, giữ group để hạn chế leakage.
def collect(origin: str, normal_per_lab: int, attack_per_lab: int, output: Path, seed: int,
            cookie_ratio: float, head_ratio: float, session_size: int = 5) -> list[dict[str, object]]:
    if normal_per_lab < 1 or attack_per_lab < 1:
        raise ValueError("normal-per-lab and attack-per-lab must both be at least 1")
    if not 0 <= cookie_ratio <= 1 or not 0 <= head_ratio <= 1:
        raise ValueError("cookie-ratio and head-ratio must be between 0 and 1")
    if session_size < 1:
        raise ValueError("session-size must be at least 1")
    registry = load_route_registry()
    normalized_origin = origin.rstrip("/")
    if normalized_origin not in set(registry.get("allowed_targets", ())):
        raise ValueError("collector target must be an allowlisted local Fusion lab origin")
    routes = registry["routes"]
    rng = random.Random(seed)
    collection_id = "fusion-" + uuid.uuid4().hex[:12]
    rows: list[dict[str, object]] = []
    for lab in LABS:
        for label, count in (("normal", normal_per_lab), ("attack", attack_per_lab)):
            for index in range(count):
                token = f"{rng.getrandbits(96):024x}"
                user_agent = rng.choice(USER_AGENTS)
                language = rng.choice(LANGUAGES)
                method = "HEAD" if label == "normal" and index / count < head_ratio else "GET"
                factory = normal_case if label == "normal" else attack_case
                if label == "normal":
                    case = factory(lab, token, user_agent, language, index, method)
                else:
                    case = factory(lab, token, user_agent, language, index)
                add_benign_cookie(case, token, rng, cookie_ratio)
                observation = observe(origin, case)
                if observation["status"] != 200:
                    raise RuntimeError(f"{lab}/{label} returned HTTP {observation['status']}; lab stack is not ready")
                if not observation["request_id"]:
                    raise RuntimeError("Fusion response has no X-Request-ID; Nginx correlation is not configured")
                if label == "attack" and not observation["effect_observed"]:
                    raise RuntimeError(f"{lab}/{label} did not produce its expected local effect; refusing to label it attack")
                session_index = index // session_size
                session_total = (count + session_size - 1) // session_size
                group_id = f"{collection_id}-{lab}-{label}-session-{session_index:05d}"
                # Attacks are evaluation-only. Train and validation remain
                # normal-only even in the raw collection record.
                split = split_for(session_index, session_total) if label == "normal" else "test"
                rows.append(build_row(collection_id, group_id, split, case, observation, routes))
            print(f"Collected {count} {label} samples for {lab}", flush=True)
    write_jsonl(output, rows)
    manifest = {
        "schema_version": "wcp-request-record-v1",
        "route_registry_schema_version": registry["schema_version"],
        "collection_id": collection_id,
        "origin": normalized_origin,
        "generated_at_epoch": round(time.time(), 3),
        "seed": seed,
        "session_size": session_size,
        "rows": len(rows),
        "counts_by_label": dict(Counter(str(row["annotation"]["label"]) for row in rows)),
        "counts_by_route": dict(Counter(str(row["route"]["id"]) for row in rows)),
        "counts_by_split": dict(Counter(str(row["annotation"]["split"]) for row in rows)),
        "counts_by_method": dict(Counter(str(row["request_features"]["method"]) for row in rows)),
        "request_id_count": sum(bool(row["evidence"]["request_id"]) for row in rows),
        "unique_request_id_count": len({row["evidence"]["request_id"] for row in rows}),
        "attack_effect_observed": sum(row["evidence"]["effect"]["observed"] is True for row in rows),
        "output": str(output).replace("\\", "/"),
        "limitations": [
            "Synthetic traffic generated only against the authorized local Fusion lab.",
            "Cache status and response metadata are retained as evidence, not ML features.",
            "Raw query values, request bodies, cookies, response bodies and cache keys are not persisted.",
            "Split is assigned by session group to avoid cross-split near-duplicate leakage.",
        ],
    }
    manifest_name = "requests_manifest.json" if output == DEFAULT_OUTPUT else f"{output.stem}_manifest.json"
    manifest_path = DEFAULT_MANIFEST_DIR / manifest_name
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {len(rows)} labelled Fusion rows to {output}")
    print(f"Manifest: {manifest_path}")
    return rows


# Đọc tham số CLI và chạy quy trình thu dataset.
def main() -> None:
    parser = argparse.ArgumentParser(description="Collect local Fusion normal/attack traffic for Chapter 5")
    parser.add_argument("--origin", default="http://127.0.0.1:8086")
    parser.add_argument("--normal-per-lab", type=int, default=50)
    parser.add_argument("--attack-per-lab", type=int, default=50)
    parser.add_argument("--cookie-ratio", type=float, default=0.60)
    parser.add_argument("--head-ratio", type=float, default=0.20)
    parser.add_argument("--session-size", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20260922)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    collect(args.origin, args.normal_per_lab, args.attack_per_lab, args.output, args.seed,
            args.cookie_ratio, args.head_ratio, args.session_size)


if __name__ == "__main__":
    main()
