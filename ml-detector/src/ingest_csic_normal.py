"""Convert CSIC 2010 normal HTTP traffic to privacy-preserving numeric features.

CSIC is retained as a shared HTTP-normal corpus. It is intentionally not
assigned to any cache-poisoning route and therefore cannot calibrate a route
threshold or replace local Fusion normal traffic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from common.features import (  # noqa: E402
    LEXICAL_FEATURE_NAMES,
    LEXICAL_PAIR_FEATURE_NAMES,
    SCHEMA_VERSION as FEATURE_SCHEMA_VERSION,
    STRUCTURAL_FEATURE_NAMES,
    extract_features,
)


DEFAULT_INPUT = ROOT / "ml-detector" / "data" / "sources" / "csic-2010" / "normalTrafficTraining.txt"
DEFAULT_OUTPUT = ROOT / "ml-detector" / "data" / "processed" / "csic_normal_features.jsonl"
DEFAULT_MANIFEST = ROOT / "ml-detector" / "data" / "manifests" / "csic_normal_manifest.json"
EXPECTED_MD5 = "80dc393c73afd08df28351e1470e3bbf"


# Đọc và tách HTTP requests từ corpus CSIC.
def _requests(raw: bytes) -> list[dict[str, object]]:
    """Parse CSIC request blocks without retaining the raw corpus in output."""
    # CSIC contains both requests without a body (three newlines between
    # request blocks) and requests with a body. Split at a request line rather
    # than a blank-line count so neither form is discarded.
    request_lines = list(re.finditer(
        rb"(?m)^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+\S+\s+HTTP/\d\.\d\r?$", raw
    ))
    requests = []
    for index, match in enumerate(request_lines):
        end = request_lines[index + 1].start() if index + 1 < len(request_lines) else len(raw)
        block = raw[match.start():end]
        lines = block.decode("utf-8", "replace").splitlines()
        if not lines:
            continue
        request_line = lines[0].split()
        if len(request_line) < 2:
            continue
        method, target = request_line[:2]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                break
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name] = value.strip()
        parsed = urlsplit(target)
        uri = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        requests.append({"method": method, "uri": uri, "headers": headers})
    return requests


# Chỉ giữ metadata request được phép làm feature.
def _safe_features(request: dict[str, object]) -> dict[str, object]:
    values = extract_features(request)
    return {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "method": request["method"],
        "uri_path": urlsplit(str(request["uri"])).path,
        "structural": {name: values[name] for name in STRUCTURAL_FEATURE_NAMES},
        "lexical_hash": {
            name: values[name]
            for name in (*LEXICAL_FEATURE_NAMES, *LEXICAL_PAIR_FEATURE_NAMES)
        },
    }


# Chuyển CSIC normal traffic thành record phù hợp pipeline.
def ingest(input_path: Path = DEFAULT_INPUT, output_path: Path = DEFAULT_OUTPUT,
           manifest_path: Path = DEFAULT_MANIFEST, limit: int = 5000, seed: int = 20260925) -> dict[str, object]:
    if limit < 1:
        raise ValueError("limit must be positive")
    raw = input_path.read_bytes()
    md5 = hashlib.md5(raw).hexdigest()  # noqa: S324 - published source integrity checksum
    if md5 != EXPECTED_MD5:
        raise ValueError(f"CSIC normal training checksum mismatch: {md5}")
    requests = _requests(raw)
    if len(requests) != 36000:
        raise ValueError(f"expected 36,000 CSIC normal requests, found {len(requests)}")
    sample_size = min(limit, len(requests))
    indices = sorted(random.Random(seed).sample(range(len(requests)), sample_size))
    rows = [
        {
            "schema_version": "csic-normal-feature-v1",
            "source": "csic-2010-normal-training",
            "source_record_index": index,
            "label": "normal",
            "route": "shared-http-normal",
            "request_features": _safe_features(requests[index]),
            "feature_policy": {
                "request_time_only": True,
                "raw_payload_stored": False,
                "raw_cookie_stored": False,
                "eligible_for_route_threshold_calibration": False,
            },
        }
        for index in indices
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": "csic-normal-ingest-manifest-v1",
        "source_file": str(input_path.relative_to(ROOT)).replace("\\", "/"),
        "source_md5": md5,
        "source_request_count": len(requests),
        "sample_count": len(rows),
        "seed": seed,
        "output": str(output_path.relative_to(ROOT)).replace("\\", "/"),
        "policy": {
            "role": "shared HTTP-normal feature corpus",
            "route_threshold_calibration": "forbidden",
            "cache_wcp_evaluation": "forbidden",
            "raw_request_persisted": False,
        },
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


# Đọc tham số CLI và chạy pipeline dữ liệu/model của ingest_csic_normal.
def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest sampled CSIC 2010 normal HTTP features")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=20260925)
    args = parser.parse_args()
    print(json.dumps(ingest(args.input, args.output, args.manifest, args.limit, args.seed), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
