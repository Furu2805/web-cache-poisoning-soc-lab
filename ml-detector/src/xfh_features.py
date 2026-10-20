"""Privacy-safe XFH relationship features for a normal-only Isolation Forest."""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from difflib import SequenceMatcher
from statistics import fmean
from urllib.parse import urlsplit

from common.features import STRUCTURAL_FEATURE_NAMES, extract_features


XFH_HASH_DIMENSION = 512
XFH_HASH_FEATURE_NAMES = tuple(f"xfh_v2_hash_{index:03d}" for index in range(XFH_HASH_DIMENSION))
XFH_DENSITY_FEATURE_NAMES = (
    "xfh_ngram_unseen_ratio",
    "xfh_ngram_idf_mean",
    "xfh_ngram_idf_max",
    "xfh_pair_unseen",
    "xfh_pair_rarity",
    "xfh_relation_distance",
    "xfh_ngram_unseen_ratio_dithered",
    "xfh_pair_unseen_dithered",
    "xfh_relation_distance_dithered",
)
XFH_DITHER_FEATURE_NAMES = XFH_DENSITY_FEATURE_NAMES[-3:]
XFH_V2_FEATURE_NAMES = STRUCTURAL_FEATURE_NAMES + XFH_HASH_FEATURE_NAMES + XFH_DENSITY_FEATURE_NAMES
DITHER_SCALE = 1e-3


# Hash ổn định token header thành mã feature.
def _fingerprint(value: str) -> int:
    digest = hashlib.blake2b(
        value.encode("utf-8", "replace"), digest_size=8, person=b"xfh-v2"
    ).digest()
    return int.from_bytes(digest, "big")


# Giới hạn chuỗi header trước khi trích xuất.
def _bounded(value: str) -> str:
    return re.sub(r"[0-9a-f]{12,}", "<token>", value.strip().lower()[:1024])


# Chuẩn hóa Host và X-Forwarded-Host để so sánh quan hệ.
def _canonical_headers(request: dict[str, object]) -> tuple[str, str]:
    headers = {str(name).lower(): str(value) for name, value in request["headers"].items()}
    return _bounded(headers.get("host", "")), _bounded(headers.get("x-forwarded-host", ""))


# Tạo tín hiệu structural/lexical và quan hệ Host–XFH.
def _source(request: dict[str, object]) -> dict[str, object]:
    host, forwarded = _canonical_headers(request)
    relation = "absent" if not forwarded else "matched" if forwarded == host else "different"
    pair = f"host={host}|xfh={forwarded or '<absent>'}|relation={relation}"
    lexical = (
        f"host:{host}|xfh:{forwarded or '<absent>'}|relation:{relation}|"
        f"path:{_bounded(urlsplit(str(request['uri'])).path)}"
    )
    padded = "^" + lexical + "$"
    ngrams = [
        _fingerprint(padded[start:start + width])
        for width in (3, 4, 5)
        for start in range(max(0, len(padded) - width + 1))
    ]
    distance = 0.0 if not forwarded else 1.0 - SequenceMatcher(None, host, forwarded).ratio()
    return {
        "host": host,
        "forwarded": forwarded,
        "pair": _fingerprint(pair),
        "ngrams": ngrams,
        "distance": distance,
    }


# Đưa n-gram header vào vector hash cố định.
def _hash_vector(ngrams: list[int]) -> dict[str, float]:
    buckets = [0] * XFH_HASH_DIMENSION
    for fingerprint in ngrams:
        bucket = fingerprint % XFH_HASH_DIMENSION
        sign = 1 if (fingerprint >> 9) & 1 else -1
        buckets[bucket] += sign
    values = [math.copysign(math.log1p(abs(value)), value) if value else 0.0 for value in buckets]
    return dict(zip(XFH_HASH_FEATURE_NAMES, values, strict=True))


# Học phân phối normal của tín hiệu XFH.
def build_xfh_v2_profile(requests: list[dict[str, object]]) -> dict[str, object]:
    if not requests:
        raise ValueError("XFH-v2 profile needs train-normal requests")
    ngram_df: Counter[int] = Counter()
    pair_counts: Counter[int] = Counter()
    for request in requests:
        source = _source(request)
        ngram_df.update(set(source["ngrams"]))
        pair_counts[source["pair"]] += 1
    return {
        "schema_version": "xfh-v2-feature-profile-v1",
        "fit_policy": "train-normal only",
        "sample_count": len(requests),
        "ngram_document_frequency": {str(key): value for key, value in ngram_df.items()},
        "pair_counts": {str(key): value for key, value in pair_counts.items()},
        "dither_scale": DITHER_SCALE,
        "privacy": "numeric fingerprints/counts only; raw Host/XFH values are not persisted",
    }


# Tạo nhiễu nhỏ ổn định cho feature XFH.
def _unit_dither(request: dict[str, object], salt: str) -> float:
    host, forwarded = _canonical_headers(request)
    material = "|".join((str(request["method"]), str(request["uri"]), host, forwarded, salt))
    digest = hashlib.blake2b(
        material.encode("utf-8", "replace"), digest_size=8, person=b"xfh-dthr"
    ).digest()
    return int.from_bytes(digest, "big") / (2**64 - 1)


# Trích feature XFH, gồm mismatch/relation, theo profile route.
def extract_xfh_v2(request: dict[str, object], profile: dict[str, object]) -> dict[str, float]:
    if profile.get("schema_version") != "xfh-v2-feature-profile-v1":
        raise ValueError("invalid XFH-v2 feature profile")
    structural_all = extract_features(request)
    structural = {name: float(structural_all[name]) for name in STRUCTURAL_FEATURE_NAMES}
    source = _source(request)
    sample_count = int(profile["sample_count"])
    counts = profile["ngram_document_frequency"]
    unique = set(source["ngrams"])
    rarity = sorted(-math.log((int(counts.get(str(item), 0)) + 1) / (sample_count + 1)) for item in unique)
    unseen_ratio = sum(str(item) not in counts for item in unique) / max(1, len(unique))
    pair_count = int(profile["pair_counts"].get(str(source["pair"]), 0))
    pair_unseen = float(pair_count == 0)
    pair_rarity = -math.log((pair_count + 1) / (sample_count + 1))
    distance = float(source["distance"])
    base = {
        "xfh_ngram_unseen_ratio": unseen_ratio,
        "xfh_ngram_idf_mean": fmean(rarity) if rarity else 0.0,
        "xfh_ngram_idf_max": rarity[-1] if rarity else 0.0,
        "xfh_pair_unseen": pair_unseen,
        "xfh_pair_rarity": pair_rarity,
        "xfh_relation_distance": distance,
        "xfh_ngram_unseen_ratio_dithered": unseen_ratio + DITHER_SCALE * _unit_dither(request, "ngram"),
        "xfh_pair_unseen_dithered": pair_unseen + DITHER_SCALE * _unit_dither(request, "pair"),
        "xfh_relation_distance_dithered": distance + DITHER_SCALE * _unit_dither(request, "distance"),
    }
    return {**structural, **_hash_vector(source["ngrams"]), **base}
