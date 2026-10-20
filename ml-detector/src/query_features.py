"""Query-v3 lexical novelty features with deterministic tie breaking.

Isolation Forest cannot split a feature that is exactly zero for every
train-normal row.  V3 keeps the normal-only n-gram reference from v2 and adds
a tiny deterministic request-derived dither to the three unseen-n-gram ratios.
This preserves their ordering while making the normal edge learnable by IF.
Only numeric features are persisted.
"""
from __future__ import annotations

import hashlib

from query_feature_base import (
    QUERY_DENSITY_FEATURE_NAMES,
    QUERY_HASH_FEATURE_NAMES,
    QUERY_V2_FEATURE_NAMES,
    build_profile,
    extract_query_v2,
)


QUERY_DITHER_FEATURE_NAMES = (
    "query_raw_unseen_ngram_ratio_dithered",
    "query_decoded_unseen_ngram_ratio_dithered",
    "query_utm_unseen_ngram_ratio_dithered",
)
QUERY_V3_DENSITY_FEATURE_NAMES = QUERY_DENSITY_FEATURE_NAMES + QUERY_DITHER_FEATURE_NAMES
QUERY_V3_FEATURE_NAMES = QUERY_V2_FEATURE_NAMES + QUERY_DITHER_FEATURE_NAMES
DITHER_SCALE = 1e-3


# Học profile normal cho Query v3.
def build_profile_v3(requests: list[dict[str, object]]) -> dict[str, object]:
    profile = build_profile(requests)
    profile["schema_version"] = "query-v3-feature-profile-v1"
    profile["tie_break_policy"] = {
        "type": "deterministic BLAKE2 numeric dither",
        "scale": DITHER_SCALE,
        "purpose": "make zero-valued normal lexical novelty learnable by Isolation Forest",
        "fit_source": "train-normal only",
    }
    return profile


# Tạo nhiễu nhỏ ổn định để tránh score trùng tuyệt đối.
def _unit_dither(uri: str, salt: str) -> float:
    digest = hashlib.blake2b(
        (salt + "\0" + uri).encode("utf-8", "replace"),
        digest_size=8,
        person=b"query-v3",
    ).digest()
    return int.from_bytes(digest, "big") / (2**64 - 1)


# Trích vector feature Query v3.
def extract_query_v3(request: dict[str, object], profile: dict[str, object]) -> dict[str, float]:
    if profile.get("schema_version") != "query-v3-feature-profile-v1":
        raise ValueError("invalid Query-v3 feature profile")
    compatibility_profile = dict(profile)
    compatibility_profile["schema_version"] = "query-v2-feature-profile-v1"
    features = extract_query_v2(request, compatibility_profile)
    uri = str(request["uri"])
    for source_name, output_name in zip((
        "query_raw_unseen_ngram_ratio",
        "query_decoded_unseen_ngram_ratio",
        "query_utm_unseen_ngram_ratio",
    ), QUERY_DITHER_FEATURE_NAMES, strict=True):
        features[output_name] = float(features[source_name]) + DITHER_SCALE * _unit_dither(uri, output_name)
    return features
