"""Privacy-safe Query-v2 request-time feature extraction.

Raw and decoded query text exists only during extraction. Persisted outputs are
structural numbers, a signed hash vector, and normal-only density statistics.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from statistics import fmean
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from common.features import STRUCTURAL_FEATURE_NAMES, extract_features


QUERY_HASH_DIMENSION = 512
QUERY_HASH_FEATURE_NAMES = tuple(f"query_v2_hash_{index:03d}" for index in range(QUERY_HASH_DIMENSION))
QUERY_DENSITY_FEATURE_NAMES = (
    "query_raw_unseen_ngram_ratio",
    "query_raw_idf_mean",
    "query_raw_idf_p95",
    "query_raw_idf_max",
    "query_decoded_unseen_ngram_ratio",
    "query_decoded_idf_mean",
    "query_decoded_idf_p95",
    "query_decoded_idf_max",
    "query_utm_unseen_ngram_ratio",
    "query_utm_idf_mean",
    "query_utm_idf_p95",
    "query_utm_idf_max",
    "query_param_name_idf_mean",
    "query_param_name_idf_max",
    "query_structure_rarity",
    "query_statistical_distance",
)
QUERY_V2_FEATURE_NAMES = STRUCTURAL_FEATURE_NAMES + QUERY_HASH_FEATURE_NAMES + QUERY_DENSITY_FEATURE_NAMES
STAT_NAMES = (
    "query_length", "query_count", "duplicate_param_count",
    "query_special_ratio", "percent_count",
)


# Hash ổn định token để tạo feature có số chiều cố định.
def _fingerprint(value: str) -> int:
    digest = hashlib.blake2b(
        value.encode("utf-8", "replace"), digest_size=8, person=b"query-v2"
    ).digest()
    return int.from_bytes(digest, "big")


# Giới hạn độ dài chuỗi trước khi trích feature.
def _bounded(value: str) -> str:
    return re.sub(r"[0-9a-f]{12,}", "<token>", value.lower()[:2048])


# Tạo n-gram ký tự để nắm mẫu lexical.
def _ngrams(source: str, prefix: str) -> list[int]:
    bounded = "^" + prefix + ":" + _bounded(source) + "$"
    return [
        _fingerprint(bounded[start:start + width])
        for width in (3, 4, 5)
        for start in range(max(0, len(bounded) - width + 1))
    ]


# Mô tả cấu trúc ký tự của giá trị đầu vào.
def _value_shape(value: str) -> str:
    if value == "":
        return "empty"
    if value.isdigit():
        return "numeric"
    if re.fullmatch(r"[0-9a-f]{12,}", value.lower()):
        return "hex-token"
    if value.isalpha():
        return "alpha"
    if value.isalnum():
        return "alnum"
    if any(character in value for character in "<>\"'();{}"):
        return "executable-punctuation"
    if any(character.isspace() for character in value):
        return "spaced"
    return "mixed"


# Tách các thành phần request dùng làm nguồn feature.
def _sources(request: dict[str, object]) -> dict[str, object]:
    query = urlsplit(str(request["uri"])).query
    decoded = unquote_plus(query)
    pairs = parse_qsl(query, keep_blank_values=True, separator="&")
    utm_values = [value for name, value in pairs if name.lower() == "utm_content"]
    names = [name.lower() for name, _ in pairs]
    structure = "|".join(
        f"{position}:{name.lower()}:{_value_shape(value)}"
        for position, (name, value) in enumerate(pairs)
    )
    return {
        "raw": _ngrams(query, "raw-query"),
        "decoded": _ngrams(decoded, "decoded-query"),
        "utm": [fingerprint for value in utm_values for fingerprint in _ngrams(value, "decoded-utm")],
        "parameter_names": [_fingerprint("param-name:" + name) for name in names],
        "structure": _fingerprint("query-structure:" + structure),
    }


# Ánh xạ token lexical vào vector hash cố định.
def _hash_vector(source: dict[str, object]) -> dict[str, float]:
    buckets = [0] * QUERY_HASH_DIMENSION
    for family in ("raw", "decoded"):
        for fingerprint in source[family]:
            bucket = fingerprint % QUERY_HASH_DIMENSION
            sign = 1 if (fingerprint >> 9) & 1 else -1
            buckets[bucket] += sign
    transformed = [math.copysign(math.log1p(abs(value)), value) if value else 0.0 for value in buckets]
    return dict(zip(QUERY_HASH_FEATURE_NAMES, transformed, strict=True))


# Học profile normal từ request train.
def build_profile(requests: list[dict[str, object]]) -> dict[str, object]:
    if not requests:
        raise ValueError("Query-v2 profile needs train-normal requests")
    raw_df: Counter[int] = Counter()
    decoded_df: Counter[int] = Counter()
    utm_df: Counter[int] = Counter()
    name_df: Counter[int] = Counter()
    structure_counts: Counter[int] = Counter()
    structural_rows = []
    for request in requests:
        source = _sources(request)
        raw_df.update(set(source["raw"]))
        decoded_df.update(set(source["decoded"]))
        utm_df.update(set(source["utm"]))
        name_df.update(set(source["parameter_names"]))
        structure_counts[source["structure"]] += 1
        structural_rows.append(extract_features(request))
    statistics = {}
    for name in STAT_NAMES:
        values = [float(row[name]) for row in structural_rows]
        mean = fmean(values)
        variance = fmean((value - mean) ** 2 for value in values)
        statistics[name] = {"mean": mean, "std": math.sqrt(variance)}
    return {
        "schema_version": "query-v2-feature-profile-v1",
        "fit_policy": "train-normal only",
        "sample_count": len(requests),
        "raw_ngram_document_frequency": {str(key): value for key, value in raw_df.items()},
        "decoded_ngram_document_frequency": {str(key): value for key, value in decoded_df.items()},
        "utm_ngram_document_frequency": {str(key): value for key, value in utm_df.items()},
        "parameter_document_frequency": {str(key): value for key, value in name_df.items()},
        "structure_counts": {str(key): value for key, value in structure_counts.items()},
        "statistics": statistics,
        "privacy": "all keys are numeric fingerprints; no raw query/payload is persisted",
    }


# Tính độ hiếm các token theo profile normal.
def _rarities(items: list[int], counts: dict[str, int], sample_count: int) -> tuple[float, float, float, float]:
    if not items:
        return 0.0, 0.0, 0.0, 0.0
    unique = set(items)
    values = sorted(-math.log((int(counts.get(str(item), 0)) + 1) / (sample_count + 1)) for item in unique)
    unseen = sum(str(item) not in counts for item in unique) / len(unique)
    p95_index = min(len(values) - 1, math.ceil(0.95 * len(values)) - 1)
    return unseen, fmean(values), values[p95_index], values[-1]


# Trích vector feature Query v2.
def extract_query_v2(request: dict[str, object], profile: dict[str, object]) -> dict[str, float]:
    if profile.get("schema_version") != "query-v2-feature-profile-v1":
        raise ValueError("invalid Query-v2 feature profile")
    structural_all = extract_features(request)
    structural = {name: float(structural_all[name]) for name in STRUCTURAL_FEATURE_NAMES}
    source = _sources(request)
    sample_count = int(profile["sample_count"])
    raw = _rarities(source["raw"], profile["raw_ngram_document_frequency"], sample_count)
    decoded = _rarities(source["decoded"], profile["decoded_ngram_document_frequency"], sample_count)
    utm = _rarities(source["utm"], profile["utm_ngram_document_frequency"], sample_count)
    names = _rarities(source["parameter_names"], profile["parameter_document_frequency"], sample_count)
    structure_rarity = -math.log(
        (int(profile["structure_counts"].get(str(source["structure"]), 0)) + 1) / (sample_count + 1)
    )
    z_values = []
    for name in STAT_NAMES:
        reference = profile["statistics"][name]
        std = float(reference["std"])
        z_values.append(abs(structural[name] - float(reference["mean"])) / std if std > 0 else 0.0)
    density = dict(zip(QUERY_DENSITY_FEATURE_NAMES, (
        *raw, *decoded, *utm, names[1], names[3], structure_rarity,
        math.sqrt(fmean(value * value for value in z_values)),
    ), strict=True))
    return {**structural, **_hash_vector(source), **density}
