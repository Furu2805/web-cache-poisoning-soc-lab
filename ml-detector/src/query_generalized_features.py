"""Generalized privacy-safe Query features for the post-blind-v1 candidate.

Lexical values are reduced to syntax shapes before hashing. This prevents new
benign words from becoming automatic anomalies while preserving delimiters,
schemes and executable punctuation. Only numeric vectors/counts are persisted.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from statistics import fmean
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from common.features import STRUCTURAL_FEATURE_NAMES, extract_features


QUERY_GENERAL_HASH_DIMENSION = 512
QUERY_GENERAL_HASH_FEATURE_NAMES = tuple(
    f"query_general_hash_{index:03d}" for index in range(QUERY_GENERAL_HASH_DIMENSION)
)
QUERY_GENERAL_DENSITY_FEATURE_NAMES = (
    "query_general_abstract_unseen_ratio",
    "query_general_abstract_idf_mean",
    "query_general_abstract_idf_max",
    "query_general_value_unseen_ratio",
    "query_general_value_idf_mean",
    "query_general_value_idf_max",
    "query_general_name_unseen_ratio",
    "query_general_name_idf_mean",
    "query_general_structure_rarity",
    "query_general_punctuation_unseen",
    "query_general_punctuation_rarity",
    "query_general_statistical_distance",
    "query_general_abstract_unseen_dithered",
    "query_general_value_unseen_dithered",
    "query_general_punctuation_unseen_dithered",
)
QUERY_GENERAL_DITHER_FEATURE_NAMES = QUERY_GENERAL_DENSITY_FEATURE_NAMES[-3:]
QUERY_GENERAL_FEATURE_NAMES = (
    STRUCTURAL_FEATURE_NAMES + QUERY_GENERAL_HASH_FEATURE_NAMES + QUERY_GENERAL_DENSITY_FEATURE_NAMES
)
DITHER_SCALE = 1e-3
STAT_NAMES = ("query_length", "query_count", "duplicate_param_count", "query_special_ratio", "percent_count")


# Hash ổn định một token query thành mã feature.
def _fingerprint(value: str) -> int:
    digest = hashlib.blake2b(
        value.encode("utf-8", "replace"), digest_size=8, person=b"query-g1"
    ).digest()
    return int.from_bytes(digest, "big")


# Trừu tượng hóa giá trị query để học cấu trúc thay vì ghi nhớ payload.
def _abstract_value(value: str) -> str:
    value = unquote_plus(value).lower()[:1024]
    value = re.sub(r"[0-9a-f]{12,}", "T", value)
    value = re.sub(r"\d+", "N", value)
    value = re.sub(r"[^\W\d_]+", "W", value, flags=re.UNICODE)
    value = re.sub(r"\s+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value


# Phân loại tên tham số query theo vai trò hình dạng.
def _name_class(name: str) -> str:
    lowered = name.lower()
    groups = {
        "callback": {"cb", "callback"},
        "paging": {"page", "limit", "offset"},
        "display": {"view", "layout", "theme", "format", "sort"},
        "marketing": {"utm_content", "campaign", "source", "ref"},
        "locale": {"locale", "currency", "region"},
        "search": {"q", "category", "tag", "filter"},
        "annotation": {"note", "channel"},
    }
    for group, names in groups.items():
        if lowered in names:
            return group
    return "other"


# Mô tả hình dạng ký tự của giá trị query đã trừu tượng hóa.
def _value_shape(abstracted: str) -> str:
    punctuation = "".join(character for character in abstracted if character in ":/()<>\"';={}[]?.")
    if punctuation:
        return "punct:" + punctuation[:32]
    if abstracted == "N":
        return "numeric"
    if abstracted == "T":
        return "token"
    if "_" in abstracted:
        return "spaced-word"
    return "word"


# Tạo n-gram có namespace từ chuỗi đầu vào.
def _ngrams(value: str, prefix: str) -> list[int]:
    padded = "^" + prefix + ":" + value + "$"
    return [
        _fingerprint(padded[start:start + width])
        for width in (3, 4, 5)
        for start in range(max(0, len(padded) - width + 1))
    ]


# Tách nguồn structural, lexical và novelty từ request Query.
def _sources(request: dict[str, object]) -> dict[str, object]:
    query = urlsplit(str(request["uri"])).query
    pairs = parse_qsl(query, keep_blank_values=True, separator="&")
    abstract_pairs = [(name.lower(), _abstract_value(value)) for name, value in pairs]
    abstract_query = "&".join(
        _name_class(name) + "=" + abstracted for name, abstracted in abstract_pairs
    )
    values = [item for _, abstracted in abstract_pairs for item in _ngrams(abstracted, "value")]
    names = [_fingerprint("name-class:" + _name_class(name)) for name, _ in abstract_pairs]
    structure = "|".join(
        f"{position}:{_name_class(name)}:{_value_shape(abstracted)}"
        for position, (name, abstracted) in enumerate(abstract_pairs)
    )
    punctuation = "|".join(
        "".join(character for character in abstracted if character in ":/()<>\"';={}[]?.") or "none"
        for _, abstracted in abstract_pairs
    )
    return {
        "abstract": _ngrams(abstract_query, "query"),
        "values": values,
        "names": names,
        "structure": _fingerprint("structure:" + structure),
        "punctuation": _fingerprint("punctuation:" + punctuation),
    }


# Ánh xạ các token Query vào vector hash cố định.
def _hash_vector(source: dict[str, object]) -> dict[str, float]:
    buckets = [0] * QUERY_GENERAL_HASH_DIMENSION
    for family in ("abstract", "values"):
        for fingerprint in source[family]:
            bucket = fingerprint % QUERY_GENERAL_HASH_DIMENSION
            sign = 1 if (fingerprint >> 9) & 1 else -1
            buckets[bucket] += sign
    values = [math.copysign(math.log1p(abs(value)), value) if value else 0.0 for value in buckets]
    return dict(zip(QUERY_GENERAL_HASH_FEATURE_NAMES, values, strict=True))


# Học tần suất cấu trúc/token trên normal train của Query.
def build_query_general_profile(requests: list[dict[str, object]]) -> dict[str, object]:
    if not requests:
        raise ValueError("generalized Query profile needs train-normal requests")
    abstract_df: Counter[int] = Counter()
    value_df: Counter[int] = Counter()
    name_df: Counter[int] = Counter()
    structures: Counter[int] = Counter()
    punctuation: Counter[int] = Counter()
    structural_rows = []
    for request in requests:
        source = _sources(request)
        abstract_df.update(set(source["abstract"]))
        value_df.update(set(source["values"]))
        name_df.update(set(source["names"]))
        structures[source["structure"]] += 1
        punctuation[source["punctuation"]] += 1
        structural_rows.append(extract_features(request))
    statistics = {}
    for name in STAT_NAMES:
        values = [float(row[name]) for row in structural_rows]
        mean = fmean(values)
        variance = fmean((value - mean) ** 2 for value in values)
        statistics[name] = {"mean": mean, "std": math.sqrt(variance)}
    return {
        "schema_version": "query-generalized-feature-profile-v1",
        "fit_policy": "train-normal only",
        "sample_count": len(requests),
        "abstract_document_frequency": {str(key): value for key, value in abstract_df.items()},
        "value_document_frequency": {str(key): value for key, value in value_df.items()},
        "name_document_frequency": {str(key): value for key, value in name_df.items()},
        "structure_counts": {str(key): value for key, value in structures.items()},
        "punctuation_counts": {str(key): value for key, value in punctuation.items()},
        "statistics": statistics,
        "dither_scale": DITHER_SCALE,
        "privacy": "abstract syntax fingerprints/counts only; raw query and values are not persisted",
    }


# Tính mức hiếm của token so với profile normal.
def _rarity(items: list[int], counts: dict[str, int], sample_count: int) -> tuple[float, float, float]:
    if not items:
        return 0.0, 0.0, 0.0
    unique = set(items)
    values = sorted(-math.log((int(counts.get(str(item), 0)) + 1) / (sample_count + 1)) for item in unique)
    unseen = sum(str(item) not in counts for item in unique) / len(unique)
    return unseen, fmean(values), values[-1]


# Tạo nhiễu rất nhỏ và ổn định để tránh điểm trùng tuyệt đối.
def _unit_dither(request: dict[str, object], salt: str) -> float:
    material = "|".join((str(request["method"]), str(request["uri"]), salt))
    digest = hashlib.blake2b(
        material.encode("utf-8", "replace"), digest_size=8, person=b"query-gd"
    ).digest()
    return int.from_bytes(digest, "big") / (2**64 - 1)


# Tạo feature Query v8 theo profile và schema route.
def extract_query_general_features(request: dict[str, object], profile: dict[str, object]) -> dict[str, float]:
    if profile.get("schema_version") != "query-generalized-feature-profile-v1":
        raise ValueError("invalid generalized Query feature profile")
    structural_all = extract_features(request)
    structural = {name: float(structural_all[name]) for name in STRUCTURAL_FEATURE_NAMES}
    source = _sources(request)
    sample_count = int(profile["sample_count"])
    abstract = _rarity(source["abstract"], profile["abstract_document_frequency"], sample_count)
    values = _rarity(source["values"], profile["value_document_frequency"], sample_count)
    names = _rarity(source["names"], profile["name_document_frequency"], sample_count)
    structure_count = int(profile["structure_counts"].get(str(source["structure"]), 0))
    structure_rarity = -math.log((structure_count + 1) / (sample_count + 1))
    punctuation_count = int(profile["punctuation_counts"].get(str(source["punctuation"]), 0))
    punctuation_unseen = float(punctuation_count == 0)
    punctuation_rarity = -math.log((punctuation_count + 1) / (sample_count + 1))
    z_values = []
    for name in STAT_NAMES:
        reference = profile["statistics"][name]
        std = float(reference["std"])
        z_values.append(abs(structural[name] - float(reference["mean"])) / std if std else 0.0)
    density_values = (
        *abstract, *values, names[0], names[1], structure_rarity,
        punctuation_unseen, punctuation_rarity,
        math.sqrt(fmean(value * value for value in z_values)),
        abstract[0] + DITHER_SCALE * _unit_dither(request, "abstract"),
        values[0] + DITHER_SCALE * _unit_dither(request, "values"),
        punctuation_unseen + DITHER_SCALE * _unit_dither(request, "punctuation"),
    )
    density = dict(zip(QUERY_GENERAL_DENSITY_FEATURE_NAMES, density_values, strict=True))
    return {**structural, **_hash_vector(source), **density}
