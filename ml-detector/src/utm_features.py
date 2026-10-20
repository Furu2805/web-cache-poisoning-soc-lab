"""Privacy-safe request-time features for the UTM parameter-cloaking lab."""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from difflib import SequenceMatcher
from statistics import fmean
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from common.features import STRUCTURAL_FEATURE_NAMES, extract_features


UTM_HASH_DIMENSION = 512
UTM_HASH_FEATURE_NAMES = tuple(f"utm_hash_{index:03d}" for index in range(UTM_HASH_DIMENSION))
UTM_DENSITY_FEATURE_NAMES = (
    "utm_raw_unseen_ngram_ratio",
    "utm_raw_idf_mean",
    "utm_raw_idf_max",
    "utm_decoded_unseen_ngram_ratio",
    "utm_decoded_idf_mean",
    "utm_decoded_idf_max",
    "utm_value_unseen_ngram_ratio",
    "utm_value_idf_mean",
    "utm_value_idf_max",
    "utm_parameter_name_unseen_ratio",
    "utm_structure_rarity",
    "utm_semicolon_key_unseen_ratio",
    "utm_callback_relation_unseen",
    "utm_callback_relation_rarity",
    "utm_callback_distance",
    "utm_semicolon_callback_count",
    "utm_semicolon_key_unseen_ratio_dithered",
    "utm_callback_relation_unseen_dithered",
    "utm_callback_distance_dithered",
)
UTM_DITHER_FEATURE_NAMES = UTM_DENSITY_FEATURE_NAMES[-3:]
UTM_FEATURE_NAMES = STRUCTURAL_FEATURE_NAMES + UTM_HASH_FEATURE_NAMES + UTM_DENSITY_FEATURE_NAMES
DITHER_SCALE = 1e-3


# Hash ổn định token UTM/callback thành mã feature.
def _fingerprint(value: str) -> int:
    digest = hashlib.blake2b(
        value.encode("utf-8", "replace"), digest_size=8, person=b"utm-if-v1"
    ).digest()
    return int.from_bytes(digest, "big")


# Giới hạn chuỗi input trước khi trích xuất.
def _bounded(value: str) -> str:
    value = unquote_plus(value).lower()[:2048]
    return re.sub(r"[0-9a-f]{12,}", "<token>", value)


# Biểu diễn hình dạng ký tự của giá trị UTM.
def _shape(value: str) -> str:
    if not value:
        return "empty"
    if value.isalpha():
        return "alpha"
    if value.isalnum():
        return "alnum"
    if value.isdigit():
        return "numeric"
    if any(character in value for character in "(){}[]<>'\""):
        return "executable-punctuation"
    if any(character.isspace() for character in value):
        return "spaced"
    return "mixed"


# Tạo n-gram có namespace cho UTM/callback.
def _ngrams(value: str, prefix: str) -> list[int]:
    padded = "^" + prefix + ":" + _bounded(value) + "$"
    return [
        _fingerprint(padded[start:start + width])
        for width in (3, 4, 5)
        for start in range(max(0, len(padded) - width + 1))
    ]


# Tách utm_content, callback và dấu hiệu parser discrepancy.
def _sources(request: dict[str, object]) -> dict[str, object]:
    query = urlsplit(str(request["uri"])).query
    decoded = unquote_plus(query)
    pairs = parse_qsl(query, keep_blank_values=True, separator="&")
    names = [name.lower() for name, _ in pairs]
    callback = next((value for name, value in pairs if name.lower() == "callback"), "")
    utm_values = [value for name, value in pairs if name.lower() == "utm_content"]
    semicolon_pairs: list[tuple[str, str]] = []
    for value in utm_values:
        fragments = unquote_plus(value).split(";")[1:]
        for fragment in fragments:
            name, separator, nested_value = fragment.partition("=")
            if separator:
                semicolon_pairs.append((name.strip().lower(), nested_value))
    hidden_callbacks = [value for name, value in semicolon_pairs if name == "callback"]
    hidden_callback = hidden_callbacks[0] if hidden_callbacks else ""
    semicolon_keys = [name for name, _ in semicolon_pairs]
    structure = "|".join(
        f"{position}:{name.lower()}:{_shape(value)}"
        for position, (name, value) in enumerate(pairs)
    )
    relation = "|".join((
        "outer=" + _shape(callback),
        "semicolon=" + ",".join(semicolon_keys or ["none"]),
        "hidden=" + _shape(hidden_callback),
    ))
    return {
        "raw": _ngrams(query, "raw"),
        "decoded": _ngrams(decoded, "decoded"),
        "utm": [item for value in utm_values for item in _ngrams(value, "utm-value")],
        "names": [_fingerprint("name:" + name) for name in names],
        "semicolon_keys": [_fingerprint("semicolon-key:" + name) for name in semicolon_keys],
        "structure": _fingerprint("structure:" + structure),
        "relation": _fingerprint("callback-relation:" + relation),
        "callback_distance": (
            1.0 - SequenceMatcher(None, _bounded(callback), _bounded(hidden_callback)).ratio()
            if hidden_callback else 0.0
        ),
        "semicolon_callback_count": len(hidden_callbacks),
    }


# Đưa token UTM vào vector hash cố định.
def _hash_vector(source: dict[str, object]) -> dict[str, float]:
    buckets = [0] * UTM_HASH_DIMENSION
    for family in ("raw", "decoded", "utm"):
        for fingerprint in source[family]:
            bucket = fingerprint % UTM_HASH_DIMENSION
            sign = 1 if (fingerprint >> 9) & 1 else -1
            buckets[bucket] += sign
    values = [math.copysign(math.log1p(abs(value)), value) if value else 0.0 for value in buckets]
    return dict(zip(UTM_HASH_FEATURE_NAMES, values, strict=True))


# Học tần suất feature UTM từ normal train.
def build_utm_profile(requests: list[dict[str, object]]) -> dict[str, object]:
    if not requests:
        raise ValueError("UTM profile needs train-normal requests")
    document_frequencies = {name: Counter() for name in ("raw", "decoded", "utm", "names", "semicolon_keys")}
    structures: Counter[int] = Counter()
    relations: Counter[int] = Counter()
    for request in requests:
        source = _sources(request)
        for name, counter in document_frequencies.items():
            counter.update(set(source[name]))
        structures[source["structure"]] += 1
        relations[source["relation"]] += 1
    return {
        "schema_version": "utm-feature-profile-v1",
        "fit_policy": "train-normal only",
        "sample_count": len(requests),
        "document_frequencies": {
            name: {str(key): value for key, value in counter.items()}
            for name, counter in document_frequencies.items()
        },
        "structure_counts": {str(key): value for key, value in structures.items()},
        "relation_counts": {str(key): value for key, value in relations.items()},
        "dither_scale": DITHER_SCALE,
        "privacy": "numeric fingerprints/counts only; raw query and callback values are not persisted",
    }


# Tính độ hiếm token so với profile UTM.
def _rarity(items: list[int], counts: dict[str, int], sample_count: int) -> tuple[float, float, float]:
    if not items:
        return 0.0, 0.0, 0.0
    unique = set(items)
    values = sorted(-math.log((int(counts.get(str(item), 0)) + 1) / (sample_count + 1)) for item in unique)
    unseen = sum(str(item) not in counts for item in unique) / len(unique)
    return unseen, fmean(values), values[-1]


# Tạo nhiễu nhỏ ổn định cho feature UTM.
def _unit_dither(request: dict[str, object], salt: str) -> float:
    material = "|".join((str(request["method"]), str(request["uri"]), salt))
    digest = hashlib.blake2b(
        material.encode("utf-8", "replace"), digest_size=8, person=b"utm-dither"
    ).digest()
    return int.from_bytes(digest, "big") / (2**64 - 1)


# Trích feature UTM và quan hệ callback ẩn theo schema route.
def extract_utm_features(request: dict[str, object], profile: dict[str, object]) -> dict[str, float]:
    if profile.get("schema_version") != "utm-feature-profile-v1":
        raise ValueError("invalid UTM feature profile")
    structural_all = extract_features(request)
    structural = {name: float(structural_all[name]) for name in STRUCTURAL_FEATURE_NAMES}
    source = _sources(request)
    sample_count = int(profile["sample_count"])
    dfs = profile["document_frequencies"]
    raw = _rarity(source["raw"], dfs["raw"], sample_count)
    decoded = _rarity(source["decoded"], dfs["decoded"], sample_count)
    utm = _rarity(source["utm"], dfs["utm"], sample_count)
    names = _rarity(source["names"], dfs["names"], sample_count)
    semicolon = _rarity(source["semicolon_keys"], dfs["semicolon_keys"], sample_count)
    structure_rarity = -math.log(
        (int(profile["structure_counts"].get(str(source["structure"]), 0)) + 1) / (sample_count + 1)
    )
    relation_count = int(profile["relation_counts"].get(str(source["relation"]), 0))
    relation_unseen = float(relation_count == 0)
    relation_rarity = -math.log((relation_count + 1) / (sample_count + 1))
    distance = float(source["callback_distance"])
    semicolon_callback_count = float(source["semicolon_callback_count"])
    density_values = (
        *raw, *decoded, *utm, names[0], structure_rarity, semicolon[0],
        relation_unseen, relation_rarity, distance, semicolon_callback_count,
        semicolon[0] + DITHER_SCALE * _unit_dither(request, "semicolon-key"),
        relation_unseen + DITHER_SCALE * _unit_dither(request, "callback-relation"),
        distance + DITHER_SCALE * _unit_dither(request, "callback-distance"),
    )
    density = dict(zip(UTM_DENSITY_FEATURE_NAMES, density_values, strict=True))
    return {**structural, **_hash_vector(source), **density}
