"""Privacy-safe method/body/header features for the Fat GET lab."""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from statistics import fmean
from urllib.parse import parse_qsl, urlsplit

from common.features import STRUCTURAL_FEATURE_NAMES, extract_features


FATGET_HASH_DIMENSION = 512
FATGET_HASH_FEATURE_NAMES = tuple(f"fatget_hash_{index:03d}" for index in range(FATGET_HASH_DIMENSION))
FATGET_DENSITY_FEATURE_NAMES = (
    "fatget_lexical_unseen_ngram_ratio",
    "fatget_lexical_idf_mean",
    "fatget_lexical_idf_max",
    "fatget_header_name_unseen_ratio",
    "fatget_header_name_idf_mean",
    "fatget_query_structure_rarity",
    "fatget_method_body_relation_unseen",
    "fatget_method_body_relation_rarity",
    "fatget_content_metadata_relation_unseen",
    "fatget_content_metadata_relation_rarity",
    "fatget_declared_body_log_length",
    "fatget_content_type_present",
    "fatget_length_header_present",
    "fatget_body_presence_unseen",
    "fatget_method_body_relation_unseen_dithered",
    "fatget_content_metadata_relation_unseen_dithered",
    "fatget_body_presence_unseen_dithered",
)
FATGET_DITHER_FEATURE_NAMES = FATGET_DENSITY_FEATURE_NAMES[-3:]
FATGET_FEATURE_NAMES = STRUCTURAL_FEATURE_NAMES + FATGET_HASH_FEATURE_NAMES + FATGET_DENSITY_FEATURE_NAMES
DITHER_SCALE = 1e-3


# Hash ổn định token Fat GET thành mã feature.
def _fingerprint(value: str) -> int:
    digest = hashlib.blake2b(
        value.encode("utf-8", "replace"), digest_size=8, person=b"fatget-v1"
    ).digest()
    return int.from_bytes(digest, "big")


# Giới hạn chuỗi input trước khi trích xuất.
def _bounded(value: str) -> str:
    return re.sub(r"[0-9a-f]{12,}", "<token>", value.lower()[:2048])


# Mô tả hình dạng ký tự của giá trị body/header.
def _shape(value: str) -> str:
    if not value:
        return "empty"
    if value.isalpha():
        return "alpha"
    if value.isalnum():
        return "alnum"
    if value.isdigit():
        return "numeric"
    if any(character.isspace() for character in value):
        return "spaced"
    return "mixed"


# Tạo n-gram từ nguồn Fat GET.
def _ngrams(value: str) -> list[int]:
    padded = "^" + _bounded(value) + "$"
    return [
        _fingerprint(padded[start:start + width])
        for width in (3, 4, 5)
        for start in range(max(0, len(padded) - width + 1))
    ]


# Tách method, body presence, content length/type và callback relation.
def _sources(request: dict[str, object]) -> dict[str, object]:
    method = str(request["method"]).upper()
    parsed = urlsplit(str(request["uri"]))
    pairs = parse_qsl(parsed.query, keep_blank_values=True, separator="&")
    headers = {str(name).lower(): str(value) for name, value in request["headers"].items()}
    try:
        declared_length = max(0, int(headers.get("content-length", "0")))
    except ValueError:
        declared_length = 0
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    has_length = "content-length" in headers
    has_content_type = bool(content_type)
    body_present = declared_length > 0
    structure = "|".join(
        f"{position}:{name.lower()}:{_shape(value)}"
        for position, (name, value) in enumerate(pairs)
    )
    method_body_relation = f"method={method}|body={int(body_present)}"
    content_relation = (
        f"method={method}|length={int(has_length)}:{int(body_present)}|"
        f"type={content_type or '<absent>'}|te={int('transfer-encoding' in headers)}"
    )
    lexical = "|".join((
        "method:" + method,
        "path:" + parsed.path,
        "query:" + structure,
        "headers:" + ",".join(sorted(headers)),
        "content:" + content_relation,
    ))
    return {
        "ngrams": _ngrams(lexical),
        "header_names": [_fingerprint("header:" + name) for name in sorted(headers)],
        "query_structure": _fingerprint("query:" + structure),
        "method_body_relation": _fingerprint(method_body_relation),
        "content_relation": _fingerprint(content_relation),
        "declared_length": declared_length,
        "content_type_present": float(has_content_type),
        "length_header_present": float(has_length),
        "body_present": float(body_present),
    }


# Đưa n-gram Fat GET vào vector hash cố định.
def _hash_vector(ngrams: list[int]) -> dict[str, float]:
    buckets = [0] * FATGET_HASH_DIMENSION
    for fingerprint in ngrams:
        bucket = fingerprint % FATGET_HASH_DIMENSION
        sign = 1 if (fingerprint >> 9) & 1 else -1
        buckets[bucket] += sign
    values = [math.copysign(math.log1p(abs(value)), value) if value else 0.0 for value in buckets]
    return dict(zip(FATGET_HASH_FEATURE_NAMES, values, strict=True))


# Học profile normal cho cấu trúc Fat GET.
def build_fatget_profile(requests: list[dict[str, object]]) -> dict[str, object]:
    if not requests:
        raise ValueError("Fat GET profile needs train-normal requests")
    ngram_df: Counter[int] = Counter()
    header_df: Counter[int] = Counter()
    structures: Counter[int] = Counter()
    method_body: Counter[int] = Counter()
    content_relations: Counter[int] = Counter()
    for request in requests:
        source = _sources(request)
        ngram_df.update(set(source["ngrams"]))
        header_df.update(set(source["header_names"]))
        structures[source["query_structure"]] += 1
        method_body[source["method_body_relation"]] += 1
        content_relations[source["content_relation"]] += 1
    return {
        "schema_version": "fatget-feature-profile-v1",
        "fit_policy": "train-normal only",
        "sample_count": len(requests),
        "ngram_document_frequency": {str(key): value for key, value in ngram_df.items()},
        "header_document_frequency": {str(key): value for key, value in header_df.items()},
        "query_structure_counts": {str(key): value for key, value in structures.items()},
        "method_body_relation_counts": {str(key): value for key, value in method_body.items()},
        "content_relation_counts": {str(key): value for key, value in content_relations.items()},
        "dither_scale": DITHER_SCALE,
        "privacy": "numeric fingerprints/counts only; request body and raw header values are not persisted",
    }


# Tính độ hiếm token so với profile normal.
def _rarity(items: list[int], counts: dict[str, int], sample_count: int) -> tuple[float, float, float]:
    if not items:
        return 0.0, 0.0, 0.0
    unique = set(items)
    values = sorted(-math.log((int(counts.get(str(item), 0)) + 1) / (sample_count + 1)) for item in unique)
    unseen = sum(str(item) not in counts for item in unique) / len(unique)
    return unseen, fmean(values), values[-1]


# Đo độ hiếm của giá trị quan hệ method/body.
def _relation(value: int, counts: dict[str, int], sample_count: int) -> tuple[float, float]:
    count = int(counts.get(str(value), 0))
    return float(count == 0), -math.log((count + 1) / (sample_count + 1))


# Tạo nhiễu nhỏ ổn định cho feature Fat GET.
def _unit_dither(request: dict[str, object], salt: str) -> float:
    headers = {str(name).lower(): str(value) for name, value in request["headers"].items()}
    material = "|".join((
        str(request["method"]), str(request["uri"]), headers.get("content-length", ""),
        headers.get("content-type", ""), headers.get("transfer-encoding", ""), salt,
    ))
    digest = hashlib.blake2b(
        material.encode("utf-8", "replace"), digest_size=8, person=b"fat-dither"
    ).digest()
    return int.from_bytes(digest, "big") / (2**64 - 1)


# Trích vector Fat GET v2, nhấn mạnh GET có body.
def extract_fatget_features(request: dict[str, object], profile: dict[str, object]) -> dict[str, float]:
    if profile.get("schema_version") != "fatget-feature-profile-v1":
        raise ValueError("invalid Fat GET feature profile")
    structural_all = extract_features(request)
    structural = {name: float(structural_all[name]) for name in STRUCTURAL_FEATURE_NAMES}
    source = _sources(request)
    sample_count = int(profile["sample_count"])
    lexical = _rarity(source["ngrams"], profile["ngram_document_frequency"], sample_count)
    headers = _rarity(source["header_names"], profile["header_document_frequency"], sample_count)
    structure_rarity = -math.log(
        (int(profile["query_structure_counts"].get(str(source["query_structure"]), 0)) + 1)
        / (sample_count + 1)
    )
    method_unseen, method_rarity = _relation(
        source["method_body_relation"], profile["method_body_relation_counts"], sample_count
    )
    content_unseen, content_rarity = _relation(
        source["content_relation"], profile["content_relation_counts"], sample_count
    )
    body_unseen = float(source["body_present"] > 0)
    density_values = (
        *lexical, headers[0], headers[1], structure_rarity,
        method_unseen, method_rarity, content_unseen, content_rarity,
        math.log1p(int(source["declared_length"])),
        float(source["content_type_present"]), float(source["length_header_present"]), body_unseen,
        method_unseen + DITHER_SCALE * _unit_dither(request, "method-body"),
        content_unseen + DITHER_SCALE * _unit_dither(request, "content-relation"),
        body_unseen + DITHER_SCALE * _unit_dither(request, "body-presence"),
    )
    density = dict(zip(FATGET_DENSITY_FEATURE_NAMES, density_values, strict=True))
    return {**structural, **_hash_vector(source["ngrams"]), **density}
