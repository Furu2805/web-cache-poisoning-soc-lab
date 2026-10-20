"""One request-only feature schema, shared by training and inference.

Input is the selected metadata actually available to the Nginx auth subrequest.
No response, label, record ID, source IP, mode or cache-result features.
"""
from collections import Counter
import hashlib
import math
import re
from urllib.parse import urlsplit, parse_qsl

SCHEMA_VERSION = "selected-http-v4-route-lexical"
LEGACY_SCHEMA_VERSION = "selected-http-v3"
PROFILE_SCHEMA_VERSION = "selected-normal-profile-v2"
HEADER_NAMES = (
    "host", "user-agent", "accept", "accept-language", "cookie",
    "content-type", "content-length", "transfer-encoding", "x-forwarded-host",
    "x-forwarded-proto", "x-original-url", "x-rewrite-url", "x-http-method-override",
)
META_HEADERS = {name: "x-meta-" + name for name in HEADER_NAMES}
STRUCTURAL_FEATURE_NAMES = (
    "path_length", "query_length", "query_count", "duplicate_param_count",
    "query_special_ratio", "percent_count", "semicolon_count", "raw_angle_bracket_count", "single_quote_count",
    "selected_header_count", "selected_header_bytes", "max_selected_value_bytes",
    "cookie_bytes", "user_agent_bytes", "has_x_forwarded_host", "host_mismatch",
    "has_x_forwarded_proto", "has_x_original_url", "has_x_rewrite_url",
    "has_method_override", "declared_body_bytes", "has_body_on_get",
    "has_transfer_encoding", "unusual_method", "rare_header_count",
)
LEXICAL_HASH_DIMENSION = 64
LEXICAL_FEATURE_NAMES = tuple(f"lexical_hash_{index:02d}" for index in range(LEXICAL_HASH_DIMENSION))
LEXICAL_PAIR_HASH_DIMENSION = 32
LEXICAL_PAIR_FEATURE_NAMES = tuple(
    f"lexical_xfh_pair_hash_{index:02d}" for index in range(LEXICAL_PAIR_HASH_DIMENSION)
)
LEXICAL_DENSITY_FEATURE_NAMES = (
    "lexical_ngram_rarity_mean", "lexical_ngram_rarity_max", "lexical_xfh_pair_rarity",
)
FEATURE_NAMES = (
    STRUCTURAL_FEATURE_NAMES + LEXICAL_FEATURE_NAMES + LEXICAL_PAIR_FEATURE_NAMES
    + LEXICAL_DENSITY_FEATURE_NAMES
)


# Tạo dấu vân tay ổn định cho token để feature không phụ thuộc hash ngẫu nhiên của Python.
def _stable_fingerprint(token: str) -> int:
    """Return a reproducible numeric fingerprint without persisting the token."""
    digest = hashlib.blake2b(token.encode("utf-8", "replace"), digest_size=8,
                             person=b"fusionlx").digest()
    return int.from_bytes(digest, "big")


# Ánh xạ token vào một ô hash có số chiều cố định.
def _stable_bucket(token: str) -> int:
    return _stable_fingerprint(token) % LEXICAL_HASH_DIMENSION


# Giới hạn và chuẩn hóa chuỗi trước khi trích xuất đặc trưng từ vựng.
def _bounded_lexical_text(value: str) -> str:
    """Bound transient request text; preserve syntax but mask long IDs."""
    return re.sub(r"[0-9a-f]{12,}", "<token>", value.lower()[:1024])


# Lấy các phần của request có thể tạo tín hiệu từ vựng, không lấy response.
def _lexical_sources(request: dict[str, object]) -> tuple[list[str], str]:
    """Return transient lexical sources and one Host/XFH relation source."""
    r = project_request(request["method"], request["uri"], request["headers"])
    parsed = urlsplit(r["uri"])
    headers = r["headers"]
    sources = [
        "path:" + _bounded_lexical_text(parsed.path),
        "query:" + _bounded_lexical_text(parsed.query),
        *("header-name:" + name for name in sorted(headers)),
    ]
    pair_source = "forwarded-host-pair:<absent>"
    if "x-forwarded-host" in headers:
        pair_source = (
            "forwarded-host-pair:" + _bounded_lexical_text(headers.get("host", ""))
            + "|" + _bounded_lexical_text(headers["x-forwarded-host"])
        )
        sources.append(pair_source)
    return sources, pair_source


# Biến các nguồn từ vựng thành dấu vân tay và đếm token.
def _lexical_fingerprints(request: dict[str, object]) -> tuple[list[int], int]:
    """Make non-persisted full n-gram fingerprints for normal-only density."""
    sources, pair_source = _lexical_sources(request)
    fingerprints = []
    for source in sources:
        padded = "^" + source + "$"
        for width in (3, 4, 5):
            fingerprints.extend(
                _stable_fingerprint(padded[start:start + width])
                for start in range(max(0, len(padded) - width + 1))
            )
    return fingerprints, _stable_fingerprint(pair_source)


# Tạo vector hash/novelty từ request theo profile đã học.
def _lexical_hash_features(request: dict[str, object], profile=None) -> dict[str, float]:
    """Hash request syntax in memory; raw query/header text is never stored.

    The Host/X-Forwarded-Host pair is included only as a transient hashed
    lexical source. It lets a route-local model learn benign matching shapes
    without placing a mismatch in normal traffic.
    """
    fingerprints, pair_fingerprint = _lexical_fingerprints(request)
    buckets = [0] * LEXICAL_HASH_DIMENSION
    for fingerprint in fingerprints:
        bucket = fingerprint % LEXICAL_HASH_DIMENSION
        buckets[bucket] = min(3, buckets[bucket] + 1)
    # Keep a dedicated, bounded one-hot hash for the complete Host/XFH pair.
    # A legitimate matching pair occupies one learned bucket. An unseen
    # mismatch therefore has a different multi-feature shape even though no
    # mismatch has ever been placed in normal training traffic.
    pair_buckets = [0] * LEXICAL_PAIR_HASH_DIMENSION
    pair_buckets[pair_fingerprint % LEXICAL_PAIR_HASH_DIMENSION] = 1

    reference = (profile or {}).get("lexical_reference", {})
    # The persisted JSON keys are numeric strings. Keep them in that form so
    # request-time inference does not rebuild a potentially large dictionary.
    ngram_counts = reference.get("ngram_counts", {})
    pair_counts = reference.get("pair_counts", {})
    reference_size = max(1, int(reference.get("sample_count", 0)))
    if ngram_counts:
        rarity = [
            -math.log((ngram_counts.get(str(fingerprint), 0) + 1) / (reference_size + 1))
            for fingerprint in fingerprints
        ]
        density = {
            "lexical_ngram_rarity_mean": sum(rarity) / max(1, len(rarity)),
            "lexical_ngram_rarity_max": max(rarity, default=0.0),
            "lexical_xfh_pair_rarity": -math.log(
                (pair_counts.get(str(pair_fingerprint), 0) + 1) / (reference_size + 1)
            ),
        }
    else:
        density = dict.fromkeys(LEXICAL_DENSITY_FEATURE_NAMES, 0.0)
    return {
        **dict(zip(LEXICAL_FEATURE_NAMES, buckets, strict=True)),
        **dict(zip(LEXICAL_PAIR_FEATURE_NAMES, pair_buckets, strict=True)),
        **density,
    }


# Thống kê token của tập normal để làm mốc tính độ hiếm.
def _lexical_reference(requests: list[dict[str, object]]) -> dict[str, object]:
    """Store only numeric normal-traffic fingerprints for IF density features."""
    ngram_counts = Counter()
    pair_counts = Counter()
    for request in requests:
        fingerprints, pair_fingerprint = _lexical_fingerprints(request)
        ngram_counts.update(fingerprints)
        pair_counts[pair_fingerprint] += 1
    return {
        "sample_count": len(requests),
        "ngram_counts": {str(key): value for key, value in ngram_counts.items()},
        "pair_counts": {str(key): value for key, value in pair_counts.items()},
    }


# Chiếu method, URI và header thành metadata đầu vào của Baseline.
def project_request(method, uri, headers):
    lower = {k.lower(): str(v) for k, v in headers.items()}
    return {"method": method.upper(), "uri": uri,
            "headers": {k: lower[k] for k in HEADER_NAMES if lower.get(k)}}


# Đọc metadata do Nginx chuyển sang từ các header nội bộ.
def from_proxy_headers(headers):
    h = {k.lower(): v for k, v in headers.items()}
    return project_request(h.get("x-meta-method", "GET"), h.get("x-meta-uri", "/"),
                           {k: h.get(v, "") for k, v in META_HEADERS.items()})


# Học profile normal cho bộ feature của Baseline.
def build_feature_profile(requests, rare_threshold=0.05):
    """Build normal-only header and numeric bounds for request-time detection.

    Bounds are a transparent unsupervised novelty guard. They deliberately use
    only normal train data; they are not labels, response fields, or a
    threshold selected from attacks.
    """
    if not 0 < rare_threshold <= 1:
        raise ValueError("rare_threshold must be in (0, 1]")
    projected = [project_request(r["method"], r["uri"], r["headers"]) for r in requests]
    if not projected:
        raise ValueError("at least one normal training request is required")
    counts = Counter(name for request in projected for name in request["headers"])
    sample_count = len(projected)
    rates = {name: counts[name] / sample_count for name in HEADER_NAMES}
    profile = {
        "schema": PROFILE_SCHEMA_VERSION,
        "sample_count": sample_count,
        "rare_threshold": rare_threshold,
        "header_rates": rates,
        "rare_headers": [name for name in HEADER_NAMES if rates[name] < rare_threshold],
    }
    # This call intentionally has no profile. Normal rows do not contain any
    # header classified as rare by the profile above, so rare_header_count is
    # zero either way and no profile state is read before it is finalized.
    features = [extract_features(request) for request in projected]
    profile["numeric_bounds"] = {
        name: {"min": min(row[name] for row in features), "max": max(row[name] for row in features)}
        for name in STRUCTURAL_FEATURE_NAMES
    }
    profile["lexical_reference"] = _lexical_reference(projected)
    return profile


# Kiểm tra profile có đủ schema và giá trị hợp lệ trước khi dùng.
def validate_feature_profile(profile):
    if profile.get("schema") != PROFILE_SCHEMA_VERSION:
        raise ValueError("feature profile schema mismatch")
    unknown = set(profile.get("rare_headers", ())) - set(HEADER_NAMES)
    if unknown:
        raise ValueError(f"feature profile contains unknown headers: {sorted(unknown)}")
    bounds = profile.get("numeric_bounds")
    if set(bounds or ()) != set(STRUCTURAL_FEATURE_NAMES):
        raise ValueError("feature profile numeric bounds mismatch")
    for name, limit in bounds.items():
        if not isinstance(limit, dict) or set(limit) != {"min", "max"} or limit["min"] > limit["max"]:
            raise ValueError(f"invalid numeric bounds for {name}")


# Trích xuất vector feature cho một request theo đúng schema Baseline.
def extract_features(request, profile=None):
    r = project_request(request["method"], request["uri"], request["headers"])
    h = r["headers"]
    if profile is not None:
        validate_feature_profile(profile)
    rare_headers = set(profile.get("rare_headers", ())) if profile else set()
    uri = urlsplit(r["uri"])
    pairs = parse_qsl(uri.query, keep_blank_values=True, separator="&")
    names = [k for k, _ in pairs]
    sizes = [len(v.encode("utf-8")) for v in h.values()]
    try:
        length = max(0, int(h.get("content-length", "0")))
    except ValueError:
        length = 0
    host = h.get("host", "").lower()
    forwarded = h.get("x-forwarded-host", "").lower()
    values = (
        len(uri.path), len(uri.query), len(pairs), len(names) - len(set(names)),
        sum(not (c.isalnum() or c in "-_.~=&") for c in uri.query) / max(1, len(uri.query)),
        uri.query.count("%"), uri.query.count(";"), uri.query.count("<") + uri.query.count(">"), uri.query.count("'"),
        len(h), sum(sizes), max(sizes, default=0),
        len(h.get("cookie", "").encode()), len(h.get("user-agent", "").encode()),
        int(bool(forwarded)), int(bool(forwarded) and forwarded != host),
        int("x-forwarded-proto" in h), int("x-original-url" in h), int("x-rewrite-url" in h),
        int("x-http-method-override" in h), length,
        int(r["method"] == "GET" and length > 0), int("transfer-encoding" in h),
        int(r["method"] not in {"GET", "HEAD", "POST"}),
        sum(name in rare_headers for name in h),
    )
    structural = dict(zip(STRUCTURAL_FEATURE_NAMES, values, strict=True))
    return {**structural, **_lexical_hash_features(r, profile)}


# Trả về các lý do request lệch khỏi profile normal.
def normal_profile_reasons(request, profile):
    """Return data-derived deviations from the normal training envelope.

    This complements Isolation Forest: tree-based isolation cannot reliably
    isolate a binary coordinate that was constant throughout model fitting.
    """
    validate_feature_profile(profile)
    features = extract_features(request, profile)
    return [
        name for name in STRUCTURAL_FEATURE_NAMES
        if features[name] < profile["numeric_bounds"][name]["min"]
        or features[name] > profile["numeric_bounds"][name]["max"]
    ]


# Trả về indicator của các rule guard xác định cho request.
def rule_reasons(request):
    """Fixed baseline, declared before evaluation; not tuned to the test set.

    Deliberately has a documented blind spot: a plain unkeyed query parameter.
    Hardened cache configuration is the stronger non-ML control.
    """
    f = extract_features(request)
    flags = ("host_mismatch", "has_x_original_url", "has_x_rewrite_url",
             "has_method_override", "has_body_on_get",
             "has_transfer_encoding", "semicolon_count", "duplicate_param_count")
    return [name for name in flags if f[name] > 0]
