"""Low-dimensional lexical-density summaries for Query v6.1."""
from __future__ import annotations

import math
from statistics import fmean

from query_generalized_features import (
    QUERY_GENERAL_FEATURE_NAMES,
    QUERY_GENERAL_HASH_FEATURE_NAMES,
    _hash_vector,
    _sources,
    build_query_general_profile,
    extract_query_general_features,
)


QUERY_V61_DENSITY_FEATURE_NAMES = (
    "query_v61_hash_cosine_distance",
    "query_v61_hash_mean_abs_z",
    "query_v61_hash_rms_z",
    "query_v61_hash_max_abs_z",
    "query_v61_hash_tail_ratio_1",
    "query_v61_hash_tail_ratio_2",
    "query_v61_hash_tail_ratio_3",
    "query_v61_active_bucket_ratio",
    "query_v61_hash_energy_ratio",
    "query_v61_positive_bucket_ratio",
    "query_v61_negative_bucket_ratio",
    "query_v61_abstract_idf_mean",
    "query_v61_abstract_idf_max",
    "query_v61_value_idf_mean",
    "query_v61_value_idf_max",
    "query_v61_statistical_distance",
)
QUERY_V61_FEATURE_NAMES = QUERY_GENERAL_FEATURE_NAMES + QUERY_V61_DENSITY_FEATURE_NAMES


# Học profile normal cho Query v6.1.
def build_query_v61_profile(requests: list[dict[str, object]]) -> dict[str, object]:
    profile = build_query_general_profile(requests)
    rows = []
    for request in requests:
        hashed = _hash_vector(_sources(request))
        rows.append([float(hashed[name]) for name in QUERY_GENERAL_HASH_FEATURE_NAMES])
    means, stds = [], []
    for index in range(len(QUERY_GENERAL_HASH_FEATURE_NAMES)):
        values = [row[index] for row in rows]
        mean = fmean(values)
        variance = fmean((value - mean) ** 2 for value in values)
        means.append(mean)
        stds.append(max(math.sqrt(variance), 0.05))
    active_counts = [sum(value != 0.0 for value in row) for row in rows]
    energies = [math.sqrt(sum(value * value for value in row)) for row in rows]
    profile["v61_density"] = {
        "fit_policy": "train-normal only",
        "hash_means": means,
        "hash_stds": stds,
        "mean_active_buckets": fmean(active_counts),
        "mean_energy": fmean(energies),
        "summary_feature_count": len(QUERY_V61_DENSITY_FEATURE_NAMES),
    }
    return profile


# Trích vector feature Query v6.1.
def extract_query_v61_features(request: dict[str, object], profile: dict[str, object]) -> dict[str, float]:
    base = extract_query_general_features(request, profile)
    density = profile.get("v61_density")
    if not density:
        raise ValueError("Query v6.1 density profile is missing")
    vector = [float(base[name]) for name in QUERY_GENERAL_HASH_FEATURE_NAMES]
    means = [float(value) for value in density["hash_means"]]
    stds = [float(value) for value in density["hash_stds"]]
    z = [abs(value - mean) / std for value, mean, std in zip(vector, means, stds, strict=True)]
    dot = sum(value * mean for value, mean in zip(vector, means, strict=True))
    norm = math.sqrt(sum(value * value for value in vector))
    mean_norm = math.sqrt(sum(value * value for value in means))
    cosine_distance = 1.0 - dot / (norm * mean_norm) if norm and mean_norm else 0.0
    active = sum(value != 0.0 for value in vector)
    positive = sum(value > 0.0 for value in vector)
    negative = sum(value < 0.0 for value in vector)
    active_denominator = max(1, active)
    values = (
        cosine_distance,
        fmean(z),
        math.sqrt(fmean(value * value for value in z)),
        max(z),
        sum(value > 1.0 for value in z) / len(z),
        sum(value > 2.0 for value in z) / len(z),
        sum(value > 3.0 for value in z) / len(z),
        active / max(1.0, float(density["mean_active_buckets"])),
        norm / max(1e-9, float(density["mean_energy"])),
        positive / active_denominator,
        negative / active_denominator,
        float(base["query_general_abstract_idf_mean"]),
        float(base["query_general_abstract_idf_max"]),
        float(base["query_general_value_idf_mean"]),
        float(base["query_general_value_idf_max"]),
        float(base["query_general_statistical_distance"]),
    )
    return {**base, **dict(zip(QUERY_V61_DENSITY_FEATURE_NAMES, values, strict=True))}
