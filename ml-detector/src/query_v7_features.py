"""One-dimensional generalized lexical novelty for Query v7."""
from __future__ import annotations

from query_generalized_features import (
    QUERY_GENERAL_FEATURE_NAMES,
    build_query_general_profile,
    extract_query_general_features,
)


QUERY_V7_NOVELTY_FEATURE = "query_v7_combined_novelty_dithered"
QUERY_V7_FEATURE_NAMES = QUERY_GENERAL_FEATURE_NAMES + (QUERY_V7_NOVELTY_FEATURE,)


# Học profile normal cho Query v7.
def build_query_v7_profile(requests: list[dict[str, object]]) -> dict[str, object]:
    profile = build_query_general_profile(requests)
    profile["v7_policy"] = {
        "fit_source": "train-normal only",
        "type": "maximum generalized lexical novelty with deterministic tie break",
        "raw_words_persisted": False,
    }
    return profile


# Trích vector feature Query v7.
def extract_query_v7_features(request: dict[str, object], profile: dict[str, object]) -> dict[str, float]:
    if "v7_policy" not in profile:
        raise ValueError("Query-v7 profile is missing")
    features = extract_query_general_features(request, profile)
    combined = max(
        float(features["query_general_abstract_unseen_dithered"]),
        float(features["query_general_value_unseen_dithered"]),
        float(features["query_general_punctuation_unseen_dithered"]),
    )
    return {**features, QUERY_V7_NOVELTY_FEATURE: combined}
