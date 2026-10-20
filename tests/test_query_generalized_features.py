import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml-detector" / "src"))

from query_generalized_features import (  # noqa: E402
    QUERY_GENERAL_DITHER_FEATURE_NAMES,
    build_query_general_profile,
    extract_query_general_features,
)


def _request(token: str, value: str, view: str = "grid") -> dict[str, object]:
    return {
        "method": "GET",
        "uri": f"/labs/query/?cb={token}&page=1&view={view}&utm_content={value}",
        "headers": {"Host": "fusion.local:8086", "User-Agent": "test"},
    }


def test_generalization_preserves_syntax_and_hides_raw_values():
    train = [_request(f"{index:024x}", value) for index, value in enumerate((
        "autumn launch", "email digest", "product guide", "mobile banner",
    ) * 10)]
    profile = build_query_general_profile(train)
    known = extract_query_general_features(_request("a" * 24, "autumn catalogue"), profile)
    oov_benign = extract_query_general_features(_request("b" * 24, "regional newsletter", "gallery"), profile)
    attack = extract_query_general_features(_request("c" * 24, "javascript:alert(81)"), profile)

    assert all(0 <= known[name] < 1e-3 for name in QUERY_GENERAL_DITHER_FEATURE_NAMES)
    assert oov_benign["query_general_punctuation_unseen_dithered"] < 1e-3
    assert attack["query_general_punctuation_unseen_dithered"] > 1
    serialized = json.dumps({"profile": profile, "features": attack})
    assert "regional newsletter" not in serialized
    assert "javascript:alert" not in serialized
