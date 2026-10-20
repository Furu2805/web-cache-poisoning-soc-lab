import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml-detector" / "src"))

from query_features import (  # noqa: E402
    QUERY_DITHER_FEATURE_NAMES,
    build_profile_v3,
    extract_query_v3,
)


def _request(token: str, utm: str) -> dict[str, object]:
    return {
        "method": "GET",
        "uri": f"/labs/query/?cb={token}&page=1&view=grid&utm_content={utm}",
        "headers": {"Host": "lab.local", "User-Agent": "test", "Accept-Language": "en"},
    }


def test_dithered_novelty_is_deterministic_numeric_and_privacy_safe():
    train = [_request(f"{index:024x}", "autumn-launch") for index in range(40)]
    profile = build_profile_v3(train)
    normal = extract_query_v3(_request("a" * 24, "autumn-launch"), profile)
    repeated = extract_query_v3(_request("a" * 24, "autumn-launch"), profile)
    novel = extract_query_v3(_request("b" * 24, "javascript:alert(9)"), profile)

    assert all(normal[name] == repeated[name] for name in QUERY_DITHER_FEATURE_NAMES)
    assert all(0 < normal[name] < 1e-3 for name in QUERY_DITHER_FEATURE_NAMES)
    assert novel["query_utm_unseen_ngram_ratio_dithered"] > 0.1
    serialized = json.dumps({"profile": profile, "features": novel})
    assert "javascript:alert" not in serialized
    assert "autumn-launch" not in serialized
