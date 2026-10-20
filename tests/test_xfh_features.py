import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml-detector" / "src"))

from xfh_features import (  # noqa: E402
    XFH_DITHER_FEATURE_NAMES, build_xfh_v2_profile, extract_xfh_v2,
)


def _request(token: str, host: str, forwarded: str = "") -> dict[str, object]:
    headers = {"Host": host, "User-Agent": "test", "Accept": "text/html"}
    if forwarded:
        headers["X-Forwarded-Host"] = forwarded
    return {"method": "GET", "uri": f"/labs/xfh/shop?cb={token}", "headers": headers}


def test_xfh_relationship_novelty_is_deterministic_and_privacy_safe():
    train = [
        _request(f"{index:024x}", "fusion.local:8086", "fusion.local:8086")
        for index in range(40)
    ]
    profile = build_xfh_v2_profile(train)
    normal_request = _request("a" * 24, "fusion.local:8086", "fusion.local:8086")
    attack_request = _request("b" * 24, "fusion.local:8086", "127.0.0.1:8087")
    normal = extract_xfh_v2(normal_request, profile)
    repeated = extract_xfh_v2(normal_request, profile)
    attack = extract_xfh_v2(attack_request, profile)

    assert all(normal[name] == repeated[name] for name in XFH_DITHER_FEATURE_NAMES)
    assert all(0 < normal[name] < 1e-3 for name in XFH_DITHER_FEATURE_NAMES)
    assert attack["xfh_pair_unseen_dithered"] > 1.0
    assert attack["xfh_relation_distance_dithered"] > 0.1
    serialized = json.dumps({"profile": profile, "features": attack})
    assert "fusion.local" not in serialized
    assert "127.0.0.1" not in serialized
