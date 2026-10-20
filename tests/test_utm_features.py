import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml-detector" / "src"))

from utm_features import UTM_DITHER_FEATURE_NAMES, build_utm_profile, extract_utm_features  # noqa: E402


def _request(token: str, suffix: str) -> dict[str, object]:
    uri = f"/labs/utm/js/geolocate.js?callback=fusionCallback{token[:8]}&locale=vi&utm_content=campaign-{token}{suffix}"
    return {"method": "GET", "uri": uri, "headers": {"Host": "fusion.local:8086"}}


def test_utm_cloaking_novelty_is_deterministic_numeric_and_privacy_safe():
    train = [_request(f"{index:024x}", ";locale=en") for index in range(40)]
    profile = build_utm_profile(train)
    normal = extract_utm_features(_request("a" * 24, ";locale=en"), profile)
    repeated = extract_utm_features(_request("a" * 24, ";locale=en"), profile)
    attack = extract_utm_features(_request("b" * 24, ";callback=alert(9)"), profile)

    assert all(normal[name] == repeated[name] for name in UTM_DITHER_FEATURE_NAMES)
    assert attack["utm_semicolon_callback_count"] == 1
    assert attack["utm_callback_relation_unseen_dithered"] > 1
    assert attack["utm_callback_distance_dithered"] > 0.1
    serialized = json.dumps({"profile": profile, "features": attack})
    assert "alert(9)" not in serialized
    assert "fusionCallback" not in serialized
