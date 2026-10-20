import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml-detector" / "src"))

from fatget_features import (  # noqa: E402
    FATGET_DITHER_FEATURE_NAMES, build_fatget_profile, extract_fatget_features,
)


def _request(token: str, length: int = 0) -> dict[str, object]:
    headers = {"Host": "fusion.local:8086", "User-Agent": "test"}
    if length:
        headers.update({"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(length)})
    return {
        "method": "GET",
        "uri": f"/labs/fatget/js/geolocate.js?callback=fusionCallback{token[:8]}&locale=vi",
        "headers": headers,
    }


def test_fatget_relationship_novelty_is_deterministic_numeric_and_privacy_safe():
    train = [_request(f"{index:024x}") for index in range(40)]
    profile = build_fatget_profile(train)
    normal = extract_fatget_features(_request("a" * 24), profile)
    repeated = extract_fatget_features(_request("a" * 24), profile)
    attack = extract_fatget_features(_request("b" * 24, 24), profile)

    assert all(normal[name] == repeated[name] for name in FATGET_DITHER_FEATURE_NAMES)
    assert attack["fatget_method_body_relation_unseen_dithered"] > 1
    assert attack["fatget_content_metadata_relation_unseen_dithered"] > 1
    assert attack["fatget_body_presence_unseen_dithered"] > 1
    serialized = json.dumps({"profile": profile, "features": attack})
    assert "callback=alert" not in serialized
    assert "application/x-www-form-urlencoded" not in serialized
