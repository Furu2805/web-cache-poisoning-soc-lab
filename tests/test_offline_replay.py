import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml-detector" / "src"))

from offline_replay import replay


def test_all_sealed_blind_records_match_runtime_scoring():
    report = replay()
    assert report["acceptance"] == {
        "all_records_match_artifact_decisions": True,
        "scores_within_published_tolerance": True,
        "no_cross_route_model_invocation": True,
        "evidence_excluded_from_model_features": True,
    }
    assert {route: item["record_count"] for route, item in report["routes"].items()} == {
        "query": 2000,
        "xfh": 2000,
        "utm": 2000,
        "fatget": 2000,
    }
