"""Replay sealed blind vectors through the exact runtime scoring function."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

import sys
sys.path.insert(0, str(ROOT))

from ml.route_detector import load_registry, score_route_feature_batch  # noqa: E402

SOURCES = {
    "query": (
        ROOT / "ml-detector/data/blind/query_v8_blind_v1/feature_records.jsonl",
        ROOT / "ml-detector/artifacts/query_v8_blind_v1/decisions.jsonl",
        {"structural": "structural_score", "relationship": "lexical_score"},
    ),
    "xfh": (
        ROOT / "ml-detector/data/blind/xfh_blind_v2/feature_records.jsonl",
        ROOT / "ml-detector/artifacts/xfh_blind_test_v2/decisions.jsonl",
        {"relationship": "if_score"},
    ),
    "utm": (
        ROOT / "ml-detector/data/blind/blind_v1/feature_records.jsonl",
        ROOT / "ml-detector/artifacts/blind_test_v1/decisions.jsonl",
        {"structural": "structural_score", "relationship": "secondary_score"},
    ),
    "fatget": (
        ROOT / "ml-detector/data/blind/fatget_blind_v2/feature_records.jsonl",
        ROOT / "ml-detector/artifacts/fatget_blind_test_v2/decisions.jsonl",
        {"relationship": "if_score"},
    ),
}


# Đọc các hàng dữ liệu để replay offline.
def _rows(path: Path):
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


# Tính checksum SHA-256 để ràng buộc dữ liệu hoặc artifact với evidence.
def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# Tính confusion matrix và các metric của candidate.
def _metrics(rows):
    tp = sum(row["label"] == 1 and row["decision"] for row in rows)
    fp = sum(row["label"] == 0 and row["decision"] for row in rows)
    tn = sum(row["label"] == 0 and not row["decision"] for row in rows)
    fn = sum(row["label"] == 1 and not row["decision"] for row in rows)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "confusion_matrix": [[tn, fp], [fn, tp]]}


# Chạy lại scoring trên artifact đã đóng băng và so sánh với evidence.
def replay(tolerance: float = 1e-12) -> dict:
    registry = load_registry()
    report = {
        "schema_version": "route-runtime-replay-v1",
        "score_tolerance": tolerance,
        "feature_source": "sealed numeric request-time vectors; evidence excluded",
        "routes": {},
    }
    all_match = True
    for route, (records_path, decisions_path, score_keys) in SOURCES.items():
        expected = {
            row["record_id"]: row for row in _rows(decisions_path)
            if row.get("route", route) == route
        }
        replayed = []
        variants = defaultdict(list)
        max_delta = 0.0
        mismatch_ids = []
        cross_route_invocations = 0
        selected_rows = []
        for row in _rows(records_path):
            if row["route"] != route:
                if route == "utm":
                    continue
                raise ValueError(f"cross-route record in {records_path}: {row['record_id']}")
            selected_rows.append(row)
        results = score_route_feature_batch(route, [row["features"] for row in selected_rows], registry)
        for row, result in zip(selected_rows, results, strict=True):
            if "evidence" not in row:
                raise ValueError("sealed replay row is missing evidence separation")
            reference = expected.get(row["record_id"])
            if reference is None:
                raise ValueError(f"missing artifact decision: {row['record_id']}")
            score_match = True
            for component, expected_key in score_keys.items():
                delta = abs(result["component_scores"][component] - float(reference[expected_key]))
                max_delta = max(max_delta, delta)
                score_match &= delta <= tolerance
            decision_match = all(
                result[name] == bool(reference[name])
                for name in ("if_anomaly", "profile_anomaly", "final_anomaly")
            )
            if not score_match or not decision_match:
                mismatch_ids.append(row["record_id"])
            item = {
                "record_id": row["record_id"],
                "label": int(row["label"]),
                "decision": result["if_anomaly"],
            }
            replayed.append(item)
            variants[row["payload_variant"]].append(item)
        count = len(selected_rows)
        if count != len(expected):
            raise ValueError(f"record/decision count mismatch for {route}: {count} != {len(expected)}")
        route_match = not mismatch_ids
        all_match &= route_match
        report["routes"][route] = {
            "candidate_id": registry[route]["candidate_id"],
            "feature_schema_version": registry[route]["feature_schema"]["schema_version"],
            "record_count": count,
            "records_sha256": _sha256(records_path),
            "decisions_sha256": _sha256(decisions_path),
            "decision_parity": route_match,
            "mismatch_count": len(mismatch_ids),
            "mismatch_record_ids": mismatch_ids,
            "max_score_absolute_error": max_delta,
            "if_metrics": _metrics(replayed),
            "variant_metrics": {name: _metrics(items) for name, items in sorted(variants.items())},
            "false_positive_record_ids": [
                item["record_id"] for item in replayed
                if item["label"] == 0 and item["decision"]
            ],
            "cross_route_model_invocations": cross_route_invocations,
        }
    report["acceptance"] = {
        "all_records_match_artifact_decisions": all_match,
        "scores_within_published_tolerance": all(
            item["max_score_absolute_error"] <= tolerance for item in report["routes"].values()
        ),
        "no_cross_route_model_invocation": all(
            item["cross_route_model_invocations"] == 0 for item in report["routes"].values()
        ),
        "evidence_excluded_from_model_features": True,
    }
    return report


# Đọc tham số CLI và chạy pipeline dữ liệu/model của offline_replay.
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "ml-detector/artifacts/runtime_replay_v1/evaluation.json")
    parser.add_argument("--tolerance", type=float, default=1e-12)
    args = parser.parse_args()
    report = replay(args.tolerance)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not all(report["acceptance"].values()):
        raise SystemExit(1)
    print(json.dumps({"output": str(args.output), "acceptance": report["acceptance"]}, indent=2))


if __name__ == "__main__":
    main()
