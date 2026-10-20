"""Add normal-variant false-positive analysis and seal blind-test v1."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RECORDS = ROOT / "ml-detector" / "data" / "blind" / "blind_v1" / "feature_records.jsonl"
ARTIFACT = ROOT / "ml-detector" / "artifacts" / "blind_test_v1"
ANALYSIS = ARTIFACT / "normal_variant_metrics.json"
REPORT = ARTIFACT / "BLIND_TEST_REPORT_DETAILED.md"


# Tính checksum SHA-256 để ràng buộc dữ liệu hoặc artifact với evidence.
def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# Đọc tham số CLI và chạy sealed blind test của analyze_blind_test_v1.
def main() -> None:
    if ANALYSIS.exists() or REPORT.exists():
        raise FileExistsError("refusing to overwrite blind-test analysis")
    normal = {}
    with RECORDS.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if int(row["label"]) == 0:
                normal[row["record_id"]] = row
    aggregate: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"count": 0, "if_fp": 0, "profile_fp": 0, "hybrid_fp": 0}
    )
    with (ARTIFACT / "decisions.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            decision = json.loads(line)
            if int(decision["label"]) != 0:
                continue
            record = normal[decision["record_id"]]
            item = aggregate[(decision["route"], record["payload_variant"])]
            item["count"] += 1
            item["if_fp"] += int(decision["if_anomaly"])
            item["profile_fp"] += int(decision["profile_anomaly"])
            item["hybrid_fp"] += int(decision["final_anomaly"])
    output: dict[str, dict[str, object]] = {}
    for (route, variant), counts in sorted(aggregate.items()):
        count = counts["count"]
        output.setdefault(route, {})[variant] = {
            **counts,
            "if_false_positive_rate": counts["if_fp"] / count,
            "profile_false_positive_rate": counts["profile_fp"] / count,
            "hybrid_false_positive_rate": counts["hybrid_fp"] / count,
        }
    ANALYSIS.write_text(json.dumps({
        "schema_version": "wcp-blind-normal-variant-analysis-v1",
        "policy": "post-score descriptive analysis only; no threshold or model changes",
        "routes": output,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    evaluation = json.loads((ARTIFACT / "evaluation.json").read_text(encoding="utf-8"))
    lines = [
        "# Independent Blind Test v1 — Detailed Result", "",
        "Frozen models, profiles and thresholds were used without fitting or recalibration.", "",
        "| Route | IF Recall | IF FPR | Precision | FDR | IF-only TP | Gate |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for route, evidence in evaluation["routes"].items():
        metric = evidence["metrics"]["if_only"]
        gate = "PASS" if all(evidence["gate"].values()) else "FAIL"
        lines.append(
            f"| {route} | {metric['recall']:.2%} | {metric['false_positive_rate']:.2%} | "
            f"{metric['precision']:.2%} | {metric['false_discovery_rate']:.2%} | "
            f"{evidence['contribution']['if_unique_tp']} | {gate} |"
        )
    lines += [
        "", "## Gate conclusion", "",
        "- All four routes retained 100% attack recall.",
        "- UTM passed the recall/FPR gate.",
        "- Query, XFH and Fat GET failed the FPR <= 2% gate.",
        "- No threshold is changed from this result; this blind set is now opened evidence.",
        "- Query false positives are broad across all new normal lexical families.",
        "- XFH false positives concentrate in unseen host/pair families.",
        "- Fat GET false positives concentrate in the benign duplicate-tag family.",
        "", "## Highest normal-variant IF false-positive rates", "",
        "| Route | Variant | Count | FP | FPR |", "| --- | --- | ---: | ---: | ---: |",
    ]
    for route, variants in output.items():
        highest = sorted(
            variants.items(), key=lambda pair: pair[1]["if_false_positive_rate"], reverse=True
        )[:5]
        for variant, item in highest:
            lines.append(
                f"| {route} | `{variant}` | {item['count']} | {item['if_fp']} | "
                f"{item['if_false_positive_rate']:.2%} |"
            )
    lines += [
        "", "This analysis is descriptive. A future fix must create a new candidate and a new blind test; "
        "the current blind set must not be used for threshold tuning.", "",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")

    manifest_path = ARTIFACT / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["outputs"]["normal_variant_metrics"] = str(ANALYSIS.relative_to(ROOT)).replace("\\", "/")
    manifest["outputs"]["detailed_report"] = str(REPORT.relative_to(ROOT)).replace("\\", "/")
    manifest["sha256"]["normal_variant_metrics"] = sha256(ANALYSIS)
    manifest["sha256"]["detailed_report"] = sha256(REPORT)
    manifest["status"] = "sealed_opened_blind_evidence"
    manifest["retuning_on_this_blind_set_forbidden"] = True
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    checksum_path = ARTIFACT / "CHECKSUMS.sha256"
    files = sorted(path for path in ARTIFACT.iterdir() if path.is_file() and path.name != checksum_path.name)
    checksum_path.write_text("".join(f"{sha256(path)}  {path.name}\n" for path in files), encoding="ascii")
    print(json.dumps({
        "routes": list(output), "normal_records": len(normal),
        "analysis_sha256": sha256(ANALYSIS), "report_sha256": sha256(REPORT),
    }, indent=2))


if __name__ == "__main__":
    main()
