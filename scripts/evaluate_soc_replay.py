"""Evaluate SOC case correlation from a replay bundle of sanitized JSONL events."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from triage.app import build_triage
from triage.cases import case_fingerprint, parse_time, read_jsonl
from triage.incidents import build_incident_report, incident_id_for


def infer_source(event):
    schema = event.get("schema", "")
    if schema == "fusion-nginx-access-v1":
        return "nginx"
    if schema == "fusion-detector-event-v2":
        return "baseline_detector"
    if schema == "fusion-ml-shadow-event-v1" and event.get("event_type") == "shadow_completed":
        return "ml_shadow"
    return None


def read_labels(path):
    if not path:
        return {}
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, list):
        return {item["request_id"]: item.get("label") for item in payload if isinstance(item, dict) and item.get("request_id")}
    raise ValueError("labels must be a JSON object or list of {request_id,label} records")


def audit_times(path):
    by_case = {}
    for event in read_jsonl(path) if path else []:
        by_case.setdefault(event.get("case_id"), []).append(event)
    return by_case


def fingerprint_file(path):
    path = Path(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "size_bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def git_provenance(requested_commit):
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, check=True, capture_output=True, text=True,
        ).stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        commit, dirty = "unknown", None
    return requested_commit or commit, dirty


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", action="append", required=True, type=Path,
                        help="Sanitized JSONL input; repeat for Nginx, detector and ML shadow streams.")
    parser.add_argument("--run-id", required=True, help="Replay run identifier recorded with the output.")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--labels", type=Path, help="Optional JSON labels keyed by request ID: false_positive/positive.")
    parser.add_argument("--actions", type=Path, help="Optional case audit JSONL for MTTA/MTTR calculations.")
    parser.add_argument("--commit", help="Source commit; defaults to the current Git HEAD when available.")
    parser.add_argument("--machine", default="unspecified local machine profile")
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--campaign-window-seconds", type=int, default=900)
    args = parser.parse_args()
    if args.concurrency < 1 or args.campaign_window_seconds < 60:
        parser.error("concurrency must be positive and campaign window at least 60 seconds")

    try:
        input_fingerprints = {
            "events": [fingerprint_file(path) for path in args.events],
            "labels": fingerprint_file(args.labels) if args.labels else None,
            "actions": fingerprint_file(args.actions) if args.actions else None,
        }
    except OSError as exc:
        parser.error(f"cannot fingerprint replay input: {exc}")
    source_commit, working_tree_dirty = git_provenance(args.commit)

    grouped = {}
    for file_path in args.events:
        for event in read_jsonl(file_path):
            source = infer_source(event)
            request_id = event.get("request_id")
            if source and request_id:
                grouped.setdefault(request_id, {})[source] = event
    alerts = [bundle for bundle in grouped.values()
              if bundle.get("baseline_detector", {}).get("classification") == "anomaly"]
    alerts.sort(key=lambda bundle: str(bundle["baseline_detector"].get("timestamp", "")))
    complete = [bundle for bundle in alerts if all(source in bundle for source in ("nginx", "baseline_detector", "ml_shadow"))]

    campaign_heads = {}
    case_for_request = {}
    cases_created = 0
    duplicates = 0
    first_seen = {}
    for bundle in complete:
        detector = bundle["baseline_detector"]
        request_id = detector["request_id"]
        nginx = bundle["nginx"]
        shadow = bundle["ml_shadow"]
        triage = build_triage(request_id, nginx, detector, shadow)
        report = build_incident_report(incident_id_for(request_id, detector.get("timestamp") or nginx.get("timestamp")),
                                       nginx, detector, triage)
        fingerprint, _ = case_fingerprint(report)
        detected = parse_time(detector.get("timestamp"))
        previous = campaign_heads.get(fingerprint)
        if previous and timedelta(0) <= detected - previous["last_seen"] <= timedelta(seconds=args.campaign_window_seconds):
            previous["last_seen"] = detected
            case_id = previous["case_id"]
            duplicates += 1
        else:
            case_id = report["incident_id"]
            campaign_heads[fingerprint] = {"case_id": case_id, "last_seen": detected}
            first_seen[case_id] = detected
            cases_created += 1
        case_for_request[request_id] = case_id

    labels = read_labels(args.labels)
    labeled_cases = {}
    for request_id, case_id in case_for_request.items():
        if request_id in labels:
            labeled_cases[case_id] = labels[request_id]
    adjudicated = {case_id: label for case_id, label in labeled_cases.items()
                   if str(label).casefold() in {"false_positive", "false-positive", "fp", "false",
                                                "true_positive", "true-positive", "tp", "true"}}
    fp_cases = sum(str(label).casefold() in {"false_positive", "false-positive", "fp", "false"} or label is False
                   for label in adjudicated.values())

    actions = audit_times(args.actions)
    mtta, mttr = [], []
    for case_id, history in actions.items():
        if case_id not in first_seen:
            continue
        history.sort(key=lambda event: str(event.get("timestamp", "")))
        ack = next((event for event in history if (
            event.get("event_type") == "status-changed" and
            event.get("details", {}).get("to") in {"investigating", "contained"}
        )), None)
        resolved = next((event for event in history if (
            event.get("event_type") == "status-changed" and event.get("details", {}).get("to") == "resolved"
        )), None)
        if ack:
            mtta.append(max(0.0, (parse_time(ack.get("timestamp")) - first_seen[case_id]).total_seconds()))
        if resolved:
            mttr.append(max(0.0, (parse_time(resolved.get("timestamp")) - first_seen[case_id]).total_seconds()))

    report = {
        "schema": "fusion-soc-replay-metrics-v1",
        "run": {"run_id": args.run_id, "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "commit": source_commit, "working_tree_dirty": working_tree_dirty,
                "machine": args.machine, "platform": platform.platform(),
                "processor": platform.processor(), "cpu_count": os.cpu_count(),
                "concurrency": args.concurrency, "campaign_window_seconds": args.campaign_window_seconds,
                "inputs": input_fingerprints,
                "evaluation_script_sha256": fingerprint_file(Path(__file__))["sha256"]},
        "scope": "local sanitized event replay; not production validation",
        "sample_sizes": {"alerts": len(alerts), "complete_evidence_alerts": len(complete),
                         "alerts_linked_to_case": len(case_for_request),
                         "cases_created": cases_created, "campaign_duplicates_collapsed": duplicates,
                         "analyst_labeled_cases": len(adjudicated), "analyst_acknowledged_cases": len(mtta),
                         "resolved_cases": len(mttr)},
        "metrics": {
            "alert_to_case_rate": len(case_for_request) / len(alerts) if alerts else None,
            "complete_evidence_case_rate": len(case_for_request) / len(complete) if complete else None,
            "duplicate_rate": duplicates / len(complete) if complete else None,
            "false_positive_rate": fp_cases / len(adjudicated) if adjudicated else None,
            "evidence_completeness": len(complete) / len(alerts) if alerts else None,
            "mtta_seconds_mean": statistics.fmean(mtta) if mtta else None,
            "mttr_seconds_mean": statistics.fmean(mttr) if mttr else None,
        },
        "labeling": {"false_positive_rate_denominator": "analyst-labelled true-positive and false-positive replay cases only",
                     "missing_labels_reported_as_zero": False},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
