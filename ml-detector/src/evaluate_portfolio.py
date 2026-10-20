"""Re-evaluate the frozen route candidates on held-out synthetic datasets.

This script reads the checked-in candidate packages and locally generated
feature records. It never fits or promotes a model and never consumes evidence
fields as model features.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn


ROOT = Path(__file__).resolve().parents[2]
ROUTES: dict[str, dict[str, str]] = {
    "xfh": {
        "dataset": "xfh_v3",
        "blind": "xfh_blind_v2",
        "artifact": "xfh_phase1_v3",
        "manifest": "xfh_v3",
        "rule_feature": "host_mismatch",
        "rule": "host_mismatch > 0 (unkeyed X-Forwarded-Host differs from Host)",
    },
    "query": {
        "dataset": "query_v8",
        "blind": "query_v8_blind_v1",
        "artifact": "query_phase2_v8",
        "manifest": "query_v8",
        "rule_feature": "raw_angle_bracket_count",
        "rule": "raw_angle_bracket_count > 0 (simple reflected-markup signature)",
    },
    "utm": {
        "dataset": "utm",
        "blind": "blind_v1",
        "artifact": "utm_phase3",
        "manifest": "utm",
        "rule_feature": "utm_semicolon_callback_count",
        "rule": "utm_semicolon_callback_count > 0 (hidden callback override signature)",
    },
    "fatget": {
        "dataset": "fatget_v2",
        "blind": "fatget_blind_v2",
        "artifact": "fatget_phase4_v2",
        "manifest": "fatget_v2",
        "rule_feature": "has_body_on_get",
        "rule": "has_body_on_get > 0 (GET request body primitive)",
    },
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _git_value(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True,
        )
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _host_memory_bytes() -> int | None:
    if os.name == "nt":
        try:
            import ctypes

            class MemoryStatus(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MemoryStatus()
            status.dwLength = ctypes.sizeof(status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullTotalPhys)
        except (AttributeError, OSError, TypeError):
            return None
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return int(pages * page_size)
    except (AttributeError, OSError, ValueError):
        return None


def _read_development(path: Path, route: str) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, Any]]:
    split_counts: dict[str, int] = defaultdict(int)
    split_groups: dict[str, set[str]] = defaultdict(set)
    seen_ids: set[str] = set()
    test_rows: list[dict[str, Any]] = []
    feature_names: set[str] | None = None
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("route") != route:
                raise ValueError(f"{path}:{line_number}: unexpected route {row.get('route')!r}")
            record_id = str(row.get("record_id", ""))
            if not record_id or record_id in seen_ids:
                raise ValueError(f"{path}:{line_number}: record_id is missing or duplicated")
            seen_ids.add(record_id)
            split = str(row.get("split", ""))
            if split not in {"train", "validation", "test"}:
                raise ValueError(f"{path}:{line_number}: invalid split {split!r}")
            label = int(row.get("label", -1))
            if label not in (0, 1):
                raise ValueError(f"{path}:{line_number}: label must be 0 or 1")
            features = row.get("features")
            if not isinstance(features, dict) or not features:
                raise ValueError(f"{path}:{line_number}: numeric features are required")
            current_feature_names = set(features)
            if feature_names is None:
                feature_names = current_feature_names
            elif current_feature_names != feature_names:
                raise ValueError(f"{path}:{line_number}: feature schema differs between records")
            split_counts[f"{split}_{'attack' if label else 'normal'}"] += 1
            group_id = str(row.get("group_id", ""))
            if not group_id:
                raise ValueError(f"{path}:{line_number}: group_id is required for leakage audit")
            split_groups[split].add(group_id)
            if split in {"train", "validation"} and label != 0:
                raise ValueError(f"{path}:{line_number}: train/validation must be normal-only")
            if split == "test":
                test_rows.append(row)

    overlaps = {
        f"{left}/{right}": sorted(split_groups[left] & split_groups[right])[:5]
        for left, right in (("train", "validation"), ("train", "test"), ("validation", "test"))
        if split_groups[left] & split_groups[right]
    }
    if overlaps:
        raise ValueError(f"group leakage detected for {route}: {overlaps}")
    labels = [int(row["label"]) for row in test_rows]
    if not labels or set(labels) != {0, 1}:
        raise ValueError(f"{route} held-out test must include both labels")
    summary = {
        "split_counts": dict(sorted(split_counts.items())),
        "group_counts": {name: len(groups) for name, groups in sorted(split_groups.items())},
        "group_overlap_count": 0,
        "feature_count": len(feature_names or ()),
    }
    return test_rows, dict(split_counts), summary


def _read_blind(path: Path, route: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("route") != route:
                continue
            record_id = str(row.get("record_id", ""))
            if not record_id or record_id in seen_ids:
                raise ValueError(f"{path}:{line_number}: {route} record_id is missing or duplicated")
            seen_ids.add(record_id)
            if int(row.get("label", -1)) not in (0, 1):
                raise ValueError(f"{path}:{line_number}: label must be 0 or 1")
            if "evidence" not in row:
                raise ValueError(f"{path}:{line_number}: blind record is missing evidence separation")
            rows.append(row)
    if not rows or {int(row["label"]) for row in rows} != {0, 1}:
        raise ValueError(f"blind holdout for {route} must include normal and attack rows")
    return rows


def _matrix(rows: list[dict[str, Any]], feature_names: list[str]) -> np.ndarray:
    try:
        result = np.asarray(
            [[float(row["features"][name]) for name in feature_names] for row in rows],
            dtype=np.float64,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("feature record does not match the frozen candidate schema") from exc
    if not np.isfinite(result).all():
        raise ValueError("feature matrix contains non-finite values")
    return result


def _metrics(prediction: np.ndarray, labels: np.ndarray) -> dict[str, Any]:
    prediction = prediction.astype(bool)
    positive = labels == 1
    negative = labels == 0
    tp = int(np.sum(prediction & positive))
    fp = int(np.sum(prediction & negative))
    tn = int(np.sum(~prediction & negative))
    fn = int(np.sum(~prediction & positive))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "normal_support": int(np.sum(negative)),
        "attack_support": int(np.sum(positive)),
    }


def _profile_prediction(rows: list[dict[str, Any]], guard: dict[str, Any]) -> np.ndarray:
    if guard.get("type") == "explicit primitive":
        feature = str(guard["feature"])
        normal_value = float(guard["normal_value"])
        return np.asarray(
            [float(row["features"][feature]) != normal_value for row in rows], dtype=bool,
        )
    bounds = guard.get("bounds")
    if not isinstance(bounds, dict) or not bounds:
        raise ValueError("candidate is missing its normal-profile bounds")
    result = []
    for row in rows:
        features = row["features"]
        result.append(any(
            float(features[name]) < float(limits["min"])
            or float(features[name]) > float(limits["max"])
            for name, limits in bounds.items()
        ))
    return np.asarray(result, dtype=bool)


def _candidate_predictions(
    rows: list[dict[str, Any]], bundle: dict[str, Any], route: str,
) -> tuple[dict[str, np.ndarray], dict[str, np.ndarray]]:
    thresholds = bundle["thresholds"]
    components: dict[str, np.ndarray] = {}
    if "structural_model" in bundle:
        names = list(bundle["structural_feature_names"])
        scores = -bundle["structural_model"].score_samples(_matrix(rows, names))
        components["structural_if"] = scores > float(thresholds["structural"])
    if "relationship_model" in bundle:
        names = list(bundle["relationship_feature_names"])
        scores = -bundle["relationship_model"].score_samples(_matrix(rows, names))
        components["relationship_if"] = scores > float(thresholds["relationship"])
    if not components:
        raise ValueError(f"candidate for {route} has no IF component")
    if_prediction = np.logical_or.reduce(list(components.values()))
    labels = np.asarray([int(row["label"]) for row in rows], dtype=np.int8)
    rule_feature = ROUTES[route]["rule_feature"]
    rule_prediction = np.asarray(
        [float(row["features"][rule_feature]) > 0 for row in rows], dtype=bool,
    )
    profile_prediction = _profile_prediction(rows, bundle["normal_profile_guard"])
    predictions = {
        "rule": rule_prediction,
        "profile": profile_prediction,
        "if": if_prediction,
        "hybrid": np.logical_or(if_prediction, profile_prediction),
    }
    # Keep metrics adjacent to predictions so later report generation cannot
    # silently change the label or support population.
    predictions["_labels"] = labels
    return predictions, components


def _evaluate_split(
    rows: list[dict[str, Any]], bundle: dict[str, Any], route: str,
) -> dict[str, Any]:
    predictions, components = _candidate_predictions(rows, bundle, route)
    labels = predictions.pop("_labels")
    metrics = {name: _metrics(prediction, labels) for name, prediction in predictions.items()}
    component_metrics = {name: _metrics(prediction, labels) for name, prediction in components.items()}
    if_prediction = predictions["if"]
    profile_prediction = predictions["profile"]
    unique_if = if_prediction & ~profile_prediction
    unique_profile = profile_prediction & ~if_prediction
    overlapping = if_prediction & profile_prediction
    contribution = {
        "if_unique_tp": int(np.sum(unique_if & (labels == 1))),
        "if_unique_fp": int(np.sum(unique_if & (labels == 0))),
        "profile_unique_tp": int(np.sum(unique_profile & (labels == 1))),
        "profile_unique_fp": int(np.sum(unique_profile & (labels == 0))),
        "overlap_tp": int(np.sum(overlapping & (labels == 1))),
        "overlap_fp": int(np.sum(overlapping & (labels == 0))),
    }
    variants: dict[str, Any] = {}
    for variant in sorted({str(row.get("payload_variant", "unknown")) for row in rows if int(row["label"]) == 1}):
        mask = np.asarray([
            int(row["label"]) == 1 and str(row.get("payload_variant", "unknown")) == variant
            for row in rows
        ], dtype=bool)
        variants[variant] = {
            "support": int(np.sum(mask)),
            **{
                name: int(np.sum(prediction[mask]))
                for name, prediction in predictions.items()
            },
        }
    return {
        "sample_count": len(rows),
        "metrics": metrics,
        "if_component_ablation": component_metrics,
        "if_vs_profile_contribution": contribution,
        "attack_variant_detection_counts": variants,
    }


def _build_report(args: argparse.Namespace) -> dict[str, Any]:
    dataset_root = args.dataset_root.resolve()
    blind_root = args.blind_root.resolve()
    artifact_root = args.artifact_root.resolve()
    manifest_root = args.manifest_root.resolve()
    routes_report: dict[str, Any] = {}

    for route, config in ROUTES.items():
        dev_path = dataset_root / config["dataset"] / "feature_records.jsonl"
        blind_path = blind_root / config["blind"] / "feature_records.jsonl"
        manifest_path = manifest_root / config["manifest"] / "dataset_manifest.json"
        package_dir = artifact_root / config["artifact"]
        model_path = package_dir / "model.joblib"
        guard_path = package_dir / "normal_profile_guard.json"
        for path in (dev_path, blind_path, manifest_path, model_path, guard_path):
            if not path.is_file():
                raise FileNotFoundError(
                    f"Required evaluation input is missing: {path.relative_to(ROOT) if ROOT in path.parents else path}. "
                    "Generate the local synthetic datasets first; see ml-detector/DATASET_CARD.md."
                )

        manifest = _json(manifest_path)
        expected_sha = manifest.get("sha256", {}).get("processed")
        if expected_sha and _sha256(dev_path) != expected_sha:
            raise ValueError(f"processed dataset checksum does not match manifest: {route}")
        bundle = joblib.load(model_path)
        if bundle.get("route") != route:
            raise ValueError(f"candidate package route mismatch: {model_path}")
        # Use the checked-in guard file and make sure it still agrees with the
        # guard embedded in the candidate package.
        guard = _json(guard_path)
        if guard != bundle.get("normal_profile_guard"):
            raise ValueError(f"normal profile guard differs from candidate package: {route}")
        dev_rows, split_counts, split_audit = _read_development(dev_path, route)
        manifest_counts = manifest.get("counts", {})
        expected_counts = {
            "train_normal": int(manifest_counts.get("train_normal", -1)),
            "validation_normal": int(manifest_counts.get("validation_normal", -1)),
            "test_normal": int(manifest_counts.get("test_normal", -1)),
            "test_attack": int(manifest_counts.get("test_attack", -1)),
        }
        if any(split_counts.get(key, 0) != expected for key, expected in expected_counts.items()):
            raise ValueError(f"processed sample counts do not match dataset manifest: {route}")
        if split_audit["feature_count"] != int(manifest.get("feature_count", -1)):
            raise ValueError(f"processed feature count does not match dataset manifest: {route}")
        blind_rows = _read_blind(blind_path, route)
        blind_predictions = _evaluate_split(blind_rows, bundle, route)
        blind_summary = {
            "split": "independent_synthetic_blind_holdout",
            "dataset_path": blind_path.relative_to(ROOT).as_posix(),
            "dataset_sha256": _sha256(blind_path),
            **blind_predictions,
        }
        routes_report[route] = {
            "candidate_id": bundle.get("candidate_id"),
            "candidate_model_sha256": _sha256(model_path),
            "normal_profile_guard_sha256": _sha256(guard_path),
            "rule_definition": config["rule"],
            "development": {
                "split": "grouped_held_out_test",
                "dataset_path": dev_path.relative_to(ROOT).as_posix(),
                "dataset_sha256": _sha256(dev_path),
                "manifest_path": manifest_path.relative_to(ROOT).as_posix(),
                "manifest_sha256": _sha256(manifest_path),
                "manifest_seed": manifest.get("seed"),
                "manifest_counts": manifest_counts,
                "split_counts": split_counts,
                "split_audit": split_audit,
                **_evaluate_split(dev_rows, bundle, route),
            },
            "blind_holdout": blind_summary,
        }

    commit = _git_value("rev-parse", "HEAD")
    dirty = bool(_git_value("status", "--porcelain"))
    code_path = Path(__file__).resolve()
    return {
        "schema_version": "route-detector-portfolio-evaluation-v1",
        "run_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8],
        "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_commit": commit,
        "working_tree_dirty": dirty,
        "evaluation_script_sha256": _sha256(code_path),
        "environment": {
            "python": sys.version.split()[0],
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "physical_memory_bytes": _host_memory_bytes(),
            "inference_parallelism": 1,
            "scoring_mode": "offline CPU; frozen candidates; no request concurrency",
        },
        "scope": {
            "traffic": "synthetic local lab only",
            "development_test": "held-out split; training and validation contain normal records only",
            "independent_holdout": "separately generated synthetic variants; a novelty holdout, not production OOD evidence",
            "production_representativeness": False,
            "automatic_model_promotion": False,
            "evidence_used_as_features": False,
            "group_leakage_checked": True,
        },
        "method_definitions": {
            "rule": "fixed route-specific signature for the modeled WCP primitive; deliberately narrow baseline",
            "profile": "frozen normal-profile guard packaged with each candidate",
            "if": "frozen route candidate; component IF predictions are OR-combined where present",
            "hybrid": "IF OR normal-profile guard; matches the candidate's final shadow decision",
            "fpr": "false positives divided by all normal records in the evaluated split",
            "support": "normal_support and attack_support are reported for every metric row",
        },
        "routes": routes_report,
    }


def _format_metric(metric: dict[str, Any]) -> str:
    return (
        f"{metric['precision']:.4f} | {metric['recall']:.4f} | {metric['f1']:.4f} | "
        f"{metric['fpr']:.4f} | {metric['normal_support']}/{metric['attack_support']}"
    )


def _markdown(report: dict[str, Any], dataset_card_link: str) -> str:
    lines = [
        "# Route detector evaluation",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Created (UTC): `{report['created_at_utc']}`",
        f"- Source commit: `{report['source_commit'] or 'unknown'}`; working tree dirty: `{str(report['working_tree_dirty']).lower()}`",
        f"- Evaluation script SHA-256: `{report['evaluation_script_sha256']}`",
        f"- Runtime: Python `{report['environment']['python']}`, scikit-learn `{report['environment']['scikit_learn']}`, CPU count `{report['environment']['cpu_count']}`, physical RAM `{report['environment']['physical_memory_bytes']}` bytes",
        f"- Scoring: `{report['environment']['scoring_mode']}`",
        "",
        "> All rows below are synthetic local lab traffic. The independent set uses separately generated variants; it is a novelty holdout, not evidence of production or external OOD performance.",
        "",
        "## Held-out metrics by route",
        "",
        "| Route | Split | Detector | Precision | Recall | F1 | FPR | Support N/A |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for route, route_data in report["routes"].items():
        for split_key, split_label in (("development", "development test"), ("blind_holdout", "independent blind")):
            split = route_data[split_key]
            for method in ("rule", "profile", "if", "hybrid"):
                lines.append(
                    f"| {route} | {split_label} | {method} | {_format_metric(split['metrics'][method])} |"
                )
    lines += [
        "",
        "`Support N/A` is the count of normal/attack samples. The rule baseline is intentionally specific to each lab primitive; repeated rule/profile values on XFH and Fat GET are expected because their packaged profile guard is the same explicit primitive.",
        "",
        "## Isolation Forest ablation",
        "",
        "| Route | Split | Component | Precision | Recall | F1 | FPR | Support N/A |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for route, route_data in report["routes"].items():
        for split_key, split_label in (("development", "development test"), ("blind_holdout", "independent blind")):
            split = route_data[split_key]
            for component, metric in split["if_component_ablation"].items():
                lines.append(
                    f"| {route} | {split_label} | {component} | {_format_metric(metric)} |"
                )
    lines += ["", "## IF contribution relative to profile", "", "| Route | Split | IF-only TP | IF-only FP | Profile-only TP | Profile-only FP | Overlap TP | Overlap FP |", "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for route, route_data in report["routes"].items():
        for split_key, split_label in (("development", "development test"), ("blind_holdout", "independent blind")):
            contribution = route_data[split_key]["if_vs_profile_contribution"]
            lines.append(
                f"| {route} | {split_label} | {contribution['if_unique_tp']} | {contribution['if_unique_fp']} | "
                f"{contribution['profile_unique_tp']} | {contribution['profile_unique_fp']} | "
                f"{contribution['overlap_tp']} | {contribution['overlap_fp']} |"
            )
    lines += ["", "## Provenance and limits", ""]
    for route, route_data in report["routes"].items():
        dev = route_data["development"]
        blind = route_data["blind_holdout"]
        counts = dev["manifest_counts"] or {}
        lines.append(
            f"- `{route}` (`{route_data['candidate_id']}`): development seed `{dev['manifest_seed']}`, "
            f"train normal `{counts.get('train_normal', 'n/a')}`, validation normal `{counts.get('validation_normal', 'n/a')}`, "
            f"test normal/attack `{counts.get('test_normal', 'n/a')}/{counts.get('test_attack', 'n/a')}`; "
            f"development data SHA-256 `{dev['dataset_sha256']}`, blind data SHA-256 `{blind['dataset_sha256']}`, "
            f"candidate SHA-256 `{route_data['candidate_model_sha256']}`."
        )
    lines += [
        "",
        f"Raw request data and generated feature sets are excluded from Git. Recreate them against the local lab with the replay command in [the dataset card]({dataset_card_link}), then rerun the evaluator. Fresh collection produces a new run ID and dataset fingerprints; do not cite a metric without those identifiers.",
        "",
        "Synthetic traffic is useful for checking the known lab primitives and pipeline behavior. It does not model the full request mix, attacker behavior, proxy variation, or analyst labels seen in production. No production effectiveness claim is made.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate frozen per-route WCP detector candidates")
    parser.add_argument("--dataset-root", type=Path, default=ROOT / "ml-detector/data/processed")
    parser.add_argument("--blind-root", type=Path, default=ROOT / "ml-detector/data/blind")
    parser.add_argument("--artifact-root", type=Path, default=ROOT / "ml-detector/artifacts/candidates")
    parser.add_argument("--manifest-root", type=Path, default=ROOT / "ml-detector/data/manifests")
    parser.add_argument("--json-output", type=Path, default=ROOT / "results/ml-detector/evaluation.json")
    parser.add_argument("--markdown-output", type=Path, default=ROOT / "results/ml-detector/evaluation.md")
    args = parser.parse_args()
    report = _build_report(args)
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_path = args.markdown_output.resolve()
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    dataset_card_path = ROOT / "ml-detector" / "DATASET_CARD.md"
    dataset_card_link = Path(os.path.relpath(dataset_card_path, markdown_path.parent)).as_posix()
    args.json_output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(_markdown(report, dataset_card_link), encoding="utf-8")
    print(json.dumps({
        "run_id": report["run_id"],
        "json_output": str(args.json_output),
        "markdown_output": str(markdown_path),
        "routes": list(report["routes"]),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
