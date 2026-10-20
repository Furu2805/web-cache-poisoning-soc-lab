"""Create a tamper-evident snapshot of the four evaluated route candidates."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "ml-detector" / "artifacts" / "evidence_freeze_v1"
RUNTIME_MODEL = ROOT / "models" / "isolation_forest.joblib"

CANDIDATES = {
    "query": {
        "directory": "ml-detector/artifacts/candidates/query_phase2_v4",
        "dataset_manifest": "ml-detector/data/manifests/query_v4/dataset_manifest.json",
        "audit": "ml-detector/data/manifests/query_v4/train_normal_variance_audit.json",
        "source": (
            "ml-detector/src/query_feature_base.py",
            "ml-detector/src/query_features.py",
            "ml-detector/src/collect_query_dataset_core.py",
            "ml-detector/src/collect_query_dataset.py",
            "ml-detector/src/train_evaluate_query_core.py",
            "ml-detector/src/train_evaluate_query.py",
            "tests/test_query_features.py",
            "docs/BAO_CAO_QUERY_IF_NORMAL_ONLY.md",
        ),
    },
    "xfh": {
        "directory": "ml-detector/artifacts/candidates/xfh_phase1_v2",
        "dataset_manifest": "ml-detector/data/manifests/xfh_v2/dataset_manifest.json",
        "audit": "ml-detector/data/manifests/xfh_v2/train_normal_variance_audit.json",
        "source": (
            "ml-detector/src/xfh_features.py",
            "ml-detector/src/collect_xfh_dataset.py",
            "ml-detector/src/train_evaluate_xfh.py",
            "tests/test_xfh_features.py",
            "docs/BAO_CAO_XFH_IF_NORMAL_ONLY.md",
        ),
    },
    "utm": {
        "directory": "ml-detector/artifacts/candidates/utm_phase3",
        "dataset_manifest": "ml-detector/data/manifests/utm/dataset_manifest.json",
        "audit": "ml-detector/data/manifests/utm/train_normal_variance_audit.json",
        "source": (
            "ml-detector/src/utm_features.py",
            "ml-detector/src/collect_utm_dataset.py",
            "ml-detector/src/train_evaluate_utm.py",
            "tests/test_utm_features.py",
            "docs/BAO_CAO_UTM_IF_NORMAL_ONLY.md",
        ),
    },
    "fatget": {
        "directory": "ml-detector/artifacts/candidates/fatget_phase4",
        "dataset_manifest": "ml-detector/data/manifests/fatget/dataset_manifest.json",
        "audit": "ml-detector/data/manifests/fatget/train_normal_variance_audit.json",
        "source": (
            "ml-detector/src/fatget_features.py",
            "ml-detector/src/collect_fatget_dataset.py",
            "ml-detector/src/train_evaluate_fatget.py",
            "tests/test_fatget_features.py",
            "docs/BAO_CAO_FATGET_IF_NORMAL_ONLY.md",
        ),
    },
}

SHARED_SOURCE = (
    "common/features.py",
    "traffic/fusion_collect.py",
    "traffic/fusion_scenarios.py",
    "ml-detector/src/audit_train_variance.py",
    "ml-detector/config/route_registry.json",
)


# Tính checksum SHA-256 để ràng buộc dữ liệu hoặc artifact với evidence.
def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# Đổi đường dẫn artifact thành đường dẫn tương đối trong manifest.
def relative(path: Path) -> str:
    return str(path.relative_to(ROOT)).replace("\\", "/")


# Kiểm tra checksum/schema của candidate artifact.
def verify_candidate(directory: Path) -> dict[str, str]:
    expected: dict[str, str] = {}
    checksums_path = directory / "CHECKSUMS.sha256"
    for line in checksums_path.read_text(encoding="ascii").splitlines():
        checksum, name = line.split("  ", 1)
        target = directory / name
        if not target.is_file():
            raise FileNotFoundError(f"candidate checksum target is missing: {target}")
        actual = sha256(target)
        if actual != checksum:
            raise ValueError(f"candidate checksum mismatch: {target}")
        expected[name] = checksum
    return expected


# Kiểm tra manifest và checksum dataset.
def verify_dataset(manifest_path: Path) -> dict[str, object]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    verified = {}
    for key, path_text in manifest["outputs"].items():
        target = ROOT / path_text
        actual = sha256(target)
        expected = manifest["sha256"][key]
        if actual != expected:
            raise ValueError(f"dataset checksum mismatch: {target}")
        verified[key] = {"path": path_text, "sha256": actual, "bytes": target.stat().st_size}
    return {
        "manifest_path": relative(manifest_path),
        "manifest_sha256": sha256(manifest_path),
        "collection_id": manifest["collection_id"],
        "counts": manifest["counts"],
        "outputs": verified,
    }


# Đọc tham số CLI và chạy đóng băng artifact của freeze_current_evidence.
def main() -> None:
    if OUTPUT.exists():
        raise FileExistsError(f"refusing to overwrite frozen evidence: {OUTPUT}")
    runtime_hash = sha256(RUNTIME_MODEL)
    routes = {}
    all_source_paths = set(SHARED_SOURCE)

    for route, config in CANDIDATES.items():
        directory = ROOT / config["directory"]
        package_hashes = verify_candidate(directory)
        evaluation_path = directory / "evaluation.json"
        candidate_manifest_path = directory / "manifest.json"
        evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
        candidate_manifest = json.loads(candidate_manifest_path.read_text(encoding="utf-8"))
        metric = evaluation["metrics"]["if_only"]
        if float(metric["recall"]) < 0.90 or float(metric["false_positive_rate"]) > 0.02:
            raise ValueError(f"{route} does not satisfy the declared freeze gate")
        if not evaluation.get("runtime_model_unchanged"):
            raise ValueError(f"{route} evaluation did not preserve the runtime model")
        if candidate_manifest.get("runtime_model_sha256") != runtime_hash:
            raise ValueError(f"{route} records a different runtime model hash")
        audit_path = ROOT / config["audit"]
        dataset = verify_dataset(ROOT / config["dataset_manifest"])
        source_paths = tuple(config["source"])
        all_source_paths.update(source_paths)
        routes[route] = {
            "candidate_id": evaluation["candidate_id"],
            "candidate_directory": config["directory"],
            "status": "evidence_frozen_not_promoted",
            "candidate_only": True,
            "automatic_promotion": False,
            "evaluation_policy": evaluation["evaluation_policy"],
            "metrics": {
                "tp": metric["tp"], "fp": metric["fp"],
                "tn": metric["tn"], "fn": metric["fn"],
                "precision": metric["precision"], "recall": metric["recall"],
                "f1": metric["f1"], "false_positive_rate": metric["false_positive_rate"],
                "false_discovery_rate": metric.get("false_discovery_rate", metric["fp"] / max(1, metric["tp"] + metric["fp"])),
            },
            "contribution": evaluation["contribution"],
            "acceptance": evaluation["acceptance"],
            "package": {
                "checksums_file_sha256": sha256(directory / "CHECKSUMS.sha256"),
                "verified_file_count": len(package_hashes),
                "files": package_hashes,
            },
            "dataset": dataset,
            "audit": {"path": config["audit"], "sha256": sha256(audit_path)},
            "source_paths": list(source_paths),
        }

    source_hashes = {}
    for path_text in sorted(all_source_paths):
        path = ROOT / path_text
        if not path.is_file():
            raise FileNotFoundError(f"freeze source is missing: {path}")
        source_hashes[path_text] = sha256(path)

    freeze = {
        "schema_version": "wcp-route-if-evidence-freeze-v1",
        "freeze_id": "route-if-evidence-freeze-v1",
        "frozen_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "frozen_not_promoted",
        "policy": {
            "test_sets_opened": True,
            "further_retuning_on_frozen_test_forbidden": True,
            "new_blind_test_required_for_new_claims": True,
            "automatic_runtime_promotion": False,
            "integrity_mechanism": "SHA-256 manifest; logical freeze, not OS-level immutable storage",
        },
        "runtime_model": {"path": relative(RUNTIME_MODEL), "sha256": runtime_hash, "changed": False},
        "routes": routes,
        "source_sha256": source_hashes,
    }

    OUTPUT.mkdir(parents=True)
    manifest_path = OUTPUT / "freeze_manifest.json"
    manifest_path.write_text(json.dumps(freeze, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    readme_path = OUTPUT / "README.md"
    rows = []
    for route, evidence in routes.items():
        metric = evidence["metrics"]
        rows.append(
            f"| {route} | `{evidence['candidate_id']}` | {metric['recall']:.1%} | "
            f"{metric['false_positive_rate']:.1%} | {evidence['contribution']['if_unique_tp']} |"
        )
    readme_path.write_text(
        "# Frozen route-aware IF evidence v1\n\n"
        "This directory seals the four evaluated candidates using SHA-256. "
        "The freeze is logical and tamper-evident; it does not promote or replace the runtime model.\n\n"
        "| Route | Candidate | IF recall | IF FPR | IF-only unique TP |\n"
        "| --- | --- | ---: | ---: | ---: |\n" + "\n".join(rows) + "\n\n"
        "The opened test sets are frozen. Any new model/feature/threshold claim requires a new candidate "
        "and a new blind test collection.\n",
        encoding="utf-8",
    )
    checksum_path = OUTPUT / "CHECKSUMS.sha256"
    checksum_path.write_text(
        f"{sha256(manifest_path)}  {manifest_path.name}\n{sha256(readme_path)}  {readme_path.name}\n",
        encoding="ascii",
    )
    print(json.dumps({
        "freeze_id": freeze["freeze_id"], "output": relative(OUTPUT),
        "routes": list(routes), "runtime_model_sha256": runtime_hash,
        "manifest_sha256": sha256(manifest_path),
    }, indent=2))


if __name__ == "__main__":
    main()
