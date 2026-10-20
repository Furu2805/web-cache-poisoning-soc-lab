"""Seal Query v5 candidate and its implementation before blind-v2."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "ml-detector/artifacts/candidates/query_phase2_v5"
DATASET_MANIFEST = ROOT / "ml-detector/data/manifests/query_v5/dataset_manifest.json"
OUTPUT = ROOT / "ml-detector/artifacts/query_v5_freeze"
RUNTIME_MODEL = ROOT / "models/isolation_forest.joblib"
SOURCE = (
    "ml-detector/src/query_generalized_features.py",
    "ml-detector/src/collect_query_candidate_v5.py",
    "ml-detector/src/train_evaluate_query_candidate_v5.py",
    "tests/test_query_generalized_features.py",
    "docs/BAO_CAO_QUERY_V5_CANDIDATE.md",
    "common/features.py",
    "traffic/fusion_collect.py",
    "traffic/fusion_scenarios.py",
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
def rel(path: Path) -> str:
    return str(path.relative_to(ROOT)).replace("\\", "/")


# Đọc tham số CLI và chạy đóng băng artifact của freeze_query_candidate_v5.
def main() -> None:
    if OUTPUT.exists():
        raise FileExistsError(f"refusing to overwrite Query v5 freeze: {OUTPUT}")

    package_files: dict[str, str] = {}
    for line in (CANDIDATE / "CHECKSUMS.sha256").read_text(encoding="ascii").splitlines():
        expected, name = line.split("  ", 1)
        target = CANDIDATE / name
        if not target.is_file() or sha256(target) != expected:
            raise ValueError(f"candidate integrity failure: {name}")
        package_files[name] = expected

    evaluation = json.loads((CANDIDATE / "evaluation.json").read_text(encoding="utf-8"))
    manifest = json.loads((CANDIDATE / "manifest.json").read_text(encoding="utf-8"))
    dataset = json.loads(DATASET_MANIFEST.read_text(encoding="utf-8"))
    metric = evaluation["metrics"]["if_only"]
    if metric["recall"] < 0.90 or metric["false_positive_rate"] > 0.02:
        raise ValueError("Query v5 does not satisfy the development gate")
    if not evaluation["acceptance"]["eligible_for_blind_v2"]:
        raise ValueError("Query v5 is not marked eligible for blind-v2")
    if evaluation["acceptance"]["eligible_for_runtime_promotion"]:
        raise ValueError("candidate was incorrectly marked runtime-promotable")
    runtime_hash = sha256(RUNTIME_MODEL)
    if manifest["runtime_model_sha256"] != runtime_hash:
        raise ValueError("runtime model hash differs from candidate provenance")
    for key, path_text in dataset["outputs"].items():
        if sha256(ROOT / path_text) != dataset["sha256"][key]:
            raise ValueError(f"dataset integrity failure: {key}")

    source_hashes = {}
    for path_text in SOURCE:
        path = ROOT / path_text
        if not path.is_file():
            raise FileNotFoundError(path)
        source_hashes[path_text] = sha256(path)

    freeze = {
        "schema_version": "wcp-query-v5-freeze-v1",
        "freeze_id": "query-v5-pre-blind-v2-freeze",
        "frozen_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "frozen_candidate_not_promoted",
        "candidate_id": evaluation["candidate_id"],
        "candidate_directory": rel(CANDIDATE),
        "candidate_package": {
            "checksums_sha256": sha256(CANDIDATE / "CHECKSUMS.sha256"),
            "files": package_files,
        },
        "dataset_manifest": {"path": rel(DATASET_MANIFEST), "sha256": sha256(DATASET_MANIFEST)},
        "development_metrics": metric,
        "policy": {
            "candidate_locked_before_blind_collection": True,
            "blind_v1_used_for_training_or_calibration": False,
            "fit_or_calibration_during_blind_v2_forbidden": True,
            "retuning_on_blind_v2_forbidden": True,
            "automatic_runtime_promotion": False,
        },
        "runtime_model": {"path": rel(RUNTIME_MODEL), "sha256": runtime_hash, "changed": False},
        "source_sha256": source_hashes,
    }
    OUTPUT.mkdir(parents=True)
    manifest_path = OUTPUT / "freeze_manifest.json"
    manifest_path.write_text(json.dumps(freeze, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    readme = OUTPUT / "README.md"
    readme.write_text(
        "# Query v5 pre-blind-v2 freeze\n\n"
        "This SHA-256 manifest locks the candidate, dataset provenance and implementation before blind-v2. "
        "It does not promote or replace the runtime model. Blind-v2 results must not be used to retune this candidate.\n",
        encoding="utf-8",
    )
    (OUTPUT / "CHECKSUMS.sha256").write_text(
        f"{sha256(manifest_path)}  freeze_manifest.json\n{sha256(readme)}  README.md\n", encoding="ascii"
    )
    print(json.dumps({"freeze_id": freeze["freeze_id"], "manifest_sha256": sha256(manifest_path),
                      "runtime_model_sha256": runtime_hash}, indent=2))


if __name__ == "__main__":
    main()
