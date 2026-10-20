"""Seal the XFH-v3 candidate before collecting independent blind-v2 data."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "ml-detector/artifacts/candidates/xfh_phase1_v3"
DATASET = ROOT / "ml-detector/data/manifests/xfh_v3/dataset_manifest.json"
OUTPUT = ROOT / "ml-detector/artifacts/xfh_v3_freeze"
RUNTIME = ROOT / "models/isolation_forest.joblib"
SOURCES = (
    "ml-detector/src/xfh_features.py",
    "ml-detector/src/collect_xfh_dataset.py",
    "ml-detector/src/collect_xfh_candidate_v3.py",
    "ml-detector/src/train_evaluate_xfh_v3.py",
    "common/features.py",
    "traffic/fusion_collect.py",
    "traffic/fusion_scenarios.py",
    "ml-detector/config/route_registry.json",
)


# Tính checksum artifact XFH v3.
def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# Đổi đường dẫn thành dạng tương đối cho manifest.
def rel(path: Path) -> str:
    return str(path.relative_to(ROOT)).replace("\\", "/")


# Đóng băng artifact, schema, profile và checksum XFH v3.
def main() -> None:
    if OUTPUT.exists():
        raise FileExistsError(f"refusing to overwrite freeze: {OUTPUT}")
    files: dict[str, str] = {}
    for line in (CANDIDATE / "CHECKSUMS.sha256").read_text(encoding="ascii").splitlines():
        expected, name = line.split("  ", 1)
        if sha256(CANDIDATE / name) != expected:
            raise ValueError(f"candidate checksum mismatch: {name}")
        files[name] = expected
    evaluation = json.loads((CANDIDATE / "evaluation.json").read_text(encoding="utf-8"))
    metric = evaluation["metrics"]["if_only"]
    if metric["recall"] < .90 or metric["false_positive_rate"] > .02 or metric["false_discovery_rate"] >= .02:
        raise ValueError("candidate does not satisfy development gate")
    if evaluation["contribution"]["if_unique_tp"] != 0:
        raise ValueError("unexpected XFH contribution semantics")
    dataset = json.loads(DATASET.read_text(encoding="utf-8"))
    for key, path_text in dataset["outputs"].items():
        if sha256(ROOT / path_text) != dataset["sha256"][key]:
            raise ValueError(f"dataset checksum mismatch: {key}")
    freeze = {
        "schema_version": "wcp-xfh-v3-freeze-v1",
        "freeze_id": "xfh-v3-pre-blind-v2-freeze",
        "frozen_at_utc": datetime.now(timezone.utc).isoformat(),
        "candidate_id": evaluation["candidate_id"],
        "candidate_directory": rel(CANDIDATE),
        "candidate_package": {"checksums_sha256": sha256(CANDIDATE / "CHECKSUMS.sha256"), "files": files},
        "dataset_manifest": {"path": rel(DATASET), "sha256": sha256(DATASET)},
        "source_sha256": {name: sha256(ROOT / name) for name in SOURCES},
        "runtime_model": {"path": rel(RUNTIME), "sha256": sha256(RUNTIME), "changed": False},
        "policy": {
            "candidate_locked_before_blind": True,
            "fit_or_calibration_in_blind_forbidden": True,
            "retuning_on_blind_forbidden": True,
            "profile_is_primary_xfh_guard": True,
            "if_mode_if_blind_passes": "shadow_monitoring_only",
            "automatic_runtime_promotion": False,
        },
    }
    OUTPUT.mkdir(parents=True)
    manifest = OUTPUT / "freeze_manifest.json"
    manifest.write_text(json.dumps(freeze, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    readme = OUTPUT / "README.md"
    readme.write_text("# XFH v3 pre-blind-v2 freeze\n\nCandidate-only; runtime is unchanged.\n", encoding="utf-8")
    (OUTPUT / "CHECKSUMS.sha256").write_text(
        f"{sha256(manifest)}  freeze_manifest.json\n{sha256(readme)}  README.md\n", encoding="ascii"
    )
    print(json.dumps({"freeze_id": freeze["freeze_id"], "manifest_sha256": sha256(manifest)}, indent=2))


if __name__ == "__main__":
    main()
