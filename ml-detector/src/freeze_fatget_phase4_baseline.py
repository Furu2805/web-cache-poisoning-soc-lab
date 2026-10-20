"""Seal the legacy Fat GET phase4 package as an immutable comparison baseline."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "ml-detector/artifacts/candidates/fatget_phase4"
BLIND = ROOT / "ml-detector/artifacts/blind_test_v1/evaluation.json"
OUTPUT = ROOT / "ml-detector/artifacts/fatget_phase4_baseline_freeze"
RUNTIME = ROOT / "models/isolation_forest.joblib"


# Tính checksum SHA-256 để ràng buộc dữ liệu hoặc artifact với evidence.
def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Đọc tham số CLI và chạy đóng băng artifact của freeze_fatget_phase4_baseline.
def main() -> None:
    if OUTPUT.exists(): raise FileExistsError(f"refusing to overwrite {OUTPUT}")
    files={}
    for line in (CANDIDATE/"CHECKSUMS.sha256").read_text(encoding="ascii").splitlines():
        expected,name=line.split("  ",1)
        if sha256(CANDIDATE/name)!=expected: raise ValueError(f"candidate checksum mismatch: {name}")
        files[name]=expected
    blind=json.loads(BLIND.read_text(encoding="utf-8"))["routes"]["fatget"]
    freeze={"schema_version":"fatget-phase4-baseline-freeze-v1","freeze_id":"fatget-phase4-legacy-baseline",
            "frozen_at_utc":datetime.now(timezone.utc).isoformat(),"candidate_directory":"ml-detector/artifacts/candidates/fatget_phase4",
            "candidate_package":{"checksums_sha256":sha256(CANDIDATE/"CHECKSUMS.sha256"),"files":files},
            "opened_blind_v1_summary":{"evaluation_sha256":sha256(BLIND),"metrics":blind["metrics"]["if_only"],
                                       "use_policy":"diagnosis only; forbidden for fit/calibration/threshold selection"},
            "runtime_model":{"path":"models/isolation_forest.joblib","sha256":sha256(RUNTIME),"changed":False},
            "status":"legacy_baseline_not_runtime_promoted"}
    OUTPUT.mkdir(parents=True); manifest=OUTPUT/"freeze_manifest.json"
    manifest.write_text(json.dumps(freeze,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    readme=OUTPUT/"README.md"; readme.write_text("# Fat GET phase4 legacy baseline\n\nImmutable comparison evidence; not a runtime artifact.\n",encoding="utf-8")
    (OUTPUT/"CHECKSUMS.sha256").write_text(f"{sha256(manifest)}  freeze_manifest.json\n{sha256(readme)}  README.md\n",encoding="ascii")
    print(json.dumps({"freeze_id":freeze["freeze_id"],"manifest_sha256":sha256(manifest)},indent=2))


if __name__=="__main__": main()
