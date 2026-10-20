"""Dry-run or archive old closed SOC cases before local retention pruning."""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, default=Path("data/reports"))
    parser.add_argument("--archive-dir", type=Path, default=Path("data/backups"))
    parser.add_argument("--retention-days", type=int, default=90)
    parser.add_argument("--apply", action="store_true", help="Archive and remove eligible closed case files.")
    args = parser.parse_args()
    if args.retention_days < 1:
        parser.error("--retention-days must be positive")

    cutoff = datetime.now(timezone.utc) - timedelta(days=args.retention_days)
    candidates = []
    for path in args.reports.glob("INC-*.json"):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            case = report.get("case", {})
            updated = datetime.fromisoformat(str(case.get("updated_at", "")).replace("Z", "+00:00"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if case.get("status") not in {"resolved", "false_positive"} or updated >= cutoff:
            continue
        candidates.append((path, report))

    result = {"mode": "apply" if args.apply else "dry-run", "cutoff": cutoff.isoformat(),
              "eligible_closed_cases": [path.stem for path, _ in candidates], "audit_logs_retained": True}
    if not args.apply or not candidates:
        print(json.dumps(result, indent=2))
        return

    args.archive_dir.mkdir(parents=True, exist_ok=True)
    archive = args.archive_dir / f"soc-retention-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.zip"
    manifest = {"schema": "fusion-soc-retention-archive-v1", "created_at": datetime.now(timezone.utc).isoformat(), "files": {}}
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path, _ in candidates:
            payload = path.read_bytes()
            name = f"reports/{path.name}"
            bundle.writestr(name, payload)
            manifest["files"][name] = {"size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        bundle.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    for path, _ in candidates:
        path.unlink()
    result.update({"archive": str(archive), "archived_count": len(candidates), "removed_after_archive": True})
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
