"""Create a checksum-manifested local backup of SOC case and audit data."""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path


SOC_EVENT_FILES = (
    "case-audit-events.jsonl",
    "case-pipeline-events.jsonl",
    "incident-report-events.jsonl",
    "triage-events.jsonl",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, default=Path("data/reports"))
    parser.add_argument("--events", type=Path, default=Path("data/events"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/backups"))
    parser.add_argument("--name", help="Optional archive stem; defaults to a UTC timestamp.")
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive = args.output_dir / f"{args.name or 'soc-backup-' + stamp}.zip"
    entries = {}
    for path in sorted(args.reports.glob("INC-*.json")):
        if path.is_file():
            entries[f"reports/{path.name}"] = path
    for name in SOC_EVENT_FILES:
        path = args.events / name
        if path.is_file():
            entries[f"events/{name}"] = path
    manifest = {
        "schema": "fusion-soc-backup-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": {},
    }
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for archive_name, path in entries.items():
            content = path.read_bytes()
            bundle.writestr(archive_name, content)
            manifest["files"][archive_name] = {"size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        bundle.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"archive": str(archive), "files": len(entries), "sha256_manifest": "manifest.json"}, indent=2))


if __name__ == "__main__":
    main()
