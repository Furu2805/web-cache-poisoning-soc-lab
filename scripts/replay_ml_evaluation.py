"""Regenerate local ML datasets and replay the frozen candidate evaluation."""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
COLLECTORS = (
    "ml-detector/src/collect_xfh_candidate_v3.py",
    "ml-detector/src/collect_query_candidate_v8.py",
    "ml-detector/src/collect_utm_dataset.py",
    "ml-detector/src/collect_fatget_candidate_v2.py",
)
BLIND_COLLECTORS = (
    "ml-detector/src/run_blind_test_v1.py",
    "ml-detector/src/run_xfh_v3_blind_v2.py",
    "ml-detector/src/run_query_v8_blind.py",
    "ml-detector/src/run_fatget_v2_blind_v2.py",
)
GENERATED_PATHS = (
    "ml-detector/data/raw/xfh_v3",
    "ml-detector/data/processed/xfh_v3",
    "ml-detector/data/manifests/xfh_v3",
    "ml-detector/artifacts/candidates/xfh_v3_feature_profile.json",
    "ml-detector/data/raw/query_v8",
    "ml-detector/data/processed/query_v8",
    "ml-detector/data/manifests/query_v8",
    "ml-detector/data/raw/query_v8/requests.jsonl",
    "ml-detector/data/processed/query_v8/feature_records.jsonl",
    "ml-detector/data/manifests/query_v8/dataset_manifest.json",
    "ml-detector/artifacts/candidates/query_v8_feature_profile.json",
    "ml-detector/data/raw/utm",
    "ml-detector/data/processed/utm",
    "ml-detector/data/manifests/utm",
    "ml-detector/data/raw/utm/requests.jsonl",
    "ml-detector/data/processed/utm/feature_records.jsonl",
    "ml-detector/data/manifests/utm/dataset_manifest.json",
    "ml-detector/artifacts/candidates/utm_feature_profile.json",
    "ml-detector/data/raw/fatget_v2",
    "ml-detector/data/processed/fatget_v2",
    "ml-detector/data/manifests/fatget_v2",
    "ml-detector/data/raw/fatget_v2/requests.jsonl",
    "ml-detector/data/processed/fatget_v2/feature_records.jsonl",
    "ml-detector/data/manifests/fatget_v2/dataset_manifest.json",
    "ml-detector/artifacts/candidates/fatget_v2_feature_profile.json",
)
BLIND_PATHS = (
    "ml-detector/data/blind/blind_v1",
    "ml-detector/artifacts/blind_test_v1",
    "ml-detector/data/blind/xfh_blind_v2",
    "ml-detector/artifacts/xfh_blind_test_v2",
    "ml-detector/data/blind/query_v8_blind_v1",
    "ml-detector/artifacts/query_v8_blind_v1",
    "ml-detector/data/blind/fatget_blind_v2",
    "ml-detector/artifacts/fatget_blind_test_v2",
)


def _run(script: str) -> None:
    print(f"\n>>> {script}", flush=True)
    subprocess.run([sys.executable, script], cwd=ROOT, check=True)


def _require_local_lab() -> None:
    try:
        with urlopen("http://127.0.0.1:8086/", timeout=3):
            pass
    except HTTPError:
        # Any HTTP response confirms a listener is available; route-specific
        # status checks are performed by each collector.
        return
    except URLError as exc:
        raise SystemExit(
            "Local Fusion lab is not reachable on http://127.0.0.1:8086. "
            "Start it with `docker compose up -d --build`, then retry."
        ) from exc


def _require_empty(paths: tuple[str, ...], label: str) -> None:
    present = [path for path in paths if (ROOT / path).exists()]
    if present:
        listing = "\n  ".join(present)
        raise SystemExit(
            f"Refusing to overwrite existing {label}. Move or archive these local files, "
            f"then retry:\n  {listing}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Optionally collect fresh synthetic datasets, then score frozen route candidates",
    )
    parser.add_argument("--collect", action="store_true", help="collect fixed-seed development datasets")
    parser.add_argument("--blind", action="store_true", help="collect independent blind variant holdouts")
    parser.add_argument("--json-output", type=Path, default=Path("results/ml-detector/evaluation.json"))
    parser.add_argument("--markdown-output", type=Path, default=Path("results/ml-detector/evaluation.md"))
    args = parser.parse_args()

    if args.collect or args.blind:
        _require_local_lab()
    if args.collect:
        _require_empty(GENERATED_PATHS, "development datasets")
        for script in COLLECTORS:
            _run(script)
    if args.blind:
        _require_empty(BLIND_PATHS, "blind holdouts")
        for script in BLIND_COLLECTORS:
            _run(script)

    json_output = args.json_output if args.json_output.is_absolute() else ROOT / args.json_output
    markdown_output = args.markdown_output if args.markdown_output.is_absolute() else ROOT / args.markdown_output
    print("\n>>> ml-detector/src/evaluate_portfolio.py", flush=True)
    # The evaluator is read-only with respect to data and candidate packages.
    subprocess.run(
        [
            sys.executable,
            "ml-detector/src/evaluate_portfolio.py",
            "--json-output", str(json_output),
            "--markdown-output", str(markdown_output),
        ],
        cwd=ROOT,
        check=True,
    )


if __name__ == "__main__":
    main()
