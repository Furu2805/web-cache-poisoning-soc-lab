"""Prove the four intentional local cache-poisoning flaws on detector-off :8086.

This verifier never writes a request body, raw query value, response body, or
cache key to disk. Those values are inspected only in memory to establish that a
separate clean client receives the attacker-selected marker from shared cache.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

from traffic.fusion_e2e_demo import clean_follow_up, send_request
from traffic.fusion_scenarios import LABS, attack_case

ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
PORT = 8086
USER_AGENT = "Mozilla/5.0 local-cache-poisoning-verifier"
LANGUAGE = "vi-VN,vi;q=0.9"


# Tính fingerprint của cache key dự kiến cho một lab.
def cache_basis(lab: str, uri: str, headers: dict[str, str]) -> str:
    """Mirror only the intentional local cache-key omission, without logging it."""
    parsed = urlsplit(uri)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if lab == "xfh":
        return f"http|{headers['Host']}|{uri}"
    if lab in {"query", "utm"}:
        retained = [(key, value) for key, value in pairs if key != "utm_content"]
        return f"http|{headers['Host']}|{parsed.path}?{urlencode(retained)}"
    if lab == "fatget":
        callback = next((value for key, value in pairs if key == "callback"), "")
        return f"http|{headers['Host']}|{parsed.path}|callback={callback}"
    raise ValueError(f"unsupported lab: {lab}")


# Tạo lại proxy container để xóa cache local trước proof.
def reset_proxy_cache() -> None:
    """Recreate only the local proxy to obtain a fresh isolated cache run."""
    subprocess.run(
        ["docker", "compose", "up", "-d", "--force-recreate", "--no-deps", "proxy"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            probe = send_request(HOST, PORT, "GET", "/labs/query/?cb=cache-ready&page=1&view=grid", {
                "Host": "127.0.0.1:8086", "User-Agent": "cache-ready", "Accept": "*/*",
                "Accept-Language": "en",
            }, "")
            if probe["status"] == 200:
                return
        except OSError:
            pass
        time.sleep(.5)
    raise RuntimeError("proxy did not become ready after cache reset")


# Rút gọn response và marker thành evidence.
def compact(response: dict[str, object], marker_observed: bool) -> dict[str, object]:
    return {key: response[key] for key in ("status", "request_id", "cache_status", "latency_ms")} | {
        "marker_observed": marker_observed,
    }


# Chạy cặp attacker/victim và xác nhận điều kiện poisoning.
def verify(lab: str) -> dict[str, object]:
    reset_proxy_cache()
    token = uuid.uuid4().hex[:24]
    attack = attack_case(lab, token, USER_AGENT, LANGUAGE)
    clean_uri, clean_headers, clean_body, marker = clean_follow_up(attack)
    victim_headers = dict(clean_headers)
    victim_headers["User-Agent"] = "Victim Browser / clean shared-cache retrieval"
    victim_headers["Accept-Language"] = "en-US,en;q=0.8"
    attack_basis = cache_basis(lab, attack.uri, attack.headers)
    victim_basis = cache_basis(lab, clean_uri, victim_headers)
    attacker = send_request(HOST, PORT, attack.method, attack.uri, attack.headers, attack.body)
    victim = send_request(HOST, PORT, attack.method, clean_uri, victim_headers, clean_body)
    attack_marker = marker in str(attacker["_body"])
    victim_marker = marker in str(victim["_body"])
    assertions = {
        "attacker_http_200": attacker["status"] == 200,
        "victim_http_200": victim["status"] == 200,
        "cache_key_equivalent": attack_basis == victim_basis,
        "attacker_populated_cache": attacker["cache_status"] == "MISS",
        "victim_received_shared_cache_hit": victim["cache_status"] == "HIT",
        "marker_reached_attacker_response": attack_marker,
        "marker_exposed_to_distinct_clean_victim": victim_marker,
        "victim_identity_is_distinct": victim_headers["User-Agent"] != attack.headers["User-Agent"],
        "detector_off": attacker["detector_mode"] == "off" and victim["detector_mode"] == "off",
    }
    return {
        "schema": "fusion-cache-poisoning-proof-v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scope": "local-educational-docker-lab",
        "scenario": lab,
        "mode": "detector-off",
        "cache_key_fingerprint": hashlib.sha256(attack_basis.encode("utf-8")).hexdigest(),
        "attacker": compact(attacker, attack_marker),
        "clean_victim": compact(victim, victim_marker),
        "assertions": assertions,
        "passed": all(assertions.values()),
        "redaction": {
            "raw_uri_stored": False, "raw_request_headers_stored": False,
            "raw_request_body_stored": False, "raw_response_body_stored": False,
            "raw_cache_key_stored": False,
        },
    }


# Đọc CLI và chạy xác minh cache poisoning.
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=LABS, action="append")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    scenarios = args.scenario or list(LABS)
    rows = [verify(lab) for lab in scenarios]
    report = {
        "schema": "fusion-cache-poisoning-proof-suite-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "local-educational-docker-lab",
        "results": rows,
        "passed": all(row["passed"] for row in rows),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"scenarios": scenarios, "passed": report["passed"]}, ensure_ascii=False))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
