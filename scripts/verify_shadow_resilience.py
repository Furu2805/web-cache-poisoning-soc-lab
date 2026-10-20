"""Exercise detector outage recovery and rolling-request behavior."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

URL = "http://127.0.0.1:8090/labs/query/?cb=resilience&page=1&view=grid"


# Gửi một request kiểm tra khi Shadow thay đổi trạng thái.
def request_once(index):
    started = time.perf_counter()
    try:
        request = urllib.request.Request(f"{URL}&run={index}", headers={"User-Agent": "section10-resilience/1"})
        with urllib.request.urlopen(request, timeout=5) as response:
            response.read()
            return {"ok": response.status == 200, "status": response.status,
                    "cache_status": response.headers.get("X-Cache-Status"),
                    "decision": response.headers.get("X-Fusion-Detector-Decision"),
                    "latency_ms": (time.perf_counter() - started) * 1000}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__, "latency_ms": (time.perf_counter() - started) * 1000}


# Gọi Docker Compose để điều khiển service Shadow.
def compose(*args):
    subprocess.run(["docker", "compose", *args], check=True, capture_output=True, text=True)


# Chờ các dependency sẵn sàng.
def wait_healthy(timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(["docker", "inspect", "--format={{.State.Health.Status}}", "web-cache-ai-lab-detector-1"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip() == "healthy":
            return True
        time.sleep(.5)
    return False


# Kiểm tra request/cache khi Shadow dừng hoặc restart.
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    compose("stop", "detector")
    unavailable = request_once(0)
    compose("up", "-d", "detector")
    recovered_health = wait_healthy()
    recovered = request_once(1)

    rows = []
    # Gửi tải kiểm tra trong một phase resilience.
    def load():
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for row in pool.map(request_once, range(1000, 1200)):
                rows.append(row)
    thread = threading.Thread(target=load)
    thread.start()
    time.sleep(.5)
    compose("restart", "detector")
    thread.join()
    reload_health = wait_healthy()
    report = {
        "schema_version": "section10-resilience-v1",
        "outage": unavailable,
        "recovery": {"healthy": recovered_health, "request": recovered},
        "reload_under_load": {
            "requests": len(rows), "success_count": sum(row["ok"] for row in rows),
            "error_count": sum(not row["ok"] for row in rows),
            "error_rate": sum(not row["ok"] for row in rows) / len(rows),
            "cache_status_counts": {key: sum(row.get("cache_status") == key for row in rows) for key in ("HIT", "MISS", "EXPIRED", "BYPASS", None)},
            "healthy_after": reload_health,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
