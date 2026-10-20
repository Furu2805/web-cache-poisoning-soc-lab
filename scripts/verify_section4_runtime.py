"""Live Docker-network smoke test for the centralized ML shadow queue."""
import json
import time
import urllib.request

BASE = "http://ml-shadow:8003"
PATHS = {
    "query": "/labs/query/?page=1&view=grid",
    "xfh": "/labs/xfh/shop",
    "utm": "/labs/utm/js/geolocate.js?callback=ready",
    "fatget": "/labs/fatget/js/geolocate.js?callback=ready",
}


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=3) as response:
        return json.load(response)


request_ids = []
for route in PATHS:
    for index in range(4):
        request_id = f"section4-live-{route}-{index}"
        request_ids.append(request_id)
        body = json.dumps({
            "request_id": request_id,
            "route": route,
            "metadata": {"method": "GET", "uri": PATHS[route], "host": "fusion.local:8090"},
        }).encode()
        request = urllib.request.Request(
            BASE + "/internal/v1/shadow/events", data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            if response.status != 202:
                raise RuntimeError(f"unexpected ingestion status: {response.status}")

deadline = time.monotonic() + 10
results = {}
while time.monotonic() < deadline and len(results) < len(request_ids):
    for request_id in request_ids:
        if request_id in results:
            continue
        item = get(f"/internal/v1/shadow/results/{request_id}")
        if item["status"] != "accepted":
            results[request_id] = item
    time.sleep(0.02)

if len(results) != len(request_ids) or any(row["status"] != "completed" for row in results.values()):
    raise SystemExit("not all shadow jobs completed")

report = {
    "submitted": len(request_ids),
    "completed": len(results),
    "fallbacks": sum(row.get("fallback_reason") is not None for row in results.values()),
    "routes": sorted({row["route"] for row in results.values()}),
    "batch_sizes": sorted({row["batch_size"] for row in results.values()}),
    "max_queue_wait_ms": max(row["queue_wait_ms"] for row in results.values()),
    "max_inference_ms": max(row["inference_ms"] for row in results.values()),
    "max_shadow_latency_ms": max(row["shadow_latency_ms"] for row in results.values()),
    "health": get("/health"),
}
print(json.dumps(report, indent=2))
