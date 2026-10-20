import os
import uuid
from urllib.parse import quote

PORTS = {"none": 8080, "rule": 8081, "ml": 8082, "hybrid": 8083, "hardened": 8084, "observe": 8085}
SCENARIOS = ("xfh", "query", "cloaking", "fatget")


def base_url(mode):
    return f"http://{os.getenv('LAB_HOST', '127.0.0.1')}:{PORTS[mode]}"


def base_headers():
    return {"Host": "lab.test", "User-Agent": "Mozilla/5.0 LabBrowser/1.0",
            "Accept": "application/json", "Accept-Language": "vi"}


def attack_case(scenario, variant="plain"):
    token = uuid.uuid4().hex
    marker = "POISON_" + token
    encoded = quote(marker)
    if variant == "encoded":
        encoded = "%50" + marker[1:]
    headers = base_headers()
    uri = f"/lab/{scenario}?id={token}"
    victim_uri = uri
    body = ""
    if scenario == "xfh":
        marker = "poison-" + token + ".test"
        headers["X-Forwarded-Host"] = marker
        if variant == "encoded":
            headers["X-Forwarded-Proto"] = "https"
    elif scenario == "query":
        uri += "&message=" + encoded
    elif scenario == "cloaking":
        uri += "&utm_content=campaign;message=" + encoded
        victim_uri += "&utm_content=campaign"
    elif scenario == "fatget":
        body = "message=" + encoded
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        raise ValueError(scenario)
    return {"scenario": scenario, "variant": variant, "method": "GET", "uri": uri,
            "headers": headers, "body": body, "victim_uri": victim_uri, "marker": marker}


def send(client, mode, case, record_id=None):
    headers = dict(case["headers"])
    if record_id:
        headers["X-Lab-Record-ID"] = record_id
    return client.request(case.get("method", "GET"), base_url(mode) + case["uri"],
                          headers=headers, content=case.get("body", ""))


def verify_case(client, mode, case):
    """Unique key per case. Victim uses a separate cookie-free connection pool."""
    import httpx
    attack = send(client, mode, case)
    attack.raise_for_status()
    with httpx.Client(timeout=10, trust_env=False) as victim:
        first = victim.get(base_url(mode) + case["victim_uri"], headers=base_headers())
        second = victim.get(base_url(mode) + case["victim_uri"], headers=base_headers())
    first.raise_for_status()
    second.raise_for_status()
    body = second.json()
    return {
        "scenario": case["scenario"], "variant": case["variant"], "mode": mode,
        "attack_cache": attack.headers.get("x-cache-status", ""),
        "victim_first_cache": first.headers.get("x-cache-status", ""),
        "victim_cache": second.headers.get("x-cache-status", ""),
        "decision": attack.headers.get("x-decision", ""),
        "score": attack.headers.get("x-anomaly-score", ""),
        "victim_received_marker": body.get("value") == case["marker"],
        "poisoning_success": body.get("value") == case["marker"] and second.headers.get("x-cache-status") == "HIT",
        "same_origin_response": body.get("origin_request_id") == attack.json().get("origin_request_id"),
        "attack": {"method": case["method"], "uri": case["uri"], "headers": case["headers"], "body": case["body"]},
        "attack_response": {"status": attack.status_code, "headers": dict(attack.headers), "body": attack.json()},
        "victim_response": {"status": second.status_code, "headers": dict(second.headers), "body": body},
    }
