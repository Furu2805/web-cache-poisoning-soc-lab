"""Linux integration runner using a real Nginx binary, without Docker.

Use --nginx /path/to/nginx. Requires ngx_http_auth_request_module.
This changes only local test paths, upstream addresses, and process settings.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import httpx

from traffic.scenarios import base_headers, base_url, attack_case, verify_case


def wait(url):
    for _ in range(100):
        try:
            r=httpx.get(url,timeout=.5,trust_env=False)
            if r.status_code==200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(.1)
    raise RuntimeError("Service not ready: "+url)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--nginx",required=True)
    p.add_argument("--quick",action="store_true")
    a=p.parse_args()
    os.chdir(ROOT)
    os.environ["LAB_HOST"]="127.0.0.1"
    runtime=ROOT/".runtime"
    runtime.mkdir(exist_ok=True)
    for name in ["cache","logs","client_body_temp","proxy_temp","fastcgi_temp","uwsgi_temp","scgi_temp"]:
        (runtime/name).mkdir(exist_ok=True)
    configs={f.name:f.read_text() for f in (ROOT/"nginx").glob("*.conf")}
    for name,text in configs.items():
        if name == "nginx.conf" and os.getuid() == 0:
            # Local single-process check: use the current filesystem owner.
            # Docker keeps its standard unprivileged nginx worker configuration.
            text = "user root;\n" + text
        text=text.replace("include /etc/nginx/mime.types;", "")
        text=text.replace("/etc/nginx/lab/",str(runtime)+"/")
        text=text.replace("/usr/share/nginx/html", str(ROOT / "frontend"))
        text=text.replace("backend:8000","127.0.0.1:8000").replace("detector:8001","127.0.0.1:8001")
        text=text.replace("/var/cache/nginx/lab",str(runtime/"cache")).replace("/tmp/nginx.pid",str(runtime/"nginx.pid"))
        text=text.replace("listen 808","listen 127.0.0.1:808")
        (runtime/name).write_text(text)
    cmd=[a.nginx,"-p",str(runtime)+"/","-c",str(runtime/"nginx.conf")]
    subprocess.run(cmd+["-t"],check=True)
    processes=[]
    logs=[]

    def start(name,command):
        log=(runtime/f"{name}.log").open("w")
        logs.append(log)
        proc=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
        processes.append(proc)
        return proc

    def detector():
        return start("detector",[sys.executable,"-m","uvicorn","detector.app:app","--host","127.0.0.1","--port","8001"])

    checks=[]
    try:
        start("backend",[sys.executable,"-m","uvicorn","backend.app:app","--host","127.0.0.1","--port","8000"])
        det=detector()
        wait("http://127.0.0.1:8000/health");wait("http://127.0.0.1:8001/health")
        start("nginx",cmd+["-g","daemon off; master_process off;"])
        wait(base_url("none")+"/health")
        with httpx.Client(timeout=10,trust_env=False) as c:
            page = c.get(base_url("none") + "/")
            css = c.get(base_url("none") + "/assets/styles.css")
            phase1_css = c.get(base_url("none") + "/assets/phase1.css")
            health = c.get(base_url("none") + "/_ui_health")
            assert page.status_code == 200 and "CacheShield Lab" in page.text
            assert css.status_code == 200 and "--accent" in css.text
            assert phase1_css.status_code == 200 and ".cache-inspector" in phase1_css.text
            assert health.status_code == 200
            checks.append("Phase-1 website UI, Cache Inspector and detector health endpoint")
            # Cacheable website content: MISS -> HIT -> explicit BYPASS.
            content_url = base_url("none") + "/api/home?lab_session=" + uuid.uuid4().hex
            first = c.get(content_url, headers={"X-Lab-Client": "A"})
            second = c.get(content_url, headers={"X-Lab-Client": "B"})
            bypass = c.get(content_url, headers={"X-Lab-Client": "A", "X-Lab-Bypass": "1"})
            assert first.headers["x-cache-status"] == "MISS"
            assert second.headers["x-cache-status"] == "HIT"
            assert bypass.headers["x-cache-status"] == "BYPASS"
            assert first.headers.get("x-request-id") and second.headers.get("x-request-id")
            checks.append("Website content MISS/HIT/BYPASS and request correlation ID")
            # Correct cache behavior and real Vary handling.
            url=base_url("none")+"/lab/query?id="+uuid.uuid4().hex
            assert c.get(url,headers=base_headers()).headers["x-cache-status"]=="MISS"
            assert c.get(url,headers=base_headers()).headers["x-cache-status"]=="HIT"
            headers=base_headers();headers["Accept-Language"]="en"
            assert c.get(url,headers=headers).headers["x-cache-status"]=="MISS"
            checks.append("MISS/HIT and Vary isolation")
            case=attack_case("xfh")
            case["headers"]["X-Lab-Mode"]="none"
            assert verify_case(c,"rule",case)["attack_cache"]=="BYPASS"
            checks.append("Client cannot override defense mode")
            if not c.get("http://127.0.0.1:8001/health").json()["model_ready"]:
                assert verify_case(c,"ml",attack_case("query"))["attack_cache"]=="BYPASS"
                checks.append("Missing model bypasses cache")
        from traffic.collect import collect
        from ml.train import train
        from ml.evaluate import evaluate
        collect(120 if a.quick else 2000,40 if a.quick else 400,3 if a.quick else 40)
        train();evaluate()
        det.terminate();det.wait(timeout=10)
        det=detector();wait("http://127.0.0.1:8001/health")
        from traffic.experiments import experiments
        from traffic.benchmark import benchmark
        experiments(2 if a.quick else 5)
        checks.append("Four poisoning scenarios; five defense modes; real victim cache retrieval")
        benchmark(30 if a.quick else 200,1 if a.quick else 3)
        # Loss of detector transport: keep origin reachable, prohibit cache storage.
        det.terminate();det.wait(timeout=10)
        failed_case=attack_case("xfh")
        with httpx.Client(timeout=10,trust_env=False) as c:
            row=verify_case(c,"rule",failed_case)
            assert row["decision"]=="detector-unavailable" and not row["victim_received_marker"]
            assert row["attack_cache"]=="BYPASS"
        det=detector();wait("http://127.0.0.1:8001/health")
        with httpx.Client(timeout=10,trust_env=False) as c:
            clean=c.get(base_url("rule")+failed_case["victim_uri"],headers=base_headers())
            assert clean.headers["x-cache-status"]=="MISS"
            assert clean.json()["value"]!=failed_case["marker"]
        checks.append("Detector transport failure bypasses cache without storing response")
        result={"status":"passed","checks":checks,"quick":a.quick,
                "runtime":"native real Nginx; Docker Compose not exercised by this runner"}
        (ROOT/"results/integration_verification.json").write_text(json.dumps(result,indent=2))
        print(json.dumps(result,indent=2))
    finally:
        for proc in reversed(processes):
            if proc.poll() is None:
                proc.terminate()
                try:proc.wait(timeout=10)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
        for log in logs:log.close()


if __name__=="__main__":
    main()
