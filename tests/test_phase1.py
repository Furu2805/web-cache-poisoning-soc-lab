import json
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]


def test_ml_shadow_dashboard_and_alerts_use_dedicated_loki_job():
    dashboard = json.loads((ROOT / "monitoring/grafana/dashboards/fusion-ml-shadow.json").read_text(encoding="utf-8"))
    titles = {panel["title"] for panel in dashboard["panels"]}
    assert {
        "Candidate coverage by route", "IF / profile / final anomaly rate by route",
        "Queue depth / queue lag / batch size", "Inference latency P50 / P95 / P99",
        "End-to-end shadow latency P50 / P95 / P99", "Fallback / error / overflow rate",
        "Registry / schema / checksum failures", "Queue overflows", "Fat GET — MONITOR CLOSELY",
    } <= titles
    expressions = [target["expr"] for panel in dashboard["panels"] for target in panel["targets"]]
    assert all('job="fusion-ml-shadow"' in expression for expression in expressions)
    alerts = (ROOT / "monitoring/grafana/provisioning/alerting/ml-shadow-alerts.yaml").read_text(encoding="utf-8")
    for uid in ["fusion-ml-queue-overflow", "fusion-ml-coverage-low", "fusion-ml-queue-lag-high"]:
        assert uid in alerts
    assert alerts.count('job="fusion-ml-shadow"') >= 5


def test_phase1_content_endpoints(tmp_path, monkeypatch):
    from backend import app as module

    monkeypatch.setattr(module, "DB", tmp_path / "backend.sqlite3")
    with TestClient(module.app) as client:
        root = client.get("/", headers={"X-Forwarded-Host": "attacker.example"})
        assert root.status_code == 200
        assert "CacheShield Lab" in root.text
        assert 'https://attacker.example/resources/js/tracking.js' in root.text
        assert root.headers["cache-control"] == "public, max-age=30"

        victim = client.post("/auth/login", content="email=victim%40cachelab.local&password=Victim%212026")
        assert victim.status_code == 200
        assert victim.json()["role"] == "victim"
        assert "lab_session=" in victim.headers["set-cookie"]
        assert client.get("/auth/me").json()["email"] == "victim@cachelab.local"
        assert client.post("/auth/login", content="email=attacker%40cachelab.local&password=wrong").status_code == 401
        status = client.get("/auth/victim/status").json()
        assert status["automated"] and status["cookie_name"] == "fusion_victim_id"
        assert status["cookie_id"].startswith("fusion-victim-local-")
        login_page = client.get("/login")
        assert login_page.status_code == 200
        assert "Đăng nhập demo" in login_page.text
        assert login_page.headers["cache-control"] == "no-store"

        home = client.get(
            "/api/home",
            headers={"X-Forwarded-Host": "preview.lab.test", "X-Request-ID": "req-home"},
        )
        assert home.status_code == 200
        assert home.json()["canonical_url"] == "http://preview.lab.test/"
        assert home.json()["request_id"] == "req-home"
        assert home.headers["cache-control"] == "public, max-age=30"

        product = client.get("/api/products/1?notice=AVAILABLE")
        assert product.json()["notice"] == "AVAILABLE"

        search = client.get("/api/search?q=LED&message=VISIBLE")
        assert search.json()["message"] == "VISIBLE"
        assert search.json()["results"][0]["name"] == "Den LED"

        news = client.get("/api/news/bao-mat-web-cache")
        assert news.status_code == 200
        assert news.headers["cache-control"] == "public, max-age=45"


def test_phase1_reverse_proxy_contract():
    nginx = (ROOT / "nginx" / "nginx.conf").read_text(encoding="utf-8")
    locations = (ROOT / "nginx" / "locations.conf").read_text(encoding="utf-8")
    servers = (ROOT / "nginx" / "servers.conf").read_text(encoding="utf-8")
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")

    for field in [
        '"schema":"fusion-nginx-access-v1"',
        '"request_id":"$request_id"',
        '"mode":"$lab_log_mode"',
        '"scenario":"$fusion_log_scenario"',
        '"cache_status":"$lab_log_cache_status"',
        '"detector_prediction":"$fusion_log_decision"',
        '"detector_action":"$fusion_log_action"',
    ]:
        assert field in nginx
    assert 'access_log /var/log/nginx/fusion-nginx-access.jsonl lab;' in nginx
    assert 'data/events:/var/log/nginx' in compose
    loki = (ROOT / "monitoring" / "loki" / "config.yaml").read_text(encoding="utf-8")
    alloy = (ROOT / "monitoring" / "alloy" / "config.alloy").read_text(encoding="utf-8")
    assert "grafana/loki:3.7.0" in compose
    assert "grafana/alloy:v1.19.2" in compose
    assert "grafana/grafana:12.4.0" in compose
    assert "triage:" in compose and "triage.app:app" in compose
    assert '127.0.0.1:13100:3100' in compose and '127.0.0.1:12345:12345' in compose
    assert '127.0.0.1:13000:3000' in compose and "grafana_data:" in compose
    assert '127.0.0.1:8002:8002' in compose
    assert "auth_enabled: false" in loki and "retention_period: 168h" in loki
    assert "loki.source.file" in alloy and "loki.write" in alloy
    assert "request_id" not in alloy and "uri_path" not in alloy
    assert "fusion-triage" in alloy and "triage-events.jsonl" in alloy
    assert "fusion-ml-shadow" in alloy and "ml-shadow-events.jsonl" in alloy
    assert '"source"   = "ml-shadow"' in alloy
    for label in ["event_schema", "event_type", "route", "model_version", "fallback_reason"]:
        assert label in alloy
    grafana_datasource = (ROOT / "monitoring" / "grafana" / "provisioning" / "datasources" / "fusion-loki.yaml").read_text(encoding="utf-8")
    grafana_dashboard = (ROOT / "monitoring" / "grafana" / "dashboards" / "fusion-cache-security.json").read_text(encoding="utf-8")
    assert "uid: fusion-loki" in grafana_datasource and "url: http://loki:3100" in grafana_datasource
    for panel in ["Total requests", "Normal requests", "Anomaly requests", "Cache HIT", "Cache MISS", "Cache BYPASS", "Latest inspected requests"]:
        assert panel in grafana_dashboard
    assert '"uid": "fusion-cache-security"' in grafana_dashboard
    assert "Header-related anomaly signals" in grafana_dashboard
    triage = (ROOT / "triage" / "app.py").read_text(encoding="utf-8")
    assert "get_loki_events" in triage and "build_triage" in triage
    assert "generative_model_used\": False" in triage
    assert "location /api/" in locations
    assert "location = /" in locations
    assert "location /assets/" in locations
    assert "proxy_cache_key" in locations
    assert "X-Cache-Status" in locations
    assert 'proxy_cache_key "$scheme|$host|$uri?$query_cache_args";' in servers
    assert "X-Cache-Key $query_cache_key_debug" in servers
    query_source = (ROOT / "vendor" / "fusion-electronics" / "backend" / "index.js").read_text(encoding="utf-8")
    assert "href='${req.originalUrl}'" in query_source
    assert 'location = /labs/utm/js/geolocate.js' in servers
    assert 'proxy_cache_key "$scheme|$host|$uri?$utm_resource_cache_args";' in servers
    assert 'callback=$arg_callback' in servers
    assert "railsStyleCallback" in (ROOT / "vendor" / "fusion-electronics" / "backend" / "index.js").read_text(encoding="utf-8")
    assert 'location = /labs/fatget/js/geolocate.js' in servers
    assert "req.body?.callback" in (ROOT / "vendor" / "fusion-electronics" / "backend" / "index.js").read_text(encoding="utf-8")
    assert "$manual_bypass" in locations
    # Legacy prototype locations already exposed six IDs; all twelve Fusion
    # vulnerable/fixed locations now expose the same Nginx-generated ID too.
    assert servers.count("add_header X-Request-ID") >= 18
    assert "8000:8000" not in compose and "8001:8001" not in compose
    assert '127.0.0.1:8080:8080' in compose
    assert 'proxy_cache_key "fusion|$scheme|$host|$fusion_cache_key"' in servers
    assert 'proxy_cache_key "$scheme|$host|$request_uri"' in servers
    assert 'proxy_cache_key "$scheme|$host|$uri"' in servers
    assert 'proxy_cache_key "$scheme|$host|$uri|id=$arg_id"' in servers
    fusion_mode = (ROOT / "nginx" / "fusion-detector-mode.conf").read_text(encoding="utf-8")
    fusion_auth = (ROOT / "nginx" / "fusion-detector-auth.conf").read_text(encoding="utf-8")
    fusion_headers = (ROOT / "nginx" / "fusion-detector-response-headers.conf").read_text(encoding="utf-8")
    # Stage 8 starts disabled and cannot be disabled/enabled by attacker input.
    assert "8086 off;" in fusion_mode
    assert "$http_x_fusion_detector_mode" not in fusion_mode
    assert "auth_request /_fusion_inspect;" in fusion_auth
    assert "error_page 500 502 503 504 = @fusion_detector_unavailable;" in fusion_auth
    assert "X-Fusion-Cache-Bypass" in fusion_headers
    # All four vulnerable and all four fixed Fusion families use the same
    # gate and apply both cache read and cache write protection.
    assert servers.count("include /etc/nginx/lab/fusion-detector-auth.conf;") == 12
    assert servers.count("include /etc/nginx/lab/fusion-detector-response-headers.conf;") == 12
    assert servers.count("proxy_cache_bypass $fusion_detector_bypass;") == 12
    assert servers.count("proxy_no_cache $fusion_detector_bypass;") == 12
    assert "location = /_fusion_inspect" in servers
    assert "location @fusion_detector_unavailable" in servers
    fusion_backend = (ROOT / "vendor" / "fusion-electronics" / "backend" / "index.js").read_text(encoding="utf-8")
    assert "app.get('/labs/:scenario/*'" in fusion_backend
    assert "renderVulnerableStorefront" in fusion_backend


def test_phase1_frontend_and_operator_scripts():
    html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
    for page in ["Home", "Product", "Search", "News"]:
        assert f'>{page}<' in html
    assert "Cache status" in html and "Request ID" in html
    assert "/api/home" in js and "/api/products/1" in js
    assert (ROOT / "run-phase1.ps1").exists()
    assert (ROOT / "reset-cache.ps1").exists()
