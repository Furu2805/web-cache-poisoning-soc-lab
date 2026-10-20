"""Intentionally vulnerable LOCAL teaching backend. Payloads are text markers.

No script execution or outbound requests are necessary to prove shared-cache
contamination. The database persists product data, not an internal cache.
"""
import os
import sqlite3
import uuid
import hashlib
import secrets
import time
from html import escape
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import parse_qsl

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

DB = Path(os.getenv("BACKEND_DB", "data/backend.sqlite3"))
FRONTEND = Path(__file__).resolve().parents[1] / "frontend"
LAB_USERS = (
    ("attacker@cachelab.local", "attacker", "Attacker!2026"),
    ("victim@cachelab.local", "victim", "Victim!2026"),
)
VICTIM_EMAIL = "victim@cachelab.local"
# Fixed only so the local victim simulator can retain a stable, demonstrable
# cookie identity across container restarts. It is never a real credential.
VICTIM_SESSION_TOKEN = "victim-session-local-7c9a4e2b"
FUSION_VICTIM_COOKIE_NAME = "fusion_victim_id"
FUSION_VICTIM_COOKIE_ID = "fusion-victim-local-7c9a4e2b"
LOGIN_PAGE = """<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Đăng nhập | CacheShield Lab</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f7f8;color:#17212b;font:15px Inter,Segoe UI,Arial,sans-serif}.card{width:min(420px,calc(100% - 40px));background:#fff;padding:34px;border-radius:10px;box-shadow:0 8px 28px #17212b1c}h1{margin:0 0 8px}p{color:#64727d;line-height:1.5}label{display:block;margin-top:18px;font-weight:700;font-size:13px}input{width:100%;box-sizing:border-box;margin-top:6px;padding:11px;border:1px solid #ccd8de;border-radius:5px;font:inherit}button{width:100%;margin-top:22px;padding:12px;border:0;border-radius:5px;background:#e95b27;color:#fff;font-weight:800;cursor:pointer}.hint{font-size:12px;background:#edf7f7;padding:10px;border-radius:5px}.error{min-height:20px;color:#bc3b3b;margin:12px 0 0;font-size:13px}a{color:#0e8394}</style></head>
<body><main class="card"><h1>Đăng nhập demo</h1><p>Chọn account attacker hoặc victim cho lab cục bộ.</p><p class="hint"><b>Victim</b>: victim@cachelab.local<br><b>Attacker</b>: attacker@cachelab.local</p>
<form id="login"><label>Email<input name="email" type="email" required autocomplete="username"></label><label>Mật khẩu<input name="password" type="password" required autocomplete="current-password"></label><button>Đăng nhập</button><p class="error" id="error" role="alert"></p></form><a href="/">← Về lab</a></main>
<script>document.querySelector('#login').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.currentTarget);const r=await fetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(f)});if(r.ok){location.assign('/')}else{document.querySelector('#error').textContent='Email hoặc mật khẩu không đúng.'}})</script></body></html>"""


# Hash mật khẩu mô phỏng để so sánh trong lab app.
def password_hash(email: str, password: str) -> str:
    """Deterministic, local-lab-only password hashing for the seeded accounts."""
    return hashlib.scrypt(
        password.encode("utf-8"), salt=email.encode("utf-8"), n=2**14, r=8, p=1
    ).hex()


# Khởi tạo dữ liệu local của ứng dụng lab.
def init_db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB) as db:
        db.execute("CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT)")
        db.execute("""CREATE TABLE IF NOT EXISTS lab_users (
            email TEXT PRIMARY KEY, role TEXT NOT NULL, password_hash TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS lab_sessions (
            token TEXT PRIMARY KEY, email TEXT NOT NULL, expires_at INTEGER NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS victim_visits (
            id INTEGER PRIMARY KEY CHECK (id = 1), visited_at INTEGER,
            cache_status TEXT, script_url TEXT, poisoned INTEGER NOT NULL DEFAULT 0
        )""")
        db.executemany("INSERT OR IGNORE INTO products VALUES (?,?)",
                       [(1, "Cam bien nhiet do"), (2, "Den LED"), (3, "ESP32")])
        db.executemany(
            "INSERT OR IGNORE INTO lab_users(email, role, password_hash) VALUES (?, ?, ?)",
            [(email, role, password_hash(email, password)) for email, role, password in LAB_USERS],
        )
        db.execute("""INSERT INTO lab_sessions(token, email, expires_at) VALUES (?, ?, ?)
                      ON CONFLICT(token) DO UPDATE SET expires_at=excluded.expires_at""",
                   (VICTIM_SESSION_TOKEN, VICTIM_EMAIL, int(time.time()) + 365 * 24 * 3600))
        db.execute("INSERT OR IGNORE INTO victim_visits(id, poisoned) VALUES (1, 0)")


# Tạo header cache control cho response public.
def public_headers(ttl: int = 30) -> dict[str, str]:
    """Headers used by origin responses that Nginx is allowed to cache."""
    return {
        "Cache-Control": f"public, max-age={ttl}",
        "Vary": "Accept-Language",
    }


# Lấy request_id để nối evidence giữa các service.
def request_id(request: Request) -> str:
    """Reuse the reverse proxy ID so browser, Nginx and backend evidence match."""
    return request.headers.get("x-request-id", uuid.uuid4().hex)


# Dựng origin từ header request cho response lab.
def external_origin(request: Request) -> str:
    """Intentionally trusts forwarded headers for the phase-2 XFH exercise."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "lab.test"))
    return f"{scheme}://{host}"


@asynccontextmanager
# Khởi tạo ứng dụng backend khi service khởi động.
async def lifespan(app):
    init_db()
    yield


app = FastAPI(title="Backend lab Web Cache Poisoning", lifespan=lifespan)
app.mount("/assets", StaticFiles(directory=FRONTEND), name="assets")


@app.get("/health")
# Báo trạng thái backend local.
def health():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
# Hiển thị giao diện ứng dụng lab.
def dashboard(request: Request):
    """Cacheable home page with the deliberate PortSwigger-style XFH sink."""
    trusted_host = request.headers.get("x-forwarded-host", request.headers.get("host", "lab.test"))
    safe_host = escape(trusted_host, quote=True)
    tracking_import = f'<script src="https://{safe_host}/resources/js/tracking.js"></script>'
    page = (FRONTEND / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(
        page.replace("</head>", f"  {tracking_import}\n</head>"),
        headers=public_headers(),
    )


@app.get("/login", response_class=HTMLResponse)
# Trả trang đăng nhập demo.
def login_page():
    return HTMLResponse(LOGIN_PAGE, headers={"Cache-Control": "no-store"})


@app.post("/auth/login")
# Xử lý đăng nhập demo và tạo session.
async def login(request: Request):
    """Issue a local-lab session for the seeded attacker or victim account."""
    raw = (await request.body()).decode("utf-8", "replace")
    form = dict(parse_qsl(raw, keep_blank_values=True))
    email = form.get("email", "").strip().lower()
    password = form.get("password", "")
    with sqlite3.connect(DB) as db:
        row = db.execute(
            "SELECT role, password_hash FROM lab_users WHERE email=?", (email,)
        ).fetchone()
        if row is None or not secrets.compare_digest(row[1], password_hash(email, password)):
            return JSONResponse({"error": "invalid credentials"}, status_code=401,
                                headers={"Cache-Control": "no-store"})
        token = secrets.token_urlsafe(32)
        db.execute("DELETE FROM lab_sessions WHERE expires_at < ?", (int(time.time()),))
        db.execute("INSERT INTO lab_sessions(token, email, expires_at) VALUES (?, ?, ?)",
                   (token, email, int(time.time()) + 3600))
    response = JSONResponse({"email": email, "role": row[0], "expires_in": 3600},
                            headers={"Cache-Control": "no-store"})
    # Deliberately readable by JavaScript only in this local XSS teaching lab,
    # so a victim can visibly observe alert(document.cookie). Never copy this
    # cookie configuration into a real application.
    response.set_cookie("lab_session", token, max_age=3600, httponly=False,
                        samesite="lax", secure=False, path="/")
    return response


@app.post("/auth/logout")
# Kết thúc session demo.
async def logout(request: Request):
    token = request.cookies.get("lab_session")
    if token:
        with sqlite3.connect(DB) as db:
            db.execute("DELETE FROM lab_sessions WHERE token=?", (token,))
    response = JSONResponse({"ok": True}, headers={"Cache-Control": "no-store"})
    response.delete_cookie("lab_session", path="/")
    return response


@app.get("/auth/me")
# Trả thông tin user hiện tại.
async def current_user(request: Request):
    token = request.cookies.get("lab_session", "")
    with sqlite3.connect(DB) as db:
        row = db.execute("""SELECT u.email, u.role FROM lab_sessions s
                          JOIN lab_users u ON u.email=s.email
                          WHERE s.token=? AND s.expires_at >= ?""",
                         (token, int(time.time()))).fetchone()
    if row is None:
        return JSONResponse({"authenticated": False}, headers={"Cache-Control": "no-store"})
    return JSONResponse({"authenticated": True, "email": row[0], "role": row[1]},
                        headers={"Cache-Control": "no-store"})


@app.post("/auth/victim/report")
# Nhận báo cáo effect từ victim bot.
async def victim_report(request: Request):
    """Receive the local victim bot's observation after its periodic visit."""
    form = dict(parse_qsl((await request.body()).decode("utf-8", "replace"), keep_blank_values=True))
    cache_status = form.get("cache_status", "UNKNOWN")[:16]
    script_url = form.get("script_url", "")[:512]
    poisoned = int(form.get("poisoned") == "1")
    with sqlite3.connect(DB) as db:
        db.execute("""UPDATE victim_visits SET visited_at=?, cache_status=?, script_url=?, poisoned=?
                      WHERE id=1""", (int(time.time()), cache_status, script_url, poisoned))
    return JSONResponse({"ok": True}, headers={"Cache-Control": "no-store"})


@app.get("/auth/victim/status")
# Trả trạng thái victim bot.
async def victim_status():
    with sqlite3.connect(DB) as db:
        row = db.execute("SELECT visited_at, cache_status, script_url, poisoned FROM victim_visits WHERE id=1").fetchone()
    return JSONResponse({
        "automated": True,
        "account": VICTIM_EMAIL,
        "cookie_name": FUSION_VICTIM_COOKIE_NAME,
        "cookie_id": FUSION_VICTIM_COOKIE_ID,
        "last_visit": row[0] if row else None,
        "cache_status": row[1] if row else "WAITING",
        "script_url": row[2] if row else "",
        "poisoned": bool(row[3]) if row else False,
    }, headers={"Cache-Control": "no-store"})


@app.get("/api/home")
# Trả trang chủ ứng dụng lab.
async def home(request: Request):
    origin = external_origin(request)
    return JSONResponse(
        {
            "page": "home",
            "title": "CacheMart Technology",
            "subtitle": "Website nội dung mẫu đi qua Nginx Reverse Proxy",
            "announcement": request.query_params.get(
                "announcement", "Miễn phí giao hàng cho đơn từ 500.000đ"
            ),
            "canonical_url": f"{origin}/",
            "asset_url": f"{origin}/assets/product-placeholder.svg",
            "request_id": request_id(request),
        },
        headers=public_headers(),
    )


@app.get("/api/products/{product_id}")
# Trả trang sản phẩm theo id.
async def product(product_id: int, request: Request):
    with sqlite3.connect(DB) as db:
        row = db.execute("SELECT id, name FROM products WHERE id=?", (product_id,)).fetchone()
    if row is None:
        return JSONResponse(
            {"error": "Không tìm thấy sản phẩm", "request_id": request_id(request)},
            status_code=404,
            headers={"Cache-Control": "no-store"},
        )
    prices = {1: 249000, 2: 79000, 3: 189000}
    return JSONResponse(
        {
            "page": "product",
            "id": row[0],
            "name": row[1],
            "price": prices.get(row[0], 99000),
            "notice": request.query_params.get("notice", "Sản phẩm đang còn hàng"),
            "request_id": request_id(request),
        },
        headers=public_headers(),
    )


@app.get("/api/search")
# Trả kết quả tìm kiếm ứng dụng lab.
async def search(request: Request, q: str = ""):
    with sqlite3.connect(DB) as db:
        rows = db.execute(
            "SELECT id, name FROM products WHERE lower(name) LIKE lower(?) ORDER BY id",
            (f"%{q}%",),
        ).fetchall()
    return JSONResponse(
        {
            "page": "search",
            "query": q,
            "message": request.query_params.get("message", "Kết quả tìm kiếm hợp lệ"),
            "results": [{"id": row[0], "name": row[1]} for row in rows],
            "request_id": request_id(request),
        },
        headers=public_headers(20),
    )


@app.get("/api/news/{slug}")
# Trả trang tin theo slug.
async def news(slug: str, request: Request):
    articles = {
        "bao-mat-web-cache": {
            "title": "Bảo vệ lớp Web Cache trong kiến trúc hiện đại",
            "summary": "Cache key, trust boundary và logging là ba lớp kiểm soát quan trọng.",
        },
        "nginx-reverse-proxy": {
            "title": "Nginx Reverse Proxy hoạt động như thế nào?",
            "summary": "Reverse proxy tiếp nhận request, chuyển tiếp đến origin và có thể lưu response.",
        },
    }
    article = articles.get(slug)
    if article is None:
        return JSONResponse(
            {"error": "Không tìm thấy bài viết", "request_id": request_id(request)},
            status_code=404,
            headers={"Cache-Control": "no-store"},
        )
    return JSONResponse(
        {"page": "news", "slug": slug, **article, "request_id": request_id(request)},
        headers=public_headers(45),
    )


@app.get("/lab/xfh-page", response_class=HTMLResponse)
# Tạo trang minh họa XFH response gadget.
async def xfh_page(request: Request):
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "lab.test"))
    safe_host = escape(host, quote=True)
    rid = uuid.uuid4().hex
    body = f"""<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <title>Unkeyed Header Lab - X-Forwarded-Host</title>
  <script src="https://{safe_host}/resources/js/tracking.js"></script>
</head>
<body>
  <h1>CacheMart</h1>
  <p>Trang nay mo phong origin tin vao X-Forwarded-Host khi tao asset URL.</p>
  <p id="asset-host">Asset host: {safe_host}</p>
  <p id="origin-request-id">Origin request: {rid}</p>
</body>
</html>"""
    headers = public_headers()
    headers["Content-Type"] = "text/html; charset=utf-8"
    headers["X-Origin-Request-ID"] = rid
    return HTMLResponse(body, headers=headers)


@app.api_route("/lab/shop/{scenario}", methods=["GET", "HEAD", "POST"], response_class=HTMLResponse)
# Tạo response gadget của scenario WCP tương ứng.
async def shop_lab(scenario: str, request: Request):
    if scenario not in {"xfh", "query", "cloaking", "fatget"}:
        return HTMLResponse("Unknown lab", status_code=404, headers={"Cache-Control": "no-store"})

    raw = request.scope["query_string"].decode("ascii", "replace")
    parsed = raw.replace(";", "&") if scenario == "cloaking" else raw
    params = dict(parse_qsl(parsed, keep_blank_values=True, separator="&"))
    body = (await request.body()).decode("utf-8", "replace") if scenario == "fatget" else ""
    body_params = dict(parse_qsl(body, keep_blank_values=True))

    trusted_host = request.headers.get("x-forwarded-host", request.headers.get("host", "lab.test"))
    injected_value = "Flash sale cuoi tuan: giam 20% cho thiet bi IoT"
    if scenario == "xfh":
        # Match the PortSwigger unkeyed-header lab's resource-import sink.
        # X-Forwarded-Host is intentionally not part of the proxy cache key.
        injected_value = f"https://{escape(trusted_host, quote=True)}/resources/js/tracking.js"
    elif scenario == "query":
        injected_value = params.get("message", injected_value)
    elif scenario == "cloaking":
        injected_value = params.get("utm_source", params.get("message", injected_value))
    elif scenario == "fatget":
        # Safe response-splitting simulation: only the application body is
        # changed.  It never creates additional HTTP headers/responses.
        simulated = params.get("redir", "")
        injected_value = simulated.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in simulated else body_params.get("message", injected_value)

    rid = uuid.uuid4().hex
    safe_value = escape(injected_value, quote=True)
    script_tag = f'<script src="{safe_value}"></script>' if scenario == "xfh" else ""
    # The three payload labs deliberately reflect content into this local lab
    # page.  XFH remains attribute-escaped because it is an asset URL sink.
    banner = "Tai nguyen giao dien dang nap tu host tin cay" if scenario == "xfh" else injected_value
    body_html = f"""<!doctype html>
<title>Products - Flaskr</title>
<link rel="stylesheet" href="/assets/flaskr-lab.css">
{script_tag}
<nav>
  <h1><a href="/lab/shop/{escape(scenario)}?id={escape(params.get('id', 'demo'))}">Flaskr Store</a></h1>
  <ul>
    <li><span>guest</span></li>
    <li><a href="#">Register</a></li>
    <li><a href="#">Log In</a></li>
  </ul>
</nav>
<section class="content">
  <header>
    <h1>Products</h1>
    <a class="action" href="#">Cart</a>
  </header>
  <div class="flash">{banner}</div>
  <article class="post">
    <header>
      <div>
        <h1>Cam bien nhiet do</h1>
        <div class="about">by cachemart on 2026-09-18</div>
      </div>
      <a class="action" href="#">View</a>
    </header>
    <p class="body">Theo doi nhiet do phong theo thoi gian thuc.
<span class="price">249.000d</span></p>
  </article>
  <hr>
  <article class="post">
    <header>
      <div>
        <h1>Den LED thong minh</h1>
        <div class="about">by cachemart on 2026-09-18</div>
      </div>
      <a class="action" href="#">View</a>
    </header>
    <p class="body">Dieu khien anh sang qua ung dung di dong.
<span class="price">79.000d</span></p>
  </article>
  <hr>
  <article class="post">
    <header>
      <div>
        <h1>ESP32 DevKit</h1>
        <div class="about">by cachemart on 2026-09-18</div>
      </div>
      <a class="action" href="#">View</a>
    </header>
    <p class="body">Bo mach thu nghiem cho du an nha thong minh.
<span class="price">189.000d</span></p>
  </article>
  <div class="meta">origin_request_id={rid} | lab={escape(scenario)}</div>
</section>"""
    headers = public_headers()
    headers["Content-Type"] = "text/html; charset=utf-8"
    headers["X-Origin-Request-ID"] = rid
    return HTMLResponse(body_html, headers=headers)


@app.api_route("/lab/{scenario}", methods=["GET", "HEAD", "POST"])
# Điều phối route lab tới scenario tương ứng.
async def lab(scenario: str, request: Request):
    if scenario not in {"xfh", "query", "cloaking", "fatget"}:
        return JSONResponse({"error": "unknown scenario"}, status_code=404,
                            headers={"Cache-Control": "no-store"})
    raw = request.scope["query_string"].decode("ascii", "replace")
    # Vulnerable legacy parser treats literal semicolon as another separator.
    parsed = raw.replace(";", "&") if scenario == "cloaking" else raw
    params = dict(parse_qsl(parsed, keep_blank_values=True, separator="&"))
    with sqlite3.connect(DB) as db:
        product = db.execute("SELECT name FROM products WHERE id=1").fetchone()[0]
    value = "NORMAL"
    if scenario == "xfh":
        value = request.headers.get("x-forwarded-host", request.headers.get("host", "lab.test"))
    elif scenario == "query":
        value = params.get("message", "NORMAL")
    elif scenario == "cloaking":
        value = params.get("utm_source", params.get("message", "NORMAL"))
    elif scenario == "fatget":
        simulated = params.get("redir", "")
        if "\r\n\r\n" in simulated:
            value = simulated.split("\r\n\r\n", 1)[1]
        else:
            body = (await request.body()).decode("utf-8", "replace")
            value = dict(parse_qsl(body, keep_blank_values=True)).get("message", "NORMAL")
    return JSONResponse({"scenario": scenario, "product": product, "value": value,
                         "origin_request_id": uuid.uuid4().hex,
                         "request_id": request_id(request)},
                        headers=public_headers())
