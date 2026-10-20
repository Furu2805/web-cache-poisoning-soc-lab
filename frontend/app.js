const modes = {
  8080: ['No detection', 'Cache co loi, khong goi detector'],
  8081: ['Rule-based detection', 'Rule phat hien request dang ngo'],
  8082: ['ML detection', 'Isolation Forest cham diem bat thuong'],
  8083: ['Hybrid detection', 'Rule HOAC ML → bypass cache'],
  8084: ['Hardened cache', 'Cache key va trust boundary an toan'],
  8085: ['Observe mode', 'Thu metadata, khong ra quyet dinh phong thu']
};
const descriptions = {
  xfh: ['X-Forwarded-Host', 'Unkeyed header anh huong vao response origin.'],
  query: ['Unkeyed Query Parameter', 'Cache bỏ utm_content khỏi key nhưng các query parameter khác vẫn keyed.'],
  cloaking: ['Unkeyed UTM Parameters', 'Cache bỏ utm_* khỏi key nhưng origin vẫn dùng dữ liệu này.'],
  fatget: ['Fat GET', 'GET body không nằm trong cache key nhưng origin vẫn xử lý body.']
};
const labPages = {
  xfh: {
    title: 'Lab: Web cache poisoning via unkeyed X-Forwarded-Host header',
    level: 'APPRENTICE',
    lead: 'This lab contains a web cache poisoning vulnerability caused by an unkeyed header. The cache does not include X-Forwarded-Host in its cache key, but the origin server uses this header to build a script URL in the HTML response.',
    code: 'GET /lab-store?lab=xfh  +  X-Forwarded-Host: attacker.com',
    goal: 'To solve the lab, poison the shared cache so a normal victim request receives a cached page that loads https://attacker.com/resources/js/tracking.js.'
  },
  query: {
    title: 'Lab: Web cache poisoning via an unkeyed query parameter',
    level: 'PRACTITIONER',
    lead: 'The cache keys normal query parameters but excludes utm_content. The origin reflects the raw request target inside a JavaScript string.',
    code: "GET /labs/query/?cb=123&utm_content='/><script>alert(1)</script>",
    goal: 'Use Param Miner to identify utm_content, then poison the cached home page while keeping other query parameters as cache busters.'
  },
  cloaking: {
    title: 'Lab: Parameter cloaking',
    level: 'PRACTITIONER',
    lead: 'Every page imports geolocate.js. The cache excludes utm_content, but the origin parses semicolons as parameter delimiters and lets a hidden callback overwrite the visible callback.',
    code: 'GET /labs/utm/js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)',
    goal: 'Poison geolocate.js via parameter cloaking, then open a normal UTM-lab page and observe the imported resource execute alert(1).'
  },
  fatget: {
    title: 'Lab: Web cache poisoning via a fat GET request',
    level: 'PRACTITIONER',
    lead: 'Every page imports geolocate.js. The origin accepts GET request bodies and lets a body callback override the URL callback, but the cache key ignores the body.',
    code: 'GET /labs/fatget/js/geolocate.js?callback=setCountryCookie  +  body: callback=alert(1)',
    goal: 'Poison geolocate.js using a GET body, then open a normal Fat GET lab page and observe the imported resource execute alert(1).'
  }
};
let current = 'xfh'; let attack = null; let victim = null;
const $ = id => document.getElementById(id);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const marker = () => $('marker').value.trim().replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 40) || 'DEMO_POISON';
let sitePage = 'home';
let siteClient = 'A';
let siteSession = 'site-' + Date.now().toString(36);

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
}

function siteUrl() {
  const session = encodeURIComponent(siteSession);
  if (sitePage === 'product') return `/api/products/1?lab_session=${session}`;
  if (sitePage === 'search') {
    const q = encodeURIComponent($('site-search-input')?.value || '');
    return `/api/search?q=${q}&lab_session=${session}`;
  }
  if (sitePage === 'news') return `/api/news/bao-mat-web-cache?lab_session=${session}`;
  return `/api/home?lab_session=${session}`;
}

function renderSitePage(data) {
  const view = $('store-view');
  if (data.error) {
    view.innerHTML = `<div class="store-error"><b>Backend trả về lỗi</b><p>${escapeHtml(data.error)}</p></div>`;
    return;
  }
  if (data.page === 'home') {
    view.innerHTML = `<div class="store-hero"><span class="store-kicker">SMART DEVICES · 2026</span><h2>${escapeHtml(data.title)}</h2><p>${escapeHtml(data.subtitle)}</p><div class="announcement">${escapeHtml(data.announcement)}</div><a class="origin-link" href="#">Canonical: ${escapeHtml(data.canonical_url)}</a></div><div class="product-row"><article><span>01</span><b>Cảm biến nhiệt độ</b><small>Dữ liệu mẫu từ SQLite</small></article><article><span>02</span><b>Đèn LED</b><small>Response đi qua shared cache</small></article><article><span>03</span><b>ESP32</b><small>Quan sát trực tiếp trên trình duyệt</small></article></div>`;
  } else if (data.page === 'product') {
    view.innerHTML = `<div class="product-detail"><div class="product-art">ESP<br>32</div><div><span class="store-kicker">PRODUCT #${escapeHtml(data.id)}</span><h2>${escapeHtml(data.name)}</h2><p class="price">${Number(data.price || 0).toLocaleString('vi-VN')} ₫</p><p>${escapeHtml(data.notice)}</p><button class="store-action">Thêm vào giỏ mô phỏng</button></div></div>`;
  } else if (data.page === 'search') {
    const items = (data.results || []).map(item => `<li><span>#${escapeHtml(item.id)}</span><b>${escapeHtml(item.name)}</b></li>`).join('') || '<li>Không có kết quả.</li>';
    view.innerHTML = `<div class="search-head"><span class="store-kicker">SEARCH ENDPOINT</span><h2>Tìm kiếm sản phẩm</h2><div class="search-box"><input id="site-search-input" value="${escapeHtml(data.query)}" placeholder="Nhập LED, ESP32..."><button id="site-search-btn">Tìm kiếm</button></div><p>${escapeHtml(data.message)}</p></div><ul class="search-results">${items}</ul>`;
    $('site-search-btn').addEventListener('click', loadSiteData);
    $('site-search-input').addEventListener('keydown', event => { if (event.key === 'Enter') loadSiteData(); });
  } else {
    view.innerHTML = `<article class="news-article"><span class="store-kicker">SECURITY NEWS · CACHEABLE CONTENT</span><h2>${escapeHtml(data.title)}</h2><p>${escapeHtml(data.summary)}</p><div class="article-rule"></div><p>Trang nội dung này có TTL dài hơn để minh họa chính sách cache theo loại tài nguyên.</p></article>`;
  }
}

async function loadSiteData() {
  const url = siteUrl();
  $('store-loading').classList.add('show');
  $('site-endpoint').textContent = url;
  try {
    const headers = {'Accept': 'application/json', 'X-Lab-Client': siteClient};
    if ($('site-bypass').checked) headers['X-Lab-Bypass'] = '1';
    const response = await fetch(url, {headers, cache: 'no-store'});
    const data = await response.json();
    renderSitePage(data);
    const status = response.headers.get('x-cache-status') || 'N/A';
    $('site-cache').textContent = status;
    $('site-cache').className = 'status-pill ' + status.toLowerCase();
    $('site-request-id').textContent = response.headers.get('x-request-id') || '—';
    $('site-key-profile').textContent = response.headers.get('x-cache-key-profile') || '—';
    $('site-origin-id').textContent = data.request_id || '—';
  } catch (error) {
    $('store-view').innerHTML = `<div class="store-error"><b>Không kết nối được môi trường lab</b><p>${escapeHtml(error.message)}</p></div>`;
    $('site-cache').textContent = 'ERROR';
  } finally {
    $('store-loading').classList.remove('show');
  }
}

function id() { return 'ui-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 7); }
function paths() {
  const key = id(), m = encodeURIComponent(marker());
  const common = '/lab/' + current + '?id=' + key;
  if (current === 'xfh') return {attacker: common, victim: common, body: '', headers: {'X-Forwarded-Host': 'poison-' + m.toLowerCase() + '.test'}, key};
  if (current === 'query') return {attacker: common + '&message=' + m, victim: common, body: '', headers: {}, key};
  if (current === 'cloaking') return {attacker: common + '&utm_content=campaign;message=' + m, victim: common + '&utm_content=campaign', body: '', headers: {}, key};
  return {attacker: common, victim: common, body: 'message=' + m, headers: {'Content-Type': 'application/x-www-form-urlencoded'}, key};
}
function renderRequest() {
  const p = paths();
  $('request-path').textContent = p.attacker;
  $('victim-path').textContent = p.victim;
  const h = {'Host': 'lab.test', 'Accept': 'application/json', 'Accept-Language': 'vi', ...p.headers};
  $('attacker-headers').innerHTML = Object.entries(h).map(([k,v]) => `<span><em>${k}:</em> ${v}</span>`).join('');
  $('request-body').textContent = p.body ? 'Body: ' + p.body : '';
  $('request-body').classList.toggle('show', Boolean(p.body));
}
function selectLab(scenario) {
  current = scenario;
  document.querySelectorAll('.lab-nav').forEach(x => x.classList.toggle('active', x.dataset.scenario === scenario));
  document.querySelectorAll('.panel').forEach(x => x.classList.toggle('active', x.id === 'lab'));
  clean();
  renderRequest();
  renderLabIntro();
}
function renderLabIntro() {
  const info = labPages[current];
  $('lab-runner').classList.add('hidden');
  $('lab-intro').classList.remove('hidden');
  $('lab-intro').innerHTML = `
    <div class="lab-brief">
      <div class="lab-brief-main">
        <h1>${escapeHtml(info.title)}</h1>
        <span class="lab-level">${escapeHtml(info.level)}</span>
        <p>${escapeHtml(info.lead)}</p>
        <pre class="lab-code">${escapeHtml(info.code)}</pre>
        <p>${escapeHtml(info.goal)}</p>
        <button class="btn primary lab-access" id="access-lab"><span>⚗</span> Access the lab</button>
        <button class="btn lab-access" id="access-fixed">Open patched variant</button>
      </div>
      <button class="share-lab" type="button" aria-label="Share lab">↗</button>
    </div>`;
  $('access-lab').addEventListener('click', () => {
    const fusionScenario = { xfh: 'xfh', query: 'query', cloaking: 'utm', fatget: 'fatget' }[current];
    const storeUrl = `${location.protocol}//${location.hostname}:8086/labs/${fusionScenario}/`;
    window.location.href = storeUrl;
  });
  $('access-fixed').addEventListener('click', () => {
    const fusionScenario = { xfh: 'xfh', query: 'query', cloaking: 'utm', fatget: 'fatget' }[current];
    window.location.href = `${location.protocol}//${location.hostname}:8086/labs/${fusionScenario}/fixed/`;
  });
}
function setMode() {
  const [name, desc] = modes[location.port] || ['Custom mode', 'Kiem tra cau hinh Nginx'];
  $('mode-chip').textContent = name;
  if ($('mode-name')) $('mode-name').textContent = name;
  if ($('mode-description')) $('mode-description').textContent = desc;
}
function headersToText(response) {
  const keys = ['x-cache-status','x-defense-mode','x-request-id','x-decision','x-anomaly-score','x-detector-ms','cache-control','vary'];
  return keys.filter(k => response.headers.get(k) !== null).map(k => k + ': ' + response.headers.get(k)).join('\n');
}
function clean() {
  attack = null; victim = null; $('victim-btn').disabled = true;
  $('attacker-cache').textContent = '—'; $('attacker-decision').textContent = 'Chua co request';
  $('anomaly-score').textContent = '—'; $('score-note').textContent = 'Chua co model result';
  $('victim-cache').textContent = '—'; $('victim-note').textContent = 'Chua kiem tra';
  $('verdict').textContent = 'DANG CHO'; $('verdict-note').textContent = 'Chua co bang chung';
  $('verdict').parentElement.className = 'metric verdict';
  $('attacker-status').textContent = '—'; $('victim-status').textContent = '—';
  $('attacker-response').textContent = 'Chua co response.'; $('victim-response').textContent = 'Chua co response.';
}
function toast(text) { const e=$('toast'); e.textContent=text; e.classList.add('show'); setTimeout(()=>e.classList.remove('show'),2500); }
async function call(path, method='GET', headers={}, body='') {
  const res = await fetch(path, {method, headers:{'Accept':'application/json','X-UI-Request':'1',...headers}, body: body || undefined, cache:'no-store'});
  const text = await res.text(); let data; try {data=JSON.parse(text)} catch {data={raw:text}};
  return {res,data};
}
async function sendAttack() {
  if (current === 'fatget') {
    $('attacker-response').textContent = 'Trinh duyet khong cho JavaScript gui GET request co body theo Fetch standard.\n\nDung Burp Repeater hoac terminal:\n\ncurl -i -X GET -H "Host: lab.test" --data "message=' + marker() + '" "' + location.origin + '/lab/fatget?id=demo-fatget"';
    $('attacker-status').textContent = 'MANUAL STEP';
    $('verdict').textContent = 'DUNG CURL / BURP'; $('verdict-note').textContent = 'Fat GET can raw HTTP request';
    toast('Fat GET can gui bang Burp Repeater hoac cURL'); return;
  }
  clean(); const p=paths(); $('attack-btn').disabled=true; $('attack-btn').textContent='Dang gui...';
  try {
    const {res,data}=await call(p.attacker,'GET',p.headers,p.body);
    attack={p,res,data};
    $('attacker-cache').textContent=res.headers.get('x-cache-status') || 'N/A';
    $('attacker-decision').textContent=res.headers.get('x-decision') || 'Khong co detector';
    $('anomaly-score').textContent=res.headers.get('x-anomaly-score') || 'N/A';
    $('score-note').textContent=(res.headers.get('x-detector-ms') || '—') + ' ms detector';
    $('attacker-status').textContent='HTTP ' + res.status;
    $('attacker-response').textContent=headersToText(res) + '\n\n' + JSON.stringify(data,null,2);
    $('victim-btn').disabled=!res.ok; $('verdict').textContent=res.ok?'SAN SANG KIEM TRA':'REQUEST LOI';
    $('verdict-note').textContent=res.ok?'Dung client doc lap de doc cache':'Kiem tra Docker/Nginx';
    toast(res.ok?'Attacker request da duoc gui':'Request tra ve loi');
  } catch(err) { $('attacker-response').textContent='Network error: '+err.message; toast('Khong ket noi duoc lab'); }
  finally {$('attack-btn').disabled=false; $('attack-btn').innerHTML='<span>▶</span> Gui request attacker';}
}
async function checkVictim() {
  if (!attack) return; $('victim-btn').disabled=true; $('victim-btn').textContent='Dang kiem tra...';
  try {
    // A fresh request with no attacker-controlled input. The browser cannot force a new TCP connection,
    // so server evidence and a no-payload request are shown; automated runner verifies a separate client pool.
    const {res,data}=await call(attack.p.victim);
    victim={res,data}; const expected=current==='xfh' ? 'poison-'+marker().toLowerCase()+'.test' : marker();
    const poisoned=data.value===expected && res.headers.get('x-cache-status')==='HIT';
    $('victim-cache').textContent=res.headers.get('x-cache-status') || 'N/A';
    $('victim-note').textContent=poisoned?'Marker xuat hien trong HIT':'Khong nhan marker tu cache';
    $('victim-status').textContent='HTTP ' + res.status;
    $('victim-response').textContent=headersToText(res) + '\n\n' + JSON.stringify(data,null,2);
    const v=$('verdict'), parent=v.parentElement; parent.className='metric verdict '+(poisoned?'unsafe':'safe');
    v.textContent=poisoned?'POISONING XAC NHAN':'CLIENT NHAN RESPONSE SACH';
    $('verdict-note').textContent=poisoned?'Marker + HIT: response da duoc chia se':'Khong co bang chung poisoning trong lan nay';
    toast(poisoned?'Poisoning da duoc xac nhan':'Client khong nhan marker');
  } catch(err) { $('victim-response').textContent='Network error: '+err.message; toast('Khong kiem tra duoc client'); }
  finally {$('victim-btn').disabled=false; $('victim-btn').innerHTML='<span>⌁</span> Kiem tra response client';}
}
async function detectorHealth() {
  try { const r=await fetch('/_ui_health',{cache:'no-store'}); const data=await r.json(); $('detector-status').textContent=data.model_ready?'Model da nap':'Model chua san sang'; }
  catch { $('detector-status').textContent='Khong the kiem tra'; }
}
async function victimBotStatus() {
  try {
    const r = await fetch('/auth/victim/status', {cache:'no-store'}); const data = await r.json();
    const suffix = data.cookie_id ? data.cookie_id.slice(-6) : '—';
    $('victim-bot-status').textContent = data.poisoned ? `POISONED · cookie …${suffix}` : `${data.cache_status || 'WAITING'} · cookie …${suffix}`;
  } catch { $('victim-bot-status').textContent = 'Không thể kiểm tra'; }
}
document.querySelectorAll('.nav-item').forEach(button=>button.addEventListener('click',()=>{
  if (button.dataset.scenario) { selectLab(button.dataset.scenario); return; }
  document.querySelectorAll('.nav-item').forEach(x=>x.classList.toggle('active',x===button));
  document.querySelectorAll('.panel').forEach(x=>x.classList.toggle('active',x.id===button.dataset.panel));
}));
document.querySelectorAll('.store-tab').forEach(button=>button.addEventListener('click',()=>{sitePage=button.dataset.page;document.querySelectorAll('.store-tab').forEach(x=>x.classList.toggle('active',x===button));loadSiteData();}));
document.querySelectorAll('.client-btn').forEach(button=>button.addEventListener('click',()=>{siteClient=button.dataset.client;$('client-label').textContent=siteClient;document.querySelectorAll('.client-btn').forEach(x=>x.classList.toggle('active',x===button));loadSiteData();}));
$('reload-site').addEventListener('click',loadSiteData);
$('new-site-key').addEventListener('click',()=>{siteSession='site-'+Date.now().toString(36);loadSiteData();toast('Đã tạo namespace cache mới');});
$('site-bypass').addEventListener('change',loadSiteData);
$('marker').addEventListener('input',()=>{ if(!attack)renderRequest(); }); $('attack-btn').addEventListener('click',sendAttack); $('victim-btn').addEventListener('click',checkVictim); $('clear-btn').addEventListener('click',()=>{clean();renderRequest();});
setMode(); renderRequest(); clean(); renderLabIntro(); detectorHealth(); victimBotStatus(); loadSiteData(); setInterval(victimBotStatus, 5000);
