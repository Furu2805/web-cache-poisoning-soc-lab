require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const seedDB = require('./seed/productSeeds');
const syncPinecone = require('./sync/syncPinecone');
const productRoutes = require('./routes/products');
const checkoutRoutes = require('./routes/checkout');
const orderRoutes = require('./routes/orders');
const authRoutes = require('./routes/auth');
const { swaggerUi, swaggerSpec, setupSwaggerUi, setupSwaggerJson } = require('./docs/swagger');

// Create Express App
const app = express();
const PORT = process.env.PORT || 8000;

// Database Connection + Seed + Vector Sync + Server Start
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(async () => {
    console.log('MongoDB Connected');

    // 1. Seed the database (only when necessary)
    const skipSeed = process.env.SKIP_SEED_ON_START === 'true';
    if (!skipSeed) {
      try {
        const forceSeed = process.env.FORCE_SEED_ON_START === 'true';
        const result = await seedDB({ force: forceSeed, skipIfExists: !forceSeed });
        if (result?.seeded) {
          console.log('🪴 Database seeded');
        } else if (result?.skipped) {
          console.log('🌱 Seed skipped (existing products retained)');
        }
      } catch (err) {
        console.error('❌ Seeding error:', err);
      }
    } else {
      console.log('🌱 SKIP_SEED_ON_START enabled. Existing products preserved.');
    }

    // 2. Sync with Pinecone (primary recommendation engine)
    try {
      await syncPinecone();
      console.log('✅ Pinecone synced');
    } catch (err) {
      console.error('❌ Pinecone sync error (continuing with fallbacks):', err);
    }

    // 3. Start Express server
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Server ready on port ${PORT}.`);
    });
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Local Web Cache Poisoning teaching route.  It obtains the real Fusion React
// storefront HTML and deliberately reflects one lab-controlled input into it.
// This route is only published by the surrounding Docker lab at port 8086.
// Tạo response gadget theo scenario; nhánh hardened escape/loại bỏ input nguy hiểm.
function buildLabInjection(req) {
  const scenario = req.labScenario || req.query.lab;
  const hardened = req.get('x-lab-hardened') === '1';
  if (scenario === 'query') {
    // Unlike arbitrary query names, this is an application-supported
    // marketing parameter. The distinct reflection is the response oracle
    // that lets Param Miner's "Guess query params" identify utm_content.
    const hasUtmContent = /(?:[?&])utm_content(?:=|&|$)/.test(req.originalUrl);
    if (!hasUtmContent) return '';
    if (hardened) {
      const safeTarget = req.originalUrl
        .replace(/&/g, '&amp;')
        .replace(/'/g, '&#39;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
      return `<link rel="canonical" href='${safeTarget}'>`;
    }
    // Deliberately vulnerable: the application supports utm_content and
    // reflects the complete raw request target into an HTML attribute only
    // when that supported parameter is present. The cache layer excludes only
    // utm_content, enabling Param Miner discovery.
    // A quote can escape this attribute and create a script element, matching
    // the PortSwigger lab's `'/><script>alert(1)</script>` proof.
    return `<link rel="canonical" href='${req.originalUrl}'>`;
  }
  if (scenario === 'utm') {
    // Every UTM-lab document imports the same cacheable geolocation resource.
    // The resource's callback is the parameter-cloaking gadget.
    const hasUtmContent = /(?:[?&])utm_content(?:=|&|$)/.test(req.originalUrl);
    // This harmless origin-side marker makes utm_content discoverable as an
    // application-supported parameter. It does not alter the cache key.
    const attributionMarker = hasUtmContent ? '<!-- campaign attribution accepted -->' : '';
    return attributionMarker + `<script>function setCountryCookie(data) { document.cookie = 'fusion_country=' + data.country; }</script>` +
      `<script src="${hardened ? '/labs/utm/fixed/js/geolocate.js' : '/labs/utm/js/geolocate.js'}?callback=setCountryCookie"></script>`;
  }
  if (scenario === 'fatget') {
    // Like the PortSwigger fat-GET lab, documents always load a cacheable JS
    // resource. The GET request body is only meaningful at that resource.
    return `<script>function setCountryCookie(data) { document.cookie = 'fusion_country=' + data.country; }</script>` +
      `<script src="${hardened ? '/labs/fatget/fixed/js/geolocate.js' : '/labs/fatget/js/geolocate.js'}?callback=setCountryCookie"></script>`;
  }
  if (scenario === 'split') {
    const redir = String(req.query.redir || '');
    const separator = '\r\n\r\n';
    return redir.includes(separator)
      ? redir.split(separator, 2)[1]
      : String(req.body?.message || '');
  }
  if (hardened) return '';
  const host = req.get('x-forwarded-host') || req.get('host') || 'lab.test';
  const requestedScheme = String(req.get('x-forwarded-proto') || 'https').toLowerCase();
  // The bundled local exploit server exposes HTTP only. Keep external lab
  // hosts HTTPS by default, while ensuring its script can actually load.
  const scheme = host === '127.0.0.1:8087' ? 'http' : (requestedScheme === 'http' ? 'http' : 'https');
  if (scenario === 'xfh') {
    // PortSwigger-style resource-import sink. Nginx omits XFH from this
    // namespace's cache key, but keeps the requested URL in the key.
    return `<script src="${scheme}://${host}/resources/js/tracking.js"></script>`;
  }
  return '';
}

// Mô phỏng parser tách cả '&' và ';' để minh họa UTM parameter cloaking.
function railsStyleCallback(req) {
  // Deliberate parser discrepancy for the parameter-cloaking lab. Nginx sees
  // utm_content=foo;callback=... as one ignored UTM parameter, whereas this
  // Rails-like parser treats ';' as another parameter separator and the final
  // callback wins.
  const rawQuery = (req.originalUrl.split('?', 2)[1] || '');
  let callback = 'setCountryCookie';
  for (const pair of rawQuery.split(/[&;]/)) {
    const [name, ...value] = pair.split('=');
    if (name === 'callback') callback = decodeURIComponent(value.join('=') || '');
  }
  return callback || 'setCountryCookie';
}

// Kiểm tra marketing parameter có mặt trong raw request target.
function hasUtmContent(req) {
  return /(?:[?&])utm_content(?:=|&|$)/.test(req.originalUrl);
}

// Route UTM vulnerable: callback có thể bị thay qua utm_content chứa dấu ';'.
app.get('/labs/utm/js/geolocate.js', (req, res) => {
  const callback = railsStyleCallback(req);
  const attributionMarker = hasUtmContent(req) ? '/* campaign attribution accepted */\n' : '';
  res.type('application/javascript')
    .set('Cache-Control', 'public, max-age=30')
    .send(`${attributionMarker}${callback}({"country":"Vietnam"})`);
});

// Route Fat GET vulnerable: callback trong GET body được ưu tiên hơn query.
app.get('/labs/fatget/js/geolocate.js', (req, res) => {
  // Intentional fat-GET discrepancy: Nginx keys only the callback in the
  // request line, while the application's GET body callback takes precedence.
  const lineCallback = String(req.query.callback || 'setCountryCookie');
  const bodyCallback = String(req.body?.callback || '');
  const callback = bodyCallback || lineCallback;
  res.type('application/javascript')
    .set('Cache-Control', 'public, max-age=30')
    .send(`${callback}({"country":"Vietnam"})`);
});

// Chỉ trả callback allowlist cho hai biến thể fixed của JSONP resource.
function trustedCallback(req) {
  return req.query.callback === 'setCountryCookie' ? 'setCountryCookie' : 'setCountryCookie';
}

// UTM fixed: callback ẩn trong utm_content không đổi được JavaScript trả về.
app.get('/labs/utm/fixed/js/geolocate.js', (req, res) => {
  res.type('application/javascript').set('Cache-Control', 'public, max-age=30')
    .send(`${trustedCallback(req)}({"country":"Vietnam"})`);
});

// Fat GET fixed: bỏ qua body GET khi chọn callback.
app.get('/labs/fatget/fixed/js/geolocate.js', (req, res) => {
  res.type('application/javascript').set('Cache-Control', 'public, max-age=30')
    .send(`${trustedCallback(req)}({"country":"Vietnam"})`);
});

// Lấy HTML React storefront, gắn gadget của lab và giữ navigation dưới /labs/.
async function renderVulnerableStorefront(req, res) {
  try {
    const storefront = await fetch('http://fusion-storefront/');
    if (!storefront.ok) throw new Error(`storefront returned ${storefront.status}`);
    const html = await storefront.text();
    const injection = buildLabInjection(req);
    // The SPA does not know the /labs/<scenario> prefix. Preserve the selected
    // Fusion page visually while the cache operates on the lab namespace URL.
    let targetPath = req.labTargetPath || '/';
    // The /fixed segment is infrastructure-only. Do not expose it to the
    // Fusion SPA router, which only knows normal storefront paths.
    if (req.get('x-lab-hardened') === '1' && (targetPath === '/fixed' || targetPath.startsWith('/fixed/'))) {
      targetPath = targetPath.slice('/fixed'.length) || '/';
    }
    // Keep /labs/... in the address bar. The Fusion SPA has matching lab
    // routes, so reloads and direct navigation continue through the cache.
    const pathFix = '';
    // Fusion is an SPA, so its normal links would otherwise navigate to
    // /shop, /cart, ... without traversing the lab cache route. Intercept
    // same-origin links in capture phase and make a real document request to
    // the corresponding /labs/<scenario>/ path so Burp can observe it.
    const labPrefix = req.labScenario
      ? `/labs/${req.labScenario}${req.get('x-lab-hardened') === '1' ? '/fixed' : ''}`
      : '';
    const labNavigationBridge = req.labScenario
      ? `<script>(() => { const prefix = ${JSON.stringify(labPrefix)};
          document.addEventListener('click', event => {
            if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
            const anchor = event.target.closest && event.target.closest('a[href]');
            if (!anchor || anchor.target || anchor.hasAttribute('download')) return;
            const destination = new URL(anchor.href, location.href);
            if (destination.origin !== location.origin || !destination.pathname.startsWith('/')) return;
            event.preventDefault(); event.stopImmediatePropagation();
            location.assign(prefix + destination.pathname + destination.search + destination.hash);
          }, true);
        })()</script>`
      : '';
    const page = html.replace('</head>', `${pathFix}${labNavigationBridge}${injection}</head>`);
    res.type('html').set('Cache-Control', 'public, max-age=30').send(page);
  } catch (err) {
    console.error('Fusion lab storefront error:', err.message);
    res.status(502).type('text').send('Fusion storefront is unavailable');
  }
}

// Compatibility route used by the earlier scenario selector.
app.get('/lab-store', renderVulnerableStorefront);

// Four isolated lab namespaces on the same Fusion host/port. The scenario is
// selected from the path, never from a client-controlled mode header.
// Ánh xạ URL gốc của từng lab vào cùng renderer của Fusion storefront.
app.get('/labs/:scenario', (req, res) => {
  req.labScenario = req.params.scenario;
  req.labTargetPath = '/';
  return renderVulnerableStorefront(req, res);
});
// Ánh xạ các trang con như /shop và /fixed/shop vào renderer.
app.get('/labs/:scenario/*', (req, res) => {
  req.labScenario = req.params.scenario;
  req.labTargetPath = '/' + req.params[0];
  return renderVulnerableStorefront(req, res);
});

// Root is retained for direct backend access only; public :8086/ is served by
// fusion-storefront and remains a normal, non-lab shop page.
app.get('/', (req, res) => res.redirect('/api-docs'));

// Setup Swagger UI with customized title
setupSwaggerJson(app); // serves /api-docs/swagger.json
setupSwaggerUi(app);

// Routes
app.use('/api/products', productRoutes);
app.use('/api/checkout', checkoutRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/search', require('./routes/search'));
app.use('/api/auth', authRoutes);

module.exports = app;
