const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET || '';
const GOOGLE_API_KEY = process.env.GOOGLE_PLACES_API_KEY || '';
const placeCache = {}; // In-memory cache for Google Places data (24h TTL)

// --- Inlinex: keep the storefront's shop review metafield in sync with the live Google rating ---
// So Inlinex's LocalBusiness JSON-LD (SEO rich-snippet stars) reads a live value instead of a stale
// hardcode. Fires ONLY for the Inlinex place, only on a fresh Google fetch (≈ every 24h / on restart),
// and never blocks the /api/place response. Needs env INLINEX_ADMIN_TOKEN (write_metafields scope).
const INLINEX_PLACE_ID = 'ChIJ0aYxeAoZ2jERw33McA4nDfE';
const INLINEX_SHOP = 'inline-skate.myshopify.com';
const INLINEX_SHOP_GID = 'gid://shopify/Shop/4392773';
function syncInlinexRating(rating, total) {
  const token = process.env.INLINEX_ADMIN_TOKEN;
  if (!token || rating == null) return;
  const variables = { mf: [
    { ownerId: INLINEX_SHOP_GID, namespace: 'reviews', key: 'rating', type: 'single_line_text_field', value: String(rating) },
    { ownerId: INLINEX_SHOP_GID, namespace: 'reviews', key: 'review_count', type: 'single_line_text_field', value: String(total == null ? '' : total) }
  ]};
  const payload = JSON.stringify({ query: 'mutation($mf:[MetafieldsSetInput!]!){ metafieldsSet(metafields:$mf){ userErrors{ field message } } }', variables });
  const r = require('https').request(`https://${INLINEX_SHOP}/admin/api/2024-10/graphql.json`, {
    method: 'POST',
    headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
  }, (resp) => { let d = ''; resp.on('data', c => d += c); resp.on('end', () => { try { const j = JSON.parse(d); const e = j && j.data && j.data.metafieldsSet && j.data.metafieldsSet.userErrors; if (e && e.length) console.log('Inlinex metafield sync errors:', e); else console.log('Inlinex rating synced:', rating, total); } catch (_) {} }); });
  r.on('error', (e) => console.log('Inlinex metafield sync failed:', e.message));
  r.write(payload); r.end();
}

const MIME = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

function verifyHmac(body, hmacHeader) {
  if (!SHOPIFY_API_SECRET) return true; // Skip if no secret configured
  const hash = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(body).digest('base64');
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(hmacHeader || ''));
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => data += chunk);
    req.on('end', () => resolve(data));
  });
}

const server = http.createServer(async (req, res) => {
  // Handle webhook endpoints
  if (req.method === 'POST' && req.url.startsWith('/webhooks/')) {
    const body = await readBody(req);
    const hmac = req.headers['x-shopify-hmac-sha256'];

    // Verify HMAC signature if secret is configured
    if (SHOPIFY_API_SECRET && hmac) {
      try {
        const hash = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(body).digest('base64');
        if (hash !== hmac) {
          console.log('Webhook HMAC mismatch:', req.url);
          res.writeHead(401); res.end('Unauthorized');
          return;
        }
      } catch (e) {
        console.log('HMAC error:', e.message);
      }
    }

    console.log('Webhook received:', req.url);

    // Respond 200 OK to all compliance webhooks
    // Our app doesn't store customer data so nothing to process
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // Google Places API proxy — fetches rating & review count
  if (req.url.startsWith('/api/place')) {
    const urlParams = new URL(req.url, 'http://localhost');
    let placeId = urlParams.searchParams.get('id');
    const mapsUrl = urlParams.searchParams.get('url');

    if (!placeId && !mapsUrl) {
      res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ error: 'Missing place ID or Maps URL' }));
      return;
    }

    // Extract Place ID or business name from various URL formats
    if (!placeId && mapsUrl) {
      const placeMatch = mapsUrl.match(/place_id[=:]([A-Za-z0-9_-]+)/);
      const hexMatch = mapsUrl.match(/(ChIJ[A-Za-z0-9_-]+)/);
      const kgmidMatch = mapsUrl.match(/kgmid=([^&]+)/);
      const qMatch = mapsUrl.match(/[?&]q=([^&]+)/);

      if (placeMatch) placeId = placeMatch[1];
      else if (hexMatch) placeId = hexMatch[1];
      // For share.google and other redirect URLs, follow the redirect first
      else if (mapsUrl.includes('share.google') || mapsUrl.includes('goo.gl') || mapsUrl.includes('maps.app')) {
        try {
          // Follow redirects up to 5 levels to get the final URL
          const redirectUrl = await new Promise((resolve) => {
            function follow(url, depth) {
              if (depth > 5) { resolve(url); return; }
              const mod = url.startsWith('https') ? require('https') : require('http');
              mod.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } }, (r) => {
                if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) {
                  follow(r.headers.location, depth + 1);
                } else {
                  let d=''; r.on('data',c=>d+=c); r.on('end',()=>resolve(url));
                }
              }).on('error', () => resolve(''));
            }
            follow(mapsUrl, 0);
          });
          if (redirectUrl) {
            const rHex = redirectUrl.match(/(ChIJ[A-Za-z0-9_-]+)/);
            const rQ = redirectUrl.match(/[?&]q=([^&]+)/);
            if (rHex) placeId = rHex[1];
            else if (rQ) {
              // Use business name to find Place ID
              const searchName = decodeURIComponent(rQ[1].replace(/\+/g, ' '));
              const findUrl2 = 'https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=' + encodeURIComponent(searchName) + '&inputtype=textquery&fields=place_id&key=' + GOOGLE_API_KEY;
              const fr = await new Promise((resolve) => {
                require('https').get(findUrl2, (r) => { let d=''; r.on('data',c=>d+=c); r.on('end',()=>{ try{resolve(JSON.parse(d))}catch{resolve(null)} }); }).on('error',()=>resolve(null));
              });
              if (fr?.candidates?.[0]?.place_id) placeId = fr.candidates[0].place_id;
            }
          }
        } catch(e) {}
      }
    }

    // If still no Place ID, try Google's Find Place API using the URL
    const cacheKey = placeId || mapsUrl;
    const cached = placeCache[cacheKey];
    if (cached && Date.now() - cached.ts < 86400000) {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify(cached.data));
      return;
    }

    const apiKey = GOOGLE_API_KEY;
    if (!apiKey) {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ error: 'No API key configured', rating: null }));
      return;
    }

    // If no Place ID extracted, use Find Place API to look it up from the URL
    if (!placeId && mapsUrl) {
      const findUrl = `https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=${encodeURIComponent(mapsUrl)}&inputtype=textquery&fields=place_id&key=${apiKey}`;
      const findResult = await new Promise((resolve) => {
        require('https').get(findUrl, (r) => {
          let d = '';
          r.on('data', c => d += c);
          r.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
        }).on('error', () => resolve(null));
      });
      if (findResult?.candidates?.[0]?.place_id) {
        placeId = findResult.candidates[0].place_id;
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ error: 'Could not find place', rating: null }));
        return;
      }
    }

    const apiUrl = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${encodeURIComponent(placeId)}&fields=rating,user_ratings_total,name&key=${apiKey}`;

    require('https').get(apiUrl, (apiRes) => {
      let data = '';
      apiRes.on('data', c => data += c);
      apiRes.on('end', () => {
        try {
          const result = JSON.parse(data);
          const placeData = {
            rating: result.result?.rating || null,
            total_reviews: result.result?.user_ratings_total || null,
            name: result.result?.name || null
          };
          placeCache[cacheKey] = { data: placeData, ts: Date.now() };
          if (placeId === INLINEX_PLACE_ID) syncInlinexRating(placeData.rating, placeData.total_reviews);
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify(placeData));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ error: 'Parse error' }));
        }
      });
    }).on('error', () => {
      res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ error: 'Fetch error' }));
    });
    return;
  }

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET', 'Access-Control-Allow-Headers': 'Content-Type' });
    res.end();
    return;
  }

  // Handle auth callback - redirect back to app in admin
  if (req.url.startsWith('/auth/callback')) {
    const cbParams = new URL(req.url, 'http://localhost');
    const shop = cbParams.searchParams.get('shop');
    if (shop) {
      res.writeHead(302, { 'Location': `https://${shop}/admin/apps/c8868bcbaffacc769e94c04755c94cc7` });
      res.end();
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><script>window.location.href="/setup";</script></body></html>');
    }
    return;
  }

  // Handle Shopify OAuth install redirect
  if (req.url.startsWith('/api/auth') || req.url.includes('?shop=') && filePath === '/api/auth') {
    const authParams = new URL(req.url, 'http://localhost');
    const shop = authParams.searchParams.get('shop');
    if (shop) {
      // For non-embedded apps, just serve the setup page
      res.writeHead(200, { 'Content-Type': 'text/html' });
      const setupHtml = require('fs').readFileSync(require('path').join(__dirname, 'setup.html'), 'utf8');
      res.end(setupHtml);
      return;
    }
  }

  // Serve static files
  let filePath = req.url.split('?')[0];

  // If opened from Shopify admin, serve setup page directly (works inside iframe)
  if (filePath === '/' && (req.url.includes('shop=') || req.url.includes('hmac=') || req.url.includes('host='))) {
    filePath = '/setup.html';
  } else if (filePath === '/') {
    filePath = '/index.html';
  }
  if (!path.extname(filePath)) filePath += '.html';

  const fullPath = path.join(__dirname, filePath);
  const ext = path.extname(fullPath);

  fs.readFile(fullPath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/html' });
      res.end('<h1>404 - Page Not Found</h1>');
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'text/html' });
    res.end(data);
  });
});

server.listen(PORT, () => console.log(`LogoBadge site running on port ${PORT}`));
