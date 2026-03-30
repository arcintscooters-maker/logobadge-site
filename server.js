const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET || '';
const GOOGLE_API_KEY = process.env.GOOGLE_PLACES_API_KEY || '';
const placeCache = {}; // In-memory cache for Google Places data (24h TTL)

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

    // Extract Place ID from Google Maps URL if provided
    if (!placeId && mapsUrl) {
      // Try various Google Maps URL formats
      const cidMatch = mapsUrl.match(/cid=(\d+)/);
      const placeMatch = mapsUrl.match(/place_id[=:]([A-Za-z0-9_-]+)/);
      const dataMatch = mapsUrl.match(/!1s(0x[0-9a-f]+:[0-9a-fx]+)/);
      const hexMatch = mapsUrl.match(/(ChIJ[A-Za-z0-9_-]+)/);

      if (placeMatch) placeId = placeMatch[1];
      else if (hexMatch) placeId = hexMatch[1];
    }

    // If still no Place ID, try Google's Find Place API using the URL
    const cacheKey = placeId || mapsUrl;
    const cached = placeCache[cacheKey];
    if (cached && Date.now() - cached.ts < 86400000) {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify(cached.data));
      return;
    }

    const apiKey = process.env.GOOGLE_PLACES_API_KEY;
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

  // Handle auth callback
  if (req.url.startsWith('/auth/callback')) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h1>App installed successfully!</h1><p>You can close this tab and go to your Theme Editor to add the Google Review Badge block.</p>');
    return;
  }

  // Serve static files
  let filePath = req.url.split('?')[0];

  // If opened from Shopify admin (has shop param or embedded), show setup page
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
