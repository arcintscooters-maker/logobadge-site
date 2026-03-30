const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET || '';

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

  // Handle auth callback
  if (req.url.startsWith('/auth/callback')) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<h1>App installed successfully!</h1><p>You can close this tab and go to your Theme Editor to add the Google Review Badge block.</p>');
    return;
  }

  // Serve static files
  let filePath = req.url.split('?')[0];
  if (filePath === '/') filePath = '/index.html';
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
