#!/usr/bin/env node
/**
 * Webapp runtime server — static SPA + same-origin API proxy.
 *
 * The pre-built bundle ships with the RELATIVE API base "/v1" (see src/api/client.ts),
 * i.e. it expects UI and API on ONE origin. This tiny zero-dependency server provides
 * that in every deployment without an external reverse proxy:
 *
 *   - serves dist/ statically, with SPA fallback to index.html for unknown paths
 *     (same behavior as `serve -s dist`)
 *   - forwards /v1/* to UNM_API_TARGET (default http://api:3000), including the SSH
 *     console WebSocket upgrade (/v1/devices/:id/console/ws) via raw socket piping
 *
 * Env:
 *   PORT            listen port (default 8080 — matches the compose deployments)
 *   UNM_API_TARGET  API origin to proxy /v1/* to (no trailing slash; default http://api:3000)
 */

'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const DIST = process.env.WEBAPP_DIST || path.join(__dirname, 'dist');
const PORT = Number(process.env.PORT || 8080);
// No trailing slash — the /v1 prefix is preserved when forwarding.
const API_TARGET = (process.env.UNM_API_TARGET || 'http://api:3000').replace(/\/+$/, '');

let target;
try {
  target = new URL(API_TARGET);
} catch {
  console.error(`[webapp] invalid UNM_API_TARGET "${API_TARGET}"`);
  process.exit(1);
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.map': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};

function sendFile(res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  res.writeHead(200, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    // Static assets are immutable per build (hashed names); index.html is not.
    'Cache-Control': filePath.endsWith('index.html') ? 'no-cache' : 'public, max-age=31536000, immutable',
  });
  fs.createReadStream(filePath).pipe(res);
}

/** Serve dist/ statically; unknown non-asset paths fall back to index.html (SPA routing). */
function serveStatic(req, res) {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  } catch {
    res.writeHead(400).end('Bad Request');
    return;
  }
  const filePath = path.normalize(path.join(DIST, pathname));
  if (!filePath.startsWith(DIST + path.sep) && filePath !== DIST) {
    res.writeHead(403).end('Forbidden'); // path traversal guard
    return;
  }
  fs.stat(filePath, (err, stat) => {
    if (!err && stat.isFile()) return sendFile(res, filePath);
    const index = path.join(DIST, 'index.html');
    fs.stat(index, (e2) => {
      if (e2) res.writeHead(404).end('Not Found');
      else sendFile(res, index);
    });
  });
}

/** Forward a plain HTTP request to the API, streaming both directions. */
function proxyRequest(req, res) {
  const headers = { ...req.headers, host: target.host };
  delete headers['x-forwarded-for']; // we are not behind a proxy — don't forge it for the API
  const upstream = http.request(
    {
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      path: req.url, // /v1/... preserved as-is
      method: req.method,
      headers,
    },
    (up) => {
      res.writeHead(up.statusCode || 502, up.headers);
      up.pipe(res);
    }
  );
  upstream.on('error', (err) => {
    if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: `api unreachable: ${err.message}` }));
  });
  req.pipe(upstream);
}

/** WebSocket upgrade (SSH console): pipe the raw sockets both ways once the API accepts. */
function proxyUpgrade(req, socket) {
  const headers = { ...req.headers, host: target.host };
  delete headers['x-forwarded-for'];
  const upstream = http.request({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port || (target.protocol === 'https:' ? 443 : 80),
    path: req.url,
    method: req.method,
    headers,
  });
  // The API can answer a handshake with a plain HTTP error (e.g. 401 unauthenticated)
  // instead of upgrading — relay that so the client's WebSocket errors out promptly.
  upstream.on('response', (upRes) => {
    const body = [];
    upRes.on('data', (c) => body.push(c));
    upRes.on('end', () => {
      socket.write(
        `HTTP/1.1 ${upRes.statusCode || 502}\r\n` +
          upRes.rawHeaders.map((h) => `${h[0]}: ${h[1]}`).join('\r\n') +
          '\r\n\r\n' +
        Buffer.concat(body).toString('binary')
      );
      socket.end();
    });
  });
  upstream.on('upgrade', (upRes, upSocket) => {
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\n` +
        upRes.rawHeaders.map((h) => `${h[0]}: ${h[1]}`).join('\r\n') +
        '\r\n\r\n'
    );
    upSocket.pipe(socket);
    socket.pipe(upSocket);
  });
  upstream.on('error', (err) => {
    socket.write(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\napi unreachable: ${err.message}\n`);
    socket.destroy();
  });
  req.pipe(upstream);
}

const server = http.createServer((req, res) => {
  if (req.url.startsWith('/v1/') || req.url === '/v1') return proxyRequest(req, res);
  serveStatic(req, res);
});
server.on('upgrade', (req, socket) => {
  if (req.url.startsWith('/v1/')) return proxyUpgrade(req, socket);
  socket.destroy(); // no other WebSocket routes exist
});

server.listen(PORT, () => {
  console.log(`[webapp] serving ${DIST} on :${PORT}, proxying /v1/* → ${API_TARGET}`);
});
