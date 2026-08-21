/**
 * Mock OPNsense appliance — end-to-end test double for plan execution.
 *
 * Runs on the host network (docker-compose `mock-appliance` service) so it can
 * bind :80 and :443 directly; plugin containers reach it as
 * http(s)://host.docker.internal (bare hostname, since device managementAddress
 * never carries a scheme/port). Answers the endpoints the OPNsense plugin
 * probes/executes in CE mode:
 *   - edition probe  /api/opncentral/...        → 403 (Community Edition)
 *   - backend probes unbound/kea                → disabled (dnsmasq backends)
 *   - snapshots supported + add returns a uuid
 *   - wireguard server/client/service endpoints return deterministic uuids
 * Every request is captured in memory and served at GET /__requests (the e2e
 * script asserts on it); POST /__reset clears the capture.
 */
'use strict';

const http = require('http');
const https = require('https');
const crypto = require('crypto');

// --- Self-signed cert for :443 (generated once at boot) -------------------------

function makeSelfSignedCert() {
  // Prefer certs mounted at /mock/tls (generated on the host — see
  // docker-compose.yml); fall back to minting one via `openssl req -x509`.
  try {
    const fs = require('fs');
    if (fs.existsSync('/mock/tls/cert.pem') && fs.existsSync('/mock/tls/key.pem')) {
      return {
        key: fs.readFileSync('/mock/tls/key.pem', 'utf8'),
        cert: fs.readFileSync('/mock/tls/cert.pem', 'utf8'),
      };
    }
  } catch (err) {
    console.warn('[mock] mounted TLS unavailable, falling back to openssl:', err.message);
  }
  // node:crypto cannot build X.509 certs in pure JS, so use `openssl req -x509`
  // (node:20-alpine ships without it — the compose entrypoint installs it).
  const { execFileSync } = require('child_process');
  try {
    const out = execFileSync(
      'openssl',
      [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-keyout', '/dev/stdout', '-subj', '/CN=mock-opnsense.local',
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    ).toString();
    // openssl prints the key + cert to stdout; split on the CERTIFICATE marker.
    const certIdx = out.indexOf('-----BEGIN CERTIFICATE-----');
    const keyIdx = out.indexOf('-----BEGIN PRIVATE KEY-----');
    if (certIdx === -1 || keyIdx === -1) throw new Error('unexpected openssl output');
    return { key: out.slice(keyIdx), cert: out.slice(certIdx) };
  } catch (err) {
    console.warn('[mock] openssl unavailable, HTTPS disabled:', err.message);
    return null;
  }
}

// --- Request capture -------------------------------------------------------------

const captured = [];
function record(method, url, user, body) {
  captured.push({ t: Date.now(), method, url, user, body });
  if (captured.length > 500) captured.shift();
}

// --- OPNsense endpoint behavior (CE mode) ----------------------------------------

const servers = new Map(); // apiKey(username) -> [uuids]
function uuid(prefix) {
  return `${prefix}-${crypto.randomBytes(4).toString('hex')}`;
}

function handleOpnsense(req, res, user, body) {
  const url = (req.url ?? '/').split('?')[0];
  const json = (status, data) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  };

  if (url.startsWith('/api/opncentral/')) return json(403, { error: 'forbidden' }); // CE
  if (url === '/api/unbound/overview/is_enabled') return json(200, { enabled: false });
  if (url === '/api/kea/service/status') return json(200, { running: false });

  switch (url) {
    case '/api/core/system/status':
      return json(200, { metadata: { system: { status: 2 } } });
    case '/api/diagnostics/cpu_usage/stream':
      res.writeHead(200, { 'Content-Type': 'text/event-stream' });
      res.write('event: message\ndata: {"total":11,"user":1,"nice":0,"sys":7,"intr":8,"idle":89}\n\n');
      return setTimeout(() => res.end(), 200);
    case '/api/diagnostics/system/system_resources':
      return json(200, { memory: { total: '8589934592', used: '4294967616' } });
    case '/api/diagnostics/system/system_information':
      return json(200, { name: 'mock-fw', versions: ['OPNsense 24.1'] });
    case '/api/diagnostics/interface/get_interface_names':
      return json(200, { wan: {}, lan: {} });
    case '/api/diagnostics/interface/get_interface_statistics':
      return json(200, { statistics: { 'igc0 / aa:bb:cc:dd:ee:ff': { name: 'wan', 'received-bytes': 1, 'sent-bytes': 2, address: 'aa:bb:cc:dd:ee:ff' } } });
    case '/api/diagnostics/interface/search_arp/':
      return json(200, { rows: [] });
    case '/api/diagnostics/interface/search_ndp/':
      return json(200, { rows: [] });
    // Snapshots (rollback points) — supported on this mock.
    case '/api/core/snapshots/is_supported':
      return json(200, true);
    case '/api/core/snapshots/add':
      return json(200, { uuid: uuid(`snap-${user}`) });
    // WireGuard.
    case '/api/wireguard/server/list_servers':
      return json(200, { rows: [] });
    case '/api/wireguard/client/get':
      return json(200, { rows: [] });
    case '/api/wireguard/server/add_server': {
      const id = uuid(`server-${user}`);
      servers.set(user, [...(servers.get(user) ?? []), id]);
      return json(200, { uuid: id });
    }
    case '/api/wireguard/client/add_client_builder':
      return json(200, { uuid: uuid(`peer-${user}`) });
    case '/api/wireguard/service/reconfigure':
      return json(200, {});
    default:
      return json(404, { error: 'not found' });
  }
}

// --- HTTP + HTTPS servers ----------------------------------------------------------

function readBody(req, cb) {
  let data = '';
  req.on('data', (c) => (data += c));
  req.on('end', () => cb(data));
}

function handler(req, res) {
  const url = (req.url ?? '/').split('?')[0];
  readBody(req, (raw) => {
    let body;
    try { body = raw ? JSON.parse(raw) : {}; } catch { body = { _raw: raw }; }

    // Test-control endpoints (not part of the OPNsense API).
    if (url === '/__requests') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(captured));
    }
    if (url === '/__reset') {
      captured.length = 0;
      servers.clear();
      res.writeHead(204);
      return res.end();
    }

    const auth = req.headers.authorization ?? '';
    let user = 'anon';
    if (auth.startsWith('Basic ')) {
      try { user = decodeURIComponent(Buffer.from(auth.slice(6), 'base64').toString().split(':')[0]); } catch { /* keep anon */ }
    }

    record(req.method, url, user, body);
    handleOpnsense(req, res, user, body);
  });
}

const tls = makeSelfSignedCert();
http.createServer(handler).listen(80, () => console.log('[mock] OPNsense mock appliance on :80'));
if (tls) {
  https.createServer({ key: tls.key, cert: tls.cert }, handler).listen(443, () => console.log('[mock] OPNsense mock appliance on :443 (self-signed)'));
} else {
  console.warn('[mock] HTTPS disabled — devices must use transport=http');
}
