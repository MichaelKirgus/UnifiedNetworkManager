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

// --- Firewall event log + state-table behavior ---------------------------------
// Models the /api/diagnostics/firewall/* surface (live-verified on OPNsense 26.x):
//   - `log` is a BARE array, newest-first, with per-row unique `__digest__`; passing
//     `digest=D` returns rows at-or-newer-than D (inclusive). Digests are zero-padded
//     and assigned chronologically, so "newer" == string >= compare.
//   - `query_states` / `pf_states` / `pf_statistics/*` return the aggregate shapes
//     the plugin's firewallEvents client consumes.
const fwEvents = []; // {__digest__, __timestamp__, action, reason, interface, src, dst, protoname, srcport, dstport, rid, label}
let fwSeq = 0;
function addFwEvent(e) {
  fwSeq += 1;
  const digest = `evt-${String(fwSeq).padStart(6, '0')}`;
  fwEvents.push({ ...e, __digest__: digest });
  return digest;
}
function seedFwEvents() {
  // Appliance-local wall clock "YYYY-MM-DDTHH:MM:SS" (no TZ), newest last. The
  // field name MUST be `__timestamp__` — that is what the real appliance emits
  // and what the plugin's RawEventRow parser reads.
  const t = (offsetSec) => new Date(Date.now() - offsetSec * 1000).toISOString().slice(0, 19);
  addFwEvent({ __timestamp__: t(3600), action: 'pass', reason: '', interface: 'lan', src: '192.168.1.50', dst: '93.184.216.34', protoname: 'tcp', srcport: 51234, dstport: 443, rid: 'rule-allow-web', label: 'Allow LAN web' });
  addFwEvent({ __timestamp__: t(3000), action: 'block', reason: 'matched rule', interface: 'wan', src: '203.0.113.9', dst: '192.168.1.1', protoname: 'tcp', srcport: 4444, dstport: 22, rid: 'rule-block-ssh', label: 'Block WAN ssh' });
  addFwEvent({ __timestamp__: t(2000), action: 'pass', reason: '', interface: 'lan', src: '192.168.1.77', dst: '142.250.0.1', protoname: 'udp', srcport: 53000, dstport: 53, rid: 'rule-allow-dns', label: 'Allow DNS' });
  addFwEvent({ __timestamp__: t(1000), action: 'rdr', reason: '', interface: 'wan', src: '203.0.113.9', dst: '10.0.0.2', protoname: 'tcp', srcport: 80, dstport: 8080, rid: 'rule-rdr-http', label: 'RDR http' });
}
function resetFw() {
  fwEvents.length = 0;
  fwSeq = 0;
  seedFwEvents();
}
seedFwEvents();

/** "at or newer than digest (inclusive)", newest-first. */
function fwLogRows(digest) {
  let rows = fwEvents;
  if (digest) rows = fwEvents.filter((e) => e.__digest__ >= digest);
  return [...rows].reverse();
}

const FW_STATE_ROWS = [
  { label: 'rule-allow-web', descr: 'Allow LAN web', iface: 'lan', proto: 'tcp', ipproto: '6', direction: 'out', src_addr: '192.168.1.50', src_port: '51234', dst_addr: '93.184.216.34', dst_port: '443', state: 'ESTABLISHED:ESTABLISHED', age: '00:01:23', expires: '00:58:37', pkts: [10, 9], bytes: [1000, 900], rule: '1', id: 's1' },
  { label: 'rule-allow-dns', descr: 'Allow DNS', iface: 'lan', proto: 'udp', ipproto: '17', direction: 'out', src_addr: '192.168.1.77', src_port: '53000', dst_addr: '142.250.0.1', dst_port: '53', state: 'UDP', age: '00:00:05', expires: '00:01:55', pkts: [2, 2], bytes: [200, 200], rule: '2', id: 's2' },
  { label: 'rule-allow-web', descr: 'Allow LAN web', iface: 'lan', proto: 'tcp', ipproto: '6', direction: 'out', src_addr: '192.168.1.50', src_port: '51300', dst_addr: '93.184.216.34', dst_port: '443', state: 'ESTABLISHED:ESTABLISHED', age: '01:23:45', expires: '02:36:15', pkts: [50, 49], bytes: [5000, 4900], rule: '1', id: 's3' },
];

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
      // Deterministic neighbors so the API's normalized `hosts` table gets data.
      return json(200, {
        rows: [
          { mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.50', intf: 'lan', manufacturer: 'Intel' },
          { mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.100.10', intf: 'vlan100', manufacturer: 'Apple' },
        ],
      });
    case '/api/diagnostics/interface/search_ndp/':
      return json(200, {
        rows: [
          { mac: 'aa:bb:cc:dd:ee:03', ip: 'fd00::50', intf: 'lan', manufacturer: '' },
        ],
      });
    // Inventory collection (Networks page): the REAL recordset shape from
    // searchRecordsetBase — assigned interfaces carry `config` + `identifier`,
    // addresses are CIDR strings, VLAN tags ride on the row.
    case '/api/interfaces/overview/interfaces_info':
      return json(200, {
        total: 3,
        rows: [
          { identifier: 'lan', description: 'LAN', device: 'igb0', macaddr: 'aa:bb:cc:dd:ee:ff', status: 'up', ipv4: [{ ipaddr: '192.168.1.1/24' }], vlan_tag: null, config: { if: 'igb0', descr: 'LAN', enable: '1' } },
          { identifier: 'wan', description: 'WAN', device: 'igc0', macaddr: 'aa:bb:cc:dd:ee:0f', status: 'up', ipv4: [{ ipaddr: '10.0.0.2/24' }], vlan_tag: null, config: { if: 'igc0', descr: 'WAN', enable: '1' } },
          { identifier: 'opt1', description: 'Guests', device: 'vlan0.100', macaddr: 'aa:bb:cc:dd:ee:10', status: 'up', ipv4: [{ ipaddr: '192.168.100.1/24' }], vlan_tag: 100, config: { if: 'vlan0.100', descr: 'Guests', enable: '1' } },
        ],
      });
    case '/api/interfaces/vlan_settings/get':
      return json(200, [
        { interface: 'igb0', vlanid: 100, description: 'guests' },
      ]);
    // Inventory collection (Hosts page): dnsmasq leases (mock runs dnsmasq backend).
    case '/api/dnsmasq/leases/search':
      return json(200, {
        rows: [
          { mac: 'aa:bb:cc:dd:ee:01', ipaddress: '192.168.1.50', hostname: 'laptop-1', interface: 'lan', expires: Math.floor(Date.now() / 1000) + 3600 },
          { mac: 'aa:bb:cc:dd:ee:04', ipaddress: '192.168.1.77', hostname: '', interface: 'lan', expires: Math.floor(Date.now() / 1000) + 7200 },
        ],
      });
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
    // Firewall event log + state table (Firewall Events page / Sessions section).
    case '/api/diagnostics/firewall/log': {
      const q = new URLSearchParams((req.url ?? '').split('?')[1] ?? '');
      return json(200, fwLogRows(q.get('digest')));
    }
    case '/api/diagnostics/firewall/query_states': {
      // The plugin sends {rowCount, current, sort:{age:'desc'}} — honor the cap.
      const n = Math.max(1, Math.min(50, Number(body?.rowCount) || 5));
      return json(200, { rows: FW_STATE_ROWS.slice(0, n), rowCount: n, total: FW_STATE_ROWS.length, current: 1 });
    }
    case '/api/diagnostics/firewall/pf_states':
      // Strings on the real appliance — the plugin numOrNull()s them.
      return json(200, { current: '42', limit: '65536' });
    case '/api/diagnostics/firewall/pf_statistics/timeouts':
      return json(200, {
        timeouts: {
          'tcp.first': '10s', 'tcp.opening': '80s', 'tcp.established': '3600s',
          'udp.single': '60s', 'icmp.first': '5s',
          'adaptive.start': '1000 states', 'adaptive.end': '5000 states',
        },
      });
    case '/api/diagnostics/firewall/pf_statistics/info':
      return json(200, {
        info: {
          'state-table': { 'current-entries': { total: 42 }, searches: { total: 1000, rate: 3.5 }, inserts: { total: 100, rate: 0.5 }, removals: { total: 98, rate: 0.4 } },
          counters: { 'state-mismatch': { total: 2 } },
          'limit-counters': { 'synfloods-detected': { total: 7 } },
        },
      });
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
      resetFw();
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
