'use strict';
/**
 * Mock Shelly device server for the E2E smoke test (smoke-test.ts).
 *
 * Test-grade emulation of three Shelly profiles:
 *
 *   'gen1'         — legacy REST (ESP8266): GET /shelly (auth-free), GET /status,
 *                    GET /ota[?update=true], POST /reboot, POST /relay/{id}?turn=on|off
 *   'gen2-classic' — JSON-RPC 2.0 with fw 1.x namespaces: Shelly.*, WiFi.*, Firmware.*
 *   'gen2-modern'  — JSON-RPC 2.0 with fw 2.x+ namespaces: Sys.*, Wifi.*, Firmware.*
 *
 * Behaviors emulated:
 *   - Reboot window: after an accepted firmware update or reboot the socket is
 *     destroyed for `rebootMs`, then the device "comes back" (an update bumps
 *     the running firmware to `latestFw` and clears the pending update).
 *   - Local login: when `authEnabled`, Gen1 requires HTTP Basic on /status,
 *     /ota and /relay; Gen2+ enforces the shellyun-auth cookie handshake (first
 *     request with valid Basic gets Set-Cookie, later requests may use the cookie).
 *   - Relay control: state.relays[] tracks each relay's ison; Gen1 POST
 *     /relay/{id}?turn=on|off and (both namespaces) Switch.Set {id, on} all
 *     mutate it. Out-of-range ids answer 404 (Gen1) / -32602 Invalid params
 *     (RPC).
 *   - Unknown RPC methods answer with JSON-RPC error -32601 — this is what
 *     makes the plugin's namespace detection distinguish classic from modern.
 */

const http = require('node:http');

const COOKIE_NAME = 'shellyun-auth';
const MOCK_COOKIE_VALUE = 'mock-shellyun-session';

/**
 * Starts one mock Shelly device on `port`.
 *
 * @param {object} opts
 * @param {number} opts.port            TCP port to listen on.
 * @param {'gen1'|'gen2-classic'|'gen2-modern'} [opts.profile='gen1']
 * @param {string} [opts.name]          Device name (shelly.name / Sys.GetDeviceInfo.name).
 * @param {string} [opts.model]         Model code (Gen1 `type`, RPC device `id`).
 * @param {string} [opts.mac]           MAC address.
 * @param {string} [opts.fw]            Running firmware version.
 * @param {string|null} [opts.latestFw=null]  Pending update target (null = up to date).
 * @param {boolean} [opts.authEnabled=false]  Simulate local login enabled.
 * @param {string} [opts.username='admin']
 * @param {string} [opts.password='***']
 * @param {number} [opts.rssi=-62]      WiFi RSSI in dBm.
 * @param {string} [opts.ssid]          Connected SSID.
 * @param {number} [opts.rebootMs=700]  Simulated reboot window after update/reboot.
 * @returns {{ server: http.Server, state: object }}
 */
function startMockShelly(opts) {
  const port = opts.port;
  const profile = opts.profile ?? 'gen1';
  const state = {
    profile,
    port, // the port this mock listens on (smoke test uses m.state.port)
    name: opts.name ?? `Mock ${profile}`,
    model: opts.model ?? (profile === 'gen1' ? 'SHSW-1' : profile === 'gen2-classic' ? 'SWN-1PM' : 'Pro4Gen4'),
    mac: opts.mac ?? 'AABBCCDDEEFF',
    fw: opts.fw ?? (profile === 'gen1' ? '4.5.0' : profile === 'gen2-classic' ? '1.4.1' : '2.0.5'),
    latestFw: opts.latestFw ?? null,
    authEnabled: opts.authEnabled ?? false,
    username: opts.username ?? 'admin',
    password: opts.password ?? 'mockpw',
    rssi: opts.rssi ?? -62,
    ssid: opts.ssid ?? 'KirgusNET_IoT',
    rebootMs: opts.rebootMs ?? 700,
    // Relay states (index = relay id). Relay 0 starts ON like the status payloads.
    relays: [true],
    // --- observability for assertions ---
    downUntil: 0,
    updateTriggers: 0,
    reboots: 0,
    rpcCalls: [], // every method name the device answered (in order)
    basicAuthSeen: false,
    cookieIssued: 0,
    cookieUses: 0,
    badAuth: 0,
  };

  const timers = new Set();
  const later = (fn, ms) => {
    const t = setTimeout(() => {
      timers.delete(t);
      fn();
    }, ms);
    timers.add(t);
    return t;
  };

  const expectedBasic = `Basic ${Buffer.from(`${state.username}:${state.password}`).toString('base64')}`;

  /** True when the request carries valid Basic or a previously issued cookie. */
  function authOk(req) {
    if (!state.authEnabled) return true;
    const cookie = String(req.headers['cookie'] ?? '');
    if (cookie.includes(`${COOKIE_NAME}=${MOCK_COOKIE_VALUE}`)) {
      state.cookieUses += 1;
      return true;
    }
    if (req.headers['authorization'] === expectedBasic) {
      state.basicAuthSeen = true;
      return true;
    }
    state.badAuth += 1;
    return false;
  }

  function beginDownWindow(bumpFirmware) {
    state.downUntil = Date.now() + state.rebootMs;
    later(() => {
      if (bumpFirmware && state.latestFw) {
        state.fw = state.latestFw;
        state.latestFw = null;
      }
    }, state.rebootMs);
  }

  function updateBlock() {
    // Real devices report old_version/new_version only while an update is pending.
    return state.latestFw
      ? { has_update: true, new_version: state.latestFw, old_version: state.fw }
      : { has_update: false };
  }

  function acceptUpdate() {
    if (!state.latestFw) return false;
    state.updateTriggers += 1;
    beginDownWindow(true);
    return true;
  }

  // --- Gen2 RPC dispatch ----------------------------------------------------

  const CLASSIC_METHODS = new Set([
    'Shelly.GetDeviceInfo', 'Shelly.GetStatus', 'WiFi.GetStatus',
    'Firmware.GetStatus', 'Shelly.Update', 'Shelly.Reboot', 'Switch.Set',
  ]);
  const MODERN_METHODS = new Set([
    'Sys.GetDeviceInfo', 'Sys.GetStatus', 'Wifi.GetStatus',
    'Firmware.GetStatus', 'Firmware.Update', 'Sys.Reboot', 'Switch.Set',
  ]);

  function dispatchRpc(method, params) {
    const isClassic = profile === 'gen2-classic';
    const allowed = isClassic ? CLASSIC_METHODS : MODERN_METHODS;
    if (!allowed.has(method)) return { __error: { code: -32601, message: `Method not found: ${method}` } };

    switch (method) {
      case 'Shelly.GetDeviceInfo':
      case 'Sys.GetDeviceInfo':
        return { id: state.model, mac: state.mac, fw_version: state.fw, name: state.name };
      case 'Shelly.GetStatus':
      case 'Sys.GetStatus':
        return {
          // Official Gen2+ docs: sys.uptime in SECONDS, RAM as ram_free/ram_size (bytes).
          sys: { uptime: 3600, temperature_c: 35, ram_free: 45000, ram_size: 87300 },
          relay: state.relays.map((on, id) => ({ id, ison: on })),
        };
      case 'WiFi.GetStatus':
      case 'Wifi.GetStatus':
        return { sta_ip: '192.168.7.50', rssi: state.rssi, ssid: state.ssid, bssid: 'AA:BB:CC:DD:EE:FF', channel: 6 };
      case 'Firmware.GetStatus':
        return updateBlock();
      case 'Shelly.Update':
      case 'Firmware.Update': {
        // stage/url are accepted but not emulated beyond the version bump.
        void params;
        if (!acceptUpdate()) return { __error: { code: -32601, message: 'No update available' } };
        return {};
      }
      case 'Shelly.Reboot':
      case 'Sys.Reboot':
        state.reboots += 1;
        beginDownWindow(false);
        return {};
      case 'Switch.Set': {
        // Gen2+ (both namespaces): Switch.Set {id, on} → {was_on}.
        const id = Number(params?.id);
        if (!Number.isInteger(id) || id < 0 || id >= state.relays.length || typeof params?.on !== 'boolean') {
          return { __error: { code: -32602, message: 'Invalid params' } };
        }
        const wasOn = state.relays[id];
        state.relays[id] = params.on;
        return { was_on: wasOn };
      }
      default:
        return { __error: { code: -32601, message: `Method not found: ${method}` } };
    }
  }

  // --- HTTP server -----------------------------------------------------------

  const server = http.createServer((req, res) => {
    // Simulated reboot window — the device is off.
    if (Date.now() < state.downUntil) {
      req.socket.destroy();
      return;
    }

    const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);

    // --- Gen1 REST ----------------------------------------------------------
    if (profile === 'gen1') {
      if (req.method === 'GET' && url.pathname === '/shelly') {
        // Auth-free on real devices even when local login is enabled.
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: `SHELLY-${state.mac}`, mac: state.mac, fw: state.fw, type: state.model, name: state.name }));
        return;
      }
      if (!authOk(req)) {
        res.writeHead(401, { 'Content-Type': 'application/json', 'WWW-Authenticate': 'Basic realm="shelly"' });
        res.end(JSON.stringify({ error: 'authentication required' }));
        return;
      }
      if (req.method === 'GET' && url.pathname === '/status') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          // Official Gen1 docs: top-level ram_*/fs_* fields, uptime in seconds.
          wifi_sta: { connected: true, ssid: state.ssid, ip: '192.168.7.50', rssi: state.rssi },
          update: updateBlock(),
          uptime: 3600,
          ram_total: 87300,
          ram_free: 45000,
          ram_lwm: 4096,
          fs_size: 262144,
          fs_free: 200000,
          relay: state.relays.map((on) => ({ ison: on })),
        }));
        return;
      }
      if (req.method === 'GET' && url.pathname === '/ota' && url.searchParams.get('update') !== 'true') {
        // Real devices answer 200 with the status object even when nothing is
        // pending ({has_update:false}) — a 404 here would make the plugin treat
        // "checked, up to date" as a transport failure and omit the key.
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ota: 'idle', ...updateBlock() }));
        return;
      }
      if (req.method === 'GET' && url.pathname === '/ota' && url.searchParams.get('update') === 'true') {
        if (!acceptUpdate()) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'no update available' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
        return;
      }
      if (req.method === 'POST' && url.pathname === '/reboot') {
        state.reboots += 1;
        beginDownWindow(false);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
        return;
      }
      const relayMatch = /^\/relay\/(\d+)$/.exec(url.pathname);
      if (relayMatch) {
        // Gen1: POST /relay/{id}?turn=on|off sets the state and answers with it.
        const idx = Number(relayMatch[1]);
        if (idx >= state.relays.length) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `no such relay: ${idx}` }));
          return;
        }
        const turn = url.searchParams.get('turn');
        if (turn === 'on' || turn === 'off') state.relays[idx] = turn === 'on';
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ison: state.relays[idx], was_just_set_up: false }));
        return;
      }
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `no such route: ${req.method} ${url.pathname}` }));
      return;
    }

    // --- Gen2+ JSON-RPC -------------------------------------------------------
    if (req.method !== 'POST' || url.pathname !== '/rpc') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `no such route: ${req.method} ${url.pathname}` }));
      return;
    }

    let rawBody = '';
    req.on('data', (c) => (rawBody += c));
    req.on('end', () => {
      if (!authOk(req)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'authentication required' }));
        return;
      }
      // Cookie handshake: a Basic-authenticated request earns the session cookie.
      if (state.authEnabled && req.headers['authorization'] === expectedBasic && !String(req.headers['cookie'] ?? '').includes(COOKIE_NAME)) {
        res.setHeader('Set-Cookie', `${COOKIE_NAME}=${MOCK_COOKIE_VALUE}; Path=/; HttpOnly`);
        state.cookieIssued += 1;
      }
      let calls;
      try {
        calls = JSON.parse(rawBody || '[]');
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
        return;
      }
      if (!Array.isArray(calls)) calls = [calls];
      const out = calls.map((c) => {
        state.rpcCalls.push(c.method);
        const r = dispatchRpc(c.method, c.params);
        return r.__error
          ? { jsonrpc: '2.0', id: c.id, error: r.__error }
          : { jsonrpc: '2.0', id: c.id, result: r };
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(out));
    });
  });

  server.on('close', () => {
    for (const t of timers) clearTimeout(t);
    timers.clear();
  });

  return { server, state };
}

module.exports = { startMockShelly, COOKIE_NAME, MOCK_COOKIE_VALUE };
