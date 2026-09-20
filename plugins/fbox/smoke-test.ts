/**
 * End-to-end smoke test for the FBox plugin.
 *
 * Boots a MOCK AVM router (plain HTTP, real SID-cookie login semantics):
 *   - :48751  full box — systeminfo64.json + overview.lua + internetinfo.json
 *              + laninfo.json + wlan0/wlan1 radios, with mutable session state
 * then boots the REAL plugin (src/index.ts on PORT=48752) and exercises:
 *   - GET  /discover    → identity, secret type, options, model catalog
 *   - POST /monitoring  → system/WAN/LAN/WiFi metrics + inventory keys;
 *                          bad creds → critical; non-AVM target → unknown;
 *                          session expiry mid-poll → transparent re-login.
 */
import crypto from 'crypto';
import http from 'http';

const MOCK_PORT = 48751;
const HTML2_MOCK_PORT = 48754; // html2-generation mock box (PBKDF2 login + /data.lua)
const UNSUPPORTED_TARGET_PORT = 48753; // must NOT collide with PLUGIN_PORT
const PLUGIN_PORT = 48752;
const BASE = `http://localhost:${PLUGIN_PORT}`;

/** Read the full request body as a utf-8 string. */
function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => resolve(data));
  });
}

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) {
    console.log(`  ✅ ${label}`);
  } else {
    failures++;
    console.error(`  ❌ ${label}${extra !== undefined ? ` — got: ${JSON.stringify(extra)}` : ''}`);
  }
}

// --- Mock box ---------------------------------------------------------------------------

interface MockState {
  sid: string; // current valid session id ('' = none)
  loginCount: number;
  requests: string[];
  /** When true, the next data request returns a login redirect (session expired). */
  expireNextDataRequest: boolean;
}

function makeMockBox(port: number): http.Server & { state: MockState } {
  const state: MockState = { sid: 'MOCKSID-001', loginCount: 0, requests: [], expireNextDataRequest: false };

  const systeminfo = {
    name: 'RouterLab-1',
    model: 'Vendor Router 7590',
    version: '183.09',
    uptime: 123456,
    temperature: 42,
    load: 12,
    memorytotal: 2_000_000_000,
    memoryused: 700_000_000,
  };

  const overview = {
    lan: {
      ip: '192.168.178.1',
      netmask: '255.255.255.0',
      dns1: '192.168.178.1',
      devices: [
        { mac: 'AA:BB:CC:DD:EE:01', ip: '192.168.178.10', name: 'laptop-01' },
        { mac: 'aa-bb-cc-dd-ee-02', ip: '192.168.178.11', name: '' }, // dash MAC + no hostname
        { mac: '', ip: '192.168.178.12' }, // no MAC — must be skipped by the parser
      ],
    },
    wan: { ip: '80.123.45.67', dns1: '1.1.1.1', dns2: '9.9.9.9' },
  };

  const internetinfo = { connectiontype: 'ipclient', online: true, ip: '80.123.45.67', dns1: '1.1.1.1', dns2: '9.9.9.9' };

  const laninfo = {
    eth0: { ifname: 'eth0', speed: 1000, duplex: 'full', status: 'up' },
    eth1: { ifname: 'eth1', speed: 100, duplex: 'half', status: 'down' },
  };

  const wlan = (ifname: string, ssid: string, channel: number, band: string, clients: unknown[]) => ({
    ifname,
    ssid,
    channel,
    band,
    encryption: 'wpa2',
    clients,
  });

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://localhost:${port}`);
    state.requests.push(`${req.method} ${url.pathname}${url.search}`);

    // --- login endpoint ---------------------------------------------------------
    if (url.pathname === '/login_sid.lua') {
      state.loginCount++;
      const user = url.searchParams.get('username');
      const pass = url.searchParams.get('password');
      if (user !== 'admin' || pass !== 'secret123') {
        res.writeHead(401, { 'Content-Type': 'text/plain' });
        res.end('login failed');
        return;
      }
      state.sid = `MOCKSID-${state.loginCount}`; // rotate the SID on every login
      res.writeHead(200, { 'Set-Cookie': [`SID=${state.sid}; Path=/`], 'Content-Type': 'text/plain' });
      res.end('login ok');
      return;
    }

    // --- data endpoints (require a valid SID) ------------------------------------
    const cookie = String(req.headers['cookie'] ?? '');
    const sidMatch = cookie.match(/SID=([^;]+)/);
    if (!sidMatch || sidMatch[1] !== state.sid) {
      res.writeHead(302, { Location: '/login_sid.lua' });
      res.end();
      return;
    }

    // Simulated session expiry — the plugin must re-login and retry.
    if (state.expireNextDataRequest) {
      state.expireNextDataRequest = false;
      state.sid = `MOCKSID-EXPIRED-${Date.now()}`; // invalidate the current SID
      res.writeHead(302, { Location: '/login_sid.lua' });
      res.end();
      return;
    }

    const sendJson = (obj: unknown) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(obj));
    };

    switch (url.pathname) {
      case '/systeminfo64.json':
        return sendJson(systeminfo);
      case '/overview.lua':
        return sendJson(overview);
      case '/internetinfo.json':
        return sendJson(internetinfo);
      case '/laninfo.json':
        return sendJson(laninfo);
      case '/wlaninfo.json': {
        const ifname = url.searchParams.get('ifname') ?? '';
        if (ifname === 'wlan0') {
          return sendJson(wlan('wlan0', 'Lab-2G', 6, '24GHz', [
            { mac: 'AA:BB:CC:DD:EE:10', ip: '192.168.178.50', hostname: 'phone' },
          ]));
        }
        if (ifname === 'wlan1') {
          return sendJson(wlan('wlan1', 'Lab-5G', 149, '5GHz', [
            { mac: 'AA:BB:CC:DD:EE:11', ip: '192.168.178.51' },
          ]));
        }
        res.writeHead(404); // wlan2 absent on this box
        return res.end();
      }
      default:
        res.writeHead(404, { 'Content-Type': 'text/html' });
        return res.end('<html>not found</html>');
    }
  });

  server.listen(port);
  return Object.assign(server, { state });
}

// --- Mock html2-generation box -------------------------------------------------------------
//
// Faithful to the live protocol: login_sid.lua returns a ZERO SID + 8-hex
// <Challenge> (a red herring), the login page embeds `const data = {…}` with a
// PBKDF2 challenge, /index.lua verifies the derived response server-side and
// serves the main page carrying `"sid":"…"`. All data flows through
// POST /data.lua — no cookies anywhere.

interface Html2MockState {
  sid: string; // current valid session id ('' = none)
  loginCount: number;
  challenge: string; // "2$<iter1>$<salt1hex>$<iter2>$<salt2hex>"
  expectedResponse: string; // hex(salt2)$hex(pass2) for the CURRENT password
  dataRequests: Record<string, number>;
  /** When true, the next /data.lua answer is a login page (session expired). */
  expireNextDataRequest: boolean;
}

function makeHtml2MockBox(port: number): http.Server & { state: Html2MockState } {
  const USER = 'mockuser'; // auto-generated username for password-only boxes
  const PASSWORD = 'html2secret!';

  const state: Html2MockState = { sid: '', loginCount: 0, challenge: '', expectedResponse: '', dataRequests: {}, expireNextDataRequest: false };

  /** Rotates the PBKDF2 challenge (salt2 changes per page load on real boxes). */
  function rotateChallenge(): void {
    const salt1 = crypto.randomBytes(8).toString('hex');
    const salt2 = crypto.randomBytes(8).toString('hex');
    state.challenge = `2$60000$${salt1}$6000$${salt2}`;
    // Verify EXACTLY like the box: parse both iteration counts from the challenge.
    const parts = state.challenge.split('$');
    const pass1 = crypto.pbkdf2Sync(Buffer.from(PASSWORD, 'utf8'), Buffer.from(parts[2], 'hex'), Number(parts[1]), 32, 'sha256');
    const pass2 = crypto.pbkdf2Sync(pass1, Buffer.from(parts[4], 'hex'), Number(parts[3]), 32, 'sha256');
    state.expectedResponse = `${parts[4]}$${pass2.toString('hex')}`;
  }

  function loginPageHtml(): string {
    return `<!DOCTYPE html><html><head></head><body>
<script>const data = {"challenge":"${state.challenge}","username":"${USER}","blockTime":0,"activeUsers":[{"value":"${USER}","text":"${USER}"}]};</script>
<form action="index.lua" method="post"></form></body></html>`;
  }

  function mainPageHtml(): string {
    return `<!DOCTYPE html><html><head></head><body>
<script>window.main = window.main || {}; main.init({"sid":"${state.sid}","pages":{"overview":{"show":true,"lua":"home/home.lua"}}});</script>
</body></html>`;
  }

  // --- /data.lua page payloads (shapes pinned from live hardware) -------------------
  const overviewData = {
    fritzos: {
      fb_name: 'RouterLab-2',
      Productname: 'Vendor Router 7530 AX',
      nspver: '8.25',
      iframeUrl: 'https://fritzhelp.avm.de/help/?hardware=256&version=256.08.25&action=feature',
    },
    internet: {
      box_type: 'dsl',
      connections: [
        {
          type: 'dsl',
          connected: true,
          state: 'connected',
          provider: 'MockTelco',
          upstream: 35870, // kbit/s
          downstream: 198036,
          ipv4: { ip: '203.0.113.7', dns: [{ ip: '1.1.1.1' }, { ip: '9.9.9.9' }] },
          // Live shape: the v6 address carries a "/<len>" suffix that must be stripped.
          ipv6: { connected: true, ip: '2001:db8::5/64', prefix: '2001:db8::/48' },
        },
      ],
    },
    wlan: [{ txt: 'an, Funknetz (5 GHz): MockNet-5G', led: 'led green', title: 'WLAN', link: 'wSet' }],
  };

  const netDevData = {
    fbox: [
      // The box itself — must NOT appear in the host inventory.
      { mac: '80:23:95:81:08:B0', name: 'Vendor Router 7530 AX', model: 'fbox', type: 'unknown', ipv4: { ip: '192.168.178.1' } },
    ],
    active: [
      { mac: 'AA:BB:CC:DD:EE:01', name: 'wired-pc', type: 'ethernet', port: 'LAN 1 mit 1 Gbit/s ', ipv4: { ip: '192.168.178.10' } },
      // Same IP as the wired PC (CARP-style) — dedupe keeps one row per mac|ip.
      { mac: 'AA:BB:CC:DD:EE:02', name: 'wired-pc-vrrp', type: 'ethernet', port: 'LAN 1 mit 1 Gbit/s ', ipv4: { ip: '192.168.178.10' } },
    ],
    passive: [
      // Passive rows carry ipv4 as a PLAIN STRING on some firmware builds.
      { mac: 'AA:BB:CC:DD:EE:10', name: 'wifi-phone', type: 'unknown', port: '', ipv4: '192.168.178.50' },
      // IP-less ARP-only row — must be skipped by the host inventory.
      { mac: 'AA:BB:CC:DD:EE:FF', name: 'no-ip-device', type: 'unknown', port: '', ipv4: '' },
    ],
  };

  const wSetData = {
    wlanSettings: {
      ssid: 'MockNet-5G',
      mac: '80:23:95:81:08:B0', // BSSID
      protocol: '26', // Wi-Fi 6 per the box's own code map
      encryption: '3', // WPA2
      knownWlanDevices: [
        { mac: 'AA:BB:CC:DD:EE:10', name: 'wifi-phone', ip: '192.168.178.50' },
        // Remembered but NOT currently associated — must not become a client.
        { mac: 'AA:BB:CC:DD:EE:99', name: 'away-laptop', ip: '' },
      ],
    },
  };

  const energyData = {
    drain: [
      { name: 'Router Gesamtsystem', statuses: 'aktiv seit 2 Tagen, 3 Stunden, 4 Minuten' }, // 2d+3h+4m = 183840 s
      { name: 'LAN-Anschlüsse', lan: [{ name: 'LAN 1', class: 'green' }, { name: 'LAN 2', class: '' }] },
    ],
  };

  const usbOvData = { usbOverview: { boxIpAddress: '192.168.178.1' } };

  // --- HTML FORM pages (answer with text/html instead of the JSON envelope) -----
  // Shapes pinned from live hardware: boxnet carries `const g_mask` in its head,
  // boxnet_ipv6 one <div class="dhcpipv6"> block per named network.
  const boxNetHtml = `<script type="module">
  import fc from "/js/focuschanger.js";
  const g_ip        = "192.168.178.1";
  const g_mask      = "255.255.255.0";
  const g_dhcp      = true;
</script>
<form method="POST" action="/net/boxnet.lua">
<input type="text" size="3" maxlength="3" id="uiNetmask_all0" name="Netmask_all0\n" value="255"  />
<input type="text" size="3" maxlength="3" id="uiNetmask_all1" name="Netmask_all1\n" value="255"  />
<input type="text" size="3" maxlength="3" id="uiNetmask_all2" name="Netmask_all2\n" value="255"  />
<input type="text" size="3" maxlength="3" id="uiNetmask_all3" name="Netmask_all3\n" value="0"  />
</form>`;

  const boxNetIpv6Html = `<style type="text/css">
  .mainContent div.dhcpipv6 { margin-bottom: 0.5rem; }
</style>
<form method="POST" action="/net/boxnet_ipv6.lua" name="main_form">
<div class="dhcpipv6"><div class="name">Heimnetz</div><div class="noBreakGroup adr"><div>2001:db8:1::</div><div class="separat">/</div><div class="prefixlen">64</div></div></div>
<div class="dhcpipv6"><div class="name">Gastnetz</div><div class="noBreakGroup adr"><div>-</div><div class="separat">/</div><div class="prefixlen">-</div></div></div>
<div class="dhcpipv6"><div class="name">WAN</div><div class="noBreakGroup adr"><div>2001:db8::5</div><div class="separat">/</div><div class="prefixlen">64</div></div></div>
<div class="dhcpipv6"><div class="name">Delegiert</div><div class="noBreakGroup adr"><div>2001:db8::</div><div class="separat">/</div><div class="prefixlen">48</div></div></div>
</form>`;

  function envelope(pid: string, data: unknown): string {
    return JSON.stringify({ pid, hide: {}, timeTillLogout: '1200', time: [], data, sid: state.sid });
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', `http://localhost:${port}`);

    // --- login_sid.lua — zero SID + red-herring challenge --------------------------
    if (url.pathname === '/login_sid.lua') {
      state.loginCount++;
      res.writeHead(200, { 'Content-Type': 'text/xml' });
      return res.end(`<SessionInfo><SID>0000000000000000</SID><Challenge>deadbeef</Challenge><BlockTime>0</BlockTime><Rights></Rights><Users><User last="1">${USER}</User></Users></SessionInfo>`);
    }

    // --- login page (GET /) — fresh PBKDF2 challenge every load ---------------------
    if (url.pathname === '/' && req.method === 'GET') {
      rotateChallenge();
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(loginPageHtml());
    }

    // --- /index.lua — verify the PBKDF2 response ------------------------------------
    if (url.pathname === '/index.lua') {
      const body = await readBody(req);
      const form = new URLSearchParams(body);
      const user = form.get('uiUser') ?? '';
      const pass = form.get('uiPass') ?? '';
      const response = form.get('response') ?? '';

      if (user !== USER || pass !== PASSWORD) {
        rotateChallenge(); // a failed attempt re-serves the login page
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end(loginPageHtml());
      }
      if (response !== state.expectedResponse) {
        // Wrong PBKDF2 response — the box re-serves the LOGIN page.
        rotateChallenge();
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end(loginPageHtml());
      }

      state.sid = crypto.randomBytes(8).toString('hex'); // the client extracts a 16-hex sid
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(mainPageHtml());
    }

    // --- /data.lua — the single multiplexed data endpoint ----------------------------
    if (url.pathname === '/data.lua') {
      const body = await readBody(req);
      const form = new URLSearchParams(body);
      const sid = form.get('sid') ?? '';
      state.dataRequests[form.get('page') ?? '(none)'] = (state.dataRequests[form.get('page') ?? '(none)'] ?? 0) + 1;

      if (sid !== state.sid || !state.sid) {
        // Session invalid — the box re-serves the login page.
        rotateChallenge();
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end(loginPageHtml());
      }

      if (state.expireNextDataRequest) {
        state.expireNextDataRequest = false;
        state.sid = crypto.randomBytes(8).toString('hex'); // invalidate the current SID
        rotateChallenge();
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end(loginPageHtml());
      }

      const page = form.get('page') ?? '';
      switch (page) {
        case '': // home overview — the SPA omits `page` for it
          return sendJson(envelope('overview', overviewData));
        case 'netDev':
          if (form.get('xhrId') !== 'all') return sendJson(envelope('netDev', [])); // xhrId required!
          return sendJson(envelope('netDev', netDevData));
        case 'wSet':
          return sendJson(envelope('wSet', wSetData));
        case 'energy':
          return sendJson(envelope('energy', energyData));
        case 'usbOv':
          return sendJson(envelope('usbOv', usbOvData));
        case 'boxnet': // LAN v4 netmask — HTML form, NOT the JSON envelope
          res.writeHead(200, { 'Content-Type': 'text/html' });
          return res.end(boxNetHtml);
        case 'boxnet_ipv6': // LAN/WAN v6 prefixes — HTML form
          res.writeHead(200, { 'Content-Type': 'text/html' });
          return res.end(boxNetIpv6Html);
        default:
          // Unknown pids fall back to the overview payload (live behavior).
          return sendJson(envelope('overview', overviewData));
      }
    }

    res.writeHead(404, { 'Content-Type': 'text/html' });
    return res.end('<html>not found</html>');

    function sendJson(s: string): void {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(s);
    }
  });

  server.listen(port);
  return Object.assign(server, { state });
}

// --- An unsupported target (answers but has no supported web UI) ---------------------------

function makeUnsupportedTargetServer(): http.Server {
  const server = http.createServer((req, res) => {
    if (req.url?.startsWith('/login_sid.lua')) {
      // A generic web server that has no such endpoint.
      res.writeHead(404);
      return res.end();
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body>some other device</body></html>');
  });
  server.listen(UNSUPPORTED_TARGET_PORT);
  return server;
}

// --- Run ----------------------------------------------------------------------------------

async function main(): Promise<void> {
  const mock = makeMockBox(MOCK_PORT);
  const h2Mock = makeHtml2MockBox(HTML2_MOCK_PORT);
  const unsupportedTarget = makeUnsupportedTargetServer();
  await new Promise((r) => setTimeout(r, 150)); // let the mocks bind

  process.env.PORT = String(PLUGIN_PORT);
  await import('./src/index');
  await new Promise((r) => setTimeout(r, 300)); // let the plugin listen

  const post = async (path: string, body: unknown): Promise<{ status: number; data: any }> => {
    const res = await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return { status: res.status, data: (await res.json()) as any };
  };

  const monitoringBody = (address: string) => ({
    deviceId: 'test-device',
    managementAddress: address,
    credentials: { username: 'admin', password: 'secret123' },
  });

  // --- /discover ---------------------------------------------------------------------
  console.log('\n/discover');
  const disc: any = await (await fetch(`${BASE}/discover`)).json();
  check('uuid is the reserved fbox uuid', disc.uuid === '00000000-0000-4000-8000-000000000008', disc.uuid);
  check('name is FBox Plugin', disc.name === 'FBox Plugin', disc.name);
  check('vendors = [avm]', JSON.stringify(disc.vendors) === '["avm"]', disc.vendors);
  check('capabilities include monitoring+inventory', ['monitoring', 'inventory'].every((c: string) => (disc.capabilities ?? []).includes(c)), disc.capabilities);
  check('requiredSecretType = usernamePassword', disc.requiredSecretType === 'usernamePassword', disc.requiredSecretType);
  check('options declare transport/requestTimeoutMs/logToApi', ['transport', 'requestTimeoutMs', 'logToApi'].every((k) => (disc.options ?? []).some((o: any) => o.key === k)), disc.options?.map((o: any) => o.key));
  check('iconUrl advertised', disc.iconUrl === '/icons/fbox.svg', disc.iconUrl);
  const models = disc.deviceModels ?? [];
  check('deviceModels has 5 entries (4 real + generic)', models.length === 5, models.map((m: any) => m.model));
  check('all model vendors are avm', models.every((m: any) => m.vendor === 'avm'));
  check('generic entry has no iconPath', models.some((m: any) => m.model === 'Custom / Other' && !m.iconPath));

  // --- /monitoring happy path ----------------------------------------------------------
  console.log('\n/monitoring (happy path)');
  const mon = await post('/monitoring', monitoringBody(`localhost:${MOCK_PORT}`));
  check('HTTP 200', mon.status === 200, mon.status);
  check('health ok', mon.data.health === 'ok', mon.data.health);
  const m = mon.data.metrics ?? {};
  check('system.name', m['system.name'] === 'RouterLab-1', m['system.name']);
  check('system.swVersion (Identity key)', m['system.swVersion'] === '183.09', m['system.swVersion']);
  check('system.uptime seconds', m['system.uptime'] === 123456, m['system.uptime']);
  check('system.cpuLoad clamped %', m['system.cpuLoad'] === 12, m['system.cpuLoad']);
  check('system.temperature °C', m['system.temperature'] === 42, m['system.temperature']);
  check('system.memoryUsedPct ≈35%', Math.round(m['system.memoryUsedPct']) === 35, m['system.memoryUsedPct']);
  check('wan.status online', m['wan.status'] === 'online', m['wan.status']);
  check('wan.type ipclient', m['wan.type'] === 'ipclient', m['wan.type']);
  check('wan.ip', m['wan.ip'] === '80.123.45.67', m['wan.ip']);
  const lanPorts = (m['lan.ports'] ?? []) as any[];
  check('lan.ports table has 2 rows', lanPorts.length === 2, lanPorts);
  check('lan port speed formatted', lanPorts[0]?.speed === '1000 Mbit/s' && lanPorts[0]?.status === 'up', lanPorts[0]);
  check('wifi.clients = 2', m['wifi.clients'] === 2, m['wifi.clients']);
  check('wifi.channel2g from wlan0', m['wifi.channel2g'] === '6', m['wifi.channel2g']);
  check('wifi.channel5g from wlan1', m['wifi.channel5g'] === '149', m['wifi.channel5g']);

  // Inventory keys.
  const nets = (m['networks'] ?? []) as any[];
  check('inventory networks: LAN v4 /24', nets.length === 1 && nets[0].name === 'LAN' && nets[0].ip === '192.168.178.1' && nets[0].prefix === 24, nets);
  const arp = (m['arp'] ?? []) as any[];
  check('inventory arp: 2 rows (MAC-less skipped)', arp.length === 2, arp);
  check('dash MAC normalized to colon form', arp.some((r) => r.mac === 'aa:bb:cc:dd:ee:02'), arp.map((r) => r.mac));
  const wlanClients = (m['wlanClients'] ?? []) as any[];
  check('inventory wlanClients: 2 rows with intf', wlanClients.length === 2 && wlanClients.every((c) => c.intf), wlanClients);
  const wifiNets = (m['wifiNetworks'] ?? []) as any[];
  check('inventory wifiNetworks: 2 SSIDs with band+channel', wifiNets.length === 2 && wifiNets.some((n) => n.band === '2g' && n.channel === 6), wifiNets);

  // Descriptors cover the emitted metrics.
  const keys = new Set((mon.data.metricDescriptors ?? []).map((d: any) => d.key));
  for (const k of ['system.swVersion', 'wan.status', 'lan.ports', 'wifi.clients']) {
    check(`descriptor present: ${k}`, keys.has(k), [...keys]);
  }

  // --- session expiry mid-poll → transparent re-login -----------------------------------
  console.log('\n/monitoring (session expiry)');
  mock.state.expireNextDataRequest = true;
  const mon2 = await post('/monitoring', monitoringBody(`localhost:${MOCK_PORT}`));
  check('still health ok after forced expiry', mon2.data.health === 'ok', mon2.data);
  check('re-login happened (loginCount grew)', mock.state.loginCount >= 2, mock.state.loginCount);

  // --- html2-generation box: PBKDF2 login + /data.lua ------------------------------------
  console.log('\n/monitoring (html2 box — happy path)');
  const h2Body = { deviceId: 'test-device-h2', managementAddress: `localhost:${HTML2_MOCK_PORT}`, credentials: { username: '', password: 'html2secret!' } };
  const h2 = await post('/monitoring', h2Body);
  check('HTTP 200', h2.status === 200, h2.status);
  check('health ok (PBKDF2 login succeeded)', h2.data.health === 'ok', h2.data);
  const hm = h2.data.metrics ?? {};
  check('system.swVersion from iframeUrl version=256.08.25', hm['system.swVersion'] === '256.08.25', hm['system.swVersion']);
  check('system.uptime parsed from German text (183840 s)', hm['system.uptime'] === 183840, hm['system.uptime']);
  check('wan.status online', hm['wan.status'] === 'online', hm['wan.status']);
  check('wan.type dsl', hm['wan.type'] === 'dsl', hm['wan.type']);
  check('wan.ip from internet.connections[0].ipv4', hm['wan.ip'] === '203.0.113.7', hm['wan.ip']);
  check('wan.downstreamMbps kbit→Mbit (198)', hm['wan.downstreamMbps'] === 198, hm['wan.downstreamMbps']);
  check('wan.upstreamMbps kbit→Mbit (35.9)', hm['wan.upstreamMbps'] === 35.9, hm['wan.upstreamMbps']);
  check('wan.provider', hm['wan.provider'] === 'MockTelco', hm['wan.provider']);
  check('wan.ipv6 with /64 suffix stripped', hm['wan.ipv6'] === '2001:db8::5', hm['wan.ipv6']);
  check('wan.ipv6Prefix delegated prefix', hm['wan.ipv6Prefix'] === '2001:db8::/48', hm['wan.ipv6Prefix']);
  const h2Ports = (hm['lan.ports'] ?? []) as any[];
  check('lan.ports from energy page (2 rows)', h2Ports.length === 2, h2Ports);
  check('LAN port LED green→up / empty→down', h2Ports[0]?.status === 'up' && h2Ports[1]?.status === 'down', h2Ports);
  check('wifi.clients = 1 (knownWlanDevices ∩ live hosts)', hm['wifi.clients'] === 1, hm['wifi.clients']);
  check('wifi.bssid5g from wSet mac', hm['wifi.bssid5g'] === '80:23:95:81:08:b0', hm['wifi.bssid5g']);

  const h2Nets = (hm['networks'] ?? []) as any[];
  check('inventory networks: LAN v4 row WITH prefix from boxnet g_mask', h2Nets.some((r) => r.name === 'LAN' && r.ip === '192.168.178.1' && r.prefix === 24 && r.version === 'v4'), h2Nets);
  check('inventory networks: LAN v6 row from boxnet_ipv6 Heimnetz', h2Nets.some((r) => r.name === 'LAN' && r.ip === '2001:db8:1::' && r.prefix === 64 && r.version === 'v6'), h2Nets);
  check('inventory networks: exactly 2 rows (no guest/wan/delegated leakage)', h2Nets.length === 2, h2Nets);
  const h2Arp = (hm['arp'] ?? []) as any[];
  check('inventory arp: 2 wired rows (WLAN client excluded, IP-less skipped)', h2Arp.length === 2 && h2Arp.every((r) => r.mac !== 'aa:bb:cc:dd:ee:10' && r.mac !== 'aa:bb:cc:dd:ee:ff'), h2Arp);
  check('arp rows carry the LAN port as intf', h2Arp.some((r) => r.intf === 'LAN 1'), h2Arp);
  const h2Wlan = (hm['wlanClients'] ?? []) as any[];
  check('inventory wlanClients: 1 row with intf=wlan0', h2Wlan.length === 1 && h2Wlan[0].mac === 'aa:bb:cc:dd:ee:10' && h2Wlan[0].intf === 'wlan0', h2Wlan);
  const h2Wifi = (hm['wifiNetworks'] ?? []) as any[];
  check('inventory wifiNetworks: SSID + band + bssid + WPA2, no channel', h2Wifi.length === 1 && h2Wifi[0].name === 'MockNet-5G' && h2Wifi[0].band === '5g' && h2Wifi[0].bssid === '80:23:95:81:08:b0' && h2Wifi[0].encryption === 'WPA2' && h2Wifi[0].channel === undefined, h2Wifi);

  const h2Keys = new Set((h2.data.metricDescriptors ?? []).map((d: any) => d.key));
  for (const k of ['system.swVersion', 'wan.downstreamMbps', 'lan.ports', 'wifi.bssid5g', 'wan.ipv6']) {
    check(`html2 descriptor present: ${k}`, h2Keys.has(k), [...h2Keys]);
  }

  // The home overview must be requested WITHOUT a page param (page:"overview" is null on real boxes).
  check('home overview fetched via omitted page param', (h2Mock.state.dataRequests['(none)'] ?? 0) >= 1, h2Mock.state.dataRequests);
  check('netDev requested once with xhrId (host table non-empty)', (h2Mock.state.dataRequests['netDev'] ?? 0) === 1 && h2Arp.length > 0, h2Mock.state.dataRequests);
  check('boxnet + boxnet_ipv6 form pages fetched', (h2Mock.state.dataRequests['boxnet'] ?? 0) >= 1 && (h2Mock.state.dataRequests['boxnet_ipv6'] ?? 0) >= 1, h2Mock.state.dataRequests);

  // --- html2 session expiry mid-poll → transparent re-login -------------------------------
  console.log('\n/monitoring (html2 box — session expiry)');
  const loginsBefore = h2Mock.state.loginCount;
  h2Mock.state.expireNextDataRequest = true;
  const h2b = await post('/monitoring', h2Body);
  check('still health ok after forced html2 expiry', h2b.data.health === 'ok', h2b.data);
  check('html2 re-login happened (loginCount grew)', h2Mock.state.loginCount > loginsBefore, { before: loginsBefore, after: h2Mock.state.loginCount });

  // --- html2 bad credentials → critical ----------------------------------------------------
  console.log('\n/monitoring (html2 box — bad creds)');
  const h2bad = await post('/monitoring', { ...h2Body, credentials: { username: '', password: 'wrong' } });
  check('health critical on html2 auth failure', h2bad.data.health === 'critical', h2bad.data);
  check('html2 system.error set', typeof h2bad.data.metrics?.['system.error'] === 'string' && h2bad.data.metrics['system.error'].length > 0, h2bad.data.metrics);

  // --- bad credentials → critical --------------------------------------------------------
  console.log('\n/monitoring (bad creds)');
  const bad = await post('/monitoring', { ...monitoringBody(`localhost:${MOCK_PORT}`), credentials: { username: 'admin', password: 'wrong' } });
  check('health critical on auth failure', bad.data.health === 'critical', bad.data);
  check('system.error set', typeof bad.data.metrics?.['system.error'] === 'string' && bad.data.metrics['system.error'].length > 0, bad.data.metrics);

  // --- unsupported target → unknown -----------------------------------------------------------
  console.log('\n/monitoring (unsupported target)');
  const nf = await post('/monitoring', monitoringBody(`localhost:${UNSUPPORTED_TARGET_PORT}`));
  check('health unknown for unsupported target', nf.data.health === 'unknown', nf.data);

  // --- missing address → critical -----------------------------------------------------------
  console.log('\n/monitoring (no address)');
  const noaddr = await post('/monitoring', { deviceId: 'x', managementAddress: '', credentials: { username: 'a', password: 'b' } });
  check('health critical without address', noaddr.data.health === 'critical', noaddr.data);

  // --- cleanup ------------------------------------------------------------------------------
  mock.close();
  h2Mock.close();
  unsupportedTarget.close();
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('smoke test crashed:', err);
  process.exit(1);
});
