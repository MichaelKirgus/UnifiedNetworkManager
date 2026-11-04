/**
 * End-to-end smoke test for the WLED plugin.
 *
 * Boots a MOCK WLED controller (plain HTTP, real /json/info + /update multipart
 * semantics incl. PIN gating and simulated reboot) AND a MOCK web-fetch broker
 * (the API's POST /v1/plugin/webfetch route — the ONLY internet egress path),
 * then boots the REAL plugin (src/index.ts on PORT=48762) and exercises:
 *   - GET  /discover    → identity, capabilities, options, action catalog, quick actions
 *   - POST /monitoring  → metrics + health (ok / critical unreachable / low-heap warning),
 *                         updates row emission (available / empty when current==latest /
 *                         OMITTED on feed failure — never wiped)
 *   - POST /config      → wled.firmware.update (multipart field "update" captured, PIN 401
 *                         path, simulated reboot + version verification), wled.rename
 *                         round-trip, wled.state.set clamping
 *   - POST /quick-action → web-UI URL resolution
 */

import http from 'http';

const MOCK_DEVICE_PORT = 49310; // mock WLED controller
const BROKER_PORT = 49311; // mock API web-fetch broker (the "internet" egress)
const PLUGIN_PORT = 49312;
const CLOSED_PORT = 49399; // nothing listens here → unreachable target
const BASE = `http://localhost:${PLUGIN_PORT}`;

// Fast reboot-wait for the firmware action (test hooks in actions.ts).
process.env.WLED_REBOOT_WAIT_MS = '5000';
process.env.WLED_REBOOT_POLL_MS = '400';
process.env.PORT = String(PLUGIN_PORT);
process.env.UNM_API_URL = `http://localhost:${BROKER_PORT}/v1`; // webFetchViaApi target

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) {
    console.log(`  ✅ ${label}`);
  } else {
    failures++;
    console.error(`  ❌ ${label}${extra !== undefined ? ` — got: ${JSON.stringify(extra)}` : ''}`);
  }
}

// --- Mock WLED device --------------------------------------------------------------------

interface DeviceState {
  ver: string;
  name: string;
  freeheap: number;
  rssi: number;
  pin: string | null; // settings PIN (null = none)
  downUntil: number; // simulated reboot window (epoch ms)
  /** Simulated flash-write delay before /update answers (ms). Real WLED writes
   *  the image to SPI flash WHILE serving the request — a slow box takes well
   *  beyond the default 5 s poll budget. Regression guard for UPLOAD_TIMEOUT_MS. */
  updateDelayMs: number;
  fsUsedKb: number; // /json/info fs.u (KB)
  fsTotalKb: number; // /json/info fs.t (KB)
  /** Captured from the last /update multipart. */
  updateFieldNames: string[];
  updateFileName: string | null;
  updateBytes: number;
  updatePinSent: string | null;
  cfgWrites: Record<string, unknown>[];
  stateWrites: Record<string, unknown>[];
}

const deviceState: DeviceState = {
  ver: '16.0.0',
  name: 'WLEDTest',
  freeheap: 131_616,
  rssi: -73,
  pin: null,
  downUntil: 0,
  updateDelayMs: 0,
  fsUsedKb: 196,
  fsTotalKb: 983,
  ssid: 'KirgusNET_IoT',
  updateFieldNames: [],
  updateFileName: null,
  updateBytes: 0,
  updatePinSent: null,
  cfgWrites: [],
  stateWrites: [],
};

function deviceInfo(): Record<string, unknown> {
  return {
    ver: deviceState.ver,
    vid: 2605030,
    cn: 'Niji',
    release: 'ESP32',
    repo: 'wled/WLED',
    arch: 'esp32',
    core: '4.4.8.240628',
    freeheap: deviceState.freeheap,
    uptime: 2_341_116,
    name: deviceState.name,
    wifi: { bssid: '00:A0:57:A8:1E:A2', rssi: deviceState.rssi, signal: 54, channel: 1 },
    leds: { count: 160, pwr: 1602, fps: 43, maxpwr: 5_000 },
    mac: 'A4:CB:88:11:22:33',
    fs: { u: deviceState.fsUsedKb, t: deviceState.fsTotalKb },
    mac: 'f8b3b75921e8',
    ip: `localhost:${MOCK_DEVICE_PORT}`,
  };
}

/** Parses a multipart/form-data body into { fields, files } (test-grade parser). */
function parseMultipart(raw: Buffer, contentType: string): { fields: Record<string, string>; files: Record<string, { filename: string; data: Buffer }> } {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType ?? '');
  const boundary = `--${(m?.[1] ?? m?.[2] ?? '').trim()}`;
  const fields: Record<string, string> = {};
  const files: Record<string, { filename: string; data: Buffer }> = {};
  if (!boundary || !Buffer.isBuffer(raw)) {
    console.error(`[mock-device] multipart parse skipped — content-type="${contentType}", body is ${Buffer.isBuffer(raw) ? `Buffer(${raw.length})` : `${typeof raw}: ${String(raw).slice(0, 200)}`}`);
    return { fields, files };
  }

  // Buffer.prototype.split was removed from Node — split on the boundary manually.
  const delim = Buffer.from(boundary);
  const parts: Buffer[] = [];
  let start = 0;
  for (;;) {
    const idx = raw.indexOf(delim, start);
    if (idx < 0) break;
    parts.push(raw.subarray(start, idx));
    start = idx + delim.length;
  }
  for (const part of parts) {
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd < 0) continue;
    const head = part.subarray(0, headerEnd).toString('utf8');
    let body = part.subarray(headerEnd + 4);
    // Strip the trailing \r\n before the next boundary.
    if (body.length >= 2 && body[body.length - 2] === 13 && body[body.length - 1] === 10) body = body.subarray(0, body.length - 2);

    const nameM = /name="([^"]+)"/i.exec(head);
    if (!nameM) continue;
    const fieldName = nameM[1];
    const fileM = /filename="([^"]*)"/i.exec(head);
    if (fileM !== null && fileM[1] !== '') {
      files[fieldName] = { filename: fileM[1], data: body };
    } else {
      fields[fieldName] = body.toString('utf8');
    }
  }
  return { fields, files };
}

function makeMockDevice(): http.Server {
  const server = http.createServer((req, res) => {
    // Simulated reboot: drop the connection while "down".
    if (Date.now() < deviceState.downUntil) {
      req.socket.destroy();
      return;
    }

    const url = req.url ?? '/';

    if (url === '/json/info' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(deviceInfo()));
    }

    if (url.startsWith('/update')) {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', async () => {
        const raw = Buffer.concat(chunks);
        // GET /update?revert — ESP8266 only; this mock is esp32 → 404 like a real box.
        if (req.method === 'GET') {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          return res.end('not found');
        }

        const { fields, files } = parseMultipart(raw, String(req.headers['content-type'] ?? ''));
        deviceState.updateFieldNames.push(...Object.keys(files));
        deviceState.updatePinSent = fields['pin'] ?? null;

        // PIN gate (source-verified: 401 when a PIN is set and missing/wrong).
        if (deviceState.pin !== null) {
          if (!fields['pin'] || fields['pin'] !== deviceState.pin) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            return res.end('PIN required');
          }
        }

        const fw = files['update'];
        if (!fw) {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          return res.end('missing file field "update"');
        }
        deviceState.updateFileName = fw.filename;
        deviceState.updateBytes = fw.data.length;

        // Simulate the flash write: real WLED only answers AFTER writing the
        // image to SPI flash, which on a slow box takes longer than the default
        // 5 s poll budget (the bug that broke every real firmware update).
        if (deviceState.updateDelayMs > 0) {
          await new Promise((r) => setTimeout(r, deviceState.updateDelayMs));
        }

        // Accept → the box reboots into the new firmware (simulated: down 1.2 s, then new ver).
        const targetM = fw.filename.match(/(\d+\.\d+(?:\.\d+)?)/);
        if (targetM) deviceState.ver = targetM[1];
        deviceState.downUntil = Date.now() + 1_200;
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end('Update successful!');
      });
      return;
    }

    // GET /json/cfg — config read (PIN-free). `nw.ins` is the preferred-network
    // list; first non-empty ssid is what the device associates with.
    if (url === '/json/cfg' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(
        JSON.stringify({
          nw: { ins: [{ ssid: deviceState.ssid, pskl: 20, bssid: '', ip: [0, 0, 0, 0] }] },
          wifi: { sleep: false, phy: false, txpwr: 78 },
        })
      );
    }

    if (url === '/json/cfg' && req.method === 'POST') {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        let body: Record<string, unknown>;
        try {
          body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch {
          res.writeHead(400);
          return res.end();
        }
        deviceState.cfgWrites.push(body);
        if (deviceState.pin !== null && String((body as Record<string, unknown>)['pin'] ?? '') !== deviceState.pin) {
          res.writeHead(401, { 'Content-Type': 'text/plain' });
          return res.end('PIN required');
        }
        const id = (body as Record<string, unknown>)['id'];
        if (id && typeof id === 'object' && typeof (id as Record<string, unknown>)['name'] === 'string') {
          deviceState.name = String((id as Record<string, unknown>)['name']);
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end('{}');
      });
      return;
    }

    if (url === '/json' && req.method === 'POST') {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        let body: Record<string, unknown>;
        try {
          body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        } catch {
          res.writeHead(400);
          return res.end();
        }
        deviceState.stateWrites.push(body);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end('{}');
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('not found');
  });
  server.listen(MOCK_DEVICE_PORT);
  return server;
}

// --- Mock web-fetch broker (the API's POST /v1/plugin/webfetch) ---------------------------

const GITHUB_RELEASE = {
  tag_name: 'v16.0.1',
  html_url: 'https://github.com/wled/WLED/releases/tag/v16.0.1',
  assets: [
    { name: 'WLED_16.0.1_ESP32.bin', size: 1_500_000, browser_download_url: 'https://github.com/wled/WLED/releases/download/v16.0.1/WLED_16.0.1_ESP32.bin' },
    { name: 'WLED_16.0.1_ESP8266.bin', size: 900_000, browser_download_url: 'https://github.com/wled/WLED/releases/download/v16.0.1/WLED_16.0.1_ESP8266.bin' },
    { name: 'WLED_16.0.1_RP2040.bin', size: 700_000, browser_download_url: 'https://github.com/wled/WLED/releases/download/v16.0.1/WLED_16.0.1_RP2040.bin' },
  ],
};

const FIRMWARE_BYTES = Buffer.alloc(4096, 0xab); // fake .bin payload

interface BrokerState {
  fail: boolean; // simulate upstream/provider outage → 502/503
  fetches: string[]; // URLs requested (asserts egress went through the broker)
}

const brokerState: BrokerState = { fail: false, fetches: [] };

function makeMockBroker(): http.Server {
  const server = http.createServer((req, res) => {
    if (req.url === '/v1/plugin/webfetch' && req.method === 'POST') {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        let url = '';
        try {
          url = String(JSON.parse(Buffer.concat(chunks).toString('utf8'))['url'] ?? '');
        } catch { /* malformed */ }
        brokerState.fetches.push(url);

        if (brokerState.fail) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Web fetch failed: simulated upstream outage' }));
        }

        let payload: Buffer;
        let contentType = 'application/octet-stream';
        if (url === 'https://api.github.com/repos/wled/WLED/releases/latest') {
          payload = Buffer.from(JSON.stringify(GITHUB_RELEASE));
          contentType = 'application/json';
        } else if (url.startsWith('https://download.wled.me/')) {
          payload = FIRMWARE_BYTES;
        } else {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: `unknown URL in mock broker: ${url}` }));
        }

        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'x-webfetch-status': '200',
          'x-webfetch-content-type': contentType,
          'x-webfetch-size-bytes': String(payload.length),
        });
        return res.end(payload);
      });
      return;
    }

    // Log shipping etc. — accept and ignore (fire-and-forget from the plugin).
    res.writeHead(204);
    return res.end();
  });
  server.listen(BROKER_PORT);
  return server;
}

// --- Run ----------------------------------------------------------------------------------

async function main(): Promise<void> {
  makeMockDevice();
  makeMockBroker();
  await new Promise((r) => setTimeout(r, 150)); // let the mocks bind

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

  const monitoringBody = (address: string) => ({ deviceId: 'test-device', managementAddress: address });

  // --- /discover ---------------------------------------------------------------------
  console.log('\n/discover');
  const disc: any = await (await fetch(`${BASE}/discover`)).json();
  check('uuid is the reserved wled uuid', disc.uuid === '00000000-0000-4000-8000-000000000016', disc.uuid);
  check('name is WLED Plugin', disc.name === 'WLED Plugin', disc.name);
  check('vendors = [wled]', JSON.stringify(disc.vendors) === '["wled"]', disc.vendors);
  check(
    'capabilities include monitoring/updates/configuration/planning/quickActions',
    ['monitoring', 'updates', 'configuration', 'planning', 'quickActions'].every((c: string) => (disc.capabilities ?? []).includes(c)),
    disc.capabilities
  );
  check('requiredSecretType = null (credential-free)', disc.requiredSecretType === null, disc.requiredSecretType);
  const pinSlot = (disc.credentialSlots ?? []).find((s: any) => s.name === 'pin');
  check('optional pin slot declared (apiKey, required:false)', !!pinSlot && pinSlot.required === false && JSON.stringify(pinSlot.secretTypes) === '["apiKey"]', disc.credentialSlots);
  check(
    'options declare httpPort/transport/timeoutMs/logToApi',
    ['httpPort', 'transport', 'timeoutMs', 'logToApi'].every((k: string) => (disc.options ?? []).some((o: any) => o.key === k)),
    disc.options?.map((o: any) => o.key)
  );
  check('iconUrl advertised', disc.iconUrl === '/icons/wled.svg', disc.iconUrl);
  const actionIds = (disc.actions ?? []).map((a: any) => a.id);
  check(
    'action catalog has all five actions',
    ['wled.firmware.update', 'wled.firmware.revert', 'wled.config.backup', 'wled.rename', 'wled.state.set'].every((id: string) => actionIds.includes(id)),
    actionIds
  );
  const backupAction = (disc.actions ?? []).find((a: any) => a.id === 'wled.config.backup');
  check('config.backup is read-level', backupAction?.riskLevel === 'read', backupAction);
  const fwAction = (disc.actions ?? []).find((a: any) => a.id === 'wled.firmware.update');
  check('firmware.update is dangerous + no retry', fwAction?.riskLevel === 'dangerous' && fwAction?.retryOnDispatchFailure === false, fwAction);
  check('quick action webui advertised', (disc.quickActions ?? []).some((q: any) => q.id === 'webui' && q.kind === 'url'), disc.quickActions);

  // --- /monitoring with feed DOWN → updates key OMITTED (never wiped on outage) --------
  console.log('\n/monitoring (feed down — updates key must be omitted)');
  brokerState.fail = true;
  let mon = await post('/monitoring', monitoringBody(`localhost:${MOCK_DEVICE_PORT}`));
  check('HTTP 200 even with feed down', mon.status === 200, mon.status);
  check('health ok (device itself is fine)', mon.data.health === 'ok', mon.data.health);
  check('updates key OMITTED on feed failure', !('updates' in (mon.data.metrics ?? {})), Object.keys(mon.data.metrics ?? {}));

  // --- /monitoring happy path ----------------------------------------------------------
  console.log('\n/monitoring (happy path)');
  brokerState.fail = false;
  mon = await post('/monitoring', monitoringBody(`localhost:${MOCK_DEVICE_PORT}`));
  check('HTTP 200', mon.status === 200, mon.status);
  check('health ok', mon.data.health === 'ok', mon.data.health);
  const m = mon.data.metrics ?? {};
  check('wled.freeHeapBytes', m['wled.freeHeapBytes'] === 131_616, m['wled.freeHeapBytes']);
  check('wled.fps', m['wled.fps'] === 43, m['wled.fps']);
  check('wled.ledCount', m['wled.ledCount'] === 160, m['wled.ledCount']);
  check('wled.ledPowerMa', m['wled.ledPowerMa'] === 1_602, m['wled.ledPowerMa']);
  check('wled.uptimeSeconds', m['wled.uptimeSeconds'] === 2_341_116, m['wled.uptimeSeconds']);
  check('wled.wifiRssiDbm', m['wled.wifiRssiDbm'] === -73, m['wled.wifiRssiDbm']);
  check('wled.wifiSignalPercent', m['wled.wifiSignalPercent'] === 54, m['wled.wifiSignalPercent']);
  check('wled.wifiBssid (AP MAC from /json/info)', m['wled.wifiBssid'] === '00:A0:57:A8:1E:A2', m['wled.wifiBssid']);
  check('wled.wifiSsid (from GET /json/cfg nw.ins[0])', m['wled.wifiSsid'] === 'KirgusNET_IoT', m['wled.wifiSsid']);
  check('wled.wifiChannel', m['wled.wifiChannel'] === 1, m['wled.wifiChannel']);
  check('wled.fsUsedKb / wled.fsTotalKb', m['wled.fsUsedKb'] === 196 && m['wled.fsTotalKb'] === 983, { u: m['wled.fsUsedKb'], t: m['wled.fsTotalKb'] });
  check('wled.ledMaxPowerMa', m['wled.ledMaxPowerMa'] === 5_000, m['wled.ledMaxPowerMa']);
  check('wled.coreVersion', m['wled.coreVersion'] === '4.4.8.240628', m['wled.coreVersion']);
  check('wled.version', m['wled.version'] === '16.0.0', m['wled.version']);
  check('canonical system.swVersion emitted', m['system.swVersion'] === '16.0.0', m['system.swVersion']);
  check('wled.release (board variant)', m['wled.release'] === 'ESP32', m['wled.release']);
  check('wled.name + hostname consistency', m['wled.name'] === 'WLEDTest' && m['hostname'] === 'WLEDTest', { name: m['wled.name'], hostname: m['hostname'] });

  const rows = (m['updates'] ?? []) as any[];
  check('exactly one updates row', rows.length === 1, rows);
  const row = rows[0] ?? {};
  check('row kind firmware + available', row.kind === 'firmware' && row.available === true, row);
  check('currentVersion 16.0.0 → latestVersion 16.0.1', row.currentVersion === '16.0.0' && row.latestVersion === '16.0.1', { c: row.currentVersion, l: row.latestVersion });
  check('rebootRequired true', row.rebootRequired === true, row.rebootRequired);
  check('sizeBytes from asset', row.sizeBytes === 1_500_000, row.sizeBytes);
  check('releaseNotesUrl = release page', row.releaseNotesUrl === GITHUB_RELEASE.html_url, row.releaseNotesUrl);
  check('applyActionId wled.firmware.update', row.applyActionId === 'wled.firmware.update', row.applyActionId);
  const applyInput = (row.applyInput ?? {}) as any;
  // WLED's own UI rewrites ONLY the host to download.wled.me and keeps the full
  // GitHub path — mirror that exactly.
  check(
    'applyInput.url host-rewritten to download.wled.me + ESP32 asset',
    applyInput.url === 'https://download.wled.me/wled/WLED/releases/download/v16.0.1/WLED_16.0.1_ESP32.bin' && applyInput.fileName === 'WLED_16.0.1_ESP32.bin',
    applyInput
  );

  // Descriptors cover the emitted metrics.
  const keys = new Set((mon.data.metricDescriptors ?? []).map((d: any) => d.key));
  for (const k of ['wled.freeHeapBytes', 'wled.fps', 'wled.wifiRssiDbm', 'wled.wifiSignalPercent', 'wled.wifiBssid', 'wled.wifiSsid', 'wled.fsUsedKb', 'wled.ledMaxPowerMa', 'wled.coreVersion', 'system.swVersion', 'wled.version']) {
    check(`descriptor present: ${k}`, keys.has(k), [...keys]);
  }

  // --- /monitoring unreachable → critical ----------------------------------------------
  console.log('\n/monitoring (unreachable)');
  mon = await post('/monitoring', monitoringBody(`localhost:${CLOSED_PORT}`));
  check('HTTP 200 with health critical', mon.status === 200 && mon.data.health === 'critical', { status: mon.status, health: mon.data.health });
  check('system.error present', typeof (mon.data.metrics ?? {})['system.error'] === 'string', mon.data.metrics);

  // --- /monitoring low heap + weak wifi → warning ---------------------------------------
  console.log('\n/monitoring (low heap + weak WiFi)');
  deviceState.freeheap = 5_000;
  deviceState.rssi = -90;
  mon = await post('/monitoring', monitoringBody(`localhost:${MOCK_DEVICE_PORT}`));
  check('health warning', mon.data.health === 'warning', mon.data.health);
  const warn = String((mon.data.metrics ?? {})['system.warning'] ?? '');
  check('warnings mention heap + wifi', /free heap/.test(warn) && /weak WiFi/.test(warn), warn);
  // --- /monitoring flash nearly full → warning ------------------------------------------
  console.log('\n/monitoring (flash nearly full)');
  deviceState.fsUsedKb = 950; // ~96.6 % of 983 KB
  mon = await post('/monitoring', monitoringBody(`localhost:${MOCK_DEVICE_PORT}`));
  check('health warning on flash ≥ 90 %', mon.data.health === 'warning', mon.data.health);
  const fsWarn = String((mon.data.metrics ?? {})['system.warning'] ?? '');
  check('warning mentions the full flash', /flash nearly full/i.test(fsWarn), fsWarn);
  deviceState.fsUsedKb = 196;

  // --- wled.firmware.update: SLOW FLASH regression (upload timeout) ----------------------
  // Real WLED writes the image to SPI flash while serving /update — a slow box
  // answers in well over the default 5 s poll budget. With the old code this
  // failed with "request timed out after 5000 ms"; UPLOAD_TIMEOUT_MS (300 s)
  // must absorb it.
  console.log('\n/config wled.firmware.update (slow flash — upload timeout regression)');
  deviceState.updateDelayMs = 6_000; // > the default 5 s poll budget
  const slowCfg = await post('/config', {
    deviceId: 'test-device',
    managementAddress: `localhost:${MOCK_DEVICE_PORT}`,
    actionId: 'wled.firmware.update',
    input: { url: 'https://download.wled.me/WLED_16.0.1_ESP32.bin', fileName: 'WLED_16.0.1_ESP32.bin' },
  });
  const slowDetails = (slowCfg.data.result?.details ?? {}) as any;
  check('slow flash succeeds (no 5 s timeout)', slowCfg.data.success === true && slowCfg.data.result?.applied === true, { success: slowCfg.data.success, details: slowDetails });
  deviceState.updateDelayMs = 0;
  // Reset the version so the later PIN full-flow section flashes for real
  // (otherwise its idempotency guard would short-circuit).
  deviceState.ver = '16.0.0';

  // --- wled.firmware.update: PIN gate first (401 without pin) ---------------------------
  console.log('\n/config wled.firmware.update (PIN 401 path)');
  deviceState.pin = '1234';
  let cfg = await post('/config', {
    deviceId: 'test-device',
    managementAddress: `localhost:${MOCK_DEVICE_PORT}`,
    actionId: 'wled.firmware.update',
    input: { url: 'https://download.wled.me/WLED_16.0.1_ESP32.bin', fileName: 'WLED_16.0.1_ESP32.bin' },
  });
  check('rejected without PIN (success:false)', cfg.data.success === false, cfg.data);
  const pinDetails = (cfg.data.result?.details ?? {}) as any;
  check('error mentions the upload rejection + PIN hint', /PIN/i.test(String(pinDetails.error ?? '')) && /pin/i.test(String(pinDetails.hint ?? '')), cfg.data.result);

  // --- wled.firmware.update: full flow with PIN (download via broker → multipart → reboot)
  console.log('\n/config wled.firmware.update (full flow)');
  const fetchesBefore = brokerState.fetches.length;
  cfg = await post('/config', {
    deviceId: 'test-device',
    managementAddress: `localhost:${MOCK_DEVICE_PORT}`,
    actionId: 'wled.firmware.update',
    input: { url: 'https://download.wled.me/WLED_16.0.1_ESP32.bin', fileName: 'WLED_16.0.1_ESP32.bin', pin: '1234' },
  });
  const fwDetails = (cfg.data.result?.details ?? {}) as any;
  check('success + applied + verified', cfg.data.success === true && cfg.data.result?.applied === true && cfg.data.result?.verified === true, cfg.data);
  check('details.from 16.0.0 → details.to 16.0.1', fwDetails.from === '16.0.0' && fwDetails.to === '16.0.1', cfg.data.result);
  const newFetches = brokerState.fetches.slice(fetchesBefore);
  check('firmware downloaded THROUGH the web-fetch broker (no direct egress)', newFetches.includes('https://download.wled.me/WLED_16.0.1_ESP32.bin'), newFetches);
  check('multipart field name is "update"', deviceState.updateFieldNames.includes('update') && !deviceState.updateFieldNames.some((f) => f !== 'update' && f !== 'pin'), deviceState.updateFieldNames);
  check('file part carried the original file name', deviceState.updateFileName === 'WLED_16.0.1_ESP32.bin', deviceState.updateFileName);
  check('PIN form param sent to /update', deviceState.updatePinSent === '1234', deviceState.updatePinSent);
  deviceState.pin = null;

  // --- updates row now EMPTY (current == latest → authoritative wipe) -------------------
  console.log('\n/monitoring (already up to date — empty updates row)');
  mon = await post('/monitoring', monitoringBody(`localhost:${MOCK_DEVICE_PORT}`));
  const postMetrics = mon.data.metrics ?? {};
  check('device reports 16.0.1 after flash', postMetrics['wled.version'] === '16.0.1' && postMetrics['system.swVersion'] === '16.0.1', { wled: postMetrics['wled.version'], canonical: postMetrics['system.swVersion'] });
  check('updates = [] (authoritative wipe)', Array.isArray(mon.data.metrics?.['updates']) && mon.data.metrics['updates'].length === 0, mon.data.metrics?.['updates']);

  // --- wled.rename round-trip ------------------------------------------------------------
  console.log('\n/config wled.rename');
  cfg = await post('/config', {
    deviceId: 'test-device',
    managementAddress: `localhost:${MOCK_DEVICE_PORT}`,
    actionId: 'wled.rename',
    input: { name: 'Living Room' },
  });
  check('rename success + verified', cfg.data.success === true && cfg.data.result?.verified === true, cfg.data);
  mon = await post('/monitoring', monitoringBody(`localhost:${MOCK_DEVICE_PORT}`));
  check('hostname reflects the new name', (mon.data.metrics ?? {})['wled.name'] === 'Living Room' && (mon.data.metrics ?? {})['hostname'] === 'Living Room', mon.data.metrics?.['wled.name']);
  deviceState.name = 'WLEDTest'; // restore for any later assertions

  // --- wled.state.set: schema range validation + in-range apply ---------------------------
  console.log('\n/config wled.state.set');
  cfg = await post('/config', {
    deviceId: 'test-device',
    managementAddress: `localhost:${MOCK_DEVICE_PORT}`,
    actionId: 'wled.state.set',
    input: { on: false, bri: 300 }, // out of range → schema rejects with a clear message
  });
  check('out-of-range bri rejected by the schema (fail-fast)', cfg.data.success === false && /bri/.test(String(cfg.data.result?.error ?? '')), cfg.data);
  cfg = await post('/config', {
    deviceId: 'test-device',
    managementAddress: `localhost:${MOCK_DEVICE_PORT}`,
    actionId: 'wled.state.set',
    input: { on: false, bri: 128 },
  });
  check('in-range state set success', cfg.data.success === true, cfg.data);
  const lastState = deviceState.stateWrites[deviceState.stateWrites.length - 1] as any;
  check('bri=128 + on=false applied verbatim', lastState?.state?.bri === 128 && lastState?.state?.on === false, lastState);

  // --- wled.firmware.revert: ESP32 guard -------------------------------------------------
  console.log('\n/config wled.firmware.revert (ESP32 guard)');
  cfg = await post('/config', {
    deviceId: 'test-device',
    managementAddress: `localhost:${MOCK_DEVICE_PORT}`,
    actionId: 'wled.firmware.revert',
    input: {},
  });
  const revertDetails = (cfg.data.result?.details ?? {}) as any;
  check('refused on esp32 with a clear error', cfg.data.success === false && /ESP8266/.test(String(revertDetails.error ?? '')), cfg.data);

  // --- wled.config.backup: full cfg snapshot ---------------------------------------------
  console.log('\n/config wled.config.backup');
  cfg = await post('/config', {
    deviceId: 'test-device',
    managementAddress: `localhost:${MOCK_DEVICE_PORT}`,
    actionId: 'wled.config.backup',
    input: {},
  });
  const bkDetails = (cfg.data.result?.details ?? {}) as any;
  check('backup success + base64 payload + size', cfg.data.success === true && typeof bkDetails.backupBase64 === 'string' && Number(bkDetails.sizeBytes) > 0, { size: bkDetails.sizeBytes });
  let decodedCfg: Record<string, unknown> = {};
  try {
    decodedCfg = JSON.parse(Buffer.from(String(bkDetails.backupBase64), 'base64').toString('utf8')) as Record<string, unknown>;
  } catch { /* leave empty → next check fails */ }
  check('decoded backup carries the wifi network list (ssid)', String((decodedCfg['nw'] as any)?.ins?.[0]?.ssid ?? '') === 'KirgusNET_IoT', decodedCfg);

  // --- input validation ------------------------------------------------------------------
  console.log('\n/config (input validation)');
  cfg = await post('/config', {
    deviceId: 'test-device',
    managementAddress: `localhost:${MOCK_DEVICE_PORT}`,
    actionId: 'wled.firmware.update',
    input: {}, // missing required url
  });
  check('missing url → invalid input error', cfg.data.success === false && /url/.test(String(cfg.data.result?.error ?? '')), cfg.data);

  // --- /plan (the API's createPlanCore contract) ------------------------------------------
  console.log('\n/plan');
  const planBody = {
    intent: { actionId: 'wled.firmware.update', inputs: { url: 'https://download.wled.me/WLED_16.0.1_ESP32.bin', fileName: 'WLED_16.0.1_ESP32.bin' } },
    devices: [{ deviceId: 'dev-1', managementAddress: `localhost:${MOCK_DEVICE_PORT}`, credentials: {} }],
  };
  let plan = await post('/plan', planBody);
  check('HTTP 200 + plan envelope', plan.status === 200 && !!plan.data.plan, { status: plan.status });
  const p1 = (plan.data.plan ?? {}) as any;
  check('intentActionId echoed', p1.intentActionId === 'wled.firmware.update', p1.intentActionId);
  check(
    'backup step prepended + update + settle/refresh tail',
    JSON.stringify(p1.steps?.map((s: any) => s.actionId)) === JSON.stringify(['wled.config.backup', 'wled.firmware.update', 'unm.wait', 'unm.inventory.refresh']),
    p1.steps?.map((s: any) => s.actionId)
  );
  check('backup step is best-effort with empty input', p1.steps?.[0]?.bestEffort === true && JSON.stringify(p1.steps?.[0]?.input ?? {}) === '{}', p1.steps?.[0]);
  check('update step input carries url + fileName verbatim', p1.steps?.[1]?.input?.url === planBody.intent.inputs.url && p1.steps?.[1]?.input?.fileName === 'WLED_16.0.1_ESP32.bin', p1.steps?.[1]?.input);
  check('settle tail is best-effort + refresh depends on the wait', p1.steps?.[2]?.bestEffort === true && p1.steps?.[3]?.bestEffort === true && JSON.stringify(p1.steps?.[3]?.dependsOn) === '[2]', p1.steps?.slice(2));
  check('no provision requests (credential-free)', Array.isArray(p1.provisionRequests) && p1.provisionRequests.length === 0, p1.provisionRequests);

  // A rename intent produces a single step with NO settle tail.
  plan = await post('/plan', { intent: { actionId: 'wled.rename', inputs: { name: 'Hallway' } }, devices: [planBody.devices[0]] });
  const p2 = (plan.data.plan ?? {}) as any;
  check('rename → exactly one step, no tail', JSON.stringify(p2.steps?.map((s: any) => s.actionId)) === '["wled.rename"]', p2.steps);

  // Invalid input is rejected at planning time (fail-fast, HTTP 400).
  plan = await post('/plan', { intent: { actionId: 'wled.firmware.update', inputs: {} }, devices: [planBody.devices[0]] });
  check('missing url → 400 with schema error', plan.status === 400 && /url/.test(String(plan.data.error ?? '')), { status: plan.status, body: plan.data });

  // Unknown action id is rejected.
  plan = await post('/plan', { intent: { actionId: 'wled.bogus', inputs: {} }, devices: [planBody.devices[0]] });
  check('unknown action → 400', plan.status === 400 && /Unknown action/.test(String(plan.data.error ?? '')), { status: plan.status, body: plan.data });

  // --- quick action ----------------------------------------------------------------------
  console.log('\n/quick-action');
  const qa = await post('/quick-action', { deviceId: 'test-device', managementAddress: `localhost:${MOCK_DEVICE_PORT}`, actionId: 'webui' });
  check('resolves to the device web-UI URL', qa.data.url === `http://localhost:${MOCK_DEVICE_PORT}`, qa.data);

  // --- Summary ---------------------------------------------------------------------------
  console.log(failures === 0 ? '\n✅ ALL CHECKS PASSED' : `\n❌ ${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('smoke test crashed:', err);
  process.exit(1);
});
