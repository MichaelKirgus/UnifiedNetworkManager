/**
 * End-to-end smoke test for the MikroTik SwOS plugin.
 *
 * Boots TWO MOCK switches (plain HTTP, real Digest-auth challenge/response):
 *   - :48741  SwOS Lite (CSS610-8G-2S+, hex field ids i01…) with PoE + LAG
 *   - :48742  SwOS      (CRS305-1G-4S+, descriptive ids id/ver/en…) without PoE/LAG
 * then boots the REAL plugin (src/index.ts on PORT=48743) and exercises:
 *   - GET  /discover    → identity, secret type, action catalog, options, models
 *   - POST /monitoring  → metrics + inventory keys for BOTH platforms; bad creds → critical
 *   - POST /plan        → fan-out + best-effort backup snapshots
 *   - POST /config      → both body shapes; wire-format assertions (even-length hex,
 *                          text/plain, complete arrays); state actually mutated on the mock
 */
import http from 'http';
import { createHash } from 'crypto';

const LITE_PORT = 48741;
const SWOS_PORT = 48742;
const PLUGIN_PORT = 48743;
const BASE = `http://localhost:${PLUGIN_PORT}`;

function md5(s: string): string {
  return createHash('md5').update(s, 'utf8').digest('hex');
}
const hex = (s: string) => Buffer.from(s, 'latin1').toString('hex');
/** Little-endian IP encoding (SwOS wire format). */
function ipLe(ip: string): number {
  const [a, b, c, d] = ip.split('.').map(Number);
  return a | (b << 8) | (c << 16) | (d << 24);
}

// --- Mock switch factory -----------------------------------------------------------------

interface CapturedPost {
  endpoint: string;
  body: string;
  contentType?: string;
}

function makeSwosMock(port: number, platform: 'lite' | 'swos'): http.Server & { captured: CapturedPost[] } {
  // --- mutable device state ---------------------------------------------------------
  const state =
    platform === 'lite'
      ? {
          sys: {
            i01: 36_000, // uptime s
            i02: ipLe('192.168.88.1'),
            i03: '48a98a1954b4',
            i04: hex('SN-LITE-001'),
            i05: hex('CSS610-Office'),
            i06: hex('SwOS Lite 2.20'),
            i07: hex('CSS610-8G-2S+'),
            i0b: hex('2024-01-15'),
            i09: ipLe('192.168.88.1'),
            i0a: 0, // DHCP with fallback
            i19: 0,
            i1a: 0,
            i12: 0x3ff,
            i1b: 1,
          },
          link: {
            i01: 0x3ff, // all enabled
            i0a: ['Port1', 'Port2', 'Port3', 'Port4', 'Port5', 'Port6', 'Port7', 'Port8', 'SFP9', 'SFP10'].map(hex),
            i02: 0x3ff, // auto-neg all
            i03: 0x3ff, // duplex config
            i07: [1, 1, 1, 1, 0, 0, 0, 0, 1, 1], // duplex status (full=1)
            i08: [2, 2, 2, 2, 7, 7, 7, 7, 2, 2], // link status array (2=up, 7=no link)
            i06: 0x40f, // up bitmask: ports 1-4 + 9,10
            i05: [3, 3, 3, 3, 0, 0, 0, 0, 7, 7], // speed codes (1G copper, down, 10G SFP)
            i16: 0x00,
            i12: 0x00,
            i09: [36_000, 36_000, 72_000, 72_000, 0, 0, 0, 0, 36_000, 36_000],
          },
          poe: {
            i01: [0, 0, 2, 0, 0, 0, 0, 0], // port 3 = auto
            i02: [0, 0, 0, 0, 0, 0, 0, 0],
            i03: [0, 0, 0, 0, 0, 0, 0, 0],
            i04: [0, 0, 3, 0, 0, 0, 0, 0], // port 3 powered on
            i05: [0, 0, 250, 0, 0, 0, 0, 0], // mA
            i06: [0, 0, 54, 0, 0, 0, 0, 0], // 0.1 V → 5.4 V
            i07: [0, 0, 13, 0, 0, 0, 0, 0], // 0.1 W → 1.3 W
            i0a: 0x08, // LLDP bitmask (port 3)
            i0b: [0, 0, 0, 0, 0, 0, 0, 0],
          },
          lag: {
            i01: [1, 1, 0, 0, 0, 0, 0, 0, 0, 0], // active on ports 1-2
            i03: [5, 5, 0, 0, 0, 0, 0, 0, 0, 0], // group 5
            i04: ['48a98a1954c0', '48a98a1954c0', '', '', '', '', '', '', '', ''],
          },
          vlanTable: [
            { i01: 1, i02: 0x3ff, i03: 0 },
            { i01: 10, i02: 0x6, i03: 1 }, // ports 2+3
          ],
          fwd: {
            i15: [0, 1, 1, 0, 0, 0, 0, 0, 0, 0], // Disabled/Optional/Optional…
            i17: [0, 0, 2, 0, 0, 0, 0, 0, 0, 0],
            i18: [1, 10, 10, 1, 1, 1, 1, 1, 1, 1],
            i19: 0x4, // force bitmask (port 3)
          },
          snmp: { i01: 1, i02: hex('public'), i03: '', i04: '' },
          dhost: [
            { i01: 'aabbccddeeff', i02: 0 },
            { i01: 'aabbccddee01', i02: 3 },
          ],
        }
      : {
          sys: {
            upt: 72_000,
            cip: ipLe('192.168.88.2'),
            mac: '48a98a1954c1',
            sid: hex('SN-CRS-002'),
            id: hex('CRS305-Lab'),
            ver: hex('SwOS 2.17'),
            brd: hex('CRS305-1G-4S+'),
            bld: hex('2023-06-01'),
            ip: ipLe('192.168.88.2'),
            iotp: 1, // static
            alla: 0,
            allm: 0,
            allp: 0x1f,
            avln: 1,
            temp: hex('45C'),
          },
          link: {
            en: 0x1f,
            nm: ['ether1', 'ether2', 'ether3', 'sfp4', 'sfp5'].map(hex),
            an: 0x07,
            dpxc: 0x1f,
            dpx: [1, 1, 1, 1, 1],
            lnk: 0x0f, // up bitmask: ports 1-4
            spd: [3, 3, 3, 7, 7],
            spdc: [0, 0, 0, 0, 0],
            fctc: 0x0,
            fctr: 0x0,
            prt: 5,
            sfp: 2,
          },
          vlanTable: [
            { vid: 1, mbr: 0x1f, igmp: 0, nm: hex('Mgmt') },
            { vid: 20, mbr: 0xc, igmp: 1, nm: hex('Storage'), piso: 0, lrn: 1, mrr: 0 },
          ],
          fwd: {
            vlan: [0, 1, 1, 0, 0],
            vlni: [0, 2, 2, 0, 0],
            dvid: [1, 20, 20, 1, 1],
            fvid: 0x6,
          },
          snmp: { en: 0, com: hex('public'), ci: '', loc: '' },
          // Cumulative per-port byte counters (verified field ids rb/tb on real CRS309).
          stats: {
            rb: [1_000_000, 2_000_000, 3_000_000, 4_000_000, 5_000_000],
            tb: [100_000, 200_000, 300_000, 400_000, 500_000],
          },
          // SwOS format (verified on real CRS309): prt is a PORT BITMASK.
          dhost: [
            { adr: 'aabbccddeef0', vid: 1, prt: 0x4 }, // port 3
            { adr: 'aabbccddee01', vid: 20, prt: 0x82 }, // ports 1+8 (multi-port entry)
            { adr: 'aabbccddeef1', vid: 1, prt: 0x0 }, // internal/CPU — must be skipped
          ],
          sfp: {
            vnd: [hex('DS'), hex('COM')],
            pnr: [hex('SFP-10G-T '), hex('C-SFP-10G-T ')],
            typ: [hex('1m copper'), hex('850nm & mmf')],
            ser: ['47323533303136393437302d31', ''],
            dat: ['32352d30382d3132', ''],
            wln: [0, 85000],
            tmp: [4294967168, 38], // sentinel + real value
          },
        };

  const captured: CapturedPost[] = [];
  let nonceCounter = 0;

  // --- wire serialization (mirrors the switch's own format) --------------------------
  function fmtValue(v: unknown): string {
    if (Array.isArray(v)) return `[${v.map((x) => (typeof x === 'number' ? `0x${Math.max(0, Math.floor(x)).toString(16).padStart(2, '0')}` : `'${x}'`)).join(',')}]`;
    if (typeof v === 'number') {
      let h = Math.max(0, Math.floor(v)).toString(16);
      if (h.length % 2 !== 0) h = `0${h}`;
      return `0x${h}`;
    }
    return `'${v}'`;
  }
  function fmtObject(obj: Record<string, unknown>): string {
    return `{${Object.entries(obj).map(([k, v]) => `${k}:${fmtValue(v)}`).join(',')}}`;
  }

  // --- digest auth --------------------------------------------------------------------
  const USERNAME = 'admin';
  const PASSWORD = 'swospass';
  function parseAuthHeader(header: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const part of header.replace(/^Digest\s+/i, '').split(',')) {
      const eq = part.indexOf('=');
      if (eq < 0) continue;
      let v = part.slice(eq + 1).trim();
      if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
      out[part.slice(0, eq).trim().toLowerCase()] = v;
    }
    return out;
  }

  const server = http.createServer((req, res) => {
    const url = (req.url ?? '/').split('?')[0];
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      // --- unauthenticated debug endpoint: inspect applied state -------------------
      if (url === '/__state') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(state));
      }

      // --- auth gate -----------------------------------------------------------------
      const auth = req.headers.authorization;
      if (!auth || !auth.toLowerCase().startsWith('digest')) {
        nonceCounter++;
        res.writeHead(401, { 'WWW-Authenticate': `Digest realm="swos", nonce="nonce${nonceCounter}", qop="auth"` });
        return res.end();
      }
      const p = parseAuthHeader(auth);
      const ha1 = md5(`${p.username}:swos:${PASSWORD}`);
      const ha2 = md5(`${req.method}:${url}`);
      const expected = md5(`${ha1}:${p.nonce}:${p.nc}:${p.cnonce}:${p.qop ?? 'auth'}:${ha2}`);
      if (p.response !== expected) {
        nonceCounter++;
        res.writeHead(401, { 'WWW-Authenticate': `Digest realm="swos", nonce="nonce${nonceCounter}", qop="auth"` });
        return res.end();
      }

      // --- routing ---------------------------------------------------------------------
      if (req.method === 'GET') {
        switch (url) {
          case '/sys.b':
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            return res.end(fmtObject(state.sys as Record<string, unknown>));
          case '/link.b':
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            return res.end(fmtObject(state.link as Record<string, unknown>));
          case '/poe.b':
            if (platform === 'swos') {
              res.writeHead(404);
              return res.end(); // CRS305 has no PoE
            }
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            return res.end(fmtObject(state.poe as Record<string, unknown>));
          case '/lacp.b':
            if (platform === 'swos') {
              res.writeHead(404);
              return res.end(); // CRS305 has no LAG in this mock
            }
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            return res.end(fmtObject(state.lag as Record<string, unknown>));
          case '/vlan.b':
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            return res.end(`[${(state.vlanTable as Record<string, unknown>[]).map((v) => fmtObject(v)).join(',')}]`);
          case '/fwd.b':
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            return res.end(fmtObject(state.fwd as Record<string, unknown>));
          case '/snmp.b':
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            return res.end(fmtObject(state.snmp as Record<string, unknown>));
          case '/sfp.b': {
            if (platform === 'swos') {
              res.writeHead(200, { 'Content-Type': 'text/plain' });
              return res.end(fmtObject(state.sfp as Record<string, unknown>));
            }
            res.writeHead(404);
            return res.end(); // unsupported in this mock
          }
          case '/stats.b': {
            if (platform === 'swos') {
              // Simulate live traffic: every read advances the counters by 100 kB/port.
              const st = state.stats as Record<string, number[]>;
              for (let i = 0; i < st.rb.length; i++) {
                st.rb[i] += 100_000;
                st.tb[i] += 50_000;
              }
              res.writeHead(200, { 'Content-Type': 'text/plain' });
              return res.end(fmtObject(st));
            }
            res.writeHead(404);
            return res.end(); // not served by the Lite mock (field ids unverified)
          }
          case '/!dhost.b':
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            return res.end(`[${(state.dhost as Record<string, unknown>[]).map((v) => fmtObject(v)).join(',')}]`);
          case '/backup.swb': {
            const blob = Buffer.from(`SWB-BACKUP-${platform}-${Date.now()}`.repeat(10));
            res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
            return res.end(blob);
          }
          default:
            res.writeHead(404);
            return res.end();
        }
      }

      if (req.method === 'POST') {
        captured.push({ endpoint: url, body, contentType: req.headers['content-type'] });
        // Apply the posted fields to state (the switch applies + persists immediately).
        try {
          const parsed = JSON.parse(
            body
              .replace(/0x([0-9a-fA-F]+)/g, (_m, h: string) => String(parseInt(h, 16)))
              .replace(/'/g, '"')
              .replace(/([a-zA-Z_][a-zA-Z0-9_]*):/g, '"$1":')
          ) as Record<string, unknown> | Record<string, unknown>[];
          const target = url === '/vlan.b' ? null : (state as Record<string, Record<string, unknown>>)[url.slice(1, -2)] ?? null;
          if (Array.isArray(parsed)) {
            if (url === '/vlan.b') state.vlanTable = parsed as Record<string, unknown>[];
          } else if (target) {
            Object.assign(target, parsed);
          }
        } catch {
          // Malformed body — the real switch would reject it too.
          res.writeHead(400);
          return res.end();
        }
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end(''); // success = empty body + 200
      }

      res.writeHead(405);
      return res.end();
    });
  }) as http.Server & { captured: CapturedPost[] };

  server.captured = captured;
  return server;
}

// --- Test helpers ---------------------------------------------------------------------------

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra) : '');
  }
}

/** Asserts every hex literal in a POST body uses even-length digits. */
function assertEvenHex(label: string, body: string): void {
  const bad = (body.match(/0x[0-9a-fA-F]+/g) ?? []).filter((h) => (h.length - 2) % 2 === 1);
  check(`${label}: even-length hex only`, bad.length === 0, { body: body.slice(0, 200), odd: bad });
}

/** Fetches the mock's applied state via its unauthenticated debug endpoint. */
async function mockState(port: number): Promise<Record<string, Record<string, unknown>>> {
  return (await (await fetch(`http://localhost:${port}/__state`)).json()) as Record<string, Record<string, unknown>>;
}

async function main(): Promise<void> {
  const lite = makeSwosMock(LITE_PORT, 'lite');
  const swos = makeSwosMock(SWOS_PORT, 'swos');
  await new Promise<void>((r) => lite.listen(LITE_PORT, () => r()));
  await new Promise<void>((r) => swos.listen(SWOS_PORT, () => r()));
  console.log(`[smoke] mock switches on :${LITE_PORT} (SwOS Lite) and :${SWOS_PORT} (SwOS)`);

  // Boot the real plugin.
  process.env.PORT = String(PLUGIN_PORT);
  await import('./src/index');
  await new Promise((r) => setTimeout(r, 300));
  console.log(`[smoke] plugin on :${PLUGIN_PORT}`);

  const creds = { username: 'admin', password: 'swospass' };

  // --- /discover ---------------------------------------------------------------------------
  const disc = (await (await fetch(`${BASE}/discover`)).json()) as Record<string, unknown>;
  console.log('\n== /discover ==');
  check('uuid is the SwOS plugin uuid', disc.uuid === '00000000-0000-4000-8000-000000000005', disc.uuid);
  check('requiredSecretType usernamePassword', disc.requiredSecretType === 'usernamePassword');
  check('capabilities include planning+configuration', ['monitoring', 'configuration', 'inventory', 'planning'].every((c) => (disc.capabilities as string[]).includes(c)), disc.capabilities);
  const actions = (disc.actions ?? []) as { id: string; riskLevel: string }[];
  check('action catalog has all 10 actions', actions.length === 10, `count=${actions.length}`);
  check('dangerous actions marked', actions.filter((a) => a.riskLevel === 'dangerous').map((a) => a.id).sort().join(',') === 'system.management.set,vlans.table.set');
  const opts = (disc.options ?? []) as { key: string }[];
  check('options advertised', ['cacheTtlSeconds', 'requestTimeoutMs'].every((k) => opts.some((o) => o.key === k)));
  check('iconUrl set', disc.iconUrl === '/icons/swos.svg');
  const models = (disc.deviceModels ?? []) as { model: string }[];
  check('device catalog has 10 entries incl. Custom', models.length === 10 && models.some((m) => m.model === 'Custom / SwOS'), `count=${models.length}`);

  // --- /monitoring (SwOS Lite) -----------------------------------------------------------------
  const monLite = (await (
    await fetch(`${BASE}/monitoring`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ deviceId: 'dev-lite', managementAddress: `localhost:${LITE_PORT}`, credentials: creds, model: 'CSS610-8G-2S+', firmwareVersion: '2.20' }) })
  ).json()) as { health?: string; metrics?: Record<string, unknown>; metricDescriptors?: { key: string }[] };
  console.log('\n== /monitoring (SwOS Lite) ==');
  check('health ok', monLite.health === 'ok', monLite.metrics?.['system.error']);
  const m = monLite.metrics ?? {};
  check('identity decoded from hex', m['system.identity'] === 'CSS610-Office', m['system.identity']);
  check('detected model + firmware', m['system.detectedModel'] === 'CSS610-8G-2S+' && m['system.detectedFirmwareVersion'] === 'SwOS Lite 2.20');
  check('MAC decoded with colons', m['system.macAddress'] === '48:a9:8a:19:54:b4', m['system.macAddress']);
  check('little-endian IP decoded', m['system.currentIp'] === '192.168.88.1', m['system.currentIp']);
  check('uptime collected', m['system.uptime'] === 36_000);
  check('selected model/firmware echoed', m['system.model'] === 'CSS610-8G-2S+' && m['system.firmwareVersion'] === '2.20');
  check('portsUp summary (6/10 up)', m['switch.portsUp'] === '6/10', m['switch.portsUp']);

  const poeRows = (m['poe.ports'] ?? []) as Record<string, unknown>[];
  check('PoE table has 8 rows', poeRows.length === 8, `count=${poeRows.length}`);
  check('PoE port 3 powered on with power/voltage/current', poeRows[2]?.status === 'powered on' && poeRows[2]?.powerW === '1.3 W' && poeRows[2]?.voltageV === '5.4 V' && poeRows[2]?.currentMa === '250 mA', poeRows[2]);
  check('total PoE draw computed', m['poe.totalPowerW'] === 1.3, m['poe.totalPowerW']);

  const lagRows = (m['lag.ports'] ?? []) as Record<string, unknown>[];
  check('LAG table: ports 1-2 active group 5 with partner MAC', lagRows.length >= 2 && lagRows[0]?.mode === 'active' && lagRows[0]?.group === '5' && lagRows[0]?.partnerMac === '48:a9:8a:19:54:c0', lagRows[0]);

  const vlanRows = (m['vlans.table'] ?? []) as Record<string, unknown>[];
  check('VLAN table has 2 rows with members decoded', vlanRows.length === 2 && vlanRows[1]?.members === '2, 3' && vlanRows[1]?.igmpSnooping === 'on', vlanRows);

  const macTable = (m['macTable'] ?? []) as Record<string, unknown>[];
  check('macTable inventory: MAC + port intf', macTable.length === 2 && macTable[0]?.mac === 'aa:bb:cc:dd:ee:ff' && macTable[0]?.intf === 'port 1', macTable);

  const netRows = (m['networks'] ?? []) as Record<string, unknown>[];
  check('VLAN network rows emitted with vlanId', netRows.length === 2 && netRows.some((r) => r.name === 'VLAN 10' && r.vlanId === 10), netRows);

  const descs = (monLite.metricDescriptors ?? []).map((d) => d.key);
  check('descriptors cover tables', ['poe.ports', 'lag.ports', 'vlans.table', 'switch.macTable', 'snmp.enabled'].every((k) => descs.includes(k)), descs);

  // --- /monitoring (SwOS — CRS, no PoE/LAG, named VLANs) ------------------------------------------
  const monSwos = (await (
    await fetch(`${BASE}/monitoring`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ deviceId: 'dev-swos', managementAddress: `localhost:${SWOS_PORT}`, credentials: creds }) })
  ).json()) as { health?: string; metrics?: Record<string, unknown> };
  console.log('\n== /monitoring (SwOS) ==');
  const ms = monSwos.metrics ?? {};
  check('health ok', monSwos.health === 'ok', ms['system.error']);
  check('platform detected as SwOS', ms['system.platform'] === 'SwOS', ms['system.platform']);
  check('identity/model decoded (descriptive ids)', ms['system.identity'] === 'CRS305-Lab' && ms['system.detectedModel'] === 'CRS305-1G-4S+', [ms['system.identity'], ms['system.detectedModel']]);
  check('no PoE group on CRS305', !('poe.ports' in ms));
  const swosVlans = (ms['vlans.table'] ?? []) as Record<string, unknown>[];
  check('SwOS VLAN names decoded', swosVlans.length === 2 && swosVlans.some((v) => v.name === 'Storage'), swosVlans);

  // SwOS MAC table: prt is a port BITMASK (verified on real CRS309).
  const swosMacs = (ms['macTable'] ?? []) as Record<string, unknown>[];
  // 0x4 = bit 2 → port 3; 0x82 = bits 2+8 (0b1000_0010) → ports 2+8.
  check('SwOS macTable bitmask ports decoded', swosMacs.length === 2 && swosMacs[0]?.mac === 'aa:bb:cc:dd:ee:f0' && swosMacs[0]?.intf === 'port 3' && swosMacs[1]?.intf === 'port 2+8', swosMacs);

  // SwOS SFP: per-slot arrays zipped into rows, hex decoded, temp sentinel → '—',
  // physical port labels from sfpo (0) + slot index.
  const sfpRows = (ms['sfp.info'] ?? []) as Record<string, unknown>[];
  check('SwOS SFP per-slot rows decoded', sfpRows.length === 2 && sfpRows[0]?.port === '1' && sfpRows[0]?.vnd === 'DS' && sfpRows[0]?.tmp === '—' && sfpRows[1]?.port === '2' && sfpRows[1]?.pnr === 'C-SFP-10G-T ' && sfpRows[1]?.tmp === '38°C', sfpRows);

  // SwOS uptime is CENTIseconds (verified: Δ=1503 over 15.0s on real CRS309): mock upt=72_000 → 720 s.
  check('SwOS uptime normalized from centiseconds', ms['system.uptime'] === 720, ms['system.uptime']);

  // Port throughput: first sample has no previous → rates '—'. The second call must
  // BYPASS the monitoring TTL cache (min 10 s) or it serves the cached snapshot and
  // never re-samples stats.b — so both calls pin cacheTtlSeconds=10, then we wait past expiry.
  const monSwosCached = (
    await (
      await fetch(`${BASE}/monitoring`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-unm-settings': JSON.stringify({ cacheTtlSeconds: 10 }) }, body: JSON.stringify({ deviceId: 'dev-swos', managementAddress: `localhost:${SWOS_PORT}`, credentials: creds }) })
    ).json()
  ) as { metrics?: Record<string, unknown> };
  const psFirst = ((monSwosCached.metrics ?? ms)['switch.portStats'] ?? []) as Record<string, unknown>[];
  check('portStats table present with 5 rows', psFirst.length === 5 && psFirst[0]?.name === 'ether1' && psFirst[0]?.rxRate === '—', psFirst);
  await new Promise((r) => setTimeout(r, 11_000)); // outlive the 10 s TTL → forces a fresh stats.b sample
  const monSwos2 = (
    await (
      await fetch(`${BASE}/monitoring`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-unm-settings': JSON.stringify({ cacheTtlSeconds: 10 }) }, body: JSON.stringify({ deviceId: 'dev-swos', managementAddress: `localhost:${SWOS_PORT}`, credentials: creds }) })
    ).json()
  ) as { metrics?: Record<string, unknown> };
  const ms2 = monSwos2.metrics ?? {};
  const psSecond = (ms2['switch.portStats'] ?? []) as Record<string, unknown>[];
  check('port rates computed on second sample', psSecond.length === 5 && /^\d+(\.\d+)? Kbps$/.test(String(psSecond[0]?.rxRate)) && /^\d+(\.\d+)? Kbps$/.test(String(psSecond[0]?.txRate)), psSecond[0]);
  check('aggregate throughput gauges > 0', typeof ms2['switch.rxThroughput'] === 'number' && (ms2['switch.rxThroughput'] as number) > 0 && (ms2['switch.txThroughput'] as number) > 0, [ms2['switch.rxThroughput'], ms2['switch.txThroughput']]);

  // Gauge ceiling = total link capacity of the mock (3×1G + 2×10G = 23 Gbps), not the
  // default max:100 — otherwise raw bits/s pin the bar at 100%.
  const descs2 = ((await (
    await fetch(`${BASE}/monitoring`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ deviceId: 'dev-swos', managementAddress: `localhost:${SWOS_PORT}`, credentials: creds }) })
  ).json()) as { metricDescriptors?: { key: string; max?: number }[] }).metricDescriptors ?? [];
  const rxDesc = descs2.find((d) => d.key === 'switch.rxThroughput');
  check('throughput gauge max = link capacity (23 Gbps)', rxDesc?.max === 23e9, rxDesc);

  // --- /monitoring (bad credentials → critical) ------------------------------------------------------
  const monBad = (await (
    await fetch(`${BASE}/monitoring`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ deviceId: 'dev-lite', managementAddress: `localhost:${LITE_PORT}`, credentials: { username: 'admin', password: 'wrong' } }) })
  ).json()) as { health?: string; error?: string };
  console.log('\n== /monitoring (bad creds) ==');
  check('health critical on auth failure', monBad.health === 'critical', monBad);

  // --- /plan -------------------------------------------------------------------------------------------
  const planRes = await fetch(`${BASE}/plan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      intent: { actionId: 'port.config.set', inputs: { port: 1, name: 'Uplink' } },
      devices: [
        { deviceId: 'devA', managementAddress: `localhost:${LITE_PORT}`, credentials: creds },
        { deviceId: 'devB', managementAddress: `localhost:${SWOS_PORT}`, credentials: creds },
      ],
    }),
  });
  const planJson = (await planRes.json()) as { plan?: { provisionRequests: unknown[]; steps: { stepIndex: number; deviceId: string; actionId: string; bestEffort?: boolean }[] } };
  console.log('\n== /plan port.config.set ==');
  check('HTTP 200', planRes.status === 200);
  const plan = planJson.plan!;
  check('no provision requests (SwOS needs no secrets)', Array.isArray(plan.provisionRequests) && plan.provisionRequests.length === 0);
  check('4 steps: 2 best-effort backups + 2 port configs', plan.steps.length === 4, `got ${plan.steps.length}`);
  const backups = plan.steps.filter((s) => s.actionId === 'swos.backup.download');
  check('backup snapshots are bestEffort per dirty device', backups.length === 2 && backups.every((s) => s.bestEffort), backups);
  const cfgSteps = plan.steps.filter((s) => s.actionId === 'port.config.set');
  check('fan-out keeps inputs on both devices', cfgSteps.length === 2 && cfgSteps.every((s) => (s.input as Record<string, unknown>).name === 'Uplink'));

  // --- /config (plan-step shape: port rename on Lite mock) -------------------------------------------------
  const cfgRes = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `localhost:${LITE_PORT}`, credentials: creds, actionId: 'port.config.set', input: { port: 1, name: 'Uplink' } }),
  });
  const cfgJson = (await cfgRes.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config port.config.set ==');
  check('success true', cfgRes.status === 200 && cfgJson.success === true, cfgJson);
  const linkPost = lite.captured.find((c) => c.endpoint === '/link.b');
  check('POSTed to link.b with text/plain', !!linkPost && (linkPost.contentType ?? '').includes('text/plain'), linkPost?.contentType);
  if (linkPost) {
    assertEvenHex('link.b body', linkPost.body);
    check('port name hex-encoded in body', linkPost.body.includes(`'${hex('Uplink')}'`), linkPost.body.slice(0, 120));
    // State actually mutated on the mock (complete array re-sent, port 1 renamed):
    const st = await mockState(LITE_PORT);
    check('mock state: port 1 renamed', (st.link?.i0a as string[] | undefined)?.[0] === hex('Uplink'), st.link?.i0a);
    check('mock state: other ports untouched', (st.link?.i0a as string[] | undefined)?.[1] === hex('Port2'));
  }

  // --- /config (legacy shape: snmp.config.set) ------------------------------------------------------------------
  const snmpRes = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `localhost:${LITE_PORT}`, credentials: creds, action: 'snmp.config.set', payload: { enabled: true, community: 'private' } }),
  });
  const snmpJson = (await snmpRes.json()) as { success?: boolean };
  console.log('\n== /config snmp.config.set (legacy shape) ==');
  check('success true via legacy {action,payload}', snmpRes.status === 200 && snmpJson.success === true, snmpJson);
  const snmpPost = lite.captured.find((c) => c.endpoint === '/snmp.b');
  if (snmpPost) {
    assertEvenHex('snmp.b body', snmpPost.body);
    check('community hex-encoded', snmpPost.body.includes(`'${hex('private')}'`), snmpPost.body);
    const st = await mockState(LITE_PORT);
    check('mock state: community applied + enabled', st.snmp?.i02 === hex('private') && st.snmp?.i01 === 1, st.snmp);
  } else {
    check('POSTed to snmp.b', false, lite.captured.map((c) => c.endpoint));
  }

  // --- /config (vlans.table.set — array body) ---------------------------------------------------------------------
  const vlanRes = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `localhost:${LITE_PORT}`, credentials: creds, actionId: 'vlans.table.set', input: { vlans: [{ id: 1, members: [1, 2, 3] }, { id: 42, members: [5], igmpSnooping: true }] } }),
  });
  const vlanJson = (await vlanRes.json()) as { success?: boolean };
  console.log('\n== /config vlans.table.set ==');
  check('success true', vlanRes.status === 200 && vlanJson.success === true, vlanJson);
  const vlanPost = lite.captured.find((c) => c.endpoint === '/vlan.b');
  if (vlanPost) {
    assertEvenHex('vlan.b body', vlanPost.body);
    check('array-of-objects wire format', vlanPost.body.startsWith('[{') && vlanPost.body.endsWith('}]'), vlanPost.body.slice(0, 120));
    // members [5] → bit 4 → 0x10 (even-length)
    check('member bitmask encoded (port 5 → 0x10)', /\{i01:0x2a,i02:0x10/i.test(vlanPost.body), vlanPost.body);
    const st = await mockState(LITE_PORT);
    check('mock state: VLAN table replaced', Array.isArray(st.vlanTable) && (st.vlanTable as Record<string, unknown>[]).length === 2 && (st.vlanTable as Record<string, unknown>)[1]?.i01 === 42 && (st.vlanTable as Record<string, unknown>)[1]?.i03 === 1, st.vlanTable);
  } else {
    check('POSTed to vlan.b', false, lite.captured.map((c) => c.endpoint));
  }

  // --- /config (system.management.set — little-endian IP + CIDR) ------------------------------------------------------
  const mgmtRes = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `localhost:${LITE_PORT}`, credentials: creds, actionId: 'system.management.set', input: { addressAcquisition: 'static', staticIp: '192.168.88.50', allowFrom: '10.0.0.0/8' } }),
  });
  const mgmtJson = (await mgmtRes.json()) as { success?: boolean };
  console.log('\n== /config system.management.set ==');
  check('success true', mgmtRes.status === 200 && mgmtJson.success === true, mgmtJson);
  const sysPosts = lite.captured.filter((c) => c.endpoint === '/sys.b');
  if (sysPosts.length > 0) {
    assertEvenHex('sys.b body', sysPosts[sysPosts.length - 1].body);
    // 192.168.88.50 little-endian = 0x3258a8c0; allow-from 10.0.0.0 LE = 0x0000000a, /8 → i1a:0x08
    check('static IP little-endian encoded', sysPosts[sysPosts.length - 1].body.includes(`i09:0x3258a8c0`), sysPosts[sysPosts.length - 1].body.slice(0, 200));
    check('allow-from CIDR bits encoded', /i1a:0x0?8/.test(sysPosts[sysPosts.length - 1].body), sysPosts[sysPosts.length - 1].body);
    const st = await mockState(LITE_PORT);
    check('mock state: static mode + IP applied', st.sys?.i0a === 1 && st.sys?.i09 === ipLe('192.168.88.50'), { i0a: st.sys?.i0a, i09: st.sys?.i09 });
  } else {
    check('POSTed to sys.b', false, lite.captured.map((c) => c.endpoint));
  }

  // --- /config (backup download → base64 in details) ------------------------------------------------------------------
  const bakRes = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'devA', managementAddress: `localhost:${LITE_PORT}`, credentials: creds, actionId: 'swos.backup.download', input: {} }),
  });
  const bakJson = (await bakRes.json()) as { success?: boolean; result?: { details?: Record<string, unknown> } };
  console.log('\n== /config swos.backup.download ==');
  check('success true with base64 payload', bakRes.status === 200 && bakJson.success === true && typeof bakJson.result?.details?.backupBase64 === 'string' && (bakJson.result.details.backupBase64 as string).length > 100, { size: bakJson.result?.details?.sizeBytes });

  // --- /config (validation + unknown action) ---------------------------------------------------------------------------
  const badInput = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ managementAddress: `localhost:${LITE_PORT}`, credentials: creds, actionId: 'port.config.set', input: { port: 99 } }),
  });
  const badInputJson = (await badInput.json()) as { success?: boolean; result?: Record<string, unknown> };
  console.log('\n== /config validation ==');
  check('out-of-range port rejected with message', badInput.status === 200 && badInputJson.success === false && /port/i.test(String(badInputJson.result?.error)), badInputJson);

  const unknown = await fetch(`${BASE}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ managementAddress: `localhost:${LITE_PORT}`, credentials: creds, actionId: 'nope.nope', input: {} }),
  });
  const unknownJson = (await unknown.json()) as { success?: boolean };
  check('unknown action → 400 + success:false', unknown.status === 400 && unknownJson.success === false);

  // --- /plan (invalid intent) --------------------------------------------------------------------------------------------
  const badPlan = await fetch(`${BASE}/plan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ intent: { actionId: 'port.config.set', inputs: {} }, devices: [{ deviceId: 'devA', managementAddress: `localhost:${LITE_PORT}`, credentials: creds }] }),
  });
  check('plan with missing required input → 400', badPlan.status === 400, await badPlan.clone().text());

  // --- /state (device-state document for the Config page) -------------------------------------------------
  const stateRes = await fetch(`${BASE}/state`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deviceId: 'dev-lite', managementAddress: `localhost:${LITE_PORT}`, credentials: creds }),
  });
  const stateJson = (await stateRes.json()) as { collectedAt?: string; sections?: { id: string; label: string; items?: { key: string; title: string; status?: string; fields?: Record<string, unknown>; actions?: { actionId: string; prefill?: Record<string, unknown> }[] }[] }[] };
  console.log('\n== /state ==');
  check('HTTP 200', stateRes.status === 200);
  const sectionIds = (stateJson.sections ?? []).map((s) => s.id);
  check('has ports + vlans + system sections', ['ports', 'vlans', 'system'].every((id) => sectionIds.includes(id)), sectionIds);
  const portsSection = (stateJson.sections ?? []).find((s) => s.id === 'ports');
  check('10 port items', portsSection?.items?.length === 10, `count=${portsSection?.items?.length}`);
  const p1 = portsSection?.items?.find((i) => i.key === '1');
  check('port 1 up with LAG group + learned MAC', p1?.status === 'up' && /group 5/.test(String(p1?.fields?.LAG)) && Array.isArray(p1?.fields?.MACs) && (p1.fields.MACs as string[]).includes('aa:bb:cc:dd:ee:ff'), p1);
  check('port 1 actions prefill port number', p1?.actions?.some((a) => a.actionId === 'port.config.set' && a.prefill?.port === 1), p1?.actions);
  const p3 = portsSection?.items?.find((i) => i.key === '3');
  check('port 3 shows PoE draw + per-port VLAN PVID', /1\.3 W/.test(String(p3?.fields?.['PoE draw'])) && p3?.fields?.PVID === 10, p3);
  const sysSection = (stateJson.sections ?? []).find((s) => s.id === 'system');
  check('system item advertises info + backup actions', !!sysSection?.items?.[0]?.actions && ['swos.system.info', 'swos.backup.download'].every((id) => sysSection.items![0].actions!.some((a) => a.actionId === id)), sysSection?.items?.[0]?.actions);

  console.log(failures === 0 ? '\nALL SMOKE TESTS PASSED' : `\n${failures} SMOKE TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('[smoke] fatal:', err);
  process.exit(1);
});
