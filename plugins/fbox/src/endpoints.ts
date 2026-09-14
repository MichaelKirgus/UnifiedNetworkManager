/**
 * Typed views over the FRITZ!Box web-UI read endpoints.
 *
 * The box's own HTTP(S) UI exposes a set of JSON/lua data endpoints that are
 * always available (no box-side enablement, unlike TR-064) and work across
 * FRITZ!OS 7.x/8.x:
 *   - GET /systeminfo64.json            → system identity + health counters
 *   - GET /overview.lua?get_data=1      → LAN/WAN overview incl. connected devices
 *   - GET /internetinfo.json            → WAN connection state (type, IP, DNS)
 *   - GET /laninfo.json                 → per-port link info (speed/duplex/status)
 *   - GET /wlaninfo.json?ifname=wlanN   → per-radio SSID/channel/clients
 *
 * Field names vary slightly between firmware versions — every parser below is
 * defensive (candidate-key lists, tolerant types). The exact live shapes are
 * pinned down by `live-probe.ts` against real hardware before release.
 */

import { normalizeMac } from '@unm/plugin-sdk';

// --- candidate-key pickers ------------------------------------------------------

type Obj = Record<string, unknown>;

/** First present string value among the given keys ('' when none). */
export function pickStr(obj: Obj | null | undefined, ...keys: string[]): string {
  if (!obj) return '';
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
    if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  }
  return '';
}

/** First present finite number among the given keys (null when none). */
export function pickNum(obj: Obj | null | undefined, ...keys: string[]): number | null {
  if (!obj) return null;
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'number' && Number.isFinite(v)) return v;
    if (typeof v === 'string') {
      const n = Number(v);
      if (v.trim() !== '' && Number.isFinite(n)) return n;
    }
  }
  return null;
}

/** IPv4 netmask string ("255.255.255.0") → prefix length, or the value itself when already a prefix. */
export function maskToPrefix(mask: unknown): number | null {
  if (typeof mask === 'number' && Number.isFinite(mask)) return Math.round(mask);
  if (typeof mask !== 'string') return null;
  const s = mask.trim();
  if (/^\d{1,2}$/.test(s)) return Number(s); // already a prefix length
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let bits = 0;
  for (const p of parts) {
    const octet = Number(p);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    // Count set bits — a valid netmask is contiguous, so the count IS the prefix.
    let n = octet;
    while (n > 0) {
      bits += n & 1;
      n >>= 1;
    }
  }
  return bits >= 8 && bits <= 32 ? bits : null;
}

/** Canonical MAC normalization (lowercase colon form, '' when unparseable) — shared SDK helper. */
export { normalizeMac };

/** Strip the vendor brand prefix from a device-reported product name → plain model number. */
export function normalizeModelName(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  const s = raw.trim();
  // "FRITZ!Box 7590" / "FritzBox 4060" / "AVM FRITZ!Box 7530 AX" → "7590" / "4060" / "7530 AX".
  const m = s.match(/\b(\d{3,5}(?:\s*[A-Za-z]+)?)\s*$/);
  return m ? m[1].replace(/\s+/g, ' ') : s;
}

// --- systeminfo64.json ------------------------------------------------------------

export interface FBoxSystemInfo {
  name: string;
  model: string; // normalized (brand prefix stripped)
  rawModel: string; // as reported by the device
  version: string; // e.g. "183.09"
  uptimeSeconds: number | null;
  temperatureC: number | null;
  loadPct: number | null;
  memoryTotalBytes: number | null;
  memoryUsedBytes: number | null;
}

export function parseSystemInfo(raw: unknown): FBoxSystemInfo {
  const o = (raw && typeof raw === 'object' ? raw : {}) as Obj;
  return {
    name: pickStr(o, 'name', 'hostname'),
    model: normalizeModelName(pickStr(o, 'model')),
    rawModel: pickStr(o, 'model'),
    version: pickStr(o, 'version', 'fwversion', 'firmware'),
    uptimeSeconds: pickNum(o, 'uptime'),
    temperatureC: pickNum(o, 'temperature'),
    loadPct: pickNum(o, 'load', 'cpuLoad'),
    memoryTotalBytes: pickNum(o, 'memorytotal', 'memoryTotal'),
    memoryUsedBytes: pickNum(o, 'memoryused', 'memoryUsed'),
  };
}

// --- overview.lua -------------------------------------------------------------------

export interface FBoxLanDevice {
  mac: string;
  ip: string;
  hostname: string;
  online: boolean | null;
  /** Physical port label (html2 netDev rows, e.g. "LAN 1 mit 1 Gbit/s") — used as the host's intf. */
  port?: string;
}

export interface FBoxOverview {
  lanIp: string;
  lanPrefix: number | null;
  dns1: string;
  dns2: string;
  devices: FBoxLanDevice[];
  wanIp: string;
  wanDns1: string;
  wanDns2: string;
}

export function parseOverview(raw: unknown): FBoxOverview {
  const o = (raw && typeof raw === 'object' ? raw : {}) as Obj;
  const lan = (o['lan'] ?? {}) as Obj;
  const wan = (o['wan'] ?? {}) as Obj;

  const devices: FBoxLanDevice[] = [];
  const rawDevices = Array.isArray(lan['devices']) ? (lan['devices'] as unknown[]) : [];
  for (const d of rawDevices) {
    if (!d || typeof d !== 'object') continue;
    const r = d as Obj;
    const mac = normalizeMac(pickStr(r, 'mac', 'hwaddr'));
    const ip = pickStr(r, 'ip', 'ipv4');
    if (!mac && !ip) continue;
    devices.push({
      mac,
      ip: ip === '0.0.0.0' ? '' : ip, // placeholder — the API skips it anyway
      hostname: pickStr(r, 'name', 'hostname'),
      online: typeof r['online'] === 'boolean' ? (r['online'] as boolean) : null,
    });
  }

  return {
    lanIp: pickStr(lan, 'ip', 'ipv4'),
    lanPrefix: maskToPrefix(pickStr(lan, 'netmask', 'subnetmask') || pickNum(lan, 'prefix')),
    dns1: pickStr(lan, 'dns1'),
    dns2: pickStr(lan, 'dns2'),
    devices,
    wanIp: pickStr(wan, 'ip', 'ipv4'),
    wanDns1: pickStr(wan, 'dns1'),
    wanDns2: pickStr(wan, 'dns2'),
  };
}

// --- internetinfo.json ----------------------------------------------------------------

export interface FBoxInternetInfo {
  connectionType: string; // dsl | cable | ipclient | fiber | mobile | '' (unknown)
  online: boolean | null;
  ip: string;
  dns1: string;
  dns2: string;
  /** html2 overview only — negotiated rates in Mbit/s. */
  downstreamMbps?: number | null;
  upstreamMbps?: number | null;
  provider?: string;
  /** html2 overview only — WAN IPv6 address WITHOUT the "/<len>" suffix. */
  ipv6Ip?: string;
  /** html2 overview only — delegated prefix, e.g. "2003:e9::/56". */
  ipv6Prefix?: string;
}

export function parseInternetInfo(raw: unknown): FBoxInternetInfo {
  const o = (raw && typeof raw === 'object' ? raw : {}) as Obj;
  return {
    connectionType: pickStr(o, 'connectiontype', 'connectionType', 'type').toLowerCase(),
    online: typeof o['online'] === 'boolean' ? (o['online'] as boolean) : null,
    ip: pickStr(o, 'ip', 'ipv4'),
    dns1: pickStr(o, 'dns1'),
    dns2: pickStr(o, 'dns2'),
  };
}

// --- laninfo.json ---------------------------------------------------------------------

export interface FBoxLanPort {
  name: string; // e.g. "eth0" / "LAN1"
  speedMbps: number | null;
  duplex: string; // 'full' | 'half' | ''
  status: string; // 'up' | 'down' | ''
}

/** laninfo.json is keyed by interface name (verify live); tolerate an array too. */
export function parseLanInfo(raw: unknown): FBoxLanPort[] {
  const ports: FBoxLanPort[] = [];
  if (!raw || typeof raw !== 'object') return ports;

  const entries: [string, unknown][] = Array.isArray(raw)
    ? (raw as Obj[]).map((r, i) => [`port${i}`, r])
    : Object.entries(raw as Obj);

  for (const [name, v] of entries) {
    if (!v || typeof v !== 'object') continue;
    const o = v as Obj;
    // Skip non-port top-level keys that some firmware versions include.
    if (typeof o['speed'] === 'undefined' && typeof o['duplex'] === 'undefined' && typeof o['status'] === 'undefined') continue;
    ports.push({
      name: pickStr(o, 'ifname', 'name') || name,
      speedMbps: pickNum(o, 'speed'),
      duplex: pickStr(o, 'duplex').toLowerCase(),
      status: pickStr(o, 'status', 'linkstate').toLowerCase() === 'up' ? 'up' : pickStr(o, 'status', 'linkstate').toLowerCase() || 'down',
    });
  }
  return ports;
}

// --- wlaninfo.json ----------------------------------------------------------------------

export type FBoxBand = '' | '2g' | '5g' | '6g';

export interface FBoxWlanClient {
  mac: string;
  ip: string;
  hostname: string;
}

export interface FBoxWlanRadio {
  ifname: string; // wlan0 / wlan1 / wlan2
  ssid: string;
  channel: number | null;
  band: FBoxBand;
  encryption: string;
  clients: FBoxWlanClient[];
  /** html2 wSet only — the radio's BSSID. */
  bssid?: string;
}

/** Map a radio interface name to its band (wlan0=2.4 GHz, wlan1=5 GHz, wlan2=6 GHz). */
export function bandFromIfname(ifname: string): FBoxBand {
  const m = ifname.match(/wlan(\d+)/i);
  if (!m) return '';
  switch (Number(m[1])) {
    case 0: return '2g';
    case 1: return '5g';
    case 2: return '6g';
    default: return '';
  }
}

/** Normalize a firmware-reported band label ("24GHz", "5 GHz", …) when present. */
export function normalizeBandLabel(raw: unknown): FBoxBand {
  const s = String(raw ?? '').toLowerCase();
  if (s.includes('6')) return '6g';
  if (s.includes('5')) return '5g';
  if (s.includes('2') || s.includes('4')) return '2g'; // "24GHz" / "2.4 GHz"
  return '';
}

export function parseWlanInfo(raw: unknown, ifname: string): FBoxWlanRadio {
  const o = (raw && typeof raw === 'object' ? raw : {}) as Obj;
  const clients: FBoxWlanClient[] = [];
  const rawClients = Array.isArray(o['clients']) ? (o['clients'] as unknown[]) : [];
  for (const c of rawClients) {
    if (!c || typeof c !== 'object') continue;
    const r = c as Obj;
    const mac = normalizeMac(pickStr(r, 'mac', 'hwaddr'));
    const ip = pickStr(r, 'ip', 'ipv4');
    if (!mac && !ip) continue;
    clients.push({ mac, ip: ip === '0.0.0.0' ? '' : ip, hostname: pickStr(r, 'hostname', 'name') });
  }

  const labelBand = normalizeBandLabel(o['band']);
  return {
    ifname: pickStr(o, 'ifname') || ifname,
    ssid: pickStr(o, 'ssid'),
    channel: pickNum(o, 'channel'),
    band: labelBand !== '' ? labelBand : bandFromIfname(ifname),
    encryption: pickStr(o, 'encryption', 'security').toLowerCase(),
    clients,
  };
}

// --- HTML2 generation (POST /data.lua multiplexed pages) ------------------------------
//
// The new FRITZ!OS UI removed every classic data endpoint; all information now
// flows through `POST /data.lua {page:<pid>, sid}`. Verified live payload shapes:
//   - no page param            → home overview (fritzos identity, internet WAN,
//                                wlan band text) — unknown pids fall back to it too
//   - netDev (+ xhrId=all)     → LAN host table: data.active[] + data.passive[]
//   - wSet                     → wlanSettings {ssid, mac=BSSID, protocol, encryption}
//   - energy                   → drain[] incl. "LAN-Anschlüsse" port LEDs + uptime text
//   - usbOv                    → usbOverview.boxIpAddress (the ONLY LAN IP source)

/** System identity from the html2 overview payload (`data.fritzos`). */
export interface FBoxHtml2System {
  name: string; // fb_name when set, else '' — hostname is user-configurable on the box
  model: string; // normalized product name ("7530 AX")
  rawModel: string; // "FRITZ!Box 7530 AX"
  version: string; // full firmware from iframeUrl (e.g. "256.08.25"), nspver fallback
}

/** WAN state from the html2 overview payload (`data.internet`). */
export interface FBoxHtml2Internet {
  connectionType: string; // dsl | cable | ipclient | … ('' when unknown)
  online: boolean | null;
  ip: string;
  dns1: string;
  dns2: string;
  downstreamMbps: number | null;
  upstreamMbps: number | null;
  provider: string;
  /** WAN IPv6 address WITHOUT the "/<len>" suffix (the box appends it). */
  ipv6Ip: string;
  /** Delegated prefix, e.g. "2003:e9::/56" ('' when none). */
  ipv6Prefix: string;
}

/** One LAN host row from the html2 netDev page (active + passive merged). */
export interface FBoxHtml2Host {
  mac: string;
  ip: string; // '' for ARP-only rows without an address yet
  hostname: string;
  port: string; // "LAN 1 mit 1 Gbit/s" / WLAN label / ''
  medium: string; // 'ethernet' | 'wlan' | … (row `type`)
}

/** WLAN settings from the html2 wSet page. */
export interface FBoxHtml2Wlan {
  ssid: string;
  bssid: string;
  protocolGen: string; // "Wi-Fi 6" — decoded via the box's own code map
  encryption: string; // "WPA2" — decoded via the box's own code map
  band: FBoxBand; // from the overview wlan[] text ("Funknetz (5 GHz)")
}

/** LAN port LED state from the html2 energy page. */
export interface FBoxHtml2LanPort {
  name: string; // "LAN 1" …
  status: 'up' | 'down';
}

const HTML2_ENCRYPTION: Record<number, string> = { 0: '', 1: 'WEP', 2: 'WPA (TKIP)', 3: 'WPA2', 4: 'WPA + WPA2', 5: 'WPA3', 6: 'WPA2 + WPA3' };
const HTML2_PROTOCOL_GEN: Record<number, string> = { 24: 'Wi-Fi 3', 23: 'Wi-Fi 4', 25: 'Wi-Fi 4', 52: 'Wi-Fi 4', 53: 'Wi-Fi 5', 26: 'Wi-Fi 6', 54: 'Wi-Fi 6', 61: 'Wi-Fi 6', 62: 'Wi-Fi 7' };

/** Firmware code → label, exactly as the box's own /js/box.js renders it. */
export function html2EncryptionLabel(code: unknown): string {
  const n = Number(code);
  return Object.prototype.hasOwnProperty.call(HTML2_ENCRYPTION, n) ? HTML2_ENCRYPTION[n] : '';
}

/** Protocol code → Wi-Fi generation (the box's getProtocolType map). */
export function html2ProtocolLabel(code: unknown): string {
  const n = Number(code);
  return Object.prototype.hasOwnProperty.call(HTML2_PROTOCOL_GEN, n) ? HTML2_PROTOCOL_GEN[n] : '';
}

/** "Funknetz (5 GHz)" / "WLAN (6 GHz)" → band ('' when no frequency found). */
export function html2BandFromText(text: unknown): FBoxBand {
  const s = String(text ?? '');
  if (/6\s*GHz/i.test(s)) return '6g';
  if (/5\s*GHz/i.test(s)) return '5g';
  if (/(2|2\.4)\s*GHz/i.test(s)) return '2g';
  return '';
}

/** Full firmware version from the help iframeUrl (`version=256.08.25`), nspver fallback. */
export function html2FirmwareVersion(fritzos: Obj): string {
  const url = pickStr(fritzos, 'iframeUrl');
  const m = url.match(/[?&]version=(\d+\.\d+(?:\.\d+)?)/);
  if (m) return m[1];
  return pickStr(fritzos, 'nspver');
}

/** Parses the html2 home-overview payload (the `data` of a no-page /data.lua answer). */
export function parseHtml2Overview(raw: unknown): { system: FBoxHtml2System; internet: FBoxHtml2Internet | null; wlanBand: FBoxBand } {
  const o = (raw && typeof raw === 'object' ? raw : {}) as Obj;
  const fz = (o['fritzos'] ?? {}) as Obj;

  const system: FBoxHtml2System = {
    name: pickStr(fz, 'fb_name'),
    model: normalizeModelName(pickStr(fz, 'Productname')),
    rawModel: pickStr(fz, 'Productname'),
    version: html2FirmwareVersion(fz),
  };

  let internet: FBoxHtml2Internet | null = null;
  const inet = (o['internet'] ?? {}) as Obj;
  const conns = Array.isArray(inet['connections']) ? (inet['connections'] as unknown[]) : [];
  if (conns.length > 0) {
    const c = (conns[0] ?? {}) as Obj;
    const v4 = (c['ipv4'] ?? {}) as Obj;
    const dnsList = Array.isArray(v4['dns']) ? (v4['dns'] as unknown[]) : [];
    const dnsIps = dnsList.map((d) => pickStr(d as Obj, 'ip')).filter(Boolean);
    internet = {
      connectionType: pickStr(c, 'type', 'medium').toLowerCase() || pickStr(inet, 'box_type').toLowerCase(),
      online: typeof c['connected'] === 'boolean' ? (c['connected'] as boolean) : null,
      ip: pickStr(v4, 'ip'),
      dns1: dnsIps[0] ?? '',
      dns2: dnsIps[1] ?? '',
      downstreamMbps: rateToMbps(pickNum(c, 'downstream', 'medium_downstream')),
      upstreamMbps: rateToMbps(pickNum(c, 'upstream', 'medium_upstream')),
      provider: pickStr(c, 'provider'),
      // The box reports the WAN v6 address WITH a "/<len>" suffix (e.g.
      // "2003:e9::8ab/64") — strip it; `prefix` carries the delegated /56.
      ipv6Ip: pickStr((c['ipv6'] ?? {}) as Obj, 'ip').split('/')[0].trim(),
      ipv6Prefix: pickStr((c['ipv6'] ?? {}) as Obj, 'prefix'),
    };
  }

  const wlanArr = Array.isArray(o['wlan']) ? (o['wlan'] as unknown[]) : [];
  let wlanBand: FBoxBand = '';
  for (const w of wlanArr) {
    if (!w || typeof w !== 'object') continue;
    const b = html2BandFromText((w as Obj)['txt']);
    if (b !== '') {
      wlanBand = b;
      break;
    }
  }

  return { system, internet, wlanBand };
}

/** The overview reports rates in kbit/s — normalize to Mbit/s. */
function rateToMbps(kbps: number | null): number | null {
  if (kbps == null) return null;
  const mb = kbps / 1000;
  return Number.isFinite(mb) ? Math.round(mb * 10) / 10 : null;
}

// --- HTML2 form pages (boxnet / boxnet_ipv6) ------------------------------------
//
// Two html2 pids answer with an HTML FORM instead of the JSON envelope:
//   - `boxnet`       (route /network/ipv4):  LAN v4 config. The page head
//     carries `const g_mask = "255.255.255.0";` plus per-octet inputs
//     Netmask_all0..3 — both sources agree on the main-LAN netmask.
//   - `boxnet_ipv6`  (route /network/ipv6):  one `<div class="dhcpipv6">` block
//     per network: name (Heimnetz/Gastnetz/WAN/Delegiert), address, prefixlen.
// Both are fetched via FBoxClient.getHtmlPage() and parsed here.

/** LAN v4 netmask from the boxnet form page. */
export interface FBoxLanV4 {
  mask: string; // "255.255.255.0" ('' when not reported)
  prefix: number | null; // via maskToPrefix
}

/** One named IPv6 network from the boxnet_ipv6 form page. */
export interface FBoxLanV6Net {
  name: string; // "Heimnetz" (LAN) / "WAN" / …
  ip: string; // address WITHOUT prefix ('' when disabled, shown as "-")
  prefixLen: number | null;
}

/** Parses the boxnet form page → main-LAN v4 netmask. */
export function parseHtml2BoxNet(html: string): FBoxLanV4 {
  // Preferred source: the page-head constant (always present on live boxes).
  const gMask = html.match(/g_mask\s*=\s*"([^"]*)"/);
  if (gMask && /^\d{1,3}(\.\d{1,3}){3}$/.test(gMask[1])) {
    return { mask: gMask[1], prefix: maskToPrefix(gMask[1]) };
  }
  // Fallback: the four per-octet inputs (Netmask_all0..3).
  const octets: string[] = [];
  for (let i = 0; i < 4; i++) {
    const m = html.match(new RegExp(`name="Netmask_all${i}"[^>]*value="(\\d{1,3})"`));
    if (!m) return { mask: '', prefix: null };
    octets.push(m[1]);
  }
  const mask = octets.join('.');
  return { mask, prefix: maskToPrefix(mask) };
}

/** Parses the boxnet_ipv6 form page → named v6 networks (LAN + WAN). */
export function parseHtml2BoxNetIpv6(html: string): FBoxLanV6Net[] {
  const out: FBoxLanV6Net[] = [];
  // Each block: <div class="dhcpipv6"><div class="name">Heimnetz</div><div
  // class="noBreakGroup adr"><div>2003:e9::</div><div class="separat">/</div>
  // <div class="prefixlen">64</div></div></div> — disabled nets show "-".
  const re = /class="dhcpipv6">[\s\S]*?class="name">([^<]+)<\/div>[\s\S]*?<div>([^<]*)<\/div><div class="separat">[^<]*<\/div><div class="prefixlen">([^<]*)<\/div>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const name = m[1].trim();
    const ip = m[2].trim() === '-' ? '' : m[2].trim().toLowerCase();
    const pl = m[3].trim() === '-' ? null : Number(m[3]);
    if (!name) continue;
    out.push({ name, ip: /^[0-9a-f:]+$/.test(ip) ? ip : '', prefixLen: pl != null && Number.isFinite(pl) && pl >= 1 && pl <= 128 ? Math.round(pl) : null });
  }
  return out;
}

/** Merges the html2 netDev host table (active + passive) into flat rows. */
export function parseHtml2NetDevHosts(raw: unknown): FBoxHtml2Host[] {
  const o = (raw && typeof raw === 'object' ? raw : {}) as Obj;
  const out: FBoxHtml2Host[] = [];
  for (const key of ['active', 'passive']) {
    const rows = Array.isArray(o[key]) ? (o[key] as unknown[]) : [];
    for (const r of rows) {
      if (!r || typeof r !== 'object') continue;
      const row = r as Obj;
      const mac = normalizeMac(pickStr(row, 'mac'));
      // ipv4 is an object on active rows and a plain string on some passive ones.
      const v4 = row['ipv4'];
      const ip = (typeof v4 === 'object' && v4 != null ? pickStr(v4 as Obj, 'ip') : typeof v4 === 'string' ? v4.trim() : '').replace(/^0\.0\.0\.0$/, '');
      if (!mac && !ip) continue;
      out.push({ mac, ip, hostname: pickStr(row, 'name'), port: pickStr(row, 'port').trim(), medium: pickStr(row, 'type', 'classes').toLowerCase() });
    }
  }
  // The box lists some hosts twice (e.g. CARP virtual MAC + physical) — dedupe on mac+ip.
  const seen = new Set<string>();
  return out.filter((h) => {
    if (!h.mac || !h.ip) return true;
    const k = `${h.mac}|${h.ip}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** Parses the html2 wSet page (`data.wlanSettings`). */
export function parseHtml2WSet(raw: unknown, band: FBoxBand = ''): FBoxHtml2Wlan | null {
  const o = (raw && typeof raw === 'object' ? raw : {}) as Obj;
  const ws = (o['wlanSettings'] ?? {}) as Obj;
  if (!ws || Object.keys(ws).length === 0) return null;
  return {
    ssid: pickStr(ws, 'ssid'),
    bssid: normalizeMac(pickStr(ws, 'mac')),
    protocolGen: html2ProtocolLabel(pickStr(ws, 'protocol')),
    encryption: html2EncryptionLabel(pickNum(ws, 'encryption') ?? pickStr(ws, 'encryption')),
    band,
  };
}

/**
 * MACs of the box's remembered WLAN devices (wSet `knownWlanDevices`). The
 * netDev host table carries no medium field — a LAN host is a CURRENTLY
 * ASSOCIATED WLAN client iff its MAC appears here AND it has a live address.
 */
export function parseHtml2KnownWlanMacs(raw: unknown): string[] {
  const o = (raw && typeof raw === 'object' ? raw : {}) as Obj;
  const ws = (o['wlanSettings'] ?? {}) as Obj;
  const known = Array.isArray(ws['knownWlanDevices']) ? (ws['knownWlanDevices'] as unknown[]) : [];
  const macs: string[] = [];
  for (const k of known) {
    if (!k || typeof k !== 'object') continue;
    const m = normalizeMac(pickStr(k as Obj, 'mac'));
    if (m && !macs.includes(m)) macs.push(m);
  }
  return macs;
}

/** "LAN 1 mit 1 Gbit/s" → "LAN 1" (the port name part only). */
export function html2PortName(port: string): string {
  const m = port.match(/^(LAN\s*\d+|WLAN[^ ]*|USB[^ ]*)/i);
  return m ? m[1].trim() : port.trim();
}

/** "aktiv seit 28 Tagen, 9 Stunden, 47 Minuten" → seconds (null when unparseable). */
export function parseGermanUptime(text: unknown): number | null {
  const s = String(text ?? '');
  if (!s) return null;
  let total = 0;
  let matched = false;
  const d = s.match(/(\d+)\s+Tagen?/i);
  const h = s.match(/(\d+)\s+Stunden?/i);
  const m = s.match(/(\d+)\s+Minuten?/i);
  if (d) { total += Number(d[1]) * 86400; matched = true; }
  if (h) { total += Number(h[1]) * 3600; matched = true; }
  if (m) { total += Number(m[1]) * 60; matched = true; }
  return matched ? total : null;
}

/** Parses the html2 energy page — LAN port LEDs + box uptime. */
export function parseHtml2Energy(raw: unknown): { lanPorts: FBoxHtml2LanPort[]; uptimeSeconds: number | null } {
  const o = (raw && typeof raw === 'object' ? raw : {}) as Obj;
  const drain = Array.isArray(o['drain']) ? (o['drain'] as unknown[]) : [];

  let lanPorts: FBoxHtml2LanPort[] = [];
  for (const d of drain) {
    if (!d || typeof d !== 'object') continue;
    const entry = d as Obj;
    if (pickStr(entry, 'name').toLowerCase() !== 'lan-anschlüsse') continue;
    const lan = Array.isArray(entry['lan']) ? (entry['lan'] as unknown[]) : [];
    lanPorts = lan.map((p): FBoxHtml2LanPort => {
      const r = (p && typeof p === 'object' ? p : {}) as Obj;
      return { name: pickStr(r, 'name'), status: pickStr(r, 'class') === 'green' ? 'up' : 'down' };
    }).filter((p) => p.name !== '');
  }

  let uptimeSeconds: number | null = null;
  for (const d of drain) {
    if (!d || typeof d !== 'object') continue;
    const entry = d as Obj;
    if (!/Gesamtsystem/i.test(pickStr(entry, 'name'))) continue;
    const statuses = entry['statuses'];
    const texts = Array.isArray(statuses) ? (statuses as unknown[]) : [statuses];
    for (const t of texts) {
      uptimeSeconds = parseGermanUptime(t);
      if (uptimeSeconds != null) break;
    }
    break;
  }

  return { lanPorts, uptimeSeconds };
}

/** Parses the html2 usbOv page — the box's own LAN IP (no netmask exists in html2). */
export function parseHtml2UsbOv(raw: unknown): { boxIp: string } {
  const o = (raw && typeof raw === 'object' ? raw : {}) as Obj;
  return { boxIp: pickStr((o['usbOverview'] ?? {}) as Obj, 'boxIpAddress') };
}
