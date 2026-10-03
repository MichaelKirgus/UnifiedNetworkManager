/**
 * TR-064 (UPnP SOAP) transport — the alternative query method for this plugin.
 *
 * In addition to the web-UI session (fboxClient.ts), these routers expose the
 * Broadband Forum's TR-064 protocol: plain-HTTP SOAP on TCP port 49003,
 * authenticated with the device user list via HTTP Basic. Unlike the web UI
 * there is NO session to maintain and NO login rate-limit penalty — each poll
 * is a handful of stateless GetParameterValues calls (see the vendor's TR-064
 * documentation). The trade-off: fewer metrics (no temperature/CPU/memory, no
 * LAN port speeds) in exchange for robustness.
 *
 * Control-URL discovery: the device serves its UPnP description at
 * GET /igdservice.xml — we parse each <service>'s serviceType + controlURL
 * from it. When that is unavailable (or a service is missing), the documented
 * convention `http://<host>:49003/ctl?<ServiceType>` is used instead.
 *
 * All parameter lists are CANDIDATE lists: TR-064 GetParameterValues returns
 * only the parameters that exist on this firmware, so unknown names are simply
 * absent from the answer — one call covers many firmware generations.
 */

import axios from 'axios';
import { FBoxCredentials } from './fboxClient';
import type { FBoxOptions, MonitoringResult, FBoxSnapshot } from './monitoring';
import { maskToPrefix, normalizeMac, normalizeModelName } from './webuiEndpoints';

/** Raised when the device rejects our TR-064 credentials (HTTP 401/403). */
export class FBoxTr064AuthError extends Error {
  constructor(
    message = 'TR-064 authentication failed — check the assigned username/password secret (this method requires a non-empty username)'
  ) {
    super(message);
    this.name = 'FBoxTr064AuthError';
  }
}

/** The standard TR-064 SOAP namespace used by all services. */
const SOAP_NS = 'urn:dslforum-org:service-1-0';

interface Tr064Ctx {
  /** Plain-HTTP base of the control channel, e.g. http://192.168.178.1:49003 (no trailing slash). */
  base: string;
  creds: FBoxCredentials;
  timeoutMs: number;
  /** serviceType → controlURL parsed from /igdservice.xml (may be empty). */
  services: Map<string, string>;
}

/** One SOAP envelope for a TR-064 action. */
function soapEnvelope(action: string, inner: string): string {
  return `<?xml version="1.0" encoding="utf-8"?>\n<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n  <s:Body>\n    <u:${action} xmlns:u="${SOAP_NS}">${inner}</u:${action}>\n  </s:Body>\n</s:Envelope>`;
}

/** Parses `<Name>x</Name><Value>y</Value>` pairs out of a GetParameterValuesResponse. */
export function parseParamList(xml: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of xml.matchAll(/<Name>([^<]*)<\/Name>\s*<Value>([\s\S]*?)<\/Value>/g)) {
    out[m[1].trim()] = m[2].trim();
  }
  return out;
}

/** One LAN host row from LanDeviceHosts GetHostEntryList. */
interface Tr064Host {
  mac: string;
  ip: string;
  hostname: string;
}

/** Parses `<HostEntry>…</HostEntry>` blocks (candidate field names per firmware). */
export function parseHostEntries(xml: string): Tr064Host[] {
  const hosts: Tr064Host[] = [];
  for (const m of xml.matchAll(/<HostEntry>([\s\S]*?)<\/HostEntry>/g)) {
    const block = m[1];
    const field = (name: string): string => {
      const fm = block.match(new RegExp(`<${name}>([^<]*)</${name}>`));
      return fm ? fm[1].trim() : '';
    };
    const mac = normalizeMac(field('MACAddress') || field('mac'));
    const ip = field('IPAddress') || field('ip');
    if (!mac && !ip) continue;
    hosts.push({ mac, ip: ip === '0.0.0.0' ? '' : ip, hostname: field('HostName') || field('Name') });
  }
  return hosts;
}

/** One SOAP POST against a service control URL (raw XML in and out). */
async function soapCall(ctx: Tr064Ctx, controlUrl: string, action: string, inner: string): Promise<string> {
  const res = await axios.post(controlUrl, soapEnvelope(action, inner), {
    headers: {
      'Content-Type': 'text/xml; charset="utf-8"',
      SOAPAction: `"${SOAP_NS}#${action}"`,
    },
    // Password-only devices (empty username) are tried without an auth header —
    // a few parameters may still be readable anonymously.
    auth: ctx.creds.username ? { username: ctx.creds.username, password: ctx.creds.password } : undefined,
    timeout: ctx.timeoutMs,
    transformResponse: [(d) => d], // keep the XML body raw — we parse it ourselves
    validateStatus: () => true,
  });
  if (res.status === 401 || res.status === 403) throw new FBoxTr064AuthError();
  if (res.status < 200 || res.status >= 300) {
    const text = String(res.data ?? '');
    const fault = text.match(/<faultstring>([\s\S]*?)<\/faultstring>/);
    throw new Error(`HTTP ${res.status}${fault ? ` (${fault[1].trim()})` : ''} from ${action}`);
  }
  return String(res.data ?? '');
}

/** Resolves the control URL for a service type (discovered → documented convention). */
function controlUrlFor(ctx: Tr064Ctx, serviceType: string): string {
  const exact = ctx.services.get(serviceType);
  if (exact) return exact;
  // Instance-suffixed types (Device.WANIPConnection.1) may be listed without the suffix.
  const bare = serviceType.replace(/\.\d+$/, '');
  if (bare !== serviceType && ctx.services.has(bare)) return ctx.services.get(bare)!;
  return `${ctx.base}/ctl?${serviceType}`; // the vendor-documented fallback convention
}

/** GetParameterValues with a candidate list — missing params are simply absent. */
async function getParams(
  ctx: Tr064Ctx,
  serviceType: string,
  candidates: string[]
): Promise<{ values: Record<string, string>; error?: string }> {
  try {
    const xml = await soapCall(
      ctx,
      controlUrlFor(ctx, serviceType),
      'GetParameterValues',
      `<ParameterList>${candidates.map((c) => `<ParameterValue><Name>${c}</Name></ParameterValue>`).join('')}</ParameterList>`
    );
    return { values: parseParamList(xml) };
  } catch (err) {
    if (err instanceof FBoxTr064AuthError) throw err; // fatal — surface to the caller
    const msg = err instanceof Error ? err.message : String(err);
    return { values: {}, error: `${serviceType}: ${msg}` };
  }
}

/** One parameterless action call (e.g. LanDeviceHosts GetHostEntryList). */
async function callAction(ctx: Tr064Ctx, serviceType: string, action: string): Promise<{ xml: string; error?: string }> {
  try {
    return { xml: await soapCall(ctx, controlUrlFor(ctx, serviceType), action, '') };
  } catch (err) {
    if (err instanceof FBoxTr064AuthError) throw err;
    const msg = err instanceof Error ? err.message : String(err);
    return { xml: '', error: `${serviceType}: ${msg}` };
  }
}

/** Parses the UPnP device description → serviceType→controlURL map. */
async function discoverServices(base: string, timeoutMs: number): Promise<Map<string, string>> {
  const res = await axios.get(`${base}/igdservice.xml`, {
    timeout: timeoutMs,
    transformResponse: [(d) => d],
    validateStatus: () => true,
  });
  if (res.status !== 200) throw new Error(`HTTP ${res.status} from /igdservice.xml`);
  const xml = String(res.data ?? '');
  const map = new Map<string, string>();
  for (const svc of xml.matchAll(/<service>([\s\S]*?)<\/service>/g)) {
    const typeM = svc[1].match(/<serviceType>([^<]*)<\/serviceType>/);
    const urlM = svc[1].match(/<controlURL>([^<]*)<\/controlURL>/);
    if (typeM && urlM) map.set(typeM[1].trim(), urlM[1].trim());
  }
  return map;
}

/** '123456' → 123456, '' / non-numeric → null. */
function toInt(v: unknown): number | null {
  if (typeof v !== 'string' || v.trim() === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

/** First present integer among candidate values. */
function firstInt(...vals: unknown[]): number | null {
  for (const v of vals) {
    const n = toInt(v);
    if (n != null) return n;
  }
  return null;
}

/** bps → Mbit/s (10^6), rounded. */
function bpsToMbps(bps: number | null): number | null {
  return bps == null || bps <= 0 ? null : Math.round(bps / 1_000_000);
}

/**
 * Collects one full snapshot over TR-064. Throws on auth failure or a target
 * that does not answer like a TR-064 device at all (the caller maps those to
 * health); per-service failures are collected into `warnings` instead.
 */
export async function getTr064Snapshot(host: string, creds: FBoxCredentials, opts: FBoxOptions): Promise<MonitoringResult> {
  const h = (host ?? '').trim().replace(/\/+$/, '');
  if (!h) throw new Error('No target address — set the device management address.');
  // The management address may carry an explicit web-UI port — TR-064 always
  // uses its own control-channel port instead.
  const bareHost = h.replace(/^https?:\/\//i, '').replace(/:\d+$/, '');
  const base = `http://${bareHost}:${opts.tr064Port ?? 49003}`;

  let services = new Map<string, string>();
  try {
    services = await discoverServices(base, opts.requestTimeoutMs);
  } catch {
    /* no device description — fall back to the /ctl? convention for every service */
  }

  const ctx: Tr064Ctx = { base, creds, timeoutMs: opts.requestTimeoutMs, services };
  const warnings: string[] = [];

  // Identity first — it also proves TR-064 is reachable AND authenticated at
  // all, so we fail fast with a clear message instead of burning the whole
  // poll budget on nine doomed calls.
  const di = await getParams(ctx, 'Device.DeviceInfo', [
    'Manufacturer',
    'ProductName',
    'ModelName',
    'SerialNumber',
    'SoftwareVersion',
    'Uptime',
  ]);
  if (di.error) {
    throw new Error(
      `TR-064 not usable on ${bareHost}: ${di.error} — note that TR-064 only answers from the router's own local network (LAN); if UNM reaches this box via its WAN address, use the webui query method. Otherwise check that TR-064 is enabled in the device settings.`
    );
  }

  // Everything else in one parallel batch (independent services).
  const WAN_CONN_PARAMS = [
    'ExternalIPAddress',
    'ConnectionStatus',
    'BytesSent',
    'BytesReceived',
    'LastConnectionFailure',
  ];
  const WLAN_PARAMS = ['SSID', 'Channel', 'BSSID', 'X_AVM-DE_BSSID', 'TotalActiveClients'];

  const [wanC, wanIp, wanPpp, dslR, hostsR, wlan1, wlan2, wlan3, lanCfg] = await Promise.allSettled([
    getParams(ctx, 'Device.WANCommonInterfaceConfig', ['ConnectionStatus', 'PhysicalLinkMaxDownloadSpeed', 'PhysicalLinkMaxUploadSpeed']),
    getParams(ctx, 'Device.WANIPConnection.1', WAN_CONN_PARAMS), // IP-connection mode (cable / IP client)
    getParams(ctx, 'Device.WANPPPConnection.1', WAN_CONN_PARAMS), // PPPoE mode (DSL)
    getParams(ctx, 'Device.WANDSLInterfaceConfig', ['DataTransferRateDownstream', 'DataTransferRateUpstream']),
    callAction(ctx, 'Device.LanDeviceHosts', 'GetHostEntryList'),
    getParams(ctx, 'Device.WLANConfiguration.1', WLAN_PARAMS),
    getParams(ctx, 'Device.WLANConfiguration.2', WLAN_PARAMS),
    getParams(ctx, 'Device.WLANConfiguration.3', WLAN_PARAMS),
    getParams(ctx, 'Device.LANHostConfigManagement', ['ExternalIPAddress', 'SubnetMask', 'HostName', 'X_AVM-DE_LANHostname']),
  ]);

  // A mid-batch auth failure is a hard error — surface it (getParams rethrows).
  for (const r of [wanC, wanIp, wanPpp, dslR, hostsR, wlan1, wlan2, wlan3, lanCfg]) {
    if (r.status === 'rejected' && r.reason instanceof FBoxTr064AuthError) throw r.reason;
  }

  const collect = <T>(r: PromiseSettledResult<T>, label: string): T | null => {
    if (r.status === 'fulfilled') return r.value;
    warnings.push(`${label}: ${r.reason instanceof Error ? r.reason.message : String(r.reason)}`);
    return null;
  };

  const diV = di.values;
  const wc = collect(wanC, 'WANCommonInterfaceConfig');
  const ipc = collect(wanIp, 'WANIPConnection.1');
  const ppp = collect(wanPpp, 'WANPPPConnection.1');
  const dsl = collect(dslR, 'WANDSLInterfaceConfig');
  const hostsXml = collect(hostsR, 'LanDeviceHosts')?.xml ?? '';
  const lc = collect(lanCfg, 'LANHostConfigManagement');

  // --- system identity ---------------------------------------------------------
  const modelRaw = diV['ProductName'] || diV['ModelName'] || '';
  const system = {
    name: lc ? (lc.values['HostName'] || lc.values['X_AVM-DE_LANHostname'] || '') : '',
    model: normalizeModelName(modelRaw),
    rawModel: modelRaw,
    version: diV['SoftwareVersion'] ?? '',
    uptimeSeconds: toInt(diV['Uptime']),
    temperatureC: null, // not available via TR-064
    loadPct: null,
    memoryTotalBytes: null,
    memoryUsedBytes: null,
  };

  // --- WAN state ------------------------------------------------------------------
  // ConnectionStatus: '0' disconnected / '1' connecting / '2' connected.
  const connStatus = wc?.values['ConnectionStatus'] ?? '';
  const online = connStatus === '2' ? true : connStatus === '0' ? false : null;

  // PPPoE (DSL) devices answer on WANPPPConnection, cable/IP-client on
  // WANIPConnection — prefer whichever actually reported an external address.
  const wanSrc: Record<string, string> = ppp?.values['ExternalIPAddress']
    ? ppp.values
    : ipc?.values['ExternalIPAddress']
      ? ipc.values
      : {};
  const connectionType = ppp?.values['ExternalIPAddress'] ? 'pppoe' : ipc?.values['ExternalIPAddress'] ? 'ipclient' : '';

  // Negotiated DSL rates win; otherwise the physical link maximum.
  const downstreamMbps = bpsToMbps(firstInt(dsl?.values['DataTransferRateDownstream'], wc?.values['PhysicalLinkMaxDownloadSpeed']));
  const upstreamMbps = bpsToMbps(firstInt(dsl?.values['DataTransferRateUpstream'], wc?.values['PhysicalLinkMaxUploadSpeed']));

  const internet = {
    connectionType,
    online,
    ip: wanSrc['ExternalIPAddress'] ?? '',
    dns1: '', // TR-064 does not expose the WAN DNS servers
    dns2: '',
    downstreamMbps,
    upstreamMbps,
  };

  // --- LAN hosts -------------------------------------------------------------------
  const devices = parseHostEntries(hostsXml).map((h) => ({
    mac: h.mac,
    ip: h.ip,
    hostname: h.hostname,
    online: true as boolean | null,
  }));

  // --- WLAN radios (instance .1/.2/.3 ≈ first/second/third radio) -------------------
  const radios: FBoxSnapshot['radios'] = [];
  for (const [r, ifname, band] of [
    [wlan1, 'wlan0', '2g'],
    [wlan2, 'wlan1', '5g'],
    [wlan3, 'wlan2', '6g'],
  ] as const) {
    const p = collect(r, `WLANConfiguration.${ifname}`);
    if (!p) continue;
    const ssid = p.values['SSID'] ?? '';
    const channel = toInt(p.values['Channel']);
    if (ssid === '' && channel == null) continue; // radio absent on this device / firmware
    radios.push({
      ifname,
      ssid,
      channel,
      band: band as FBoxSnapshot['radios'][number]['band'],
      encryption: '', // not exposed via TR-064 in v1
      clients: [], // per-client lists are a later phase
      bssid: p.values['BSSID'] || p.values['X_AVM-DE_BSSID'] || undefined,
    });
  }

  // --- LAN subnet (the device's own address + netmask) -------------------------------
  const lanIp = lc?.values['ExternalIPAddress'] ?? '';
  const lanPrefix = lc ? maskToPrefix(lc.values['SubnetMask']) : null;

  // Neither identity nor any other service answered → not a TR-064 device (or
  // the protocol is disabled on it).
  if (!system.model && !system.version && devices.length === 0 && !internet.ip) {
    throw new Error('No TR-064 services responded with data — the target did not answer as a TR-064 device (or TR-064 is disabled on it).');
  }

  const snapshot: FBoxSnapshot = {
    system,
    overview: {
      lanIp,
      lanPrefix,
      dns1: '',
      dns2: '',
      devices,
      wanIp: internet.ip,
      wanDns1: '',
      wanDns2: '',
    },
    internet,
    lanPorts: [], // not exposed via TR-064 in v1
    radios,
  };

  return { snapshot, warnings };
}
