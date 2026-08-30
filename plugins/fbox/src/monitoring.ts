/**
 * FBox monitoring collection + metric/inventory assembly.
 *
 * One poll = login (once) + a single PARALLEL batch of data endpoints
 * (systeminfo64.json, overview.lua, internetinfo.json, laninfo.json and the
 * three wlan radios). The box's nginx-based web UI handles concurrent requests
 * fine — unlike SwOS there is no serialization constraint. Worst case ≈ login
 * timeout + one request timeout, comfortably inside the API's hard 10 s budget.
 */

import { MetricDescriptor, modelFirmwareDescriptors } from '@unm/plugin-sdk';
import { FBoxClient, FBoxCredentials, FBoxTransport } from './fboxClient';
import {
  FBoxInternetInfo,
  FBoxLanPort,
  FBoxLanV4,
  FBoxLanV6Net,
  FBoxOverview,
  FBoxSystemInfo,
  FBoxWlanRadio,
  html2PortName,
  parseHtml2BoxNet,
  parseHtml2BoxNetIpv6,
  parseHtml2Energy,
  parseHtml2KnownWlanMacs,
  parseHtml2NetDevHosts,
  parseHtml2Overview,
  parseHtml2UsbOv,
  parseHtml2WSet,
  parseInternetInfo,
  parseLanInfo,
  parseOverview,
  parseSystemInfo,
  parseWlanInfo,
} from './endpoints';

export interface FBoxOptions {
  transport?: FBoxTransport;
  requestTimeoutMs: number;
}

export const DEFAULT_OPTIONS: FBoxOptions = {
  transport: 'auto',
  requestTimeoutMs: 3000,
};

/** Everything one poll knows about the box (nulls = endpoint absent/failed). */
export interface FBoxSnapshot {
  system: FBoxSystemInfo | null;
  overview: FBoxOverview | null;
  internet: FBoxInternetInfo | null;
  lanPorts: FBoxLanPort[];
  radios: FBoxWlanRadio[];
  /**
   * html2 mode only — MACs of hosts that are CURRENTLY ASSOCIATED WLAN clients
   * (netDev host ∩ wSet knownWlanDevices). buildMetrics routes those into
   * wlanClients[] EXCLUSIVELY so the API does not store one device twice
   * (once as 'arp', once as 'wlan').
   */
  wlanHostMacs?: string[];
  /** html2 mode only — main-LAN v4 netmask from the boxnet form page. */
  lanV4?: FBoxLanV4 | null;
  /** html2 mode only — named v6 networks (Heimnetz=LAN, WAN) from boxnet_ipv6. */
  lanV6Nets?: FBoxLanV6Net[];
}

export interface MonitoringResult {
  snapshot: FBoxSnapshot;
  /** Non-empty when some endpoints failed but the poll still produced data. */
  warnings: string[];
}

/**
 * Collects one full snapshot. Throws on auth failure / non-AVM target / total
 * unreachability (the caller maps those to health); partial endpoint failures
 * are collected into `warnings` instead.
 */
export async function getMonitoring(host: string, creds: FBoxCredentials, opts: FBoxOptions): Promise<MonitoringResult> {
  const client = new FBoxClient(host, creds, { transport: opts.transport ?? 'auto', timeoutMs: opts.requestTimeoutMs });

  // Login first — it also pins the transport scheme (auto: https→http) and
  // detects the UI generation. html2 boxes have NO classic endpoints at all.
  await client.login();

  if (client.mode === 'html2') return getHtml2Snapshot(client);

  const [sysR, ovrR, inetR, lanR, w0R, w1R, w2R] = await Promise.allSettled([
    client.getJson('/systeminfo64.json'),
    client.getJson('/overview.lua?get_data=1&lang_id=en'),
    client.getJson('/internetinfo.json'),
    client.getJson('/laninfo.json'),
    client.getJson('/wlaninfo.json?ifname=wlan0'),
    client.getJson('/wlaninfo.json?ifname=wlan1'),
    client.getJson('/wlaninfo.json?ifname=wlan2'),
  ]);

  const warnings: string[] = [];
  const value = (r: PromiseSettledResult<unknown>, label: string): unknown => {
    if (r.status === 'fulfilled') return r.value;
    // A session/auth error mid-batch is a hard failure — surface it.
    const msg = r.reason instanceof Error ? r.reason.message : String(r.reason);
    if (/auth|SID/i.test(msg)) throw r.reason instanceof Error ? r.reason : new Error(msg);
    warnings.push(`${label}: ${msg}`);
    return null;
  };

  const systemRaw = value(sysR, 'systeminfo64.json');
  const overviewRaw = value(ovrR, 'overview.lua');
  const internetRaw = value(inetR, 'internetinfo.json');
  const lanRaw = value(lanR, 'laninfo.json');

  // Neither identity endpoint answered → this is not a FRITZ!OS web UI.
  if (systemRaw == null && overviewRaw == null) {
    throw new Error('No FRITZ!OS data endpoints responded — target does not look like an AVM router.');
  }

  const radios: FBoxWlanRadio[] = [];
  for (const [r, ifname] of [[w0R, 'wlan0'], [w1R, 'wlan1'], [w2R, 'wlan2']] as const) {
    if (r.status !== 'fulfilled' || r.value == null) continue; // absent radio / endpoint — not a warning
    const parsed = parseWlanInfo(r.value, ifname);
    if (parsed.ssid === '' && parsed.clients.length === 0) continue; // no SSID data at all
    radios.push(parsed);
  }

  return {
    snapshot: {
      system: systemRaw != null ? parseSystemInfo(systemRaw) : null,
      overview: overviewRaw != null ? parseOverview(overviewRaw) : null,
      internet: internetRaw != null ? parseInternetInfo(internetRaw) : null,
      lanPorts: lanRaw != null ? parseLanInfo(lanRaw) : [],
      radios,
    },
    warnings,
  };
}

/**
 * HTML2-generation snapshot — the five /data.lua pages in one parallel batch:
 *   '' (home overview), netDev (+xhrId=all), wSet, energy, usbOv.
 * Mapped into the SAME FBoxSnapshot shape as classic mode so buildMetrics /
 * buildDescriptors stay shared. html2 has no temperature/CPU/memory — those
 * fields simply stay null and their metrics are absent.
 */
async function getHtml2Snapshot(client: FBoxClient): Promise<MonitoringResult> {
  const [ovrR, netR, wSetR, energyR, usbR, boxNetR, boxNet6R] = await Promise.allSettled([
    client.getDataPage(''), // home overview — the page param must be OMITTED
    client.getDataPage('netDev', { xhrId: 'all' }),
    client.getDataPage('wSet'),
    client.getDataPage('energy'),
    client.getDataPage('usbOv'),
    client.getHtmlPage('boxnet'), // LAN v4 netmask (HTML form page)
    client.getHtmlPage('boxnet_ipv6'), // LAN/WAN v6 prefixes (HTML form page)
  ]);

  const warnings: string[] = [];
  const value = (r: PromiseSettledResult<unknown>, label: string): unknown => {
    if (r.status === 'fulfilled') return r.value;
    const msg = r.reason instanceof Error ? r.reason.message : String(r.reason);
    // A session/auth error mid-batch is a hard failure — surface it.
    if (/auth|SID/i.test(msg)) throw r.reason instanceof Error ? r.reason : new Error(msg);
    warnings.push(`${label}: ${msg}`);
    return null;
  };

  const overviewRaw = value(ovrR, 'overview');
  const netDevRaw = value(netR, 'netDev');
  const wSetRaw = value(wSetR, 'wSet');
  const energyRaw = value(energyR, 'energy');
  const usbRaw = value(usbR, 'usbOv');
  // Form pages: null means "not a form page on this firmware" — not an error.
  const boxNetHtml = boxNetR.status === 'fulfilled' ? boxNetR.value : null;
  const boxNet6Html = boxNet6R.status === 'fulfilled' ? boxNet6R.value : null;

  // The home overview carries the system identity — without it we cannot tell
  // this is a FRITZ!OS box at all.
  if (overviewRaw == null) {
    throw new Error('No FRITZ!OS data endpoints responded — target does not look like an AVM router.');
  }

  const ovr = parseHtml2Overview(overviewRaw);
  const energy = energyRaw != null ? parseHtml2Energy(energyRaw) : { lanPorts: [], uptimeSeconds: null };
  const usb = usbRaw != null ? parseHtml2UsbOv(usbRaw) : { boxIp: '' };

  // Host table → LAN devices. WLAN classification: the netDev rows carry no
  // medium field, so a host is a CURRENTLY ASSOCIATED WLAN client iff its MAC
  // is in the box's remembered WLAN device list (wSet knownWlanDevices).
  const hosts = netDevRaw != null ? parseHtml2NetDevHosts(netDevRaw) : [];
  const wlanMacs = new Set(wSetRaw != null ? parseHtml2KnownWlanMacs(wSetRaw) : []);

  const devices: FBoxOverview['devices'] = [];
  for (const h of hosts) {
    if (!h.mac && !h.ip) continue;
    // IP-less rows are not ARP-able — they go to the MAC table instead.
    if (!h.ip) continue; // (kept explicit: macTable support is a later phase)
    devices.push({
      mac: h.mac,
      ip: h.ip === '0.0.0.0' ? '' : h.ip,
      hostname: h.hostname,
      online: true,
      port: h.port || undefined,
    });
  }

  // MACs of hosts that are actually on the WLAN right now (live address +
  // remembered as a WLAN device). These leave arp[] and join wlanClients[].
  const wlanHostMacs = devices.filter((d) => d.mac && d.ip && wlanMacs.has(d.mac)).map((d) => d.mac);

  // WiFi radio — wSet is the settings page (one SSID per configured radio).
  const wlan = wSetRaw != null ? parseHtml2WSet(wSetRaw, ovr.wlanBand) : null;
  const radios: FBoxWlanRadio[] = [];
  if (wlan && wlan.ssid !== '') {
    const clients = devices
      .filter((d) => d.mac && d.ip && wlanMacs.has(d.mac))
      .map((d) => ({ mac: d.mac, ip: d.ip, hostname: d.hostname }));
    radios.push({ ifname: 'wlan0', ssid: wlan.ssid, channel: null, band: wlan.band || '', encryption: wlan.encryption, clients, bssid: wlan.bssid });
  }

  const system: FBoxSystemInfo = {
    name: ovr.system.name,
    model: ovr.system.model,
    rawModel: ovr.system.rawModel,
    version: ovr.system.version,
    uptimeSeconds: energy.uptimeSeconds,
    temperatureC: null, // not reported by the html2 UI
    loadPct: null,
    memoryTotalBytes: null,
    memoryUsedBytes: null,
  };

  return {
    snapshot: {
      system,
      overview: {
        lanIp: usb.boxIp,
        lanPrefix: null, // html2 payloads carry no netmask anywhere
        dns1: '',
        dns2: '',
        devices,
        wanIp: ovr.internet?.ip ?? '',
        wanDns1: ovr.internet?.dns1 ?? '',
        wanDns2: ovr.internet?.dns2 ?? '',
      },
      internet: ovr.internet ? { ...ovr.internet } : null,
      lanPorts: energy.lanPorts.map((p) => ({ name: p.name, speedMbps: null, duplex: '', status: p.status })),
      radios,
      wlanHostMacs,
      lanV4: boxNetHtml != null ? parseHtml2BoxNet(boxNetHtml) : null,
      lanV6Nets: boxNet6Html != null ? parseHtml2BoxNetIpv6(boxNet6Html) : [],
    },
    warnings,
  };
}

// --- metric assembly ------------------------------------------------------------------

/** Builds the metrics map for one snapshot (inventory arrays included). */
export function buildMetrics(s: FBoxSnapshot, selectedModel?: string | null, selectedFirmware?: string | null): Record<string, unknown> {
  const m: Record<string, unknown> = {};

  if (s.system) {
    if (s.system.name) m['system.name'] = s.system.name;
    if (s.system.version) m['system.swVersion'] = s.system.version; // DeviceDetail Identity section reads this key
    if (s.system.uptimeSeconds != null) m['system.uptime'] = Math.round(s.system.uptimeSeconds);
    if (s.system.loadPct != null) m['system.cpuLoad'] = clamp0100(s.system.loadPct);
    if (s.system.temperatureC != null) m['system.temperature'] = s.system.temperatureC;
    if (s.system.memoryTotalBytes && s.system.memoryUsedBytes != null) {
      const pct = (s.system.memoryUsedBytes / s.system.memoryTotalBytes) * 100;
      if (Number.isFinite(pct)) m['system.memoryUsedPct'] = Math.round(clamp0100(pct));
    }
  }

  // WAN state — prefer the dedicated internetinfo endpoint, fall back to overview.
  const wanOnline = s.internet?.online ?? null;
  if (s.internet || s.overview) {
    m['wan.status'] = wanOnline == null ? 'unknown' : wanOnline ? 'online' : 'offline';
    const type = s.internet?.connectionType ?? '';
    if (type) m['wan.type'] = type;
    const ip = s.internet?.ip || s.overview?.wanIp || '';
    if (ip) m['wan.ip'] = ip;
    // html2 overview reports negotiated rates + provider — classic boxes don't.
    if (s.internet?.downstreamMbps != null) m['wan.downstreamMbps'] = s.internet.downstreamMbps;
    if (s.internet?.upstreamMbps != null) m['wan.upstreamMbps'] = s.internet.upstreamMbps;
    if (s.internet?.provider) m['wan.provider'] = s.internet.provider;
    // html2 overview carries the WAN IPv6 address (suffix already stripped).
    const v6Ip = s.internet?.ipv6Ip || '';
    if (v6Ip) {
      m['wan.ipv6'] = v6Ip;
      if (s.internet?.ipv6Prefix) m['wan.ipv6Prefix'] = s.internet.ipv6Prefix; // delegated prefix, e.g. /56
    }
  }

  // LAN port table.
  if (s.lanPorts.length > 0) {
    m['lan.ports'] = s.lanPorts.map((p) => ({
      port: p.name,
      speed: p.speedMbps != null ? `${p.speedMbps} Mbit/s` : '—',
      duplex: p.duplex || '—',
      status: p.status || 'unknown',
    }));
  }

  // WiFi per-band channel + total client count.
  const clients = s.radios.reduce((n, r) => n + r.clients.length, 0);
  if (clients > 0) m['wifi.clients'] = clients;
  for (const band of ['2g', '5g', '6g'] as const) {
    const radio = s.radios.find((r) => r.band === band && r.channel != null);
    if (radio) m[`wifi.channel${band}`] = String(radio.channel);
  }
  // html2 wSet reports the Wi-Fi generation + BSSID (no channel in that UI).
  for (const radio of s.radios) {
    const bandKey = radio.band || 'main';
    if (radio.bssid) m[`wifi.bssid${bandKey}`] = radio.bssid;
  }

  // User-selected model/firmware echo (only when set on the device row).
  if (selectedModel) m['system.model'] = selectedModel;
  if (selectedFirmware) m['system.firmwareVersion'] = selectedFirmware;

  // --- inventory propagation (API ingests these into Hosts/Networks/WiFi pages) ---
  const networks: Record<string, unknown>[] = [];
  // LAN v4 — the html2 boxnet form page carries the real netmask; classic
  // boxes get it from laninfo.json. Null prefix when neither reported one.
  if (s.overview?.lanIp) {
    const v4Prefix = s.lanV4?.prefix ?? s.overview.lanPrefix ?? undefined;
    networks.push({ name: 'LAN', ip: s.overview.lanIp, prefix: v4Prefix, version: 'v4' });
  }
  // LAN v6 — the boxnet_ipv6 form page lists the Heimnetz (home network) with
  // its /prefixlen. Same NAME as the v4 row so the API's mergeNetworkRows
  // groups both subnets into ONE dual-stack network.
  const lanV6 = s.lanV6Nets?.find((n) => n.name === 'Heimnetz' && n.ip);
  if (lanV6) {
    networks.push({ name: 'LAN', ip: lanV6.ip, prefix: lanV6.prefixLen ?? undefined, version: 'v6' });
  }
  if (networks.length > 0) m['networks'] = networks;

  const arp: Record<string, unknown>[] = [];
  // html2 mode: WLAN-associated hosts are reported via wlanClients[] ONLY —
  // the API upserts on (mac|ip|source), so emitting both would duplicate them.
  const wlanMacs = new Set(s.wlanHostMacs ?? []);
  for (const d of s.overview?.devices ?? []) {
    if (!d.mac || !d.ip) continue; // IP-less rows are only allowed for source 'mac'
    if (wlanMacs.has(d.mac)) continue;
    arp.push({ mac: d.mac, ip: d.ip, hostname: d.hostname || undefined, intf: d.port ? html2PortName(d.port) : undefined });
  }
  if (arp.length > 0) m['arp'] = arp;

  const wlanClients: Record<string, unknown>[] = [];
  for (const r of s.radios) {
    for (const c of r.clients) {
      if (!c.mac || !c.ip) continue;
      wlanClients.push({ mac: c.mac, ip: c.ip, hostname: c.hostname || undefined, intf: r.ifname });
    }
  }
  if (wlanClients.length > 0) m['wlanClients'] = wlanClients;

  const wifiNetworks: Record<string, unknown>[] = [];
  for (const r of s.radios) {
    if (!r.ssid) continue;
    wifiNetworks.push({
      name: r.ssid,
      band: r.band || 'unknown',
      channel: r.channel ?? undefined,
      bssid: r.bssid || undefined, // html2 wSet — the API's wifiSsids table stores it
      encryption: r.encryption || undefined,
    });
  }
  if (wifiNetworks.length > 0) m['wifiNetworks'] = wifiNetworks;

  return m;
}

/** Descriptors matching the metrics actually present in this snapshot. */
export function buildDescriptors(s: FBoxSnapshot, selectedModel?: string | null, selectedFirmware?: string | null): MetricDescriptor[] {
  const d: MetricDescriptor[] = [];
  if (s.system) {
    if (s.system.name) d.push({ key: 'system.name', label: 'Hostname', type: 'string', visualization: 'text', group: 'System' });
    if (s.system.version) d.push({ key: 'system.swVersion', label: 'Firmware Version', type: 'string', visualization: 'text', group: 'System' });
    if (s.system.uptimeSeconds != null) d.push({ key: 'system.uptime', label: 'Uptime', type: 'number', visualization: 'gauge', format: 'duration', unit: 's', group: 'System' });
    if (s.system.loadPct != null) d.push({ key: 'system.cpuLoad', label: 'CPU Load', type: 'number', visualization: 'gauge', unit: '%', min: 0, max: 100, group: 'System', summary: true });
    if (s.system.temperatureC != null) d.push({ key: 'system.temperature', label: 'Temperature', type: 'number', visualization: 'gauge', unit: '°C', group: 'System' });
    if (s.system.memoryTotalBytes && s.system.memoryUsedBytes != null) {
      d.push({ key: 'system.memoryUsedPct', label: 'Memory Used', type: 'number', visualization: 'gauge', unit: '%', min: 0, max: 100, group: 'System' });
    }
  }

  if (s.internet || s.overview) {
    d.push({ key: 'wan.status', label: 'WAN Status', type: 'string', visualization: 'text', group: 'WAN', summary: true });
    const type = s.internet?.connectionType ?? '';
    if (type) d.push({ key: 'wan.type', label: 'Connection Type', type: 'string', visualization: 'text', group: 'WAN' });
    const ip = s.internet?.ip || s.overview?.wanIp || '';
    if (ip) d.push({ key: 'wan.ip', label: 'WAN IP Address', type: 'string', visualization: 'text', group: 'WAN' });
    if (s.internet?.downstreamMbps != null) d.push({ key: 'wan.downstreamMbps', label: 'Downstream Rate', type: 'number', visualization: 'gauge', unit: 'Mbit/s', min: 0, group: 'WAN' });
    if (s.internet?.upstreamMbps != null) d.push({ key: 'wan.upstreamMbps', label: 'Upstream Rate', type: 'number', visualization: 'gauge', unit: 'Mbit/s', min: 0, group: 'WAN' });
    if (s.internet?.provider) d.push({ key: 'wan.provider', label: 'Provider', type: 'string', visualization: 'text', group: 'WAN' });
    const v6Ip = s.internet?.ipv6Ip || '';
    if (v6Ip) {
      d.push({ key: 'wan.ipv6', label: 'WAN IPv6 Address', type: 'string', visualization: 'text', group: 'WAN' });
      if (s.internet?.ipv6Prefix) d.push({ key: 'wan.ipv6Prefix', label: 'Delegated Prefix', type: 'string', visualization: 'text', group: 'WAN' });
    }
  }

  if (s.lanPorts.length > 0) {
    d.push({
      key: 'lan.ports',
      label: 'LAN Ports',
      type: 'string',
      visualization: 'table',
      columns: ['port', 'speed', 'duplex', 'status'],
      rows: s.lanPorts.map((p) => p.name),
      group: 'LAN',
    });
  }

  const clients = s.radios.reduce((n, r) => n + r.clients.length, 0);
  if (clients > 0) d.push({ key: 'wifi.clients', label: 'WiFi Clients', type: 'number', visualization: 'gauge', group: 'WiFi' });
  for (const band of ['2g', '5g', '6g'] as const) {
    const radio = s.radios.find((r) => r.band === band && r.channel != null);
    if (radio) d.push({ key: `wifi.channel${band}`, label: `WiFi Channel (${band.toUpperCase()})`, type: 'string', visualization: 'text', group: 'WiFi' });
  }
  for (const radio of s.radios) {
    if (!radio.bssid) continue;
    const bandKey = radio.band || 'main';
    d.push({ key: `wifi.bssid${bandKey}`, label: `BSSID (${(radio.band || 'main').toUpperCase()})`, type: 'string', visualization: 'text', group: 'WiFi' });
  }

  if (selectedModel || selectedFirmware) d.push(...modelFirmwareDescriptors(selectedModel, selectedFirmware));
  return d;
}

function clamp0100(v: number): number {
  return Math.max(0, Math.min(100, v));
}
