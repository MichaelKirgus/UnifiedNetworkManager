/**
 * Monitoring collectors — one per Shelly generation, both returning the same
 * metric model so the API/webapp see one plugin regardless of device age.
 *
 * Gen1 (legacy REST): a single GET /status carries everything we need
 * (wifi_sta, update, uptime, ram, fs + model-specific extras like relays and
 * power meters). Detection already fetched /shelly, so model/name/mac/fw come
 * from the cached profile.
 *
 * Gen2+ (JSON-RPC): ONE batched POST /rpc per poll — [GetDeviceInfo,
 * GetStatus, WiFi/Wifi.GetStatus, Firmware.GetStatus] in a single round-trip,
 * using whichever namespace family detection resolved (classic fw 1.x vs
 * modern fw 2.x+). Per-method RPC errors degrade gracefully (that component's
 * metrics are omitted); only a transport-level failure is critical.
 *
 * Canonical contract: `system.swVersion` (running firmware) and `hostname`
 * are emitted every poll when the device reports them.
 */

import type { Health } from '@unm/plugin-sdk';
import { gen1Get, rpc, type ShellyAuth, type ShellyClientOptions, type ShellyErrorKind } from './client';
import type { DeviceProfile } from './detect';

/** Outcome of one monitoring poll for one device. */
export interface CollectResult {
  metrics: Record<string, string | number>;
  health: Health;
  /** Human-readable reasons for a non-ok health (empty when healthy). */
  warnings: string[];
  /** Set when the poll failed at transport level (health = critical). */
  error?: string;
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function isNum(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

function isStr(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

/** Health for a transport-level failure — unreachable vs auth-rejected. */
export function failureHealth(r: { ok: boolean; status: number; errorKind?: ShellyErrorKind; error?: string }): Pick<CollectResult, 'health' | 'error'> {
  if (r.errorKind === 'auth-rejected') {
    return { health: 'critical', error: `authentication rejected by device (HTTP ${r.status}) — check the bound credentials` };
  }
  return { health: 'critical', error: r.error ?? `device answered HTTP ${r.status}` };
}

/** WLAN RSSI warning threshold (dBm). */
export const WEAK_RSSI_DBM = -85;
/** Gen2+ overtemperature warning threshold (°C). */
export const OVERTEMP_C = 70;
/** Flash-usage warning threshold (Gen1 fs). */
export const FLASH_FULL_PCT = 90;

function addWifiMetrics(metrics: Record<string, string | number>, sta: Record<string, unknown> | null | undefined, warnings: string[]): void {
  if (!sta) return;
  if (isNum(sta.rssi)) {
    metrics['shelly.wifiRssiDbm'] = sta.rssi;
    if (sta.rssi <= WEAK_RSSI_DBM) warnings.push(`weak WLAN RSSI (${sta.rssi} dBm)`);
  }
  if (isStr(sta.ssid)) metrics['shelly.wifiSsid'] = sta.ssid;
  // Gen1 reports the station IP as `ip`, Gen2+ as `sta_ip`.
  const ip = sta.ip ?? sta.sta_ip;
  if (isStr(ip)) metrics['shelly.wifiStaIp'] = ip;
}

function addRelayMetrics(metrics: Record<string, string | number>, relays: unknown): void {
  if (!Array.isArray(relays)) return;
  let n = 0;
  for (const r of relays) {
    const rec = r as Record<string, unknown> | null;
    if (!rec || typeof rec !== 'object') continue;
    // Component id when present (Gen2+), positional index otherwise (Gen1).
    const idx = isNum(rec.id) ? rec.id : n;
    metrics[`shelly.relay${idx}On`] = rec.ison === true ? 1 : 0;
    n += 1;
  }
}

function addPowerMeterMetrics(metrics: Record<string, string | number>, meters: unknown): void {
  if (!Array.isArray(meters) || !meters.length) return;
  const m = (meters[0] ?? null) as Record<string, unknown> | null;
  if (!m || typeof m !== 'object') return;
  if (isNum(m.power)) metrics['shelly.powerW'] = m.power;
  // Gen1 reports `total` in kWh directly; Gen2+ nests it under energy.total.
  const kwh = isNum(m.total) ? m.total : isNum((m.energy as Record<string, unknown> | undefined)?.total) ? ((m.energy as Record<string, unknown>).total as number) : undefined;
  if (kwh !== undefined) metrics['shelly.energyWh'] = Math.round(kwh * 1000);
}

// ---------------------------------------------------------------------------
// Gen1 — legacy REST
// ---------------------------------------------------------------------------

/** Shape of GET /status on a Gen1 device (best-effort, model-dependent parts optional). */
export interface Gen1Status {
  wifi_sta?: { connected?: boolean; ssid?: string; ip?: string; rssi?: number } | null;
  update?: { has_update?: boolean; new_version?: string; old_version?: string } | null;
  uptime?: number;
  ram?: { total?: number; free?: number; threshold?: number } | null;
  fs?: { total?: number; free?: number } | null;
  relay?: Array<{ ison?: boolean }>;
  relays?: Array<{ id?: number; ison?: boolean }>;
  meters?: Array<{ voltage?: number; current?: number; power?: number; total?: number }>;
}

/** Collects one Gen1 poll: GET /status (detection already ran GET /shelly). */
export async function collectGen1(
  opts: ShellyClientOptions,
  profile: DeviceProfile,
  auth?: ShellyAuth,
): Promise<CollectResult> {
  const r = await gen1Get<Gen1Status>(opts, '/status', auth);
  if (!r.ok) return { metrics: {}, warnings: [], ...failureHealth(r) };

  const s = r.data ?? {};
  const metrics: Record<string, string | number> = {};
  const warnings: string[] = [];

  // Canonical — running firmware version every poll.
  if (isStr(s.update?.old_version)) metrics['system.swVersion'] = s.update.old_version;
  else if (isStr(profile.fw)) metrics['system.swVersion'] = profile.fw;

  if (isStr(profile.name)) metrics['hostname'] = profile.name;
  if (isStr(profile.model)) metrics['shelly.model'] = profile.model;
  if (isStr(profile.mac)) metrics['shelly.mac'] = profile.mac;

  if (isNum(s.uptime)) metrics['shelly.uptimeSeconds'] = s.uptime;

  if (isNum(s.ram?.free) && isNum(s.ram?.total)) {
    metrics['shelly.ramFreeBytes'] = s.ram.free;
    metrics['shelly.ramTotalBytes'] = s.ram.total;
    // The device ships its own low-RAM threshold — use it when present.
    const threshold = isNum(s.ram?.threshold) ? s.ram.threshold : 4096;
    if (s.ram.free <= threshold) warnings.push(`RAM low (${s.ram.free} B free, threshold ${threshold} B)`);
  }

  if (isNum(s.fs?.free) && isNum(s.fs?.total)) {
    metrics['shelly.fsFreeBytes'] = s.fs.free;
    const usedPct = ((s.fs.total - s.fs.free) / s.fs.total) * 100;
    if (usedPct >= FLASH_FULL_PCT) warnings.push(`flash nearly full (${usedPct.toFixed(1)}% used)`);
  }

  addWifiMetrics(metrics, s.wifi_sta ?? null, warnings);

  if (typeof s.update?.has_update === 'boolean') {
    metrics['shelly.fwUpdateAvailable'] = s.update.has_update ? 1 : 0;
  }

  // Model-specific extras — best effort across models.
  addRelayMetrics(metrics, s.relay ?? s.relays);
  addPowerMeterMetrics(metrics, s.meters);

  return { metrics, health: warnings.length ? 'warning' : 'ok', warnings };
}

// ---------------------------------------------------------------------------
// Gen2+ — JSON-RPC (batched)
// ---------------------------------------------------------------------------

/** The four methods polled in one batched round-trip, per namespace family. */
export function gen2PollMethods(ns: 'classic' | 'modern'): string[] {
  return ns === 'classic'
    ? ['Shelly.GetDeviceInfo', 'Shelly.GetStatus', 'WiFi.GetStatus', 'Firmware.GetStatus']
    : ['Sys.GetDeviceInfo', 'Sys.GetStatus', 'Wifi.GetStatus', 'Firmware.GetStatus'];
}

/** Collects one Gen2+ poll: ONE batched POST /rpc (four methods, one round-trip). */
export async function collectGen2(
  opts: ShellyClientOptions,
  profile: DeviceProfile,
  auth?: ShellyAuth,
): Promise<CollectResult> {
  const ns = profile.ns ?? 'classic';
  const r = await rpc(opts, gen2PollMethods(ns).map((method) => ({ method })), auth);
  if (!r.ok) return { metrics: {}, warnings: [], ...failureHealth(r) };

  const [devRes, statusRes, wifiRes, fwRes] = r.results;
  const devInfo = (devRes?.result ?? null) as Record<string, unknown> | null;
  const status = (statusRes?.result ?? null) as Record<string, unknown> | null;
  const wifi = (wifiRes?.result ?? null) as Record<string, unknown> | null;
  const fw = (fwRes?.result ?? null) as Record<string, unknown> | null;

  const metrics: Record<string, string | number> = {};
  const warnings: string[] = [];

  // Canonical — running firmware version every poll.
  if (isStr(fw?.old_version)) metrics['system.swVersion'] = fw.old_version;
  else if (isStr(devInfo?.fw_version)) metrics['system.swVersion'] = devInfo.fw_version;
  else if (isStr(profile.fw)) metrics['system.swVersion'] = profile.fw;

  if (isStr(devInfo?.name)) metrics['hostname'] = devInfo.name;
  else if (isStr(profile.name)) metrics['hostname'] = profile.name;
  if (isStr(devInfo?.id)) metrics['shelly.model'] = devInfo.id;
  else if (isStr(profile.model)) metrics['shelly.model'] = profile.model;
  if (isStr(devInfo?.mac)) metrics['shelly.mac'] = devInfo.mac;
  else if (isStr(profile.mac)) metrics['shelly.mac'] = profile.mac;

  const sys = (status?.sys ?? null) as Record<string, unknown> | null;
  if (sys && isNum(sys.uptime)) metrics['shelly.uptimeSeconds'] = sys.uptime;
  if (sys && isNum(sys.temperature_c) && sys.temperature_c >= OVERTEMP_C) {
    warnings.push(`overtemperature (${sys.temperature_c} °C)`);
  }

  // RAM when the firmware reports it (not all generations do).
  if (sys && isNum(sys.ram_free_bytes)) metrics['shelly.ramFreeBytes'] = sys.ram_free_bytes;
  if (sys && isNum(sys.ram_total_bytes)) metrics['shelly.ramTotalBytes'] = sys.ram_total_bytes;

  // WLAN — first-class: RSSI gauge + SSID/channel/BSSID/station IP.
  addWifiMetrics(metrics, wifi ?? null, warnings);
  if (wifi && isNum(wifi.channel)) metrics['shelly.wifiChannel'] = wifi.channel;
  if (wifi && isStr(wifi.bssid)) metrics['shelly.wifiBssid'] = wifi.bssid;

  if (typeof fw?.has_update === 'boolean') {
    metrics['shelly.fwUpdateAvailable'] = fw.has_update ? 1 : 0;
  }

  // Component state from the (all-components) status object.
  addRelayMetrics(metrics, status?.relay);
  addPowerMeterMetrics(metrics, status?.powermeter);

  return { metrics, health: warnings.length ? 'warning' : 'ok', warnings };
}
