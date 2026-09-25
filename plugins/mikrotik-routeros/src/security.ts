/**
 * MikroTik RouterOS plugin — per-appliance security checks (capability 'securityChecks').
 *
 * Emits `metrics['securityChecks']` = SecurityCheckRow[] during monitoring. The
 * API persists only non-'ok' rows into the cross-device Security page; a clean
 * device emits no persisted findings. This plugin is REST-only (no shell data
 * path), so the checks use RouterOS's own `/rest` endpoints — every one of them
 * is best-effort: an endpoint that 404s on older firmware degrades to "not
 * applicable" and never sinks the poll.
 *
 * Checks:
 *  - service-exposure   /ip/service/print — management services (telnet, ftp,
 *                     www, ssh) bound to interfaces OTHER than loopback. Telnet
 *                     anywhere is critical (cleartext); other non-loopback
 *                     bindings are warnings with the interface list in detail.
 *  - auth-failures      /log/print — "login" entries within the look-back window
 *                     (RouterOS logs failed console/SSH/API logins). A few
 *                     failures are background scanner noise → 'info';
 *                     configurable warn/critical thresholds escalate it.
 */

import type { SecurityCheckRow } from '@unm/plugin-sdk';
import { RouterOsClient, rosString } from './routerosClient';
import type { RouterOsOptions } from './monitoring';

// ---------------------------------------------------------------------------
// Settings (resolved per request in index.ts from plugin options)
// ---------------------------------------------------------------------------

export interface SecuritySettings {
  enabled: boolean;
  /** Look-back window for failed-login counting. */
  authFailureWindowHours: number;
  /** ≥ this many failures in the window → warning. */
  authFailureWarnThreshold: number;
  /** ≥ this many failures in the window → critical. */
  authFailureCriticalThreshold: number;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/** Re-collection throttle — /log/print + /ip/service are comparatively heavy;
 * the API polls every 30 s but security checks only need a ~15-min cadence. */
const RECOLLECT_TTL_MS = 15 * 60_000;
const lastRun = new Map<string, { at: number; rows: SecurityCheckRow[] }>();

/** Runs every check (best-effort, never throws). Throttled per host. */
export async function collectSecurityChecks(
  address: string,
  credentials: { username: string; password: string },
  opts: RouterOsOptions,
  settings: SecuritySettings,
): Promise<SecurityCheckRow[]> {
  if (!settings.enabled) return [];

  const host = (address ?? '').trim();
  const cached = lastRun.get(host);
  if (cached && Date.now() - cached.at < RECOLLECT_TTL_MS) return cached.rows;

  const client = new RouterOsClient(address, {
    username: credentials.username,
    password: credentials.password,
    timeoutMs: Math.max(opts.requestTimeoutMs, 4_000),
    insecureTls: opts.insecureTls,
    schemeMode: opts.schemeMode,
    httpsPort: opts.httpsPort,
    httpPort: opts.httpPort,
  });

  const [serviceRows, authRows] = await Promise.all([
    checkServiceExposure(client).catch(() => [] as SecurityCheckRow[]),
    checkAuthFailures(client, settings).catch(() => [] as SecurityCheckRow[]),
  ]);

  const rows = [...serviceRows, ...authRows];
  lastRun.set(host, { at: Date.now(), rows });
  return rows;
}

/** Test hook: clears the per-host security-check cache. */
export function clearSecurityCache(): void {
  lastRun.clear();
}

// ---------------------------------------------------------------------------
// Service exposure (/ip/service/print)
// ---------------------------------------------------------------------------

/** Services that are acceptable on loopback only (the sane default). */
const LOOPBACK_ONLY_SERVICES = new Set(['telnet', 'ftp', 'www', 'www-ssl', 'ssh']);

async function checkServiceExposure(client: RouterOsClient): Promise<SecurityCheckRow[]> {
  const services = await client.get<Record<string, unknown>[]>('/ip/service');
  if (!Array.isArray(services)) return [];

  const rows: SecurityCheckRow[] = [];
  for (const svc of services) {
    const name = rosString(svc, ['name']);
    if (!name) continue;
    // "disabled" is a RouterOS string flag ("true"/"false").
    const disabled = String(svc['disabled'] ?? '').toLowerCase() === 'true';
    if (disabled) continue;

    // interfaces: comma-separated list, or "all". loopback-only = safe default.
    const rawIfaces = rosString(svc, ['interfaces']) ?? '';
    const ifaces = rawIfaces.split(',').map((s) => s.trim()).filter(Boolean);
    const nonLoopback = ifaces.filter((i) => i !== 'loopback' && i !== '');

    // Telnet is cleartext — enabled anywhere (even loopback is a red flag for
    // console access, but only non-loopback is remotely exploitable).
    if (name === 'telnet') {
      rows.push({
        name: `service-telnet`,
        kind: 'service-exposure',
        status: nonLoopback.length > 0 ? 'critical' : 'warning',
        detail: nonLoopback.length > 0
          ? `telnet service is ENABLED and bound to ${nonLoopback.join(', ')} — cleartext management access`
          : 'telnet service is enabled (loopback only) — disable it if not needed',
      });
      continue;
    }

    // Other services: flag when reachable from a non-loopback interface.
    if (nonLoopback.length > 0 && LOOPBACK_ONLY_SERVICES.has(name)) {
      rows.push({
        name: `service-${name}`,
        kind: 'service-exposure',
        status: 'warning',
        detail: `${name} service is bound to ${nonLoopback.join(', ')} — restrict to loopback or a management VLAN if possible`,
        extra: { interfaces: nonLoopback },
      });
    }
  }

  return rows;
}

// ---------------------------------------------------------------------------
// Failed logins (/log/print)
// ---------------------------------------------------------------------------

/** RouterOS `time-uptime` is a RELATIVE age ("59s", "2m30s", "1h5m", "1d2h"). */
function parseUptimeAgeMs(raw: string | undefined): number | null {
  if (!raw) return null;
  const parts = raw.trim().matchAll(/(\d+)([dhms])/g);
  let total = 0;
  let matched = false;
  for (const m of parts) {
    const n = Number(m[1]);
    switch (m[2]) {
      case 'd': total += n * 86_400_000; break;
      case 'h': total += n * 3_600_000; break;
      case 'm': total += n * 60_000; break;
      case 's': total += n * 1_000; break;
    }
    matched = true;
  }
  return matched ? total : null;
}

async function checkAuthFailures(client: RouterOsClient, settings: SecuritySettings): Promise<SecurityCheckRow[]> {
  const hours = Math.max(1, Math.min(720, settings.authFailureWindowHours));
  // /log/print with a filter — "login" entries cover failed console/SSH/API logins.
  const logs = await client.get<Record<string, unknown>[]>('/log/print?filter=("%topic%"%="login")&limit=500');
  if (!Array.isArray(logs)) return [];

  const windowMs = hours * 3_600_000;
  let count = 0;
  const byIp = new Map<string, number>();

  for (const entry of logs) {
    // time-uptime is the age of the entry — keep only entries inside the window.
    const ageMs = parseUptimeAgeMs(rosString(entry, ['time-uptime']));
    if (ageMs === null || ageMs > windowMs) continue;
    // Only count actual failures — RouterOS also logs successful logins.
    const message = rosString(entry, ['message']) ?? '';
    if (!/failed|invalid|denied/i.test(message)) continue;
    count++;

    const m = message.match(/from\s+(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)/i);
    if (m) byIp.set(m[1], (byIp.get(m[1]) ?? 0) + 1);
  }

  if (count === 0) return []; // no failures in the window → 'ok' (dropped)

  const topIps = [...byIp.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, n]) => ({ ip, count: n }));

  const warnAt = Math.max(1, settings.authFailureWarnThreshold);
  const critAt = Math.max(warnAt + 1, settings.authFailureCriticalThreshold);
  let status: SecurityCheckRow['status'];
  if (count >= critAt) status = 'critical';
  else if (count >= warnAt) status = 'warning';
  else status = 'info'; // a handful of failures is normal scanner noise — still worth seeing

  return [{
    name: 'auth-failures',
    kind: 'auth-failures',
    status,
    detail: `${count} failed login attempt${count === 1 ? '' : 's'} in the last ${hours}h` +
      (topIps.length > 0 ? ` — top source: ${topIps[0].ip} (${topIps[0].count})` : ''),
    count,
    extra: { windowHours: hours, sources: topIps },
  }];
}
