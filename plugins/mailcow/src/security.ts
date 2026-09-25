/**
 * Mailcow plugin — per-instance security checks (capability 'securityChecks').
 *
 * Emits `metrics['securityChecks']` = SecurityCheckRow[] during inventory
 * collection. The API persists only non-'ok' rows into the cross-device
 * Security page; a clean instance emits no persisted findings. This plugin is
 * REST-only, so every check degrades to "not applicable" on failure and never
 * sinks the poll.
 *
 * Checks (the two security surfaces reachable through mailcow's JSON API):
 *  - rate-limiting   GET /api/v1/get/fail2ban — fail2ban is mailcow's built-in
 *                    brute-force protection for IMAP/SMTP/SOGo logins. Active
 *                    or permanent bans are surfaced as 'info' (positive state:
 *                    the protection is working and has caught something).
 *  - email-auth      GET /api/v1/get/dkim/<domain> — per-domain DKIM key
 *                    presence + strength. A domain without a generated key
 *                    cannot sign outgoing mail (spoofing risk) → warning; a
 *                    1024-bit key is cryptographically weak → critical.
 *
 * SPF/DMARC are intentionally NOT checked: mailcow only exposes them through
 * its live DNS diagnostics ajax endpoint, which is not part of the JSON API —
 * and they describe external DNS records this plugin cannot see anyway.
 */

import type { AxiosInstance } from 'axios';
import type { SecurityCheckRow } from '@unm/plugin-sdk';
import { getDkimDetails, getFail2ban } from './client/mailcowClient';

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/** Re-collection throttle — fail2ban + one DKIM GET per domain are cheap but
 * pointless at a 30 s cadence; ~15 min matches the other plugins. */
const RECOLLECT_TTL_MS = 15 * 60_000;
const lastRun = new Map<string, { at: number; rows: SecurityCheckRow[] }>();

/** Runs every check (best-effort, never throws). Throttled per host. */
export async function collectSecurityChecks(
  host: string,
  client: AxiosInstance,
  domains: string[],
): Promise<SecurityCheckRow[]> {
  const key = (host ?? '').trim();
  if (!key) return [];

  const cached = lastRun.get(key);
  if (cached && Date.now() - cached.at < RECOLLECT_TTL_MS) return cached.rows;

  const [fail2banRows, dkimRows] = await Promise.all([
    checkFail2ban(client).catch(() => [] as SecurityCheckRow[]),
    checkDkim(client, domains).catch(() => [] as SecurityCheckRow[]),
  ]);

  const rows = [...fail2banRows, ...dkimRows];
  lastRun.set(key, { at: Date.now(), rows });
  return rows;
}

/** Test hook: clears the per-host security-check cache. */
export function clearSecurityCache(): void {
  lastRun.clear();
}

// ---------------------------------------------------------------------------
// fail2ban (rate limiting)
// ---------------------------------------------------------------------------

async function checkFail2ban(client: AxiosInstance): Promise<SecurityCheckRow[]> {
  const f2b = await getFail2ban(client);

  // mailcow's fail2ban('get') returns PHP `false` for non-admin API keys, which
  // arrives as an empty object — indistinguishable from "no bans configured".
  // Only emit when we actually saw ban data or config values; otherwise the
  // check is not verifiable with this key and must stay silent (absent = no wipe).
  const hasData = f2b.activeBans.length > 0 || f2b.permBans.length > 0 || f2b.blacklist.length > 0 || f2b.maxAttempts !== undefined;
  if (!hasData) return [];

  const activeCount = f2b.activeBans.length;
  const permCount = f2b.permBans.length;
  const total = activeCount + permCount;

  // No bans at all is a clean state — 'ok' (dropped by the API).
  if (total === 0 && f2b.blacklist.length === 0) return [];

  const parts: string[] = [];
  if (activeCount > 0) parts.push(`${activeCount} active ban${activeCount === 1 ? '' : 's'}`);
  if (permCount > 0) parts.push(`${permCount} permanent ban${permCount === 1 ? '' : 's'}`);
  if (f2b.blacklist.length > 0) parts.push(`${f2b.blacklist.length} denylisted`);

  return [{
    name: 'fail2ban',
    kind: 'rate-limiting',
    status: 'info', // positive state — brute-force protection is active and has caught something
    detail: `fail2ban is protecting the mail services (${parts.join(', ')})`,
    count: total,
    extra: {
      activeBans: f2b.activeBans.slice(0, 10),
      permBans: f2b.permBans.slice(0, 10),
      blacklist: f2b.blacklist.slice(0, 10),
      ...(f2b.maxAttempts !== undefined ? { maxAttempts: f2b.maxAttempts } : {}),
    },
  }];
}

// ---------------------------------------------------------------------------
// DKIM (per-domain email authentication)
// ---------------------------------------------------------------------------

async function checkDkim(client: AxiosInstance, domains: string[]): Promise<SecurityCheckRow[]> {
  const unique = [...new Set(domains.map((d) => d.trim()).filter(Boolean))].slice(0, 50);
  if (unique.length === 0) return [];

  // One GET per domain — mailcow instances typically carry a handful of domains.
  const results = await Promise.allSettled(unique.map(async (domain) => ({ domain, dkim: await getDkimDetails(client, domain) })));

  const rows: SecurityCheckRow[] = [];
  for (const r of results) {
    if (r.status !== 'fulfilled') continue; // per-domain failure → skip that domain only
    const { domain, dkim } = r.value;

    if (!dkim.present) {
      rows.push({
        name: `dkim-${domain}`,
        kind: 'email-auth',
        status: 'warning',
        detail: `${domain} has no DKIM key — outgoing mail is unsigned and the domain can be spoofed`,
      });
      continue;
    }

    // mailcow reports estimated bit lengths as "1024" | "2048" | "3072" | "4096" | ">= 8192".
    const bits = Number(String(dkim.length ?? '').replace(/[^0-9]/g, ''));
    if (Number.isFinite(bits) && bits > 0 && bits <= 1024) {
      rows.push({
        name: `dkim-${domain}`,
        kind: 'email-auth',
        status: 'critical',
        detail: `${domain} uses a ${dkim.length}-bit DKIM key — too weak (RSA-1024 is breakable); regenerate with ≥ 2048 bits`,
      });
    }
    // Present + adequate length → clean ('ok' = absence of a row).
  }

  return rows;
}
