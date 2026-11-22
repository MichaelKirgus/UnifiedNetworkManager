/**
 * Mailcow plugin — per-instance security checks (capability 'securityChecks').
 *
 * Emits `metrics['securityChecks']` = SecurityCheckRow[] during inventory
 * collection. The API persists only non-'ok' rows into the cross-device
 * Security page; a clean instance emits no persisted findings. This plugin is
 * REST-only, so every check degrades to "not applicable" on failure and never
 * sinks the poll.
 *
 * Checks (the security surfaces reachable through mailcow's JSON API):
 *  - rate-limiting   GET /api/v1/get/fail2ban — fail2ban is mailcow's built-in
 *                    brute-force protection for IMAP/SMTP/SOGo logins. Active
 *                    or permanent bans are surfaced as 'info' (positive state:
 *                    the protection is working and has caught something).
 *  - email-auth      GET /api/v1/get/dkim/<domain> — per-domain DKIM key
 *                    presence + strength. A domain without a generated key
 *                    cannot sign outgoing mail (spoofing risk) → warning; a
 *                    1024-bit key is cryptographically weak → critical.
 *  - spam-filtering  GET /api/v1/get/logs/rspamd-stats — rspamd version +
 *                    cumulative action tallies. Surfaces as 'info' once the
 *                    filter has actually rejected/soft-rejected mail (positive
 *                    state, like fail2ban); a never-blocked instance stays silent.
 *  - auth-activity   GET /api/v1/get/logs/sasl — recent mail logins by source
 *                    IP. An EXTERNAL ip authenticating as ≥3 distinct users in
 *                    the visible window is a credential-stuffing signal →
 *                    warning; any external login activity otherwise surfaces as
 *                    'info' (who is logging in from where, alongside fail2ban).
 *
 * SPF/DMARC are intentionally NOT checked: mailcow only exposes them through
 * its live DNS diagnostics ajax endpoint, which is not part of the JSON API —
 * and they describe external DNS records this plugin cannot see anyway.
 */

import type { AxiosInstance } from 'axios';
import type { SecurityCheckRow } from '@unm/plugin-sdk';
import {
  getDkimDetails,
  getFail2ban,
  getSaslLogins,
  getRspamdStats,
  MailcowRspamdStats,
  MailcowSaslLogin,
} from './client/mailcowClient';

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

  const [fail2banRows, dkimRows, rspamdRows, saslRows] = await Promise.all([
    checkFail2ban(client).catch(() => [] as SecurityCheckRow[]),
    checkDkim(client, domains).catch(() => [] as SecurityCheckRow[]),
    checkRspamd(client).catch(() => [] as SecurityCheckRow[]),
    checkSaslLogins(client).catch(() => [] as SecurityCheckRow[]),
  ]);

  const rows = [...fail2banRows, ...dkimRows, ...rspamdRows, ...saslRows];
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

// ---------------------------------------------------------------------------
// rspamd (spam-filtering state)
// ---------------------------------------------------------------------------

/**
 * Pure builder for the rspamd check row from normalized stats. Returns null
 * when nothing is worth surfacing: no data at all (endpoint absent / not
 * verifiable with this key) or a filter that has never blocked anything.
 */
export function buildRspamdRow(stats: MailcowRspamdStats): SecurityCheckRow | null {
  if (!stats.version && Object.keys(stats.actions).length === 0) return null; // not verifiable

  const actions = stats.actions;
  const rejected = (actions['reject'] ?? 0) + (actions['soft reject'] ?? 0);
  if (rejected <= 0) return null; // clean — no row, per the file's convention

  const parts: string[] = [];
  if ((actions['reject'] ?? 0) > 0) parts.push(`${actions['reject']} rejected`);
  if ((actions['soft reject'] ?? 0) > 0) parts.push(`${actions['soft reject']} soft-rejected`);
  const greylisted = actions['greylist'] ?? 0;

  const detailParts: string[] = [];
  if (stats.scanned !== undefined) detailParts.push(`scanned ${stats.scanned.toLocaleString('en-US')} messages since start`);
  detailParts.push(parts.join(', '));
  if (greylisted > 0) detailParts.push(`${greylisted} greylisted`);

  return {
    name: 'rspamd',
    kind: 'spam-filtering',
    status: 'info', // positive state — the filter is active and has caught spam
    detail: `rspamd ${stats.version ?? '(unknown version)'} has ${detailParts.join('; ')}`,
    count: rejected,
    extra: {
      ...(stats.version ? { version: stats.version } : {}),
      ...(stats.uptimeSec !== undefined ? { uptimeSec: stats.uptimeSec } : {}),
      ...(stats.scanned !== undefined ? { scanned: stats.scanned } : {}),
      actions,
    },
  };
}

/** GET rspamd-stats → check row (best-effort, never throws). */
async function checkRspamd(client: AxiosInstance): Promise<SecurityCheckRow[]> {
  const row = buildRspamdRow(await getRspamdStats(client));
  return row ? [row] : [];
}

// ---------------------------------------------------------------------------
// SASL login activity (auth-activity)
// ---------------------------------------------------------------------------

/** One source IP's aggregated login activity in the visible log window. */
export interface SaslOffender {
  ip: string;
  /** Distinct usernames this IP authenticated as (lowercased, sorted). */
  usernames: string[];
  /** Total login events from this IP in the window. */
  count: number;
}

/** Distinct-user threshold for one EXTERNAL ip → credential-stuffing warning. */
export const CREDENTIAL_STUFFING_THRESHOLD = 3;

/**
 * True for addresses that are not "external": RFC1918, loopback and link-local
 * IPv4; unique-local/loopback/link-local IPv6 (basic forms); IPv4-mapped v6.
 * LAN clients legitimately use several accounts from one machine, so only
 * external sources are treated as a signal.
 */
export function isPrivateIp(ip: string): boolean {
  const t = ip.trim();
  if (/^10\./.test(t)) return true;
  if (/^192\.168\./.test(t)) return true;
  const m172 = t.match(/^172\.(\d+)\./);
  if (m172 && Number(m172[1]) >= 16 && Number(m172[1]) <= 31) return true;
  if (/^127\./.test(t)) return true;
  if (/^169\.254\./.test(t)) return true;

  const v6 = t.toLowerCase();
  if (v6 === '::1' || v6.startsWith('fe80:')) return true;
  // Unique-local fc00::/7 — covers both fc and fd first hextets.
  if (/^f[cd][0-9a-f]{2}:/.test(v6)) return true;
  const mapped = v6.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIp(mapped[1]);
  return false;
}

/**
 * Pure builder for the SASL auth-activity check rows from raw login events.
 * Aggregates the visible window (~newest 1000 logins mailcow retains) per
 * source IP. Returns [] when there is no data or only internal activity —
 * absence of a row is the clean state, per the file's convention.
 */
export function saslAuthRows(logins: MailcowSaslLogin[]): SecurityCheckRow[] {
  if (logins.length === 0) return [];

  const byIp = new Map<string, { count: number; users: Set<string> }>();
  for (const l of logins) {
    let agg = byIp.get(l.ip);
    if (!agg) {
      agg = { count: 0, users: new Set() };
      byIp.set(l.ip, agg);
    }
    agg.count += 1;
    agg.users.add(l.username.toLowerCase());
  }

  const external = [...byIp.entries()].filter(([ip]) => !isPrivateIp(ip));
  if (external.length === 0) return []; // all internal → clean state, no row

  const toOffender = ([ip, v]: [string, { count: number; users: Set<string> }]): SaslOffender => ({
    ip,
    usernames: [...v.users].sort(),
    count: v.count,
  });

  // Credential-stuffing signal: one external IP authenticating as several
  // different accounts within the visible window.
  const offenders = external.filter(([, v]) => v.users.size >= CREDENTIAL_STUFFING_THRESHOLD).map(toOffender);
  if (offenders.length > 0) {
    offenders.sort((a, b) => b.usernames.length - a.usernames.length || b.count - a.count);
    const top = offenders[0];
    return [{
      name: 'sasl-auth',
      kind: 'auth-activity',
      status: 'warning',
      detail: `IP ${top.ip} authenticated as ${top.usernames.length} different users in the recent login log — possible credential stuffing`,
      count: top.count,
      extra: { offenders: offenders.slice(0, 5) },
    }];
  }

  // Neutral state: external logins exist but look normal (one user per IP).
  const totalExternal = external.reduce((s, [, v]) => s + v.count, 0);
  const top = external.sort((a, b) => b[1].count - a[1].count).slice(0, 5).map(toOffender);
  return [{
    name: 'sasl-auth',
    kind: 'auth-activity',
    status: 'info',
    detail: `${totalExternal} recent mail logins from ${external.length} external IP${external.length === 1 ? '' : 's'} (top: ${top.map((t) => `${t.ip} ×${t.count}`).join(', ')})`,
    count: totalExternal,
    extra: { top },
  }];
}

/** GET sasl log → check rows (best-effort, never throws). */
async function checkSaslLogins(client: AxiosInstance): Promise<SecurityCheckRow[]> {
  return saslAuthRows(await getSaslLogins(client));
}
