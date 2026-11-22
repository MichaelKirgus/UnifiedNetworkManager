/**
 * Mailcow plugin — netfilter jail log → UNM firewall events (pure logic).
 *
 * mailcow's netfilter "jail" (GET /api/v1/get/logs/netfilter) is an append-only
 * ring buffer (~newest 1000 entries) of security-relevant connections seen on
 * the mail ports: brute-force pre-ban warnings, failed IMAP/SMTP auth attempts
 * and non-SMTP port scans. Each entry carries only {time (epoch seconds),
 * priority, message} — no structured fields — so this module classifies the
 * free-form message into a reason + offending IP and builds the wire rows for
 * the API's internal POST /plugin/firewall-events endpoint (the same table the
 * OPNsense plugin feeds from its firewall log).
 *
 * Dedupe: mailcow has no per-row id, so vendorEventId is a deterministic sha1
 * of (time|message) — identical in spirit to the DNS qstats synthesized key.
 * Re-sent batches are absorbed by the API's on-conflict-ignore unique index.
 *
 * The push pipeline itself (state-store cursor + HTTP) lives in index.ts, next
 * to the plugin identity/logger it needs; everything here is pure and unit-testable.
 */

import { createHash } from 'node:crypto';
import type { MailcowNetfilterLogEntry } from './client/mailcowClient';

/** Classification of a netfilter log line (the `reason` column in UNM). */
export type NetfilterReason = 'brute-force-pre-ban' | 'auth-failed' | 'port-scan';

/** One classified event ready for the firewall-events wire format. */
export interface ParsedNetfilterEvent {
  reason: NetfilterReason;
  /** Offending source IP (bare form — CIDR suffix stripped). */
  srcIp?: string;
  /** Human description shown in the Rule column (parenthetical when present). */
  ruleName?: string;
}

// --- Message classification ----------------------------------------------------
// Patterns verified against a live 2026-11b instance (MAIL04):
//   "9 more attempts in the next 600 seconds until 139.59.10.109/32 is banned"
//   "a.b.c.d matched rule id N (MAILCOWAUTH: Login failed for user u@x with service imap from IP a.b.c.d)"
//   "a.b.c.d matched rule id N (warning: unknown[a.b.c.d]: SASL PLAIN authentication failed: …)"
//   "a.b.c.d matched rule id N (warning: non-SMTP command from unknown[a.b.c.d]: GET _ HTTP/1.1)"

const PRE_BAN_RE = /until\s+([\d.]+)(?:\/\d+)?\s+is banned/i;
const LOGIN_FAILED_RE = /Login failed for user (\S+) with service (\w+) from IP ([\d.]+)/i;
const SASL_FAILED_RE = /SASL \w+ authentication failed/i;
const NON_SMTP_RE = /non-SMTP command from [^\[]*\[([\d.]+)\]/i;

/** Extracts the parenthetical detail of a "… matched rule id N (…)" line. */
function parenDetail(message: string): string | undefined {
  const m = message.match(/\(([^()]*)\)\s*$/);
  return m && m[1].trim() !== '' ? m[1].trim() : undefined;
}

/** Leading IPv4 address of a log line (mailcow prefixes every rule match). */
function leadingIp(message: string): string | undefined {
  const m = message.match(/^([\d.]+)/);
  return m && m[1] !== '' ? m[1] : undefined;
}

/**
 * Classifies one netfilter log entry. Returns null for lines that are not
 * security events (chain setup, allowlist changes, redis bookkeeping) — those
 * must never reach the firewall-events table.
 */
export function parseNetfilterEntry(entry: MailcowNetfilterLogEntry): ParsedNetfilterEvent | null {
  const msg = entry.message;

  // Pre-ban warning: "N more attempts in the next N seconds until a.b.c.d/32 is banned".
  const preBan = msg.match(PRE_BAN_RE);
  if (preBan) {
    return { reason: 'brute-force-pre-ban', srcIp: preBan[1], ruleName: msg };
  }

  // MAILCOWAUTH jail: failed IMAP/SMTP login with the offending IP in the line.
  const login = msg.match(LOGIN_FAILED_RE);
  if (login) {
    return { reason: 'auth-failed', srcIp: login[3], ruleName: parenDetail(msg) ?? msg };
  }

  // SASL auth failure without an explicit "from IP" — take the leading address.
  if (SASL_FAILED_RE.test(msg)) {
    return { reason: 'auth-failed', srcIp: leadingIp(msg), ruleName: parenDetail(msg) ?? msg };
  }

  // Non-SMTP command on a mail port = scanner/crawler probing the service.
  const scan = msg.match(NON_SMTP_RE);
  if (scan) {
    return { reason: 'port-scan', srcIp: scan[1], ruleName: (parenDetail(msg) ?? msg).slice(0, 200) };
  }

  return null; // chain setup / allowlist / redis lines — not security events
}

// --- Dedupe key + cursor ---------------------------------------------------------

/** Deterministic dedupe key for one netfilter entry (sha1 of time|message). */
export function netfilterVendorEventId(timeSec: number, message: string): string {
  return createHash('sha1').update(`${timeSec}|${message}`).digest('hex');
}

/** Entries strictly newer than the stored cursor (ALL entries on first run — baseline). */
export function selectFreshNetfilterEntries(
  entries: MailcowNetfilterLogEntry[],
  cursorSec: number | null,
): MailcowNetfilterLogEntry[] {
  if (cursorSec === null) return entries;
  return entries.filter((e) => e.time > cursorSec);
}

/** Newest epoch seconds among the given entries (null when empty). */
export function newestNetfilterTimeSec(entries: MailcowNetfilterLogEntry[]): number | null {
  if (entries.length === 0) return null;
  let max = -Infinity;
  for (const e of entries) if (e.time > max) max = e.time;
  return Number.isFinite(max) ? max : null;
}

// --- Wire rows --------------------------------------------------------------------

/**
 * Builds the /plugin/firewall-events wire rows for a set of FRESH entries.
 * Unparseable lines are skipped silently — they were already counted into the
 * cursor advance, so they are not re-fetched on later beats.
 */
export function toFirewallEventRows(entries: MailcowNetfilterLogEntry[]): Array<Record<string, unknown>> {
  const rows: Array<Record<string, unknown>> = [];
  for (const e of entries) {
    const parsed = parseNetfilterEntry(e);
    if (!parsed) continue;
    rows.push({
      vendorEventId: netfilterVendorEventId(e.time, e.message),
      // mailcow's `time` is unix epoch SECONDS (UTC) — full ISO with Z so the
      // API's tsToMs needs no local-clock offset correction.
      ts: new Date(Math.round(e.time * 1000)).toISOString(),
      // All jail lines are security WARNINGS, not packet verdicts — mailcow's
      // netfilter logs and fail2ban bans; nothing here is an allow/deny decision.
      action: 'warn',
      reason: parsed.reason,
      srcIp: parsed.srcIp ?? '',
      ruleName: (parsed.ruleName ?? '').slice(0, 512),
    });
  }
  return rows;
}
