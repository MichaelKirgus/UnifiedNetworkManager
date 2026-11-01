/**
 * OPNsense plugin — per-appliance security checks (capability 'securityChecks').
 *
 * Emits `metrics['securityChecks']` = SecurityCheckRow[] during inventory
 * collection. The API persists only non-'ok' rows into the cross-device
 * Security page; a clean device emits no persisted findings.
 *
 * TRANSPORT: OPNsense's REST API exposes NO log or file access — every check
 * rides the OPTIONAL `ssh` credential slot (the same one that powers ZFS
 * inventory). No ssh slot bound → all checks are skipped silently (API-only
 * mode), exactly like the ZFS enrichment. ONE combined SSH round-trip per
 * inventory cycle collects everything; each section is best-effort — a missing
 * tool degrades that check to "not applicable" and never sinks the poll.
 *
 * Checks:
 *  - file-integrity   sha256 of important identity/config files (/etc/master.passwd,
 *                     /etc/passwd, sshd_config) against a TOFU baseline persisted
 *                     in UNM's database (plugin state store). First sight =
 *                     baseline saved silently; a later DIFFERENT hash is critical
 *                     and the baseline is NOT auto-updated — an attacker editing
 *                     the file must not be able to re-baseline. Re-baselining is
 *                     an explicit action (security.rebaseline).
 *  - auth-failures    unsuccessful sshd login attempts from /var/log/auth.log
 *                     (FreeBSD syslog). A few failures are background scanner
 *                     noise → 'info'; configurable warn/critical thresholds
 *                     escalate it.
 *  - rate-limiting    brute-force protection ACTIVE on the box: fail2ban jails +
 *                     banned counts (when installed) and pf ruleset entries with
 *                     rate/limit modifiers. Positive state → 'info'.
 *  - account          hygiene findings: unexpected uid-0 accounts in
 *                     /etc/master.passwd.
 */

import type { SecurityCheckRow } from '@unm/plugin-sdk';
import { hostFromAddress, resolveSshCredentials, resolveSshPort } from '@unm/plugin-sdk';
import { execViaSshSlot } from './zfsSsh';
// The shared instance-scoped store (see ./stateStore) — baselines are keyed by
// host+path and scoped to THIS plugin instance's effective uuid.
import { stateStore } from './stateStore';

// ---------------------------------------------------------------------------
// Settings (resolved per request in index.ts from plugin options)
// ---------------------------------------------------------------------------

export interface SecuritySettings {
  enabled: boolean;
  /** Important files to watch for changes (absolute paths). */
  watchedFiles: string[];
  /** Look-back window for failed-login counting. */
  authFailureWindowHours: number;
  /** ≥ this many failures in the window → warning. */
  authFailureWarnThreshold: number;
  /** ≥ this many failures in the window → critical. */
  authFailureCriticalThreshold: number;
}

export const DEFAULT_WATCHED_FILES = ['/etc/master.passwd', '/etc/passwd', '/etc/ssh/sshd_config'];

const STATE_NAMESPACE = 'file-integrity';

interface FileBaseline {
  hash: string;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Runs every check in ONE SSH round-trip (best-effort, never throws).
 *
 * Return contract — the caller MUST distinguish "no fresh data" from "clean":
 *   - `null`  = checks did NOT run this cycle (disabled, no ssh slot bound, or
 *     the SSH exec failed). The caller omits the metric key entirely so stored
 *     rows survive a transient failure AND notification mirroring leaves live
 *     security alerts untouched.
 *   - `[]`    = checks ran and found nothing actionable — an AUTHORITATIVE wipe
 *     (the API clears this device's findings) and a signal to resolve any
 *     lingering notification-center entries for this host.
 */
export async function collectSecurityChecks(
  managementAddress: string,
  credentials: Record<string, unknown> | undefined,
  sshPort: number | undefined,
  deviceId: string | null,
  settings: SecuritySettings,
): Promise<SecurityCheckRow[] | null> {
  if (!settings.enabled) return null;

  // Bare host for stable baseline keys (a management address may carry scheme/port).
  const host = hostFromAddress(managementAddress) ?? managementAddress;

  // No ssh slot bound → API-only mode: skip all checks silently.
  if (!resolveSshCredentials(credentials, { slotOnly: true })) return null;

  const list = settings.watchedFiles.map((p) => `'${p.replace(/'/g, "'\\''")}'`).join(' ');
  const command = [
    // FreeBSD has `sha256`, not `sha256sum` — try both.
    'hashfile() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" 2>/dev/null | cut -d\' \' -f1; else sha256 -h "$1" 2>/dev/null | awk \'{print $NF}\'; fi; }',
    'echo __HASH__',
    `for f in ${list}; do if [ -f "$f" ]; then printf 'HASH %s %s\\n' "$(hashfile "$f")" "$f"; else printf 'MISSING %s\\n' "$f"; fi; done`,
    'echo __AUTH__',
    "[ -r /var/log/auth.log ] && tail -n 3000 /var/log/auth.log 2>/dev/null | grep -Ei 'failed password|invalid user' | tail -n 500 || true",
    'echo __RATE_F2B__',
    'if command -v fail2ban-client >/dev/null 2>&1; then',
    "  jails=$(fail2ban-client status 2>/dev/null | awk '/Jail list/{sub(/.*Jail list:[ \\t]*/,\" \"); print}')",
    '  for j in $jails; do',
    "    banned=$(fail2ban-client status \"$j\" 2>/dev/null | awk -F': *' '/Banned:/{print $2}')",
    '    echo "JAIL|$j|${banned:-0}"',
    '  done',
    'fi',
    'echo __RATE_PF__',
    'pfctl -sr 2>/dev/null | grep -cE \'rate|limit\' || true',
    'echo __ACCT__',
    "awk -F: '$3==0 {print $1}' /etc/master.passwd 2>/dev/null",
  ].join('\n');

  const r = await execViaSshSlot(host, credentials, command, { port: sshPort, timeoutMs: 25_000 }).catch(() => null);
  if (!r) return null; // no usable SSH path / exec failed — checks not applicable (keep previous data + alerts)

  const out = r.stdout ?? '';
  const section = (start: string, end?: string): string[] => {
    const i = out.indexOf(start);
    if (i === -1) return [];
    let body = out.slice(i + start.length);
    if (end) {
      const j = body.indexOf(end);
      if (j !== -1) body = body.slice(0, j);
    }
    return body.split('\n').map((l) => l.trim()).filter(Boolean);
  };

  const [fileRows, authRows, rateRows, accountRows] = await Promise.all([
    checkFileIntegrity(host, deviceId, section('__HASH__', '__AUTH__'), settings.watchedFiles).catch(() => [] as SecurityCheckRow[]),
    checkAuthFailures(section('__AUTH__', '__RATE_F2B__'), settings).catch(() => [] as SecurityCheckRow[]),
    Promise.resolve(checkRateLimiting(section('__RATE_F2B__', '__RATE_PF__'), section('__RATE_PF__', '__ACCT__'))),
    Promise.resolve(checkAccounts(section('__ACCT__'))),
  ]);

  return [...fileRows, ...authRows, ...rateRows, ...accountRows];
}

// ---------------------------------------------------------------------------
// File integrity (TOFU baselines in the UNM database)
// ---------------------------------------------------------------------------

async function checkFileIntegrity(
  host: string,
  deviceId: string | null,
  hashLines: string[],
  watchedFiles: string[],
): Promise<SecurityCheckRow[]> {
  if (watchedFiles.length === 0) return [];

  const current = new Map<string, string>(); // path → hash
  const missing = new Set<string>();
  for (const line of hashLines) {
    if (line.startsWith('HASH ')) {
      const [hash, ...rest] = line.slice(5).trim().split(/\s+/);
      const path = rest.join(' ');
      if (hash && path) current.set(path, hash);
    } else if (line.startsWith('MISSING ')) {
      missing.add(line.slice(8).trim());
    }
  }

  // Baselines live in UNM's database keyed "<host>|<path>" — they survive plugin
  // container rebuilds and are scoped to the device for cascade-on-delete.
  const baselines = await stateStore.list(STATE_NAMESPACE);
  const prefix = `${host}|`;
  const baselineFor = (path: string): FileBaseline | undefined => {
    const v = baselines[`${prefix}${path}`];
    if (!v || typeof v !== 'object') return undefined;
    const b = v as Record<string, unknown>;
    return typeof b['hash'] === 'string' ? (b as unknown as FileBaseline) : undefined;
  };

  const rows: SecurityCheckRow[] = [];
  const toStore: { key: string; value: unknown }[] = [];

  for (const path of watchedFiles) {
    const hash = current.get(path);
    if (hash !== undefined) {
      const base = baselineFor(path);
      if (!base) {
        // First sight — TOFU: save the baseline silently, no finding.
        toStore.push({ key: `${prefix}${path}`, value: { hash } });
      } else if (base.hash !== hash) {
        rows.push({
          name: path,
          kind: 'file-integrity',
          status: 'critical',
          detail: `changed since last check (sha256 ${base.hash.slice(0, 12)}… → ${hash.slice(0, 12)}…) — re-baseline via the security.rebaseline action once verified`,
          extra: { baselineHash: base.hash, currentHash: hash },
        });
        // Deliberately NOT updating the baseline — an attacker who can edit the
        // file must not be able to make the finding disappear on its own.
      }
      // else: unchanged → 'ok' (dropped by the API)
    } else if (missing.has(path)) {
      const base = baselineFor(path);
      if (base) {
        rows.push({
          name: path,
          kind: 'file-integrity',
          status: 'warning',
          detail: 'no longer present on the device (was baselined earlier)',
          extra: { baselineHash: base.hash },
        });
      }
      // never seen before → simply not applicable on this box, no finding
    }
  }

  if (toStore.length > 0) {
    await stateStore.put(toStore.map((e) => ({ namespace: STATE_NAMESPACE, key: e.key, value: e.value, deviceId: deviceId ?? undefined })));
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Failed logins (sshd via /var/log/auth.log — FreeBSD syslog)
// ---------------------------------------------------------------------------

const AUTH_FAIL_RE = /failed password|invalid user/i;

async function checkAuthFailures(linesIn: string[], settings: SecuritySettings): Promise<SecurityCheckRow[]> {
  const lines = linesIn.filter((l) => AUTH_FAIL_RE.test(l));
  if (lines.length === 0) return []; // no failures in the window → 'ok' (dropped)

  // Aggregate source IPs ("… from 1.2.3.4 port …" / "Invalid user x from 1.2.3.4").
  const byIp = new Map<string, number>();
  for (const line of lines) {
    const m = line.match(/from\s+(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)/i);
    if (m) byIp.set(m[1], (byIp.get(m[1]) ?? 0) + 1);
  }
  const topIps = [...byIp.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, n]) => ({ ip, count: n }));

  const warnAt = Math.max(1, settings.authFailureWarnThreshold);
  const critAt = Math.max(warnAt + 1, settings.authFailureCriticalThreshold);
  let status: SecurityCheckRow['status'];
  if (lines.length >= critAt) status = 'critical';
  else if (lines.length >= warnAt) status = 'warning';
  else status = 'info'; // a handful of failures is normal scanner noise — still worth seeing

  return [{
    name: 'auth-failures',
    kind: 'auth-failures',
    status,
    detail: `${lines.length} unsuccessful login attempt${lines.length === 1 ? '' : 's'} (sshd, recent log window)` +
      (topIps.length > 0 ? ` — top source: ${topIps[0].ip} (${topIps[0].count})` : ''),
    count: lines.length,
    extra: { windowHours: settings.authFailureWindowHours, sources: topIps },
  }];
}

// ---------------------------------------------------------------------------
// Rate limiting / brute-force protection active on the box
// ---------------------------------------------------------------------------

function checkRateLimiting(f2bLines: string[], pfCountLines: string[]): SecurityCheckRow[] {
  const rows: SecurityCheckRow[] = [];

  // fail2ban — one info row summarizing all jails (positive state: protection active).
  const jailLines = f2bLines.filter((l) => l.startsWith('JAIL|'));
  if (jailLines.length > 0) {
    const jails = jailLines.map((l) => {
      const [, name, banned] = l.split('|');
      return { name: name ?? 'unknown', banned: Number(banned) || 0 };
    });
    const totalBanned = jails.reduce((a, j) => a + j.banned, 0);
    rows.push({
      name: 'fail2ban',
      kind: 'rate-limiting',
      status: 'info',
      detail: `fail2ban active — ${totalBanned} IP(s) banned across ${jails.length} jail${jails.length === 1 ? '' : 's'}`,
      count: totalBanned,
      extra: { jails },
    });
  }

  // pf ruleset entries carrying rate/limit modifiers (anti-brute-force rules).
  const pfCount = Number(pfCountLines[0]) || 0;
  if (pfCount > 0) {
    rows.push({
      name: 'pf-rate-limit',
      kind: 'rate-limiting',
      status: 'info',
      detail: `${pfCount} pf rule(s) with rate/limit modifiers active in the ruleset`,
      count: pfCount,
    });
  }

  return rows;
}

// ---------------------------------------------------------------------------
// Account hygiene (uid-0 accounts)
// ---------------------------------------------------------------------------

function checkAccounts(uid0Lines: string[]): SecurityCheckRow[] {
  // Any uid-0 account besides root is a privilege-escalation red flag.
  const uid0 = uid0Lines.filter((u) => u !== 'root');
  if (uid0.length === 0) return [];
  return [{
    name: 'uid0-accounts',
    kind: 'account',
    status: 'critical',
    detail: `unexpected uid-0 account(s): ${uid0.join(', ')}`,
    count: uid0.length,
    extra: { accounts: uid0 },
  }];
}
