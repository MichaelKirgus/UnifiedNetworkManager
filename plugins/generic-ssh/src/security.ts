/**
 * Generic SSH plugin — per-appliance security checks (capability 'securityChecks').
 *
 * Emits `metrics['securityChecks']` = SecurityCheckRow[] during inventory
 * collection. The API persists only non-'ok' rows into the cross-device
 * Security page; a clean device emits no persisted findings. Every check is
 * best-effort POSIX — a missing tool (no journalctl, no fail2ban) degrades that
 * check to "not applicable" and never sinks the poll.
 *
 * Checks:
 *  - file-integrity   sha256 of important identity/config files (/etc/passwd,
 *                     /etc/shadow, /etc/sudoers, sshd_config, …) against a TOFU
 *                     baseline persisted in UNM's database (plugin state store).
 *                     First sight = baseline saved silently; a later DIFFERENT
 *                     hash is critical and the baseline is NOT auto-updated — an
 *                     attacker editing the file must not be able to re-baseline.
 *                     Re-baselining is an explicit action (security.rebaseline).
 *  - auth-failures    unsuccessful login attempts in the last N hours from
 *                     journald (preferred) or /var/log/{auth.log,secure,messages}.
 *                     A few failures are background scanner noise → 'info';
 *                     configurable warn/critical thresholds escalate it.
 *  - rate-limiting    brute-force protection ACTIVE on the box: fail2ban jails +
 *                     banned counts, nftables `limit rate` rules. Positive state
 *                     → 'info' (the user asked to see when rate limits are active).
 *  - account          hygiene findings: unexpected uid-0 accounts, shadow entries
 *                     with an EMPTY password field.
 */

import type { PluginStateStore, SecurityCheckRow } from '@unm/plugin-sdk';
import type { CommandRunner } from './client/privilege';

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

export const DEFAULT_WATCHED_FILES = ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config'];

const STATE_NAMESPACE = 'file-integrity';

interface FileBaseline {
  hash: string;
  sizeBytes?: number | null;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/** Runs every check in parallel; each is independently best-effort (never throws). */
export async function collectSecurityChecks(
  host: string,
  deviceId: string | null,
  backend: CommandRunner,
  store: PluginStateStore,
  settings: SecuritySettings,
): Promise<SecurityCheckRow[]> {
  if (!settings.enabled) return [];

  const [fileRows, authRows, rateRows, accountRows] = await Promise.all([
    checkFileIntegrity(host, deviceId, backend, store, settings.watchedFiles).catch(() => [] as SecurityCheckRow[]),
    checkAuthFailures(backend, settings).catch(() => [] as SecurityCheckRow[]),
    checkRateLimiting(backend).catch(() => [] as SecurityCheckRow[]),
    checkAccounts(backend).catch(() => [] as SecurityCheckRow[]),
  ]);

  return [...fileRows, ...authRows, ...rateRows, ...accountRows];
}

// ---------------------------------------------------------------------------
// File integrity (TOFU baselines in the UNM database)
// ---------------------------------------------------------------------------

/** Shell-quotes a path for safe embedding (single quotes). */
function shq(v: string): string {
  return `'${v.replace(/'/g, "'\\''")}'`;
}

async function checkFileIntegrity(
  host: string,
  deviceId: string | null,
  backend: CommandRunner,
  store: PluginStateStore,
  watchedFiles: string[],
): Promise<SecurityCheckRow[]> {
  if (watchedFiles.length === 0) return [];

  // ONE round-trip: hash every watched file that exists; report missing ones.
  const list = watchedFiles.map(shq).join(' ');
  const r = await backend.exec(
    `for f in ${list}; do if [ -f "$f" ]; then printf 'HASH %s %s\\n' "$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)" "$f"; else printf 'MISSING %s\\n' "$f"; fi; done`,
    20_000,
  ).catch(() => null);
  if (!r || r.code !== 0) return []; // no sha256sum / exec failed — check not applicable

  const current = new Map<string, string>(); // path → hash
  const missing = new Set<string>();
  for (const line of (r.stdout ?? '').split('\n')) {
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
  const baselines = await store.list(STATE_NAMESPACE);
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
    await store.put(toStore.map((e) => ({ namespace: STATE_NAMESPACE, key: e.key, value: e.value, deviceId: deviceId ?? undefined })));
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Failed logins (journald preferred, syslog files as fallback)
// ---------------------------------------------------------------------------

const AUTH_FAIL_RE = /failed password|invalid user|authentication failure/i;

async function checkAuthFailures(backend: CommandRunner, settings: SecuritySettings): Promise<SecurityCheckRow[]> {
  const hours = Math.max(1, Math.min(720, settings.authFailureWindowHours));
  // `date -d` is GNU coreutils; busybox date lacks it → fall back to a plain tail.
  const r = await backend.exec([
    'echo __JOURNAL__',
    `if command -v journalctl >/dev/null 2>&1; then`,
    `  since=$(date -d '${hours} hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null) || since=`,
    '  if [ -n "$since" ]; then',
    `    journalctl --no-pager -u sshd -u ssh --since "$since" 2>/dev/null | grep -Ei 'failed password|invalid user|authentication failure' | tail -n 500`,
    '  fi',
    'fi',
    'echo __FILES__',
    'for f in /var/log/auth.log /var/log/secure /var/log/messages; do [ -r "$f" ] && { echo "# $f"; tail -n 3000 "$f" | grep -Ei \'failed password|invalid user|authentication failure\' | tail -n 500; }; done',
  ].join('\n'), 20_000).catch(() => null);
  if (!r || r.code !== 0) return [];

  const out = r.stdout ?? '';
  const section = (start: string, end?: string): string[] => {
    const i = out.indexOf(start);
    if (i === -1) return [];
    let body = out.slice(i + start.length);
    if (end) {
      const j = body.indexOf(end);
      if (j !== -1) body = body.slice(0, j);
    }
    return body.split('\n').map((l) => l.trim()).filter((l) => AUTH_FAIL_RE.test(l));
  };

  // Prefer journald (real time window); fall back to the syslog files. On boxes
  // where sshd logs to BOTH, using both would double-count — hence the fallback.
  const journalLines = section('__JOURNAL__', '__FILES__');
  const fileLines = section('__FILES__').filter((l) => !l.startsWith('#'));
  const lines = journalLines.length > 0 ? journalLines : fileLines;

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
    detail: `${lines.length} unsuccessful login attempt${lines.length === 1 ? '' : 's'} in the last ${hours}h` +
      (topIps.length > 0 ? ` — top source: ${topIps[0].ip} (${topIps[0].count})` : ''),
    count: lines.length,
    extra: { windowHours: hours, sources: topIps },
  }];
}

// ---------------------------------------------------------------------------
// Rate limiting / brute-force protection active on the box
// ---------------------------------------------------------------------------

async function checkRateLimiting(backend: CommandRunner): Promise<SecurityCheckRow[]> {
  const r = await backend.exec([
    'echo __FAIL2BAN__',
    'if command -v fail2ban-client >/dev/null 2>&1; then',
    "  jails=$(fail2ban-client status 2>/dev/null | awk '/Jail list/{sub(/.*Jail list:[ \\t]*/,\" \"); print}')",
    '  for j in $jails; do',
    "    banned=$(fail2ban-client status \"$j\" 2>/dev/null | awk -F': *' '/Banned:/{print $2}')",
    '    echo "JAIL|$j|${banned:-0}"',
    '  done',
    'fi',
    'echo __NFT__',
    'if command -v nft >/dev/null 2>&1; then nft list ruleset 2>/dev/null | grep -c \'limit rate\'; fi',
  ].join('\n'), 20_000).catch(() => null);
  if (!r || r.code !== 0) return [];

  const out = r.stdout ?? '';
  const rows: SecurityCheckRow[] = [];

  // fail2ban — one info row summarizing all jails (positive state: protection active).
  const jailLines = out.split('\n').filter((l) => l.startsWith('JAIL|'));
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

  // nftables rate-limit rules present in the live ruleset.
  const nftSection = out.split('__NFT__')[1] ?? '';
  const nftCount = Number(nftSection.trim().split('\n')[0]) || 0;
  if (nftCount > 0) {
    rows.push({
      name: 'nftables-limit',
      kind: 'rate-limiting',
      status: 'info',
      detail: `${nftCount} nftables rate-limit rule(s) active in the ruleset`,
      count: nftCount,
    });
  }

  return rows;
}

// ---------------------------------------------------------------------------
// Account hygiene (uid-0 accounts, empty shadow passwords)
// ---------------------------------------------------------------------------

async function checkAccounts(backend: CommandRunner): Promise<SecurityCheckRow[]> {
  const r = await backend.exec([
    'echo __UID0__',
    "awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null",
    'echo __EMPTYPASS__',
    '[ -r /etc/shadow ] && awk -F: \'($2==""){print $1}\' /etc/shadow 2>/dev/null || true',
  ].join('\n'), 15_000).catch(() => null);
  if (!r || r.code !== 0) return [];

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

  const rows: SecurityCheckRow[] = [];

  // Any uid-0 account besides root is a privilege-escalation red flag.
  const uid0 = section('__UID0__', '__EMPTYPASS__').filter((u) => u !== 'root');
  if (uid0.length > 0) {
    rows.push({
      name: 'uid0-accounts',
      kind: 'account',
      status: 'critical',
      detail: `unexpected uid-0 account(s): ${uid0.join(', ')}`,
      count: uid0.length,
      extra: { accounts: uid0 },
    });
  }

  // A shadow entry with an EMPTY password field allows login without a password.
  // ('!' / '*' = locked — those are fine and must not be flagged.)
  const emptyPass = section('__EMPTYPASS__');
  if (emptyPass.length > 0) {
    rows.push({
      name: 'empty-passwords',
      kind: 'account',
      status: 'critical',
      detail: `account(s) with an EMPTY password field in /etc/shadow: ${emptyPass.join(', ')}`,
      count: emptyPass.length,
      extra: { accounts: emptyPass },
    });
  }

  return rows;
}
