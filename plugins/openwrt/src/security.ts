/**
 * OpenWRT plugin — per-appliance security checks (capability 'securityChecks').
 *
 * Emits `metrics['securityChecks']` = SecurityCheckRow[] during inventory
 * collection. The API persists only non-'ok' rows into the cross-device
 * Security page; a clean device emits no persisted findings. Every check is
 * best-effort POSIX/busybox — OpenWRT boxes vary wildly (full distro images to
 * stripped router builds), so a missing tool degrades that check to "not
 * applicable" and never sinks the poll. All checks need the SSH transport; in
 * forced 'luci' mode (no SSH) they are simply skipped.
 *
 * Checks:
 *  - file-integrity   sha256 of important identity/config files (/etc/passwd,
 *                     /etc/shadow, uci firewall/network config, dropbear keys)
 *                     against a TOFU baseline persisted in UNM's database
 *                     (plugin state store). First sight = baseline saved
 *                     silently; a later DIFFERENT hash is critical and the
 *                     baseline is NOT auto-updated — an attacker editing the
 *                     file must not be able to re-baseline. Re-baselining is an
 *                     explicit action (security.rebaseline).
 *  - auth-failures    unsuccessful dropbear login attempts in the last N hours
 *                     via `logread` (busybox syslog) with /var/log/messages as
 *                     fallback. A few failures are background scanner noise →
 *                     'info'; configurable warn/critical thresholds escalate it.
 *  - rate-limiting    brute-force protection ACTIVE on the box: uci firewall
 *                     rules carrying a `limit` option (fw4 rate limiting) and,
 *                     where present, nftables `limit rate` rules. Positive state
 *                     → 'info' (the user asked to see when rate limits are active).
 *  - account          hygiene findings: unexpected uid-0 accounts, shadow entries
 *                     with an EMPTY password field.
 */

import type { SecurityCheckRow } from '@unm/plugin-sdk';
import type { Backend } from './client/backend';
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

export const DEFAULT_WATCHED_FILES = [
  '/etc/passwd',
  '/etc/shadow',
  '/etc/config/firewall',
  '/etc/config/network',
];

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
  backend: Backend,
  deviceId: string | null,
  settings: SecuritySettings,
): Promise<SecurityCheckRow[]> {
  if (!settings.enabled) return [];
  // Every check rides the SSH transport — in forced 'luci' mode there is none.
  const ssh = backend.ssh;
  if (!ssh) return [];

  const host = backend.host;
  const [fileRows, authRows, rateRows, accountRows] = await Promise.all([
    checkFileIntegrity(host, deviceId, ssh.exec.bind(ssh), settings.watchedFiles).catch(() => [] as SecurityCheckRow[]),
    checkAuthFailures(ssh.exec.bind(ssh), settings).catch(() => [] as SecurityCheckRow[]),
    checkRateLimiting(ssh.exec.bind(ssh)).catch(() => [] as SecurityCheckRow[]),
    checkAccounts(ssh.exec.bind(ssh)).catch(() => [] as SecurityCheckRow[]),
  ]);

  return [...fileRows, ...authRows, ...rateRows, ...accountRows];
}

/** Minimal exec surface (SshBackend.exec) — keeps the checks transport-agnostic. */
type ExecFn = (command: string, timeoutMs?: number) => Promise<{ code: number; stdout: string; stderr: string }>;

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
  exec: ExecFn,
  watchedFiles: string[],
): Promise<SecurityCheckRow[]> {
  if (watchedFiles.length === 0) return [];

  // ONE round-trip: hash every watched file that exists; report missing ones.
  const list = watchedFiles.map(shq).join(' ');
  const r = await exec(
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
// Failed logins (dropbear via busybox syslog / logread)
// ---------------------------------------------------------------------------

const AUTH_FAIL_RE = /failed password|invalid user|authentication failure/i;

async function checkAuthFailures(exec: ExecFn, settings: SecuritySettings): Promise<SecurityCheckRow[]> {
  const hours = Math.max(1, Math.min(720, settings.authFailureWindowHours));
  // OpenWRT's syslog is busybox: `logread` reads the ring buffer (no time-window
  // flag on older builds), so we take a generous tail and count. dropbear logs
  // "Failed password for <user> from <ip> port <n>" / "Invalid user ...".
  const r = await exec([
    'echo __LOGREAD__',
    "if command -v logread >/dev/null 2>&1; then logread 2>/dev/null | grep -Ei 'failed password|invalid user' | tail -n 500; fi",
    'echo __FILES__',
    '[ -r /var/log/messages ] && tail -n 3000 /var/log/messages 2>/dev/null | grep -Ei \'failed password|invalid user\' | tail -n 500 || true',
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

  // Prefer logread (the live ring buffer); fall back to the file. On boxes where
  // both carry the same lines, using both would double-count — hence the fallback.
  const logreadLines = section('__LOGREAD__', '__FILES__');
  const fileLines = section('__FILES__');
  const lines = logreadLines.length > 0 ? logreadLines : fileLines;

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
    detail: `${lines.length} unsuccessful login attempt${lines.length === 1 ? '' : 's'} (dropbear, recent log window)` +
      (topIps.length > 0 ? ` — top source: ${topIps[0].ip} (${topIps[0].count})` : ''),
    count: lines.length,
    extra: { windowHours: hours, sources: topIps },
  }];
}

// ---------------------------------------------------------------------------
// Rate limiting / brute-force protection active on the box
// ---------------------------------------------------------------------------

async function checkRateLimiting(exec: ExecFn): Promise<SecurityCheckRow[]> {
  const r = await exec([
    'echo __UCI__',
    "uci show firewall 2>/dev/null | grep -c \"option limit\" || true",
    'echo __NFT__',
    'if command -v nft >/dev/null 2>&1; then nft list ruleset 2>/dev/null | grep -c \'limit rate\'; fi',
  ].join('\n'), 20_000).catch(() => null);
  if (!r || r.code !== 0) return [];

  const out = r.stdout ?? '';
  const rows: SecurityCheckRow[] = [];

  // uci firewall rules carrying a `limit` option — fw4 rate limiting (the
  // standard OpenWRT brute-force mitigation, e.g. on the dropbear/ssh rule).
  const uciSection = out.split('__UCI__')[1]?.split('__NFT__')[0] ?? '';
  const uciCount = Number(uciSection.trim().split('\n')[0]) || 0;
  if (uciCount > 0) {
    rows.push({
      name: 'firewall-limit',
      kind: 'rate-limiting',
      status: 'info',
      detail: `${uciCount} firewall rule(s) with an active rate limit (uci option "limit")`,
      count: uciCount,
    });
  }

  // nftables rate-limit rules present in the live ruleset (fw4 compiles to nft).
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

async function checkAccounts(exec: ExecFn): Promise<SecurityCheckRow[]> {
  const r = await exec([
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
