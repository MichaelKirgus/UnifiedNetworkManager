/**
 * OPNsense plugin — notification-center mirroring (SDK createNotifier).
 *
 * Mirrors APPLIANCE-LEVEL conditions into the UNM notification center, exactly
 * like the ix-truenas plugin mirrors TrueNAS `alert.list`. Device-state
 * mirroring (offline/degraded/critical) is done API-side from telemetry — we do
 * NOT push that here. The two condition classes OPNsense exposes that are not
 * derivable by the API from a scalar health value:
 *
 *   - ZFS pool states (DEGRADED / FAULTED / OFFLINE) — only visible when an
 *     `ssh` credential slot is bound (the OPNsense REST API has no ZFS listing).
 *   - Security-check findings at warning/critical (file-integrity change,
 *     brute-force login burst, unexpected uid-0 account) — also ssh-slot-gated.
 *
 * Semantics mirror ix-truenas:
 *   - Each condition carries a STABLE dedupe key so re-polls UPSERT the live row
 *     (occurrences++ / lastSeenAt refresh) instead of flooding the center.
 *   - Conditions that vanish from a FRESH snapshot are RESOLVED, so a recovered
 *     pool or a rebaselined file clears its bell entry automatically.
 *
 * ANTI-FLAP CONTRACT: callers pass `null` for a source when they do NOT have
 * fresh authoritative data this cycle (metrics-only poll, no ssh slot bound, or
 * the collection failed). A `null` source leaves that host's known-set UNTOUCHED
 * — we neither notify new conditions nor resolve existing ones. This is the same
 * "absent = keep previous" contract the rest of the plugin uses for metrics, and
 * it guarantees a transient SSH failure can never wrongly clear a live alert.
 */

import type { PluginNotifier } from '@unm/plugin-sdk';

/** One ZFS pool in a non-healthy state (status already lower-cased). */
export interface ZfsPoolCondition {
  name: string;
  /** 'degraded' | 'faulted' | 'offline' — anything that is not online/healthy. */
  status: string;
}

/** One actionable security finding (warning or critical only). */
export interface SecurityFinding {
  kind: string;
  name: string;
  status: 'warning' | 'critical';
  detail?: string;
}

// Per-host snapshot of the last-seen condition dedupe keys — used to diff across
// polls so each condition notifies ONCE (dedupeKey upsert keeps it live) and is
// resolved when it disappears. Keyed by management address, like ix-truenas's
// knownAlertsByHost. Two independent maps: a ZFS recovery must not touch the
// security set and vice versa.
const zfsKnownByHost = new Map<string, Set<string>>();
const securityKnownByHost = new Map<string, Set<string>>();

/** Stable dedupe key for a problematic pool (stable across degraded→offline). */
function zfsKey(pool: ZfsPoolCondition): string {
  return `zfs-pool:${pool.name}`;
}

/** Severity for a ZFS pool state. */
function zfsSeverity(status: string): 'warning' | 'critical' {
  const s = status.toLowerCase();
  if (s === 'offline' || s === 'faulted') return 'critical';
  return 'warning'; // degraded / maintenance / anything else non-online
}

/** Stable dedupe key for a security finding. */
function securityKey(f: SecurityFinding): string {
  return `security:${f.kind}:${f.name}`;
}

/**
 * Mirrors the given fresh conditions into the notification center and resolves
 * any that disappeared since this host's last snapshot. Pure with respect to the
 * appliance — all state lives in the module-level known-set maps. Never throws:
 * a notification must not break a poll (createNotifier is fire-and-forget).
 *
 * @param zfsPools      Fresh non-healthy pools, or `null` when no fresh ZFS data
 *                      this cycle (don't touch the ZFS known-set).
 * @param securityFindings  Fresh warning/critical findings, or `null` when none
 *                      were collected this cycle (don't touch the security set).
 */
export function mirrorOpnsenseConditions(
  notifier: PluginNotifier,
  host: string,
  deviceId: string | null,
  hostname: string | undefined,
  zfsPools: ZfsPoolCondition[] | null,
  securityFindings: SecurityFinding[] | null,
): void {
  const label = hostname && hostname.trim() !== '' ? hostname : host;

  // --- ZFS pool states ------------------------------------------------------
  if (zfsPools !== null) {
    const seen = new Set<string>();
    for (const p of zfsPools) {
      if (!p.name) continue;
      const key = zfsKey(p);
      seen.add(key);
      const sev = zfsSeverity(p.status);
      notifier.notify({
        severity: sev,
        title: `${label}: ZFS pool ${p.name} is ${p.status.toUpperCase()}`,
        message: `Pool "${p.name}" reports state ${p.status.toUpperCase()} — check disks / run a scrub.`,
        dedupeKey: key,
        deviceId,
        context: { source: 'zfs', pool: p.name, status: p.status },
      });
    }
    const prev = zfsKnownByHost.get(host) ?? new Set<string>();
    const gone = Array.from(prev).filter((k) => !seen.has(k));
    if (gone.length > 0) notifier.resolve(gone);
    zfsKnownByHost.set(host, seen);
  }

  // --- Security findings ----------------------------------------------------
  if (securityFindings !== null) {
    const seen = new Set<string>();
    for (const f of securityFindings) {
      if (!f.name || !f.kind) continue;
      const key = securityKey(f);
      seen.add(key);
      notifier.notify({
        severity: f.status,
        title: `${label}: ${securityTitle(f)}`,
        message: (f.detail ?? '').slice(0, 500),
        dedupeKey: key,
        deviceId,
        context: { source: 'security', kind: f.kind, name: f.name },
      });
    }
    const prev = securityKnownByHost.get(host) ?? new Set<string>();
    const gone = Array.from(prev).filter((k) => !seen.has(k));
    if (gone.length > 0) notifier.resolve(gone);
    securityKnownByHost.set(host, seen);
  }
}

/** Short human title for a security finding (the detail carries the specifics). */
function securityTitle(f: SecurityFinding): string {
  switch (f.kind) {
    case 'file-integrity':
      return `watched file changed — ${f.name}`;
    case 'auth-failures':
      return `unusual failed-login activity (${f.name})`;
    case 'account':
      return `unexpected privileged account — ${f.name}`;
    default:
      return `${f.kind} finding — ${f.name}`;
  }
}
