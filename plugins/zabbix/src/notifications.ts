/**
 * Zabbix plugin — notification-center mirroring (SDK createNotifier).
 *
 * Mirrors ACTIVE PROBLEMS from the Zabbix server into the UNM notification
 * center, exactly like ix-truenas mirrors TrueNAS `alert.list`. Problems are
 * the one condition class a Zabbix frontend exposes that is NOT derivable by
 * the API from the scalar telemetry health value (health only says "the API
 * answered", not what it reports).
 *
 * Semantics mirror ix-truenas / opnsense:
 *   - Each problem carries a STABLE dedupe key so re-polls UPSERT the live row
 *     (occurrences++ / lastSeenAt refresh) instead of flooding the center. The
 *     key is the opening event id (`event:<eventid>`) — stable for the whole
 *     lifetime of the problem; on servers that don't return it we fall back to
 *     `problem:<object>:<name>`.
 *   - Problems that vanish from a FRESH, COMPLETE snapshot are RESOLVED, so an
 *     acknowledged/recovered problem clears its bell entry automatically.
 *
 * Severity mapping (Zabbix 0..5 → UNM): High(4)/Disaster(5) = critical,
 * Warning(2)/Average(3) = warning, Not-classified(0)/Information(1) = info —
 * but only when the caller's `minSeverity` threshold admits them. The default
 * threshold is 2 (Warning): properly classified deployments never get noise,
 * while deployments that leave triggers at "Not classified" can lower it to 0
 * via the plugin option and still see every active problem as an info entry.
 *
 * ANTI-FLAP CONTRACT: callers pass `null` when they do NOT have fresh
 * authoritative data this cycle (the problem read failed, or the API was
 * unreachable). A `null` snapshot leaves the known-set UNTOUCHED — we neither
 * notify new problems nor resolve existing ones. When the snapshot is TRUNCATED
 * (more active problems than the poll's cap), visible problems are still
 * notified but NOTHING is resolved — a problem beyond the cap must not be
 * mistaken for one that disappeared.
 */

import type { PluginNotifier } from '@unm/plugin-sdk';

/** One active Zabbix problem as returned by `problem.get`. */
export interface ZabbixProblem {
  /** Opening event id — stable while the problem persists (null on old servers). */
  eventid: string | null;
  /** Problem object type code: '0' host, '1' item, '2' trigger, … */
  object: string;
  /** Human-readable problem text (e.g. "CPU load is too high on gwbn01"). */
  name: string;
  /** Zabbix severity code 0..5. */
  severity: number;
}

// Per-host snapshot of the last-seen problem dedupe keys — used to diff across
// polls so each problem notifies ONCE (dedupeKey upsert keeps it live) and is
// resolved when it disappears. Keyed by management address, like ix-truenas's
// knownAlertsByHost.
const problemsKnownByHost = new Map<string, Set<string>>();

/** Stable dedupe key for one problem — event id preferred (stable per lifetime). */
function problemKey(p: ZabbixProblem): string {
  return p.eventid ? `event:${p.eventid}` : `problem:${p.object}:${p.name}`;
}

/** UNM severity for a Zabbix severity code. */
function severityOf(code: number): 'info' | 'warning' | 'critical' {
  if (code >= 4) return 'critical'; // High, Disaster
  if (code >= 2) return 'warning'; // Warning, Average
  return 'info'; // Not classified / Information — only notified when minSeverity admits them
}

const SEVERITY_LABELS: Record<number, string> = {
  0: 'Not classified',
  1: 'Information',
  2: 'Warning',
  3: 'Average',
  4: 'High',
  5: 'Disaster',
};

const OBJECT_TYPES: Record<string, string> = {
  '0': 'host',
  '1': 'item',
  '2': 'trigger',
  '3': 'discovery rule',
  '4': 'service',
};

/**
 * Mirrors the given fresh problem snapshot into the notification center and
 * resolves any that disappeared since this host's last snapshot. Pure with
 * respect to Zabbix — all state lives in the module-level known-set map. Never
 * throws: a notification must not break a poll (createNotifier is fire-and-forget).
 *
 * @param problems  Fresh active problems, or `null` when there was no fresh
 *                  authoritative read this cycle — then the known-set is left
 *                  untouched. Problems below `minSeverity` are skipped (they stay
 *                  in the `zabbix.problems` metric table only).
 * @param truncated True when more active problems exist than were returned by the
 *                  poll's cap — visible ones are still notified, but nothing is
 *                  resolved (a problem beyond the cap ≠ a disappeared one).
 * @param minSeverity Lowest Zabbix severity code to mirror (0..5, default 2 = Warning).
 */
export function mirrorZabbixProblems(
  notifier: PluginNotifier,
  host: string,
  deviceId: string | null,
  problems: ZabbixProblem[] | null,
  truncated = false,
  minSeverity = 2,
): void {
  if (problems === null) return;

  const seen = new Set<string>();
  for (const p of problems) {
    if (!p.name) continue;
    if (p.severity < minSeverity) continue; // below threshold — metric table only
    const sev = severityOf(p.severity);
    const key = problemKey(p);
    seen.add(key);
    notifier.notify({
      severity: sev,
      title: `${host}: ${p.name}`.slice(0, 300),
      message: `Zabbix severity "${SEVERITY_LABELS[p.severity] ?? p.severity}"${OBJECT_TYPES[p.object] ? ` (${OBJECT_TYPES[p.object]})` : ''}.`,
      dedupeKey: key,
      deviceId,
      context: { source: 'zabbix', object: p.object, eventid: p.eventid, severity: p.severity },
    });
  }

  const prev = problemsKnownByHost.get(host) ?? new Set<string>();

  if (truncated) {
    // A truncated snapshot cannot distinguish "disappeared" from "beyond the cap":
    // resolve NOTHING, and keep every previously-known key alive so those rows
    // stay open until a complete snapshot can settle them.
    for (const k of seen) prev.add(k);
    problemsKnownByHost.set(host, prev);
    return;
  }

  // Complete snapshot — resolve everything that vanished since the last poll.
  const gone = Array.from(prev).filter((k) => !seen.has(k));
  if (gone.length > 0) notifier.resolve(gone);
  problemsKnownByHost.set(host, seen);
}
