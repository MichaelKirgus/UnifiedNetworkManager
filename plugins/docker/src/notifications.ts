/**
 * Docker plugin — notification-center mirroring (SDK createNotifier).
 *
 * Mirrors NON-RUNNING containers from the Docker Engine into the UNM
 * notification center, exactly like ix-truenas mirrors TrueNAS `alert.list`.
 * A container that has exited / died / is paused or stuck in "created" is a
 * real condition an operator wants to see; one that is running is not. The API
 * already mirrors device-level offline/degraded automatically — this covers the
 * per-container granularity only the plugin can see.
 *
 * Semantics mirror ix-truenas / zabbix:
 *   - Each non-running container carries a STABLE dedupe key so re-polls UPSERT
 *     the live row (occurrences++ / lastSeenAt refresh) instead of flooding the
 *     center. The key is `container:<name>` — the docker name, which survives a
 *     restart (same name, new id) and is unique per daemon.
 *   - A container that returns to RUNNING, or vanishes from a FRESH COMPLETE
 *     snapshot, is RESOLVED so its bell entry clears automatically.
 *
 * Severity mapping (docker state → UNM): dead = critical; exited / paused =
 * warning; created = info (usually transient mid-start). The `restarting` state
 * is deliberately NOT mirrored — it is a self-healing transition that resolves
 * within seconds, and mirroring it would flap the bell on every deploy.
 *
 * ANTI-FLAP CONTRACT: callers pass `null` when they do NOT have fresh
 * authoritative data this cycle (a metrics-only poll skipped container listing,
 * or the /containers/json read failed). A `null` snapshot leaves the known-set
 * UNTOUCHED — we neither notify new conditions nor resolve existing ones. Only
 * a full inventory poll with a successful container list is an authoritative
 * snapshot that may add AND clear entries.
 */

import type { PluginNotifier } from '@unm/plugin-sdk';

/** One non-running container worth mirroring (running containers are omitted). */
export interface ContainerCondition {
  /** Docker container name — stable across restarts, unique per daemon. */
  name: string;
  /** Docker-native lowercase state ('exited', 'dead', 'paused', 'created'). */
  state: string;
  /** Exit code for exited containers (null when unknown / not applicable). */
  exitCode?: number | null;
}

// Per-host snapshot of the last-seen non-running container dedupe keys — used to
// diff across polls so each condition notifies ONCE (dedupeKey upsert keeps it
// live) and is resolved when the container recovers or disappears. Keyed by
// management address, like ix-truenas's knownAlertsByHost / zabbix's problemsKnownByHost.
const conditionsKnownByHost = new Map<string, Set<string>>();

/** Stable dedupe key for one non-running container — docker name (restart-stable). */
function conditionKey(name: string): string {
  return `container:${name}`;
}

/** UNM severity for a docker state. */
function severityOf(state: string): 'info' | 'warning' | 'critical' {
  if (state === 'dead') return 'critical';
  if (state === 'exited' || state === 'paused') return 'warning';
  return 'info'; // created — usually transient mid-start
}

/**
 * Mirrors the given fresh non-running-container snapshot into the notification
 * center and resolves any that recovered or disappeared since this host's last
 * snapshot. Pure with respect to Docker — all state lives in the module-level
 * known-set map. Never throws: a notification must not break a poll (the SDK
 * notifier is fire-and-forget).
 *
 * @param conditions  Fresh non-running containers, or `null` when there was no
 *                    fresh authoritative read this cycle — then the known-set is
 *                    left untouched (no new entries, no resolves).
 */
export function mirrorDockerContainers(
  notifier: PluginNotifier,
  host: string,
  deviceId: string | null,
  conditions: ContainerCondition[] | null,
): void {
  if (conditions === null) return;

  const seen = new Set<string>();
  for (const c of conditions) {
    if (!c.name || !c.state) continue;
    // Only terminal / stuck non-running states are worth a bell entry. 'running'
    // and the self-healing 'restarting' transition are intentionally skipped so
    // deploys don't flap the notification center.
    if (c.state === 'running' || c.state === 'restarting') continue;

    const key = conditionKey(c.name);
    seen.add(key);
    const exitNote =
      c.state === 'exited' && typeof c.exitCode === 'number' ? ` (exit code ${c.exitCode})` : '';
    notifier.notify({
      severity: severityOf(c.state),
      title: `${host}: container "${c.name}" is ${c.state}`.slice(0, 300),
      message: `Docker container "${c.name}" reported state "${c.state}".${exitNote}`,
      dedupeKey: key,
      deviceId,
      context: { source: 'docker', name: c.name, state: c.state, exitCode: c.exitCode ?? null },
    });
  }

  const prev = conditionsKnownByHost.get(host) ?? new Set<string>();

  // Complete authoritative snapshot — resolve every condition that recovered to
  // running or vanished since the last full poll.
  const gone = Array.from(prev).filter((k) => !seen.has(k));
  if (gone.length > 0) notifier.resolve(gone);
  conditionsKnownByHost.set(host, seen);
}
