import { eq } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { getEffectiveValues } from '../systemSettings';
import { emitNotification, resolveNotificationsByDedupeKeys } from '../notifications';
import { queryNtp } from '@unm/plugin-sdk';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';

/**
 * Public NTP reference poller — the fleet's time-base check (Time page "Time
 * base" card).
 *
 * The telemetry worker only ever polls ASSIGNED devices; nothing in UNM checks
 * whether UNM's OWN clock is sane, even though every device that syncs to it
 * inherits its error. This worker closes that gap: on a configurable cadence
 * (default 5 min) it sends one lightweight SNTP request per configured public
 * reference (`ntpReferenceServers` setting — pool.ntp.org + time.google.com by
 * default) and stores the result in `ntp_reference_readings`. The drift of
 * each reference is `served instant − Date.now()` at read time (same semantics
 * as generic-ntp's ntp.driftMs), so a large |drift| means UNM's clock — and
 * therefore every device synced to it — is off relative to the international
 * consensus. The consensus itself (median of healthy rows) is computed at READ
 * time by GET /v1/ntp-references, never stored.
 *
 * One dead reference must never break the cycle: queryNtp() never throws and
 * each server's failure lands in its own row as status='unreachable'.
 */

const BEAT_MS = 30_000; // fixed timer beat — the effective interval comes from settings
const QUERY_TIMEOUT_MS = 5_000; // one SNTP round-trip to a public pool should be well under this

/** Consensus thresholds (|median drift|) for notifications. */
const WARN_DRIFT_MS = 500;
const CRIT_DRIFT_MS = 2_000;

export interface NtpReferenceTarget {
  host: string;
  port: number;
}

/**
 * Parses the `ntpReferenceServers` setting — a comma-separated list of
 * `host[:port]` entries (default port 123). Tolerant on purpose: blank items,
 * whitespace and malformed ports are skipped rather than failing the cycle.
 * Accepts bare IPv6 literals (`2001:db8::1`) and bracketed forms
 * (`[2001:db8::1]:124`).
 */
export function parseNtpReferenceList(raw: string): NtpReferenceTarget[] {
  const out: NtpReferenceTarget[] = [];
  for (const part of String(raw ?? '').split(',')) {
    const entry = part.trim();
    if (!entry) continue;

    let host = entry;
    let port = 123;
    // Bracketed IPv6 with explicit port: [addr]:port
    if (entry.startsWith('[')) {
      const close = entry.indexOf(']');
      if (close > 0 && entry[close + 1] === ':') {
        host = entry.slice(1, close);
        const p = Number(entry.slice(close + 2));
        if (Number.isInteger(p) && p >= 1 && p <= 65535) port = p;
      } else {
        host = entry.replace(/^\[|\]$/g, ''); // [addr] without port — keep default
      }
    } else {
      const idx = entry.lastIndexOf(':');
      if (idx > 0) {
        const maybePort = Number(entry.slice(idx + 1));
        const head = entry.slice(0, idx);
        // A bare IPv6 literal has several colons and no port — don't split it.
        const looksLikeIpv6 = head.includes(':');
        if (!looksLikeIpv6 && Number.isInteger(maybePort) && maybePort >= 1 && maybePort <= 65535) {
          host = head;
          port = maybePort;
        }
      }
    }

    host = host.trim();
    if (!host) continue;
    if (out.some((t) => t.host === host && t.port === port)) continue; // dedupe
    out.push({ host, port });
  }
  return out;
}

/** One stored reading as the worker writes it. */
interface ReferenceReading {
  server: string;
  status: 'ok' | 'unreachable' | 'unsynced';
  error: string;
  driftMs: number | null;
  stratum: number | null;
}

/**
 * Consensus verdict over the stored rows — median of the healthy (status='ok')
 * drifts. Exported pure so GET /v1/ntp-references and tests share one
 * definition. `sampleCount` = how many references contributed to the median.
 */
export function consensusDrift(rows: ReferenceReading[]): { value: number | null; sampleCount: number } {
  const drifts = rows
    .filter((r) => r.status === 'ok' && typeof r.driftMs === 'number')
    .map((r) => r.driftMs as number)
    .sort((a, b) => a - b);
  if (drifts.length === 0) return { value: null, sampleCount: 0 };
  const mid = Math.floor(drifts.length / 2);
  const median = drifts.length % 2 === 1 ? drifts[mid] : Math.round((drifts[mid - 1] + drifts[mid]) / 2);
  return { value: median, sampleCount: drifts.length };
}

/**
 * Maps one queryNtp() result onto a stored reading (status + drift).
 * `receivedAtMs` is the instant THIS reply arrived — drift must be measured
 * against it, NOT against Date.now() after Promise.all: a slow/unreachable
 * target would otherwise delay the whole mapping and bake its timeout into
 * every fast target's drift.
 */
function toReading(
  target: NtpReferenceTarget,
  r: Awaited<ReturnType<typeof queryNtp>>,
  receivedAtMs: number
): ReferenceReading {
  const base = { server: target.host, stratum: typeof r.stratum === 'number' ? r.stratum : null };
  if (!r.ok) return { ...base, status: 'unreachable', error: (r.error ?? 'no reply').slice(0, 300), driftMs: null };
  // Stratum 0/15 = unsynchronized (kiss-o'-death), leap indicator 3 = alarm.
  const unsynced = r.stratum === 0 || r.stratum === 15 || r.leapIndicator === 3;
  if (unsynced) {
    return { ...base, status: 'unsynced', error: `stratum ${r.stratum ?? '?'}`, driftMs: null };
  }
  const driftMs = typeof r.timeEpochMs === 'number' ? Math.round(r.timeEpochMs - receivedAtMs) : null;
  return { ...base, status: 'ok', error: '', driftMs };
}

/** Upsert one row per reference (PK = server). */
async function persistReadings(
  targets: NtpReferenceTarget[],
  results: Awaited<ReturnType<typeof queryNtp>>[],
  readings: ReferenceReading[]
): Promise<void> {
  const now = new Date().toISOString();
  for (let i = 0; i < targets.length; i++) {
    const t = targets[i];
    const r = results[i];
    const rd = readings[i];
    await db.insert(schema.ntpReferenceReadings)
      .values({
        server: t.host,
        port: t.port,
        status: rd.status,
        error: rd.error,
        rttMs: typeof r.rttMs === 'number' ? Math.round(r.rttMs) : null,
        driftMs: rd.driftMs,
        stratum: rd.stratum,
        precision: typeof r.precision === 'number' ? r.precision : null,
        rootDelaySeconds: typeof r.rootDelaySeconds === 'number' ? r.rootDelaySeconds : null,
        rootDispersionSeconds: typeof r.rootDispersionSeconds === 'number' ? r.rootDispersionSeconds : null,
        referenceId: (r.referenceId ?? '').slice(0, 64),
        timeUtc: (r.timeIsoUtc ?? '').slice(0, 64),
        collectedAt: now,
      })
      .onConflictDoUpdate({
        target: schema.ntpReferenceReadings.server,
        set: {
          port: t.port,
          status: rd.status,
          error: rd.error,
          rttMs: typeof r.rttMs === 'number' ? Math.round(r.rttMs) : null,
          driftMs: rd.driftMs,
          stratum: rd.stratum,
          precision: typeof r.precision === 'number' ? r.precision : null,
          rootDelaySeconds: typeof r.rootDelaySeconds === 'number' ? r.rootDelaySeconds : null,
          rootDispersionSeconds: typeof r.rootDispersionSeconds === 'number' ? r.rootDispersionSeconds : null,
          referenceId: (r.referenceId ?? '').slice(0, 64),
          timeUtc: (r.timeIsoUtc ?? '').slice(0, 64),
          collectedAt: now,
        },
      });
  }
}

/** Drop rows for servers no longer in the configured list. */
async function pruneRemovedServers(keepHosts: string[]): Promise<void> {
  const all = await db.query.ntpReferenceReadings.findMany();
  for (const row of all) {
    if (!keepHosts.includes(row.server)) {
      await db.delete(schema.ntpReferenceReadings).where(eq(schema.ntpReferenceReadings.server, row.server));
    }
  }
}

/**
 * Emits/refreshes the consensus notification for this cycle and resolves it
 * when healthy. dedupeKey `ntp-consensus:<bucket>` keeps one live row per
 * condition class; emitNotification never downgrades severity of a live row,
 * so we resolve+re-emit on improvement instead.
 */
async function notifyConsensus(
  consensus: { value: number | null; sampleCount: number },
  allUnreachable: boolean
): Promise<void> {
  const abs = consensus.value === null ? Infinity : Math.abs(consensus.value);
  let bucket: 'ok' | 'warn' | 'crit';
  if (allUnreachable || abs > CRIT_DRIFT_MS) bucket = 'crit';
  else if (abs > WARN_DRIFT_MS) bucket = 'warn';
  else bucket = 'ok';

  if (bucket === 'ok') {
    // Healthy — clear any live consensus condition.
    await resolveNotificationsByDedupeKeys(['ntp-consensus:warn', 'ntp-consensus:crit']);
    return;
  }

  // A live row in a WORSE bucket must not mask the improved condition.
  if (bucket === 'warn') await resolveNotificationsByDedupeKeys(['ntp-consensus:crit']);

  const driftText =
    consensus.value === null ? 'no healthy reference' : `${consensus.value > 0 ? '+' : ''}${consensus.value} ms`;
  await emitNotification({
    severity: bucket === 'crit' ? 'critical' : 'warning',
    source: 'system',
    title: allUnreachable
      ? 'All NTP references unreachable'
      : `UNM clock drift vs international consensus: ${driftText}`,
    message: allUnreachable
      ? 'Every configured public NTP reference failed to answer — UNM cannot verify its own time base. Check outbound UDP/123 or the ntpReferenceServers setting.'
      : `Median drift across ${consensus.sampleCount} healthy reference(s) is ${driftText}. Devices that sync their clock from UNM inherit this offset.`,
    dedupeKey: `ntp-consensus:${bucket}`,
  });
}

async function pollCycle(): Promise<void> {
  const values = await getEffectiveValues();
  const targets = parseNtpReferenceList(String(values.ntpReferenceServers ?? ''));
  if (targets.length === 0) return; // nothing configured — no rows, no noise

  // One query per reference, in parallel. queryNtp never throws. Each reading
  // is computed the moment ITS OWN reply settles (Date.now() right after this
  // target's await — NOT after Promise.all), so a target that times out after
  // 5 s cannot skew the drift of targets that answered in milliseconds.
  const settled = await Promise.all(
    targets.map(async (t) => {
      const r = await queryNtp(t.host, t.port, QUERY_TIMEOUT_MS);
      return { result: r, reading: toReading(t, r, Date.now()) };
    })
  );
  const results = settled.map((s) => s.result);
  const readings = settled.map((s) => s.reading);

  await persistReadings(targets, results, readings);
  await pruneRemovedServers(targets.map((t) => t.host));

  const consensus = consensusDrift(readings);
  const allUnreachable = readings.every((r) => r.status === 'unreachable');
  await notifyConsensus(consensus, allUnreachable);
}

/**
 * Starts the reference-polling loop. Must be called only after the API has
 * bound its port (same rule as every other worker — see index.ts app.listen).
 */
export function startNtpReferencesWorker(): () => void {
  initWorker('ntpReferences', LEADER_KEYS.ntpReferences);
  // eslint-disable-next-line no-console
  console.log('[ntp-references] worker started');

  let lastCycleAt = 0;
  const beat = async (): Promise<void> => {
    const values = await getEffectiveValues();
    const intervalMs = Number(values.ntpReferencePollIntervalMs) || 300_000;
    if (Date.now() - lastCycleAt < intervalMs) return; // not due yet — settings may have been raised mid-flight
    lastCycleAt = Date.now();
    await pollCycle();
  };

  void trackBeat('ntpReferences', beat).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[ntp-references] initial cycle failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('ntpReferences', beat).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[ntp-references] poll cycle failed:', err);
    });
  }, BEAT_MS);

  return () => clearInterval(timer);
}
