import { pluginAxios } from '../utils/pluginHttp';
import { v4 as uuidv4 } from 'uuid';
import { db } from '../db';
import { and, eq, inArray, lt, notInArray, or, sql } from 'drizzle-orm';
import * as schema from '../db/schema';
import { getSecret } from '../secretsProvider';
import { getEffectiveSettings, settingsHeaders } from '../pluginSettings';
import { parseExtraCredentials } from '../types/credentialSlots';
import type { DeviceAddressView } from '../types/deviceAddressView';
import { decryptCredentialSlots, withSlots } from '../utils/slotCredentials';
import { getEffectiveSettingValue, getSystemSettings, type SystemSettings } from '../systemSettings';
import { parseDeviceTimeToEpochMs, type Health } from '@unm/plugin-sdk';
import {
  deviceStatusDedupeKey,
  emitNotification,
  statusToSeverity,
} from '../notifications';
import { LEADER_KEYS } from './leader';
import { onDeviceStatusTransition, onUpdateTransitions } from './automations';
import { diffUpdateTransitions } from '../automations/engine';
import type { DeviceStatus } from '../automations/types';
import {
  initWorker,
  recordSkippedTelemetryBeat,
  recordTelemetryCycle,
  recordTelemetryPoll,
  telemetryStats,
  trackBeat,
} from './stats';

// --- Window-based staggered scheduling --------------------------------------
// Instead of polling every device on a fixed beat (a synchronized burst that
// spikes API + plugin CPU, then sleeps), each assignment carries its own
// next-due deadline inside a configurable WINDOW:
//   - metrics window  (system setting telemetryPollIntervalMs, default 30 s):
//     how often /monitoring is called at all;
//   - inventory window (telemetryInventoryWindowMs, default 15 min): how often
//     the slow/static collection runs — polls in between send
//     collectInventory:false and plugins skip it.
// Deadlines are spread across each window by a stable per-target hash + jitter
// so fleet load stays flat instead of bursty; a global in-flight budget
// (telemetryMaxConcurrency) caps parallelism during catch-up bursts. Env vars
// only seed the defaults — system_settings (Workers page) wins at runtime.

const DISPATCH_TICK_MS = 1_000; // dispatcher resolution (due-list scan cadence)
const ROSTER_REFRESH_MS = 30_000; // re-read devices/assignments + windows this often
// Inventory rows not refreshed within the cutoff are swept away (offline
// devices must not accumulate stale networks/hosts in the cross-device views).
// The effective cutoff is max(this, 3 × inventory window) — see sweepStaleInventory.
const INVENTORY_STALE_AFTER_MS = 24 * 60 * 60 * 1000;
const INVENTORY_SWEEP_INTERVAL_MS = 10 * 60 * 1000;

/** Metric keys that carry cross-device inventory (ingested into their own tables). */
const INVENTORY_METRIC_KEYS = [
  'networks', 'arp', 'ndp', 'hosts', 'dhcpLeases', 'wlanClients', 'macTable', 'dockerHosts', 'vmHosts',
  'tunnels', 'routes', 'dnsEntries', 'dhcpNetworks', 'dhcpReservations', 'firewallRules', 'certificates', 'services',
  'wifiNetworks', 'wifiAirtime', 'wifiRadios', 'wifiNeighbors',
  'ports', 'filesystems', 'disks', 'containers', 'images', 'vms', 'gpus', 'updates',
  'mailDomains', 'mailMailboxes', 'mailAliases',
] as const;

/** True when a snapshot carries at least one inventory array (any length). */
function hasInventoryKeys(metrics: Record<string, unknown>): boolean {
  for (const key of INVENTORY_METRIC_KEYS) {
    if (Array.isArray(metrics[key])) return true;
  }
  return false;
}

/** FNV-1a — stable across restarts/processes, used to spread deadlines. */
function stableHash(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function toIntOrNull(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.round(v);
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v);
    if (Number.isFinite(n)) return Math.round(n);
  }
  return null;
}

function clampInt(v: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.round(v)));
}

/** One plugin-reported reason for a non-ok health (SDK `HealthReason`). */
interface PluginHealthReason {
  severity: 'warning' | 'critical';
  message: string;
}

interface MonitoringResponse {
  /** Plugin monitoring health — the SDK's canonical vocabulary (ok/warning/critical/unknown). */
  health?: Health;
  /** Optional human-readable reasons for a non-ok health (newer plugins only). */
  healthReasons?: unknown;
  metrics?: Record<string, unknown>;
  metricDescriptors?: unknown[];
}

/** Normalizes the plugin's `healthReasons` field — tolerant of anything. */
function parseHealthReasons(raw: unknown): PluginHealthReason[] {
  if (!Array.isArray(raw)) return [];
  const out: PluginHealthReason[] = [];
  for (const r of raw) {
    if (!r || typeof r !== 'object') continue;
    const o = r as Record<string, unknown>;
    const severity = o['severity'] === 'critical' ? 'critical' : o['severity'] === 'warning' ? 'warning' : null;
    const message = typeof o['message'] === 'string' ? o['message'].trim() : '';
    if (!severity || !message) continue;
    out.push({ severity, message: message.slice(0, 300) });
    if (out.length >= 10) break; // tooltip budget — keep it short by contract
  }
  return out;
}

// DeviceAddressView comes from types/deviceAddressView (shared).

/** One plugin's view of a device (assignment + its plugin row). */
interface AssignmentTarget {
  deviceId: string;
  managementAddress: string;
  /** All device addresses, primary first. Lets plugins reach secondary IPs. */
  ipAddresses: DeviceAddressView[];
  pluginId: string;
  secretId: string | null;
  /** Bound extra credential slots (slot name → secrets.id). */
  extraCredentials: Record<string, string>;
  endpoint: string;
  // User-selected hardware model / firmware version (from a plugin's advertised
  // catalog). Forwarded to /monitoring so vendor plugins can adapt their data
  // gathering to the specific device. Null when unset.
  model: string | null;
  firmwareVersion: string | null;
  /** Per-device metrics-window override in ms (devices.pollIntervalMs); null = inherit. */
  pollIntervalMs: number | null;
}

/** One assignment's poll outcome. `reachable` = the plugin answered at all
 * (transport OK); a transport failure yields health 'unknown' + reachable false.
 * `inventoryEmitted` tells the dispatcher whether this snapshot carried any
 * inventory arrays — used to decide if the inventory deadline may advance.
 * `error` carries the transport/credential error message for diagnostics
 * (forced refresh reports it back to the caller; the scheduler ignores it).
 * `healthReasons` are plugin-reported human-readable reasons for a non-ok
 * health — persisted on the telemetry snapshot and rolled up into the
 * device's status tooltip.
 */
interface PollOutcome {
  /** The plugin's reported monitoring health (SDK Health vocabulary). */
  health: Health;
  reachable: boolean;
  inventoryEmitted: boolean;
  /** Transport-level failure reason (set when `reachable` is false). */
  error?: string;
  /** Plugin-reported reasons for a non-ok health (empty when healthy/absent). */
  healthReasons: PluginHealthReason[];
}

interface PollOptions {
  /**
   * Whether this poll is an INVENTORY-due one. When false the plugin skips its
   * slow/static collection and omits inventory keys from `metrics` (absent key
   * = no wipe, per the ingestion contract). Old plugin images ignore the flag
   * and always answer with a full snapshot — harmless.
   */
  collectInventory: boolean;
  /**
   * Ask the plugin to trigger an immediate device-side update search (OPNsense:
   * POST /api/core/firmware/status, ~30–90 s). Set by forced refreshes ("Check
   * now" on the Updates page) so a stale appliance cache can't keep hiding
   * updates. Old plugin images ignore the field — harmless.
   */
  forceUpdateCheck?: boolean;
}

async function pollAssignment(target: AssignmentTarget, opts: PollOptions): Promise<PollOutcome> {
  try {
    // The secrets provider plugin owns the crypto; the broker fetches the
    // decrypted secret on our behalf. Secrets are typed: `fields` holds the
    // decrypted values. For backward compatibility we also pass the legacy
    // `apiKey`/`apiSecret` keys when the secret is of type `apiKey`.
    const decrypted = target.secretId ? await getSecret(target.secretId) : null;
    const credentials = withSlots(
      decrypted?.fields ?? {},
      await decryptCredentialSlots(target.extraCredentials)
    );

    // Per-device settings overrides are resolved for THIS assignment scope.
    const headers = await settingsHeaders(target.pluginId, target.deviceId).catch(() => ({}));

    // mTLS (Stage 1): pluginAxios picks https+client-cert when this plugin is
    // TLS-live, plain http otherwise — identical behavior for un-enrolled plugins.
    const response = await pluginAxios(target.endpoint).post<MonitoringResponse>(
      '/monitoring',
      {
        deviceId: target.deviceId,
        managementAddress: target.managementAddress,
        ipAddresses: target.ipAddresses,
        // Hardware model / firmware version selected by the user (may be null).
        model: target.model,
        firmwareVersion: target.firmwareVersion,
        credentials,
        // Window-based scheduling hint (see header comment): true only on
        // inventory-due polls so plugins can skip slow collection in between.
        collectInventory: opts.collectInventory,
        ...(opts.forceUpdateCheck ? { forceUpdateCheck: true } : {}),
        ...(decrypted?.type === 'apiKey'
          ? { apiKey: credentials.apiKey, apiSecret: credentials.apiSecret }
          : {})
      },
      // 30 s — slow inventory RPCs (e.g. TrueNAS pool.dataset.query on a
      // degraded appliance) can take well over the old 10 s; a timeout here
      // would drop the ENTIRE snapshot (pools, disks, apps, VMs), not just the
      // one slow section (plugins settle their calls internally).
      { timeout: 30_000, headers }
    );

    const health = response.data?.health ?? 'unknown';
    // Reasons only make sense for a non-ok poll — drop them when healthy so
    // the column stays NULL in the common case.
    const healthReasons = parseHealthReasons(response.data?.healthReasons);
    const metrics = response.data?.metrics ?? {};
    const metricDescriptors = response.data?.metricDescriptors;
    const collectedAt = new Date().toISOString();

    await db.insert(schema.telemetry).values({
      id: uuidv4(),
      deviceId: target.deviceId,
      pluginId: target.pluginId,
      collectedAt,
      health,
      healthReasons: health !== 'ok' && healthReasons.length > 0 ? JSON.stringify(healthReasons) : null,
      metrics: JSON.stringify(metrics),
      metricDescriptors: metricDescriptors ? JSON.stringify(metricDescriptors) : null,
    });

    // Normalize the device clock (Time page) into the dedicated `device_times`
    // table — runs on EVERY poll (not inventory-gated) so drift stays fresh.
    // Best-effort; a parse failure must never break the telemetry cycle.
    ingestDeviceTime(target.deviceId, target.pluginId, metrics, collectedAt);

    // Device updates (Updates page) — also per-poll: plugins that emit `updates`
    // do so on every beat (OPNsense reads its cached check result each poll),
    // and a forced refresh ("Check now") must surface fresh rows IMMEDIATELY
    // instead of waiting up to the next 15-min inventory window. Absent key =
    // no-op, present-but-empty = authoritative wipe — same contract as before.
    ingestUpdates(target.deviceId, target.pluginId, metrics, collectedAt).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[telemetry] updates ingestion failed:', err);
    });

    // Installed packages (CVE tracking) — also per-poll: a package upgrade must
    // refresh the row's version + collectedAt so the cve worker's input-change
    // gate re-matches within one beat. Absent key = no-op, present-but-empty =
    // authoritative wipe — same contract as containers/updates.
    ingestInstalledPackages(target.deviceId, target.pluginId, metrics, collectedAt).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[telemetry] installed-packages ingestion failed:', err);
    });

    // Normalize the inventory parts of this snapshot into the cross-device
    // tables (Networks + Hosts pages) — ONLY on inventory-due polls. Metrics-
    // only polls carry no inventory keys, so ingesting them would be a no-op;
    // skipping saves the DB round-trips entirely. Best-effort — a parse failure
    // must never break the telemetry cycle.
    if (opts.collectInventory) {
      ingestInventory(target.deviceId, target.pluginId, metrics, collectedAt);
    }

    return { health, reachable: true, inventoryEmitted: hasInventoryKeys(metrics), healthReasons };
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(
      `[telemetry] failed to poll device ${target.deviceId} via plugin ${target.pluginId}:`,
      (err as Error).message
    );
    return { health: 'unknown', reachable: false, inventoryEmitted: false, error: (err as Error).message, healthReasons: [] };
  }
}

/**
 * Normalizes the device clock from one monitoring snapshot into the dedicated
 * `device_times` table (Time page). Two independent blobs may be present:
 *   - `system.deviceTime` — the device's OWN system wall clock (OPNsense,
 *     TrueNAS, RouterOS, …) → localIso/timezone/utcOffsetMinutes/epochMs.
 *   - `system.ntpServed`  — the instant the device SERVES over its NTP/SNTP
 *     service (generic-ntp plugin) → ntpTimeUtc/ntpEpochMs/ntpStratum/…
 * The row is keyed by (deviceId, pluginId), so each plugin writes its own row:
 * a box watched by BOTH an OS-capable and the NTP plugin gets one row per
 * source, and the /device-time route merges the newest of each kind. Only
 * plugins that CAN read one of these emit the key — ICMP/SNMP-only assignments
 * touch nothing. Drift is computed at READ time against `collectedAt`, not here.
 * Best-effort: a malformed blob must not break the telemetry cycle.
 */
async function ingestDeviceTime(
  deviceId: string,
  pluginId: string,
  metrics: Record<string, unknown>,
  collectedAt: string
): Promise<void> {
  try {
    const dt = metrics['system.deviceTime'];
    const ntp = metrics['system.ntpServed'];
    const hasClock = !!dt && typeof dt === 'object';
    const hasNtp = !!ntp && typeof ntp === 'object';
    if (!hasClock && !hasNtp) return; // no clock keys → nothing to store

    // --- System wall-clock fields (absent blob → nulls, never clobbered by NTP).
    let localIso: string | null = null;
    let timezone: string | null = null;
    let utcOffsetMinutes: number | null = null;
    let epochMs: number | null = null;
    if (hasClock) {
      const r = dt as Record<string, unknown>;
      localIso = typeof r['localIso'] === 'string' && (r['localIso'] as string).trim() !== '' ? (r['localIso'] as string) : null;
      timezone = typeof r['timezone'] === 'string' && (r['timezone'] as string).trim() !== '' ? (r['timezone'] as string) : null;
      utcOffsetMinutes = typeof r['utcOffsetMinutes'] === 'number' && Number.isFinite(r['utcOffsetMinutes']) ? Math.round(r['utcOffsetMinutes'] as number) : null;
      // Resolve the absolute instant ONCE at ingest (the reading is immutable):
      // prefer the plugin's pre-computed epochMs, else derive it from localIso +
      // zone/offset via the SDK helper. Null = unresolvable → the page shows the
      // local time with drift "not computable" instead of a fake value.
      const precomputed = typeof r['epochMs'] === 'number' && Number.isFinite(r['epochMs']) ? Math.round(r['epochMs'] as number) : null;
      // Derive from localIso + zone/offset only when a wall clock is present —
      // an NTP-only blob has no localIso and must not be force-parsed.
      epochMs = precomputed ?? (localIso !== null ? parseDeviceTimeToEpochMs({ localIso, timezone, utcOffsetMinutes }) : null);
    }

    // --- NTP-served fields (the time the device transmits to its clients).
    let ntpTimeUtc: string | null = null;
    let ntpEpochMs: number | null = null;
    let ntpStratum: number | null = null;
    let ntpReferenceId: string | null = null;
    if (hasNtp) {
      const r = ntp as Record<string, unknown>;
      ntpTimeUtc = typeof r['timeUtc'] === 'string' && (r['timeUtc'] as string).trim() !== '' ? (r['timeUtc'] as string) : null;
      // Prefer the plugin's pre-computed epoch; fall back to parsing timeUtc.
      const precomputedNtp = typeof r['epochMs'] === 'number' && Number.isFinite(r['epochMs']) ? Math.round(r['epochMs'] as number) : null;
      ntpEpochMs = precomputedNtp ?? (ntpTimeUtc !== null && !Number.isNaN(Date.parse(ntpTimeUtc)) ? Date.parse(ntpTimeUtc) : null);
      if (!hasClock && ntpEpochMs === null && ntpTimeUtc === null) return; // useless blob
      ntpStratum = typeof r['stratum'] === 'number' && Number.isFinite(r['stratum']) ? Math.round(r['stratum'] as number) : null;
      ntpReferenceId = typeof r['referenceId'] === 'string' && (r['referenceId'] as string).trim() !== '' ? (r['referenceId'] as string) : null;
    }

    await db.insert(schema.deviceTimes).values({
      deviceId,
      pluginId,
      localIso,
      timezone,
      utcOffsetMinutes,
      epochMs,
      collectedAt,
      ntpTimeUtc,
      ntpEpochMs,
      ntpStratum,
      ntpReferenceId,
    }).onConflictDoUpdate({
      target: [schema.deviceTimes.deviceId, schema.deviceTimes.pluginId],
      set: {
        localIso: sql`excluded."localIso"`,
        timezone: sql`excluded."timezone"`,
        utcOffsetMinutes: sql`excluded."utcOffsetMinutes"`,
        epochMs: sql`excluded."epochMs"`,
        collectedAt: sql`excluded."collectedAt"`,
        ntpTimeUtc: sql`excluded."ntpTimeUtc"`,
        ntpEpochMs: sql`excluded."ntpEpochMs"`,
        ntpStratum: sql`excluded."ntpStratum"`,
        ntpReferenceId: sql`excluded."ntpReferenceId"`,
      },
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`[telemetry] failed to ingest device time for ${deviceId} via ${pluginId}:`, (err as Error).message);
  }
}

/**
 * Normalizes the inventory parts of one monitoring snapshot into the
 * cross-device `networks` and `hosts` tables (Networks + Hosts pages). The
 * metric keys are generic — any plugin may emit them:
 *   - networks[]    { name, ip?, prefix?, version?, vlanId?, mac?, status? }
 *   - arp[] / ndp[] { mac, ip, intf?, manufacturer? }
 *   - dhcpLeases[]  { mac, ip, hostname?, expiry?, intf? }
 *   - wlanClients[] { mac, ip, hostname?, intf? } — associated WLAN clients
 *   - macTable[]    { mac, intf? } — switch MAC tables (e.g. SwOS !dhost.b):
 *                     learned MAC + port only, no IP → stored with source 'mac'
 * Rows are upserted on their natural key; a host seen again simply refreshes
 * lastSeenAt. Unknown/missing fields are tolerated — plugins evolve
 * independently of the API. Never throws: an inventory parse failure must not
 * break the telemetry cycle.
 */
/**
 * Ingests the `updates` metric into device_updates (Updates page). Runs on
 * EVERY poll — not inventory-gated — because plugins that emit it do so on
 * every beat and a forced refresh must surface fresh rows immediately.
 *
 * Generic key — any plugin advertising capability 'updates' may emit it:
 *   updates[] { name, kind, currentVersion?, latestVersion?, available,
 *               rebootRequired?, sizeBytes?, applyActionId?, applyInput?, extra? }
 * Same CONFIG-object lifecycle as containers: upsert-per-poll + delete-on-
 * absent (an applied update must vanish on the next poll), present-but-nothing
 * available = authoritative wipe. Only rows with available=true persist — a
 * plugin that reports "checked, nothing new" emits an empty array and its
 * stale rows are wiped.
 */
async function ingestUpdates(
  deviceId: string,
  pluginId: string,
  metrics: Record<string, unknown>,
  collectedAt: string
): Promise<void> {
  const rawUpdates = Array.isArray(metrics['updates']) ? (metrics['updates'] as unknown[]) : null;
  if (rawUpdates === null) return; // absent key — keep previous rows

  // Local helpers (same semantics as ingestInventory's closures).
  const numOrNull = (v: unknown): number | null =>
    typeof v === 'number' && Number.isFinite(v) ? v : null;
  const extraOf = (r: Record<string, unknown>): string => {
    const e = r['extra'];
    if (!e || typeof e !== 'object' || Array.isArray(e)) return '{}';
    try {
      return JSON.stringify(e);
    } catch {
      return '{}';
    }
  };

  const values: {
    deviceId: string; pluginId: string; kind: string; name: string;
    currentVersion: string | null; latestVersion: string | null;
    rebootRequired: boolean | null; sizeBytes: number | null;
    releaseNotesUrl: string | null; releaseNotes: string | null;
    branch: string | null;
    applyActionId: string | null; applyInput: string; extra: string; collectedAt: string;
  }[] = [];
  for (const raw of rawUpdates) {
    if (!raw || typeof raw !== 'object') continue;
    const r = raw as Record<string, unknown>;
    // Only genuinely-available updates persist.
    if (r['available'] !== true) continue;
    const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
    if (!name) continue; // name is part of the conflict key
    const kind = typeof r['kind'] === 'string' && (r['kind'] as string).trim() !== '' ? (r['kind'] as string).trim() : 'firmware';
    values.push({
      deviceId,
      pluginId,
      kind,
      name,
      currentVersion: typeof r['currentVersion'] === 'string' && (r['currentVersion'] as string) !== '' ? (r['currentVersion'] as string) : null,
      latestVersion: typeof r['latestVersion'] === 'string' && (r['latestVersion'] as string) !== '' ? (r['latestVersion'] as string) : null,
      rebootRequired: typeof r['rebootRequired'] === 'boolean' ? (r['rebootRequired'] as boolean) : null,
      sizeBytes: numOrNull(r['sizeBytes']),
      releaseNotesUrl: typeof r['releaseNotesUrl'] === 'string' && (r['releaseNotesUrl'] as string).trim() !== '' ? (r['releaseNotesUrl'] as string).trim() : null,
      // Cap notes text at 16 KB — a runaway feed must not bloat the table.
      releaseNotes: typeof r['releaseNotes'] === 'string' && (r['releaseNotes'] as string).trim() !== '' ? (r['releaseNotes'] as string).slice(0, 16_384) : null,
      branch: typeof r['branch'] === 'string' && (r['branch'] as string).trim() !== '' ? (r['branch'] as string).trim().slice(0, 128) : null,
      applyActionId: typeof r['applyActionId'] === 'string' && (r['applyActionId'] as string).trim() !== '' ? (r['applyActionId'] as string) : null,
      applyInput: (() => {
        const ai = r['applyInput'];
        if (!ai || typeof ai !== 'object' || Array.isArray(ai)) return '{}';
        try { return JSON.stringify(ai); } catch { return '{}'; }
      })(),
      extra: extraOf(r),
      collectedAt,
    });
  }
  // Capture the pre-poll row set BEFORE mutating — the automation worker's
  // updateAvailable triggers fire on TRANSITIONS (appeared / advanced /
  // disappeared), so we diff old vs new after the commit below.
  const prevRows = await db.query.deviceUpdates.findMany({
    where: and(eq(schema.deviceUpdates.deviceId, deviceId), eq(schema.deviceUpdates.pluginId, pluginId)),
  });

  // Dedupe within the poll (same kind|name reported twice = one row, last wins) —
  // used for BOTH the insert and the transition diff below.
  const byKey = new Map<string, typeof values[number]>();
  for (const v of values) byKey.set(`${v.kind}|${v.name}`, v);
  const deduped = Array.from(byKey.values());

  if (deduped.length > 0) {
    await db.insert(schema.deviceUpdates).values(deduped).onConflictDoUpdate({
      target: [schema.deviceUpdates.deviceId, schema.deviceUpdates.pluginId, schema.deviceUpdates.kind, schema.deviceUpdates.name],
      set: {
        currentVersion: sql`excluded."currentVersion"`,
        latestVersion: sql`excluded."latestVersion"`,
        rebootRequired: sql`excluded."rebootRequired"`,
        sizeBytes: sql`excluded."sizeBytes"`,
        releaseNotesUrl: sql`excluded."releaseNotesUrl"`,
        releaseNotes: sql`excluded."releaseNotes"`,
        branch: sql`excluded."branch"`,
        applyActionId: sql`excluded."applyActionId"`,
        applyInput: sql`excluded."applyInput"`,
        extra: sql`excluded.extra`,
        collectedAt: sql`excluded."collectedAt"`,
      },
    });
    const seenKeys = new Set(deduped.map((v) => `${v.kind}|${v.name}`));
    await db.delete(schema.deviceUpdates)
      .where(and(
        eq(schema.deviceUpdates.deviceId, deviceId),
        eq(schema.deviceUpdates.pluginId, pluginId),
        notInArray(sql`"kind" || '|' || name`, Array.from(seenKeys))
      ));
  } else {
    // Present-but-nothing-available is the authoritative wipe — same contract as containers.
    await db.delete(schema.deviceUpdates)
      .where(and(
        eq(schema.deviceUpdates.deviceId, deviceId),
        eq(schema.deviceUpdates.pluginId, pluginId)
      ));
  }

  // Actions & Schedules — updateAvailable triggers fire on TRANSITIONS between
  // this poll's row set and the previous one (appeared / advanced / disappeared).
  // Fire-and-forget: automation failures must never disturb telemetry bookkeeping.
  const parseApplyInput = (raw: string): Record<string, unknown> | undefined => {
    try {
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : undefined;
    } catch {
      return undefined;
    }
  };
  const transitions = diffUpdateTransitions(
    prevRows.map((r) => ({ kind: r.kind, name: r.name, currentVersion: r.currentVersion, latestVersion: r.latestVersion, rebootRequired: r.rebootRequired, applyActionId: r.applyActionId, applyInput: parseApplyInput(r.applyInput) })),
    deduped.map((v) => ({ kind: v.kind, name: v.name, currentVersion: v.currentVersion, latestVersion: v.latestVersion, rebootRequired: v.rebootRequired, applyActionId: v.applyActionId, applyInput: parseApplyInput(v.applyInput) }))
  );
  if (transitions.length > 0) {
    void onUpdateTransitions(deviceId, pluginId, transitions).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[telemetry] automation update-transition hook failed:', err);
    });
  }
}

/**
 * Ingests the `installedPackages` metric into device_packages (CVE tracking).
 * Runs on EVERY poll — not inventory-gated — so a package upgrade refreshes the
 * row's version + collectedAt immediately and the cve worker re-matches within
 * one beat.
 *
 * Generic key — any plugin may emit it:
 *   installedPackages[] { name, version?, ecosystem?, extra? }
 * `ecosystem` is a free-form tag ('debian', 'alpine', 'npm', …) the cve worker
 * maps onto its provider's source names; missing = 'unknown' (skipped by the
 * fetch, but still stored so the UI can show untracked packages). Same
 * CONFIG-object lifecycle as containers: upsert-per-poll + delete-on-absent,
 * present-but-empty = authoritative wipe. Never throws.
 */
async function ingestInstalledPackages(
  deviceId: string,
  pluginId: string,
  metrics: Record<string, unknown>,
  collectedAt: string
): Promise<void> {
  const rawPkgs = Array.isArray(metrics['installedPackages']) ? (metrics['installedPackages'] as unknown[]) : null;
  if (rawPkgs === null) return; // absent key — keep previous rows

  const extraOf = (r: Record<string, unknown>): string => {
    const e = r['extra'];
    if (!e || typeof e !== 'object' || Array.isArray(e)) return '{}';
    try {
      return JSON.stringify(e);
    } catch {
      return '{}';
    }
  };

  const values: {
    deviceId: string; pluginId: string; name: string; version: string | null;
    ecosystem: string; extra: string; collectedAt: string;
  }[] = [];
  for (const raw of rawPkgs) {
    if (!raw || typeof raw !== 'object') continue;
    const r = raw as Record<string, unknown>;
    const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
    if (!name) continue; // name is part of the conflict key
    values.push({
      deviceId,
      pluginId,
      name,
      version: typeof r['version'] === 'string' && (r['version'] as string).trim() !== '' ? (r['version'] as string).trim() : null,
      ecosystem: typeof r['ecosystem'] === 'string' && (r['ecosystem'] as string).trim() !== '' ? (r['ecosystem'] as string).trim().toLowerCase() : 'unknown',
      extra: extraOf(r),
      collectedAt,
    });
  }

  if (values.length > 0) {
    const byKey = new Map<string, typeof values[number]>();
    for (const v of values) byKey.set(v.name, v); // one row per package name (PK is case-sensitive; the cve worker matches case-insensitively)
    await db.insert(schema.devicePackages).values(Array.from(byKey.values())).onConflictDoUpdate({
      target: [schema.devicePackages.deviceId, schema.devicePackages.pluginId, schema.devicePackages.name],
      set: {
        version: sql`excluded.version`,
        ecosystem: sql`excluded.ecosystem`,
        extra: sql`excluded.extra`,
        collectedAt: sql`excluded."collectedAt"`,
      },
    });
    const seenNames = new Set(values.map((v) => v.name));
    await db.delete(schema.devicePackages)
      .where(and(
        eq(schema.devicePackages.deviceId, deviceId),
        eq(schema.devicePackages.pluginId, pluginId),
        notInArray(schema.devicePackages.name, Array.from(seenNames))
      ));
  } else {
    // Present-but-EMPTY is the authoritative wipe — same contract as containers.
    await db.delete(schema.devicePackages)
      .where(and(
        eq(schema.devicePackages.deviceId, deviceId),
        eq(schema.devicePackages.pluginId, pluginId)
      ));
  }
}

async function ingestInventory(
  deviceId: string,
  pluginId: string,
  metrics: Record<string, unknown>,
  collectedAt: string
): Promise<void> {
  try {
    // --- networks ---------------------------------------------------------
    const rawNetworks = Array.isArray(metrics['networks']) ? (metrics['networks'] as unknown[]) : [];
    if (rawNetworks.length > 0) {
      const values: {
        deviceId: string; pluginId: string; name: string; ip: string; prefix: number | null;
        version: string | null; vlanId: number | null; mac: string | null; status: string | null;
        collectedAt: string;
      }[] = [];
      for (const raw of rawNetworks) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue;
        values.push({
          deviceId,
          pluginId,
          name,
          // '' = interface without an IP (kept for topology detection).
          ip: typeof r['ip'] === 'string' && (r['ip'] as string).trim() !== '' ? (r['ip'] as string).trim() : '',
          prefix: typeof r['prefix'] === 'number' && Number.isFinite(r['prefix']) ? Math.round(r['prefix']) : null,
          version: typeof r['version'] === 'string' ? (r['version'] as string) : null,
          vlanId: typeof r['vlanId'] === 'number' && Number.isFinite(r['vlanId']) ? Math.round(r['vlanId']) : null,
          mac: typeof r['mac'] === 'string' ? (r['mac'] as string).toLowerCase() : null,
          status: typeof r['status'] === 'string' ? (r['status'] as string) : null,
          collectedAt,
        });
      }
      // De-duplicate on the upsert conflict key — two rows with the same
      // (name, ip) in one snapshot make Postgres reject the whole batch
      // ("ON CONFLICT DO UPDATE command cannot affect row a second time").
      const netByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        netByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}|${v.ip}`, v);
      }
      if (netByKey.size > 0) {
        await db.insert(schema.networks).values(Array.from(netByKey.values())).onConflictDoUpdate({
          target: [schema.networks.deviceId, schema.networks.pluginId, schema.networks.name, schema.networks.ip],
          set: {
            prefix: sql`excluded."prefix"`,
            version: sql`excluded."version"`,
            vlanId: sql`excluded."vlanId"`,
            mac: sql`excluded.mac`,
            status: sql`excluded.status`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
    }

    // --- hosts (ARP / NDP neighbors + DHCP leases) -------------------------
    const hostValues: {
      deviceId: string; pluginId: string; mac: string; ip: string; source: string;
      hostname: string | null; manufacturer: string | null; intf: string | null;
      expiry: string | null; lastSeenAt: string;
    }[] = [];
    // Sources: arp/ndp/dhcp/wlan = neighbors observed by the device; 'self' =
    // the appliance's OWN interfaces (plugins emit these with their hostname so
    // cross-device MAC merging can name the box — neighbor tables carry no names).
    const pushHostRow = (source: string, raw: unknown): void => {
      if (!raw || typeof raw !== 'object') return;
      const r = raw as Record<string, unknown>;
      const mac = typeof r['mac'] === 'string' ? (r['mac'] as string).trim().toLowerCase() : '';
      const ip = typeof r['ip'] === 'string' ? (r['ip'] as string).trim() : '';
      // Skip placeholder addresses ("0.0.0.0" / "::") — some plugins report them
      // for hosts without an address yet; they are not joinable IPs.
      if (!mac) return;
      if (ip === '0.0.0.0' || ip === '::') return;
      // IP-less rows are allowed ONLY for sources that legitimately have no
      // address: 'mac' — switch MAC tables (e.g. SwOS !dhost.b) report learned
      // MAC + port with no address; 'vm' — VM NIC MACs exist even when the
      // guest has no live IP yet (stopped VM, or no SSH enrichment for IPs).
      if (!ip && source !== 'mac' && source !== 'vm') return;
      hostValues.push({
        deviceId,
        pluginId,
        mac,
        ip,
        source,
        hostname: typeof r['hostname'] === 'string' && (r['hostname'] as string).trim() !== '' ? (r['hostname'] as string) : null,
        manufacturer: typeof r['manufacturer'] === 'string' && (r['manufacturer'] as string).trim() !== '' ? (r['manufacturer'] as string) : null,
        intf: typeof r['intf'] === 'string' ? (r['intf'] as string) : null,
        expiry: typeof r['expiry'] === 'string' && (r['expiry'] as string).trim() !== '' ? (r['expiry'] as string) : null,
        lastSeenAt: collectedAt,
      });
    };
    for (const source of ['arp', 'ndp'] as const) {
      const rows = Array.isArray(metrics[source]) ? (metrics[source] as unknown[]) : [];
      for (const raw of rows) pushHostRow(source, raw);
    }
    // The appliance's OWN interfaces — plugins emit these under `hosts` with
    // source 'self' + their hostname so cross-device MAC merging can name the box.
    const selfRows = Array.isArray(metrics['hosts']) ? (metrics['hosts'] as unknown[]) : [];
    for (const raw of selfRows) pushHostRow('self', raw);
    const leases = Array.isArray(metrics['dhcpLeases']) ? (metrics['dhcpLeases'] as unknown[]) : [];
    for (const raw of leases) pushHostRow('dhcp', raw);
    // WLAN clients (e.g. LANCOM station table) — source 'wlan'.
    const wlanClients = Array.isArray(metrics['wlanClients']) ? (metrics['wlanClients'] as unknown[]) : [];
    for (const raw of wlanClients) pushHostRow('wlan', raw);
    // Switch MAC tables (e.g. SwOS !dhost.b) — learned MAC + port, no IP.
    const macRows = Array.isArray(metrics['macTable']) ? (metrics['macTable'] as unknown[]) : [];
    for (const raw of macRows) pushHostRow('mac', raw);

    // Docker/container hosts (e.g. TrueNAS Apps via `docker inspect` over SSH)
    // — source 'docker'. Rows carry a REAL MAC + IP + hostname, so they flow
    // through the standard pushHostRow path and merge by MAC with ARP/NDP
    // entries other devices report for the same container. Plugins only emit
    // these when a real MAC was retrieved (no empty-MAC rows).
    const dockerHosts = Array.isArray(metrics['dockerHosts']) ? (metrics['dockerHosts'] as unknown[]) : [];
    for (const raw of dockerHosts) pushHostRow('docker', raw);

    // VM guests (e.g. TrueNAS SCALE VM NIC MACs, live IPs via `virsh domifaddr`
    // over SSH) — source 'vm'. Same contract as dockerHosts: only rows with a
    // REAL MAC are emitted; they merge by MAC with ARP/NDP entries other
    // devices report for the same guest.
    const vmHosts = Array.isArray(metrics['vmHosts']) ? (metrics['vmHosts'] as unknown[]) : [];
    for (const raw of vmHosts) pushHostRow('vm', raw);

    // Same guard as above — one snapshot must not repeat a (mac, ip, source) row.
    const hostByKey = new Map<string, typeof hostValues[number]>();
    for (const v of hostValues) {
      hostByKey.set(`${v.deviceId}|${v.pluginId}|${v.mac}|${v.ip}|${v.source}`, v);
    }
    if (hostByKey.size > 0) {
      await db.insert(schema.hosts).values(Array.from(hostByKey.values())).onConflictDoUpdate({
        target: [schema.hosts.deviceId, schema.hosts.pluginId, schema.hosts.mac, schema.hosts.ip, schema.hosts.source],
        set: {
          hostname: sql`excluded.hostname`,
          manufacturer: sql`excluded.manufacturer`,
          intf: sql`excluded.intf`,
          expiry: sql`excluded.expiry`,
          lastSeenAt: sql`excluded."lastSeenAt"`,
        },
      });
    }

    // --- tunnels (WireGuard / OpenVPN / IPsec / PPPoE / GRE) -----------------
    const rawTunnels = Array.isArray(metrics['tunnels']) ? (metrics['tunnels'] as unknown[]) : [];
    if (rawTunnels.length > 0) {
      const values: {
        deviceId: string; pluginId: string; name: string; type: string; peerAddress: string;
        localAddress: string; subnet: string | null; status: string; uptimeSeconds: number | null;
        lastHandshakeSeconds: number | null;
        interfaceName: string | null; rxRate: number | null; txRate: number | null;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawTunnels) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        const type = typeof r['type'] === 'string' ? (r['type'] as string).trim().toLowerCase() : '';
        if (!name || !type) continue; // both are part of the conflict key
        values.push({
          deviceId,
          pluginId,
          name,
          type,
          peerAddress: typeof r['peerAddress'] === 'string' ? (r['peerAddress'] as string).trim() : '',
          localAddress: typeof r['localAddress'] === 'string' ? (r['localAddress'] as string).trim() : '',
          subnet: typeof r['subnet'] === 'string' && (r['subnet'] as string).trim() !== '' ? (r['subnet'] as string).trim() : null,
          status: typeof r['status'] === 'string' && (r['status'] as string).trim() !== '' ? (r['status'] as string).trim().toLowerCase() : 'unknown',
          uptimeSeconds: typeof r['uptimeSeconds'] === 'number' && Number.isFinite(r['uptimeSeconds']) ? r['uptimeSeconds'] : null,
          lastHandshakeSeconds: typeof r['lastHandshakeSeconds'] === 'number' && Number.isFinite(r['lastHandshakeSeconds']) ? r['lastHandshakeSeconds'] : null,
          interfaceName: typeof r['interfaceName'] === 'string' && (r['interfaceName'] as string).trim() !== '' ? (r['interfaceName'] as string).trim() : null,
          rxRate: typeof r['rxRate'] === 'number' && Number.isFinite(r['rxRate']) ? r['rxRate'] : null,
          txRate: typeof r['txRate'] === 'number' && Number.isFinite(r['txRate']) ? r['txRate'] : null,
          extra: r['extra'] && typeof r['extra'] === 'object' ? JSON.stringify(r['extra']) : '{}',
          collectedAt,
        });
      }
      // Same de-dup guard as the other inventory blocks.
      const tunnelByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        tunnelByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}|${v.type}`, v);
      }
      if (tunnelByKey.size > 0) {
        await db.insert(schema.tunnels).values(Array.from(tunnelByKey.values())).onConflictDoUpdate({
          target: [schema.tunnels.deviceId, schema.tunnels.pluginId, schema.tunnels.name, schema.tunnels.type],
          set: {
            peerAddress: sql`excluded."peerAddress"`,
            localAddress: sql`excluded."localAddress"`,
            subnet: sql`excluded.subnet`,
            status: sql`excluded.status`,
            uptimeSeconds: sql`excluded."uptimeSeconds"`,
            lastHandshakeSeconds: sql`excluded."lastHandshakeSeconds"`,
            interfaceName: sql`excluded."interfaceName"`,
            rxRate: sql`excluded."rxRate"`,
            txRate: sql`excluded."txRate"`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      // Tunnels are CONFIG objects — a tunnel deleted on the device must vanish
      // from the page, not linger until the 24h sweep. Drop rows this snapshot
      // no longer reports (only when the key is present at all: an ABSENT key
      // means "plugin doesn't report tunnels", which must not wipe other data).
      const seenTunnelNames = new Set(values.map((v) => v.name));
      if (seenTunnelNames.size > 0) {
        await db.delete(schema.tunnels)
          .where(and(
            eq(schema.tunnels.deviceId, deviceId),
            eq(schema.tunnels.pluginId, pluginId),
            notInArray(schema.tunnels.name, Array.from(seenTunnelNames))
          ));
      }
    }

    // --- routes (static + dynamically-learned route entries) ----------------
    // The key is only processed when PRESENT in the snapshot: a present-but-EMPTY
    // array is authoritative ("this device has no routes right now" — e.g. TrueNAS
    // reports per-interface static_routes and emits [] once all are removed), so
    // stale rows get wiped below. An ABSENT key means "plugin doesn't report
    // routes at all" and must not touch the table (24h sweep still applies).
    const rawRoutes = Array.isArray(metrics['routes']) ? (metrics['routes'] as unknown[]) : null;
    if (rawRoutes !== null) {
      const ROUTE_PROTOCOLS = new Set(['static', 'connected', 'ospf', 'bgp', 'rip', 'other']);
      const values: {
        deviceId: string; pluginId: string; destination: string; gateway: string; protocol: string;
        distance: number | null; metric: number | null; mtu: number | null; status: string;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawRoutes) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const destination = typeof r['destination'] === 'string' ? (r['destination'] as string).trim() : '';
        let protocol = typeof r['protocol'] === 'string' ? (r['protocol'] as string).trim().toLowerCase() : '';
        if (!ROUTE_PROTOCOLS.has(protocol)) protocol = 'other'; // unknown labels never break the PK enum
        if (!destination) continue; // destination is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          destination,
          gateway: typeof r['gateway'] === 'string' ? (r['gateway'] as string).trim() : '',
          protocol,
          distance: typeof r['distance'] === 'number' && Number.isFinite(r['distance']) ? r['distance'] : null,
          metric: typeof r['metric'] === 'number' && Number.isFinite(r['metric']) ? r['metric'] : null,
          mtu: typeof r['mtu'] === 'number' && Number.isFinite(r['mtu']) ? Math.trunc(r['mtu']) : null,
          status: typeof r['status'] === 'string' && (r['status'] as string).trim() !== '' ? (r['status'] as string).trim().toLowerCase() : 'unknown',
          extra: r['extra'] && typeof r['extra'] === 'object' ? JSON.stringify(r['extra']) : '{}',
          collectedAt,
        });
      }
      // Same de-dup guard as the other inventory blocks.
      const routeByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        routeByKey.set(`${v.deviceId}|${v.pluginId}|${v.destination}|${v.protocol}`, v);
      }
      if (routeByKey.size > 0) {
        await db.insert(schema.routes).values(Array.from(routeByKey.values())).onConflictDoUpdate({
          target: [schema.routes.deviceId, schema.routes.pluginId, schema.routes.destination, schema.routes.protocol],
          set: {
            gateway: sql`excluded.gateway`,
            distance: sql`excluded.distance`,
            metric: sql`excluded.metric`,
            mtu: sql`excluded.mtu`,
            status: sql`excluded.status`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      // Routes are CONFIG/runtime objects — a route removed on the device must
      // vanish from the page, not linger until the 24h sweep. Drop rows this
      // snapshot no longer reports (only when the key is present at all: an
      // ABSENT key means "plugin doesn't report routes", which must not wipe
      // other data). Keyed on destination|protocol pairs — NOT destination
      // alone — so a static and an OSPF-learned route to the same prefix can't
      // wipe each other when only one of them is reported by this plugin.
      const existingRouteKeys = await db
        .select({ destination: schema.routes.destination, protocol: schema.routes.protocol })
        .from(schema.routes)
        .where(and(eq(schema.routes.deviceId, deviceId), eq(schema.routes.pluginId, pluginId)));
      const seenRouteKeys = new Set(values.map((v) => `${v.destination}|${v.protocol}`));
      const staleRoutes = existingRouteKeys.filter(
        (k) => !seenRouteKeys.has(`${k.destination}|${k.protocol}`)
      );
      if (staleRoutes.length > 0) {
        await db.delete(schema.routes).where(
          and(
            eq(schema.routes.deviceId, deviceId),
            eq(schema.routes.pluginId, pluginId),
            or(...staleRoutes.map((k) => and(eq(schema.routes.destination, k.destination), eq(schema.routes.protocol, k.protocol))))
          )
        );
      }
    }

    // --- dnsEntries (static DNS host entries) ---------------------------------
    // Same present-vs-absent contract as routes: a PRESENT-but-empty array is
    // authoritative ("this device has no static DNS entries right now") so stale
    // rows are wiped; an ABSENT key means "plugin doesn't report DNS entries"
    // and must not touch the table (24h sweep still applies). `name` is lowercased
    // at ingest — the DNS page groups case-insensitively. Identity is name|ip so a
    // name with several addresses yields multiple rows.
    const rawDnsEntries = Array.isArray(metrics['dnsEntries']) ? (metrics['dnsEntries'] as unknown[]) : null;
    if (rawDnsEntries !== null) {
      const values: { deviceId: string; pluginId: string; name: string; ip: string; domain: string | null; description: string | null; collectedAt: string }[] = [];
      for (const raw of rawDnsEntries) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim().toLowerCase() : '';
        const ip = typeof r['ip'] === 'string' ? (r['ip'] as string).trim() : '';
        if (!name || !ip) continue; // both are part of the conflict key
        // Optional domain suffix (OPNsense unbound: bare hostname + separate
        // domain field). Lowercased, trailing dot stripped — ''/absent → NULL.
        const rawDomain = typeof r['domain'] === 'string' ? (r['domain'] as string).trim().toLowerCase() : '';
        const domain = rawDomain !== '' ? rawDomain.replace(/\.$/, '') || null : null;
        // Optional vendor note (e.g. RouterOS `comment`) — ''/absent → NULL.
        const description = typeof r['description'] === 'string' && (r['description'] as string).trim() !== '' ? (r['description'] as string).trim() : null;
        values.push({ deviceId, pluginId, name, ip, domain, description, collectedAt });
      }
      const dnsByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        dnsByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}|${v.ip}`, v);
      }
      if (dnsByKey.size > 0) {
        await db.insert(schema.deviceDnsEntries).values(Array.from(dnsByKey.values())).onConflictDoUpdate({
          target: [schema.deviceDnsEntries.deviceId, schema.deviceDnsEntries.pluginId, schema.deviceDnsEntries.name, schema.deviceDnsEntries.ip],
          // description + domain are refreshed too — a note or domain edited on
          // the device (or its removal) must track the live table.
          set: { collectedAt: sql`excluded."collectedAt"`, description: sql`excluded."description"`, domain: sql`excluded."domain"` },
        });
      }
      // A DNS entry removed on the device must vanish from the page. Drop rows
      // this snapshot no longer reports (only when the key is present at all).
      const existingDnsKeys = await db
        .select({ name: schema.deviceDnsEntries.name, ip: schema.deviceDnsEntries.ip })
        .from(schema.deviceDnsEntries)
        .where(and(eq(schema.deviceDnsEntries.deviceId, deviceId), eq(schema.deviceDnsEntries.pluginId, pluginId)));
      const seenDnsKeys = new Set(values.map((v) => `${v.name}|${v.ip}`));
      const staleDns = existingDnsKeys.filter((k) => !seenDnsKeys.has(`${k.name}|${k.ip}`));
      if (staleDns.length > 0) {
        await db.delete(schema.deviceDnsEntries).where(
          and(
            eq(schema.deviceDnsEntries.deviceId, deviceId),
            eq(schema.deviceDnsEntries.pluginId, pluginId),
            or(...staleDns.map((k) => and(eq(schema.deviceDnsEntries.name, k.name), eq(schema.deviceDnsEntries.ip, k.ip))))
          )
        );
      }
    }

    // --- dhcpNetworks (configured DHCP server networks/pools) -----------------
    // Same present-vs-absent contract as dnsEntries: a PRESENT-but-empty array is
    // authoritative ("this device has no DHCP networks right now") so stale rows
    // are wiped; an ABSENT key means "plugin doesn't report DHCP networks" and must
    // not touch the table (24h sweep still applies). Identity is name|rangeStart so
    // a scope with several ranges yields multiple rows.
    const rawDhcpNetworks = Array.isArray(metrics['dhcpNetworks']) ? (metrics['dhcpNetworks'] as unknown[]) : null;
    if (rawDhcpNetworks !== null) {
      const values: {
        deviceId: string; pluginId: string; name: string; iface: string | null; rangeStart: string; rangeEnd: string;
        cidr: string | null; leaseTimeSeconds: number | null; gateway: string | null; dnsServers: string | null; refId: string | null; collectedAt: string;
      }[] = [];
      for (const raw of rawDhcpNetworks) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        const rangeStart = typeof r['rangeStart'] === 'string' ? (r['rangeStart'] as string).trim() : '';
        const rangeEnd = typeof r['rangeEnd'] === 'string' ? (r['rangeEnd'] as string).trim() : '';
        if (!name || !rangeStart) continue; // both are part of the conflict key
        const iface = typeof r['interface'] === 'string' && (r['interface'] as string).trim() !== '' ? (r['interface'] as string).trim() : null;
        const cidr = typeof r['cidr'] === 'string' && (r['cidr'] as string).trim() !== '' ? (r['cidr'] as string).trim() : null;
        const leaseTimeSeconds = typeof r['leaseTimeSeconds'] === 'number' && Number.isFinite(r['leaseTimeSeconds']) ? Math.round(r['leaseTimeSeconds'] as number) : null;
        const gateway = typeof r['gateway'] === 'string' && (r['gateway'] as string).trim() !== '' ? (r['gateway'] as string).trim() : null;
        const dnsServers = typeof r['dnsServers'] === 'string' && (r['dnsServers'] as string).trim() !== '' ? (r['dnsServers'] as string).trim() : null;
        const refId = typeof r['refId'] === 'string' && (r['refId'] as string).trim() !== '' ? (r['refId'] as string).trim() : null;
        values.push({ deviceId, pluginId, name, iface, rangeStart, rangeEnd: rangeEnd || rangeStart, cidr, leaseTimeSeconds, gateway, dnsServers, refId, collectedAt });
      }
      const dhcpNetByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        dhcpNetByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}|${v.rangeStart}`, v);
      }
      if (dhcpNetByKey.size > 0) {
        await db.insert(schema.deviceDhcpNetworks).values(Array.from(dhcpNetByKey.values())).onConflictDoUpdate({
          target: [schema.deviceDhcpNetworks.deviceId, schema.deviceDhcpNetworks.pluginId, schema.deviceDhcpNetworks.name, schema.deviceDhcpNetworks.rangeStart],
          // All display columns are refreshed — a range/lease-time edited on the device must track the live table.
          set: {
            collectedAt: sql`excluded."collectedAt"`, iface: sql`excluded.iface`, rangeEnd: sql`excluded."rangeEnd"`,
            cidr: sql`excluded.cidr`, leaseTimeSeconds: sql`excluded."leaseTimeSeconds"`, gateway: sql`excluded.gateway`, dnsServers: sql`excluded."dnsServers"`, refId: sql`excluded."refId"`,
          },
        });
      }
      // A DHCP network removed on the device must vanish from the page. Drop rows
      // this snapshot no longer reports (only when the key is present at all).
      const existingDhcpNetKeys = await db
        .select({ name: schema.deviceDhcpNetworks.name, rangeStart: schema.deviceDhcpNetworks.rangeStart })
        .from(schema.deviceDhcpNetworks)
        .where(and(eq(schema.deviceDhcpNetworks.deviceId, deviceId), eq(schema.deviceDhcpNetworks.pluginId, pluginId)));
      const seenDhcpNetKeys = new Set(values.map((v) => `${v.name}|${v.rangeStart}`));
      const staleDhcpNets = existingDhcpNetKeys.filter((k) => !seenDhcpNetKeys.has(`${k.name}|${k.rangeStart}`));
      if (staleDhcpNets.length > 0) {
        await db.delete(schema.deviceDhcpNetworks).where(
          and(
            eq(schema.deviceDhcpNetworks.deviceId, deviceId),
            eq(schema.deviceDhcpNetworks.pluginId, pluginId),
            or(...staleDhcpNets.map((k) => and(eq(schema.deviceDhcpNetworks.name, k.name), eq(schema.deviceDhcpNetworks.rangeStart, k.rangeStart))))
          )
        );
      }
    }

    // --- dhcpReservations (static MAC→IP mappings) ----------------------------
    // Same present-vs-absent contract as dnsEntries. Identity is mac — a MAC with
    // several fixed IPs on one device collapses to the last-seen IP (vendors key
    // reservations by MAC). `refId`/`ip`/`hostname` are refreshed on conflict so an
    // edited reservation tracks the live table; NULLs in the snapshot overwrite.
    const rawDhcpReservations = Array.isArray(metrics['dhcpReservations']) ? (metrics['dhcpReservations'] as unknown[]) : null;
    if (rawDhcpReservations !== null) {
      const values: { deviceId: string; pluginId: string; mac: string; ip: string | null; hostname: string | null; iface: string | null; refId: string | null; status: string | null; collectedAt: string }[] = [];
      for (const raw of rawDhcpReservations) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const mac = typeof r['mac'] === 'string' ? (r['mac'] as string).trim().toLowerCase() : '';
        if (!mac) continue; // mac is part of the conflict key
        const ip = typeof r['ip'] === 'string' && (r['ip'] as string).trim() !== '' ? (r['ip'] as string).trim() : null;
        const hostname = typeof r['hostname'] === 'string' && (r['hostname'] as string).trim() !== '' ? (r['hostname'] as string).trim() : null;
        const iface = typeof r['interface'] === 'string' && (r['interface'] as string).trim() !== '' ? (r['interface'] as string).trim() : null;
        const refId = typeof r['refId'] === 'string' && (r['refId'] as string).trim() !== '' ? (r['refId'] as string).trim() : null;
        const status = typeof r['status'] === 'string' && (r['status'] as string).trim() !== '' ? (r['status'] as string).trim().toLowerCase() : null;
        values.push({ deviceId, pluginId, mac, ip, hostname, iface, refId, status, collectedAt });
      }
      const dhcpResByMac = new Map<string, typeof values[number]>();
      for (const v of values) {
        dhcpResByMac.set(`${v.deviceId}|${v.pluginId}|${v.mac}`, v);
      }
      if (dhcpResByMac.size > 0) {
        await db.insert(schema.deviceDhcpReservations).values(Array.from(dhcpResByMac.values())).onConflictDoUpdate({
          target: [schema.deviceDhcpReservations.deviceId, schema.deviceDhcpReservations.pluginId, schema.deviceDhcpReservations.mac],
          set: { collectedAt: sql`excluded."collectedAt"`, ip: sql`excluded.ip`, hostname: sql`excluded.hostname`, iface: sql`excluded.iface`, refId: sql`excluded."refId"`, status: sql`excluded.status` },
        });
      }
      // A reservation removed on the device must vanish from the page. Drop rows
      // this snapshot no longer reports (only when the key is present at all).
      const existingDhcpResMacs = await db
        .select({ mac: schema.deviceDhcpReservations.mac })
        .from(schema.deviceDhcpReservations)
        .where(and(eq(schema.deviceDhcpReservations.deviceId, deviceId), eq(schema.deviceDhcpReservations.pluginId, pluginId)));
      const seenDhcpResMacs = new Set(values.map((v) => v.mac));
      const staleDhcpRes = existingDhcpResMacs.filter((k) => !seenDhcpResMacs.has(k.mac));
      if (staleDhcpRes.length > 0) {
        await db.delete(schema.deviceDhcpReservations).where(
          and(
            eq(schema.deviceDhcpReservations.deviceId, deviceId),
            eq(schema.deviceDhcpReservations.pluginId, pluginId),
            or(...staleDhcpRes.map((k) => eq(schema.deviceDhcpReservations.mac, k.mac)))
          )
        );
      }
    }

    // --- services (systemd / OpenRC / runit / SysVinit / rc / middleware) -----
    // Same present-vs-absent contract as routes: a PRESENT-but-empty array is
    // authoritative ("this device reports no services right now") so stale rows
    // are wiped; an ABSENT key means "plugin doesn't report services" and must
    // not touch the table (24h sweep still applies). Identity is name|type —
    // NOT name alone — because a service managed by two frameworks on one box
    // coexists in the PK, so one framework's snapshot must never wipe another's.
    const rawServices = Array.isArray(metrics['services']) ? (metrics['services'] as unknown[]) : null;
    if (rawServices !== null) {
      const values: {
        deviceId: string; pluginId: string; name: string; type: string; status: string;
        enabled: boolean | null; pid: number | null; description: string; extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawServices) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue; // name is part of the conflict key
        const type = typeof r['type'] === 'string' && (r['type'] as string).trim() !== ''
          ? (r['type'] as string).trim().toLowerCase()
          : 'unknown';
        let status = typeof r['status'] === 'string' ? (r['status'] as string).trim().toLowerCase() : '';
        if (!['running', 'stopped', 'failed', 'unknown'].includes(status)) status = 'unknown';
        values.push({
          deviceId,
          pluginId,
          name,
          type,
          status,
          enabled: typeof r['enabled'] === 'boolean' ? (r['enabled'] as boolean) : null,
          pid: typeof r['pid'] === 'number' && Number.isFinite(r['pid']) ? Math.trunc(r['pid']) : null,
          description: typeof r['description'] === 'string' ? (r['description'] as string).trim() : '',
          extra: r['extra'] && typeof r['extra'] === 'object' ? JSON.stringify(r['extra']) : '{}',
          collectedAt,
        });
      }
      // Same de-dup guard as the other inventory blocks.
      const serviceByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        serviceByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}|${v.type}`, v);
      }
      if (serviceByKey.size > 0) {
        await db.insert(schema.deviceServices).values(Array.from(serviceByKey.values())).onConflictDoUpdate({
          target: [schema.deviceServices.deviceId, schema.deviceServices.pluginId, schema.deviceServices.name, schema.deviceServices.type],
          set: {
            status: sql`excluded.status`,
            enabled: sql`excluded.enabled`,
            pid: sql`excluded.pid`,
            description: sql`excluded.description`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      // A service removed on the device must vanish from the page, not linger
      // until the 24h sweep. Keyed on name|type pairs (see above).
      const existingServiceKeys = await db
        .select({ name: schema.deviceServices.name, type: schema.deviceServices.type })
        .from(schema.deviceServices)
        .where(and(eq(schema.deviceServices.deviceId, deviceId), eq(schema.deviceServices.pluginId, pluginId)));
      const seenServiceKeys = new Set(values.map((v) => `${v.name}|${v.type}`));
      const staleServices = existingServiceKeys.filter(
        (k) => !seenServiceKeys.has(`${k.name}|${k.type}`)
      );
      if (staleServices.length > 0) {
        await db.delete(schema.deviceServices).where(
          and(
            eq(schema.deviceServices.deviceId, deviceId),
            eq(schema.deviceServices.pluginId, pluginId),
            or(...staleServices.map((k) => and(eq(schema.deviceServices.name, k.name), eq(schema.deviceServices.type, k.type))))
          )
        );
      }
    }

    // --- mail inventory (domains / mailboxes / aliases — mailcow) --------------
    // Same present-vs-absent contract as services: a PRESENT-but-empty array is
    // authoritative ("this device reports no <thing> right now") so stale rows
    // are wiped; an ABSENT key means "plugin doesn't report this inventory"
    // and must not touch the table (24h sweep still applies). Identities:
    // domain / username / address.
    const rawMailDomains = Array.isArray(metrics['mailDomains']) ? (metrics['mailDomains'] as unknown[]) : null;
    if (rawMailDomains !== null) {
      const values: {
        deviceId: string; pluginId: string; domain: string; active: boolean; description: string;
        quotaBytes: number | null; maxQuotaPerMailboxBytes: number | null; defaultQuotaBytes: number | null;
        mailboxCount: number | null; aliasCount: number | null; backupMx: boolean; collectedAt: string;
      }[] = [];
      for (const raw of rawMailDomains) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const domain = typeof r['domain'] === 'string' ? (r['domain'] as string).trim() : '';
        if (!domain) continue; // domain is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          domain,
          active: typeof r['active'] === 'boolean' ? (r['active'] as boolean) : false,
          description: typeof r['description'] === 'string' ? (r['description'] as string).trim() : '',
          quotaBytes: toIntOrNull(r['quotaBytes']),
          maxQuotaPerMailboxBytes: toIntOrNull(r['maxQuotaPerMailboxBytes']),
          defaultQuotaBytes: toIntOrNull(r['defaultQuotaBytes']),
          mailboxCount: toIntOrNull(r['mailboxCount']),
          aliasCount: toIntOrNull(r['aliasCount']),
          backupMx: typeof r['backupMx'] === 'boolean' ? (r['backupMx'] as boolean) : false,
          collectedAt,
        });
      }
      const mailDomainByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        mailDomainByKey.set(`${v.deviceId}|${v.pluginId}|${v.domain}`, v);
      }
      if (mailDomainByKey.size > 0) {
        await db.insert(schema.mailDomains).values(Array.from(mailDomainByKey.values())).onConflictDoUpdate({
          target: [schema.mailDomains.deviceId, schema.mailDomains.pluginId, schema.mailDomains.domain],
          set: {
            active: sql`excluded.active`,
            description: sql`excluded.description`,
            quotaBytes: sql`excluded."quotaBytes"`,
            maxQuotaPerMailboxBytes: sql`excluded."maxQuotaPerMailboxBytes"`,
            defaultQuotaBytes: sql`excluded."defaultQuotaBytes"`,
            mailboxCount: sql`excluded."mailboxCount"`,
            aliasCount: sql`excluded."aliasCount"`,
            backupMx: sql`excluded."backupMx"`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const existingMailDomains = await db
        .select({ domain: schema.mailDomains.domain })
        .from(schema.mailDomains)
        .where(and(eq(schema.mailDomains.deviceId, deviceId), eq(schema.mailDomains.pluginId, pluginId)));
      const seenMailDomains = new Set(values.map((v) => v.domain));
      const staleMailDomains = existingMailDomains.filter((k) => !seenMailDomains.has(k.domain)).map((k) => k.domain);
      if (staleMailDomains.length > 0) {
        await db.delete(schema.mailDomains).where(
          and(
            eq(schema.mailDomains.deviceId, deviceId),
            eq(schema.mailDomains.pluginId, pluginId),
            inArray(schema.mailDomains.domain, staleMailDomains)
          )
        );
      }
    }

    const rawMailMailboxes = Array.isArray(metrics['mailMailboxes']) ? (metrics['mailMailboxes'] as unknown[]) : null;
    if (rawMailMailboxes !== null) {
      const values: {
        deviceId: string; pluginId: string; username: string; domain: string; localPart: string; name: string;
        active: boolean; quotaBytes: number | null; quotaUsedBytes: number | null; messageCount: number | null;
        forcePwUpdate: boolean; forceTfa: boolean; sogoAccess: boolean; collectedAt: string;
      }[] = [];
      for (const raw of rawMailMailboxes) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const username = typeof r['username'] === 'string' ? (r['username'] as string).trim() : '';
        if (!username) continue; // username is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          username,
          domain: typeof r['domain'] === 'string' ? (r['domain'] as string).trim() : '',
          localPart: typeof r['localPart'] === 'string' ? (r['localPart'] as string).trim() : '',
          name: typeof r['name'] === 'string' ? (r['name'] as string).trim() : '',
          active: typeof r['active'] === 'boolean' ? (r['active'] as boolean) : false,
          quotaBytes: toIntOrNull(r['quotaBytes']),
          quotaUsedBytes: toIntOrNull(r['quotaUsedBytes']),
          messageCount: toIntOrNull(r['messageCount']),
          forcePwUpdate: typeof r['forcePwUpdate'] === 'boolean' ? (r['forcePwUpdate'] as boolean) : false,
          forceTfa: typeof r['forceTfa'] === 'boolean' ? (r['forceTfa'] as boolean) : false,
          sogoAccess: typeof r['sogoAccess'] === 'boolean' ? (r['sogoAccess'] as boolean) : false,
          collectedAt,
        });
      }
      const mailboxByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        mailboxByKey.set(`${v.deviceId}|${v.pluginId}|${v.username}`, v);
      }
      if (mailboxByKey.size > 0) {
        await db.insert(schema.mailMailboxes).values(Array.from(mailboxByKey.values())).onConflictDoUpdate({
          target: [schema.mailMailboxes.deviceId, schema.mailMailboxes.pluginId, schema.mailMailboxes.username],
          set: {
            domain: sql`excluded.domain`,
            localPart: sql`excluded."localPart"`,
            name: sql`excluded.name`,
            active: sql`excluded.active`,
            quotaBytes: sql`excluded."quotaBytes"`,
            quotaUsedBytes: sql`excluded."quotaUsedBytes"`,
            messageCount: sql`excluded."messageCount"`,
            forcePwUpdate: sql`excluded."forcePwUpdate"`,
            forceTfa: sql`excluded."forceTfa"`,
            sogoAccess: sql`excluded."sogoAccess"`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const existingMailboxes = await db
        .select({ username: schema.mailMailboxes.username })
        .from(schema.mailMailboxes)
        .where(and(eq(schema.mailMailboxes.deviceId, deviceId), eq(schema.mailMailboxes.pluginId, pluginId)));
      const seenMailboxes = new Set(values.map((v) => v.username));
      const staleMailboxes = existingMailboxes.filter((k) => !seenMailboxes.has(k.username)).map((k) => k.username);
      if (staleMailboxes.length > 0) {
        await db.delete(schema.mailMailboxes).where(
          and(
            eq(schema.mailMailboxes.deviceId, deviceId),
            eq(schema.mailMailboxes.pluginId, pluginId),
            inArray(schema.mailMailboxes.username, staleMailboxes)
          )
        );
      }
    }

    const rawMailAliases = Array.isArray(metrics['mailAliases']) ? (metrics['mailAliases'] as unknown[]) : null;
    if (rawMailAliases !== null) {
      const values: {
        deviceId: string; pluginId: string; address: string; domain: string; goto: string;
        active: boolean; isCatchAll: boolean; isMailboxBound: boolean; senderAllowed: boolean;
        mailcowId: number | null; collectedAt: string;
      }[] = [];
      for (const raw of rawMailAliases) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const address = typeof r['address'] === 'string' ? (r['address'] as string).trim() : '';
        if (!address) continue; // address is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          address,
          domain: typeof r['domain'] === 'string' ? (r['domain'] as string).trim() : '',
          goto: typeof r['goto'] === 'string' ? (r['goto'] as string).trim() : '',
          active: typeof r['active'] === 'boolean' ? (r['active'] as boolean) : false,
          isCatchAll: typeof r['isCatchAll'] === 'boolean' ? (r['isCatchAll'] as boolean) : false,
          isMailboxBound: typeof r['isMailboxBound'] === 'boolean' ? (r['isMailboxBound'] as boolean) : false,
          senderAllowed: typeof r['senderAllowed'] === 'boolean' ? (r['senderAllowed'] as boolean) : true,
          mailcowId: toIntOrNull(r['mailcowId']),
          collectedAt,
        });
      }
      const aliasByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        aliasByKey.set(`${v.deviceId}|${v.pluginId}|${v.address}`, v);
      }
      if (aliasByKey.size > 0) {
        await db.insert(schema.mailAliases).values(Array.from(aliasByKey.values())).onConflictDoUpdate({
          target: [schema.mailAliases.deviceId, schema.mailAliases.pluginId, schema.mailAliases.address],
          set: {
            domain: sql`excluded.domain`,
            goto: sql`excluded.goto`,
            active: sql`excluded.active`,
            isCatchAll: sql`excluded."isCatchAll"`,
            isMailboxBound: sql`excluded."isMailboxBound"`,
            senderAllowed: sql`excluded."senderAllowed"`,
            mailcowId: sql`excluded."mailcowId"`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const existingAliases = await db
        .select({ address: schema.mailAliases.address })
        .from(schema.mailAliases)
        .where(and(eq(schema.mailAliases.deviceId, deviceId), eq(schema.mailAliases.pluginId, pluginId)));
      const seenAliases = new Set(values.map((v) => v.address));
      const staleAliases = existingAliases.filter((k) => !seenAliases.has(k.address)).map((k) => k.address);
      if (staleAliases.length > 0) {
        await db.delete(schema.mailAliases).where(
          and(
            eq(schema.mailAliases.deviceId, deviceId),
            eq(schema.mailAliases.pluginId, pluginId),
            inArray(schema.mailAliases.address, staleAliases)
          )
        );
      }
    }

    // --- firewall rules (filter + NAT kinds) ---------------------------------
    // Same present-vs-absent contract as routes: a PRESENT-but-empty array is
    // authoritative ("this device has no firewall rules right now") so stale rows
    // are wiped; an ABSENT key means "plugin doesn't report firewall rules" and
    // must not touch the table (24h sweep still applies). Identity is
    // ruleType|vendorRuleId — NOT vendorRuleId alone — because RouterOS .ids are
    // per-table (a filter rule and a NAT rule can share the same .id), so one
    // rule type's snapshot must never wipe another type's rows.
    const rawFirewallRules = Array.isArray(metrics['firewallRules']) ? (metrics['firewallRules'] as unknown[]) : null;
    if (rawFirewallRules !== null) {
      const FW_RULE_TYPES = new Set(['filter', 'dnat', 'snat', 'one-to-one', 'npt']);
      const values: {
        deviceId: string; pluginId: string; ruleType: string; vendorRuleId: string; position: number;
        protocol: string; sourceIp: string; destIp: string; sourcePort: string | null; destPort: string | null;
        action: string; enabled: boolean; description: string; scope: string; ipVersion: string;
        packets: number | null; bytes: number | null; states: number | null;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawFirewallRules) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        let ruleType = typeof r['ruleType'] === 'string' ? (r['ruleType'] as string).trim().toLowerCase() : '';
        if (!FW_RULE_TYPES.has(ruleType)) ruleType = 'filter'; // unknown labels never break the PK enum
        const vendorRuleId = typeof r['vendorRuleId'] === 'string' ? (r['vendorRuleId'] as string).trim() : '';
        if (!vendorRuleId) continue; // part of the conflict key
        values.push({
          deviceId,
          pluginId,
          ruleType,
          vendorRuleId,
          position: typeof r['position'] === 'number' && Number.isFinite(r['position']) ? Math.trunc(r['position']) : 0,
          protocol: typeof r['protocol'] === 'string' ? (r['protocol'] as string).trim().toLowerCase() : '',
          sourceIp: typeof r['sourceIp'] === 'string' ? (r['sourceIp'] as string).trim() : '',
          destIp: typeof r['destIp'] === 'string' ? (r['destIp'] as string).trim() : '',
          sourcePort: typeof r['sourcePort'] === 'string' && (r['sourcePort'] as string).trim() !== '' ? (r['sourcePort'] as string).trim() : null,
          destPort: typeof r['destPort'] === 'string' && (r['destPort'] as string).trim() !== '' ? (r['destPort'] as string).trim() : null,
          action: typeof r['action'] === 'string' && (r['action'] as string).trim() !== '' ? (r['action'] as string).trim().toLowerCase() : 'other',
          enabled: r['enabled'] !== false, // absent/true = enabled; only explicit false disables
          description: typeof r['description'] === 'string' ? (r['description'] as string).trim() : '',
          scope: typeof r['scope'] === 'string' ? (r['scope'] as string).trim() : '',
          ipVersion: (() => {
            const v = typeof r['ipVersion'] === 'string' ? (r['ipVersion'] as string).trim().toLowerCase() : '';
            return v === 'v6' || v === 'both' ? v : 'v4'; // default v4 when absent
          })(),
          packets: typeof r['packets'] === 'number' && Number.isFinite(r['packets']) ? Math.trunc(r['packets']) : null,
          bytes: typeof r['bytes'] === 'number' && Number.isFinite(r['bytes']) ? Math.trunc(r['bytes']) : null,
          states: typeof r['states'] === 'number' && Number.isFinite(r['states']) ? Math.trunc(r['states']) : null,
          extra: r['extra'] && typeof r['extra'] === 'object' ? JSON.stringify(r['extra']) : '{}',
          collectedAt,
        });
      }
      // Same de-dup guard as the other inventory blocks.
      const fwByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        fwByKey.set(`${v.deviceId}|${v.pluginId}|${v.ruleType}|${v.vendorRuleId}`, v);
      }
      if (fwByKey.size > 0) {
        await db.insert(schema.firewallRules).values(Array.from(fwByKey.values())).onConflictDoUpdate({
          target: [schema.firewallRules.deviceId, schema.firewallRules.pluginId, schema.firewallRules.ruleType, schema.firewallRules.vendorRuleId],
          set: {
            position: sql`excluded.position`,
            protocol: sql`excluded.protocol`,
            sourceIp: sql`excluded."sourceIp"`,
            destIp: sql`excluded."destIp"`,
            sourcePort: sql`excluded."sourcePort"`,
            destPort: sql`excluded."destPort"`,
            action: sql`excluded.action`,
            enabled: sql`excluded.enabled`,
            description: sql`excluded.description`,
            scope: sql`excluded.scope`,
            ipVersion: sql`excluded."ipVersion"`,
            packets: sql`excluded.packets`,
            bytes: sql`excluded.bytes`,
            states: sql`excluded.states`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      // A rule deleted on the device must vanish from the page, not linger until
      // the 24h sweep. Keyed on ruleType|vendorRuleId pairs (see note above).
      const existingFwKeys = await db
        .select({ ruleType: schema.firewallRules.ruleType, vendorRuleId: schema.firewallRules.vendorRuleId })
        .from(schema.firewallRules)
        .where(and(eq(schema.firewallRules.deviceId, deviceId), eq(schema.firewallRules.pluginId, pluginId)));
      const seenFwKeys = new Set(values.map((v) => `${v.ruleType}|${v.vendorRuleId}`));
      const staleFw = existingFwKeys.filter(
        (k) => !seenFwKeys.has(`${k.ruleType}|${k.vendorRuleId}`)
      );
      if (staleFw.length > 0) {
        await db.delete(schema.firewallRules).where(
          and(
            eq(schema.firewallRules.deviceId, deviceId),
            eq(schema.firewallRules.pluginId, pluginId),
            or(...staleFw.map((k) => and(eq(schema.firewallRules.ruleType, k.ruleType), eq(schema.firewallRules.vendorRuleId, k.vendorRuleId))))
          )
        );
      }
    }

    // --- certificates (management HTTPS cert + SSH host key) -----------------
    // Same present-vs-absent contract as routes/firewallRules: a PRESENT-but-empty
    // array is authoritative ("this device reports no certificate endpoints right
    // now") so stale rows are wiped; an ABSENT key means "plugin doesn't report
    // certificates" and must not touch the table (24h sweep still applies).
    // Identity is `name` ("https:443"/"ssh:22") — one row per endpoint. After the
    // upsert we mirror expiry/invalidity into the notification center so users get
    // alerted when a cert expires or its chain fails validation (auto-resolved by
    // the notifications worker once renewed).
    const rawCertificates = Array.isArray(metrics['certificates']) ? (metrics['certificates'] as unknown[]) : null;
    if (rawCertificates !== null) {
      // Load the CURRENT rows BEFORE the upsert overwrites them: needed to seed
      // trustedFingerprint on first observation, detect fingerprint CHANGES
      // (critical notification + history row), and preserve trust across polls.
      const prevCerts = await db.query.certificates.findMany({
        where: and(eq(schema.certificates.deviceId, deviceId), eq(schema.certificates.pluginId, pluginId)),
      });
      const prevByName = new Map(prevCerts.map((r) => [r.name, r]));

      const values: {
        deviceId: string; pluginId: string; name: string; type: string; host: string; port: number | null;
        fingerprint: string | null; trustedFingerprint: string | null; commonName: string; subject: string; issuer: string; selfSigned: boolean;
        notBefore: string; notAfter: string; keyAlgorithm: string; keySizeBits: number | null; curveName: string | null;
        signatureAlgorithm: string; sanNames: string; serialNumber: string; valid: boolean | null; invalidReason: string | null;
        daysToExpiry: number | null; chainDaysToExpiry: number | null; chain: string; collectedAt: string;
      }[] = [];
      for (const raw of rawCertificates) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue; // part of the conflict key
        const type = typeof r['type'] === 'string' && (r['type'] as string).trim().toLowerCase() === 'ssh' ? 'ssh' : 'https';
        const cert = (r['cert'] ?? null) as Record<string, unknown> | null;
        const chainArr = Array.isArray(r['chain']) ? (r['chain'] as unknown[]) : [];
        const fingerprint = typeof r['fingerprint'] === 'string' && (r['fingerprint'] as string).trim() !== '' ? (r['fingerprint'] as string).trim() : null;
        // Trusted-fingerprint lifecycle: an EXISTING trust is never touched by
        // ingestion (a changed key stays a mismatch until the user accepts or
        // rolls it back); a FIRST observation seeds trust from the observed key
        // (TOFU — "if no certificate is known, save it and allow the connection").
        const prev = prevByName.get(name);
        let trustedFingerprint: string | null = null;
        if (fingerprint) {
          trustedFingerprint = prev?.trustedFingerprint ?? fingerprint;
        } else if (prev?.trustedFingerprint) {
          // No key readable this poll (endpoint down) — keep the old trust.
          trustedFingerprint = prev.trustedFingerprint;
        }
        values.push({
          deviceId,
          pluginId,
          name,
          type,
          host: typeof r['host'] === 'string' ? (r['host'] as string).trim() : '',
          port: typeof r['port'] === 'number' && Number.isFinite(r['port']) ? Math.trunc(r['port']) : null,
          fingerprint,
          trustedFingerprint,
          commonName: cert && typeof cert['commonName'] === 'string' ? (cert['commonName'] as string) : '',
          subject: cert && typeof cert['subject'] === 'string' ? (cert['subject'] as string) : '',
          issuer: cert && typeof cert['issuer'] === 'string' ? (cert['issuer'] as string) : '',
          selfSigned: !!(cert && cert['selfSigned'] === true),
          notBefore: cert && typeof cert['notBefore'] === 'string' ? (cert['notBefore'] as string) : '',
          notAfter: cert && typeof cert['notAfter'] === 'string' ? (cert['notAfter'] as string) : '',
          keyAlgorithm: cert && typeof cert['keyAlgorithm'] === 'string' ? (cert['keyAlgorithm'] as string) : '',
          keySizeBits: cert && typeof cert['keySizeBits'] === 'number' && Number.isFinite(cert['keySizeBits']) ? Math.trunc(cert['keySizeBits'] as number) : null,
          curveName: cert && typeof cert['curveName'] === 'string' ? (cert['curveName'] as string) : null,
          signatureAlgorithm: cert && typeof cert['signatureAlgorithm'] === 'string' ? (cert['signatureAlgorithm'] as string) : '',
          sanNames: Array.isArray(cert?.['sanNames']) ? JSON.stringify(cert['sanNames']) : '[]',
          serialNumber: cert && typeof cert['serialNumber'] === 'string' ? (cert['serialNumber'] as string) : '',
          valid: typeof r['valid'] === 'boolean' ? r['valid'] : null,
          invalidReason: typeof r['invalidReason'] === 'string' && (r['invalidReason'] as string).trim() !== '' ? (r['invalidReason'] as string).trim() : null,
          daysToExpiry: typeof r['daysToExpiry'] === 'number' && Number.isFinite(r['daysToExpiry']) ? Math.trunc(r['daysToExpiry'] as number) : null,
          chainDaysToExpiry: typeof r['chainDaysToExpiry'] === 'number' && Number.isFinite(r['chainDaysToExpiry']) ? Math.trunc(r['chainDaysToExpiry'] as number) : null,
          chain: JSON.stringify(chainArr),
          collectedAt,
        });
      }
      const certByName = new Map<string, typeof values[number]>();
      for (const v of values) certByName.set(`${v.deviceId}|${v.pluginId}|${v.name}`, v);
      if (certByName.size > 0) {
        await db.insert(schema.certificates).values(Array.from(certByName.values())).onConflictDoUpdate({
          target: [schema.certificates.deviceId, schema.certificates.pluginId, schema.certificates.name],
          set: {
            type: sql`excluded.type`,
            host: sql`excluded.host`,
            port: sql`excluded.port`,
            fingerprint: sql`excluded.fingerprint`,
            trustedFingerprint: sql`excluded."trustedFingerprint"`,
            commonName: sql`excluded."commonName"`,
            subject: sql`excluded.subject`,
            issuer: sql`excluded.issuer`,
            selfSigned: sql`excluded."selfSigned"`,
            notBefore: sql`excluded."notBefore"`,
            notAfter: sql`excluded."notAfter"`,
            keyAlgorithm: sql`excluded."keyAlgorithm"`,
            keySizeBits: sql`excluded."keySizeBits"`,
            curveName: sql`excluded."curveName"`,
            signatureAlgorithm: sql`excluded."signatureAlgorithm"`,
            sanNames: sql`excluded."sanNames"`,
            serialNumber: sql`excluded."serialNumber"`,
            valid: sql`excluded.valid`,
            invalidReason: sql`excluded."invalidReason"`,
            daysToExpiry: sql`excluded."daysToExpiry"`,
            chainDaysToExpiry: sql`excluded."chainDaysToExpiry"`,
            chain: sql`excluded.chain`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      // A cert endpoint removed on the device must vanish, not linger until sweep.
      const existingCertNames = await db
        .select({ name: schema.certificates.name })
        .from(schema.certificates)
        .where(and(eq(schema.certificates.deviceId, deviceId), eq(schema.certificates.pluginId, pluginId)));
      const seenCertNames = new Set(values.map((v) => v.name));
      const staleCerts = existingCertNames.filter((k) => !seenCertNames.has(k.name));
      if (staleCerts.length > 0) {
        await db.delete(schema.certificates).where(
          and(
            eq(schema.certificates.deviceId, deviceId),
            eq(schema.certificates.pluginId, pluginId),
            notInArray(schema.certificates.name, Array.from(seenCertNames))
          )
        );
      }

      // Certificate HISTORY — append-only audit of every fingerprint ever seen on
      // an endpoint. One row per (endpoint, fingerprint): first observation
      // inserts; re-observation refreshes lastSeenAt only. This is what lets the
      // Certificates page show "which key was used when" and makes a changed key
      // auditable even after it is accepted or rolled back.
      for (const v of values) {
        if (!v.fingerprint) continue;
        await db.insert(schema.certificateHistory).values({
          deviceId,
          pluginId,
          name: v.name,
          type: v.type,
          fingerprint: v.fingerprint,
          commonName: v.commonName,
          subject: v.subject,
          issuer: v.issuer,
          selfSigned: v.selfSigned,
          notBefore: v.notBefore,
          notAfter: v.notAfter,
          keyAlgorithm: v.keyAlgorithm,
          keySizeBits: v.keySizeBits,
          curveName: v.curveName,
          signatureAlgorithm: v.signatureAlgorithm,
          firstSeenAt: collectedAt,
          lastSeenAt: collectedAt,
        }).onConflictDoUpdate({
          target: [schema.certificateHistory.deviceId, schema.certificateHistory.pluginId, schema.certificateHistory.name, schema.certificateHistory.fingerprint],
          set: {
            commonName: sql`excluded."commonName"`,
            subject: sql`excluded.subject`,
            issuer: sql`excluded.issuer`,
            selfSigned: sql`excluded."selfSigned"`,
            notBefore: sql`excluded."notBefore"`,
            notAfter: sql`excluded."notAfter"`,
            keyAlgorithm: sql`excluded."keyAlgorithm"`,
            keySizeBits: sql`excluded."keySizeBits"`,
            curveName: sql`excluded."curveName"`,
            signatureAlgorithm: sql`excluded."signatureAlgorithm"`,
            lastSeenAt: sql`excluded."lastSeenAt"`,
          },
        });
      }

      // Fingerprint CHANGE DETECTION — the observed key differs from the TRUSTED
      // one (a re-key OR a possible MITM). Critical notification with a stable
      // dedupe key; it stays live while the mismatch persists and auto-resolves
      // once the user accepts the new key (or the old key returns).
      try {
        const deviceRow = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
        const deviceName = deviceRow?.name ?? null;
        for (const v of values) {
          if (!v.fingerprint || !v.trustedFingerprint) continue;
          if (v.fingerprint === v.trustedFingerprint) continue; // in sync — nothing to flag
          await emitNotification({
            severity: 'critical',
            source: 'device',
            title: `Certificate changed on ${deviceName ?? deviceId}`,
            message: `${v.commonName || v.name} (${v.name}) now presents a DIFFERENT key than UNM has trusted. ` +
              `Expected ${v.trustedFingerprint}, observed ${v.fingerprint}. Strict pinning refuses connections to this endpoint until the new key is accepted on the Certificates page.`,
            dedupeKey: `cert-change:${deviceId}:${v.name}`,
            deviceId,
            pluginId,
            context: { certName: v.name, type: v.type, expectedFingerprint: v.trustedFingerprint, observedFingerprint: v.fingerprint },
          });
        }
      } catch {
        // best-effort — never break the poll cycle over notifications.
      }

      // Mirror expiry/invalidity into the notification center (best-effort — a
      // notification failure must never break the poll cycle). Expired or
      // near-expiry certs and chain-invalid certs each carry a stable dedupe key;
      // the notifications worker auto-resolves them once renewed.
      try {
        const deviceRow = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
        const deviceName = deviceRow?.name ?? null;
        const warnDays = Number(await getEffectiveSettingValue('certExpiryWarnDays')) || 30;
        for (const v of values) {
          if (v.type !== 'https') continue; // ssh host keys have no expiry/chain
          let severity: 'warning' | 'critical' | null = null;
          let title = '';
          let message = '';
          const dn = v.commonName || v.name;
          if (v.daysToExpiry !== null && v.daysToExpiry < 0) {
            severity = 'critical';
            title = `Certificate expired on ${deviceName ?? deviceId}`;
            message = `${dn} (${v.name}) expired ${Math.abs(v.daysToExpiry)} day(s) ago.`;
          } else if (v.chainDaysToExpiry !== null && v.chainDaysToExpiry < 0) {
            severity = 'critical';
            title = `Certificate issuer expired on ${deviceName ?? deviceId}`;
            message = `${dn} (${v.name}) — an issuer in its chain is already expired.`;
          } else if (v.daysToExpiry !== null && v.daysToExpiry <= warnDays) {
            severity = 'warning';
            title = `Certificate expiring soon on ${deviceName ?? deviceId}`;
            message = `${dn} (${v.name}) expires in ${v.daysToExpiry} day(s).`;
          } else if (v.valid === false && v.invalidReason) {
            severity = 'critical';
            title = `Invalid certificate chain on ${deviceName ?? deviceId}`;
            message = `${dn} (${v.name}): ${v.invalidReason}`;
          }
          if (!severity) continue;
          await emitNotification({
            severity,
            source: 'device',
            title,
            message,
            dedupeKey: `cert-expiry:${deviceId}:${v.name}`,
            deviceId,
            pluginId,
            context: { certName: v.name, type: v.type, commonName: v.commonName, daysToExpiry: v.daysToExpiry },
          });
        }
      } catch {
        // best-effort — never break the poll cycle over notifications.
      }
    }

    // --- WiFi (SSIDs / per-channel airtime / associated clients) ------------
    const numOrNull = (v: unknown): number | null =>
      typeof v === 'number' && Number.isFinite(v) ? v : null;

    const rawWifiNetworks = Array.isArray(metrics['wifiNetworks']) ? (metrics['wifiNetworks'] as unknown[]) : [];
    if (rawWifiNetworks.length > 0) {
      const values: {
        deviceId: string; pluginId: string; name: string; band: string; channel: number | null;
        bssid: string | null; encryption: string | null; vlanId: number | null; ifc: string | null;
        collectedAt: string;
      }[] = [];
      for (const raw of rawWifiNetworks) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue;
        values.push({
          deviceId,
          pluginId,
          name,
          band: typeof r['band'] === 'string' ? (r['band'] as string).trim() : '',
          channel: numOrNull(r['channel']),
          bssid: typeof r['bssid'] === 'string' && (r['bssid'] as string).trim() !== '' ? (r['bssid'] as string).trim().toLowerCase() : null,
          encryption: typeof r['encryption'] === 'string' && (r['encryption'] as string).trim() !== '' ? (r['encryption'] as string).trim() : null,
          vlanId: numOrNull(r['vlanId']),
          ifc: typeof r['ifc'] === 'string' && (r['ifc'] as string).trim() !== '' ? (r['ifc'] as string).trim() : null,
          collectedAt,
        });
      }
      const wifiByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        wifiByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}|${v.band}`, v);
      }
      if (wifiByKey.size > 0) {
        await db.insert(schema.wifiSsids).values(Array.from(wifiByKey.values())).onConflictDoUpdate({
          target: [schema.wifiSsids.deviceId, schema.wifiSsids.pluginId, schema.wifiSsids.name, schema.wifiSsids.band],
          set: {
            channel: sql`excluded.channel`,
            bssid: sql`excluded.bssid`,
            encryption: sql`excluded.encryption`,
            vlanId: sql`excluded."vlanId"`,
            ifc: sql`excluded.ifc`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      // SSIDs are CONFIG objects — a removed network must vanish from the page.
      const seenWifiNames = new Set(values.map((v) => v.name));
      if (seenWifiNames.size > 0) {
        await db.delete(schema.wifiSsids)
          .where(and(
            eq(schema.wifiSsids.deviceId, deviceId),
            eq(schema.wifiSsids.pluginId, pluginId),
            notInArray(schema.wifiSsids.name, Array.from(seenWifiNames))
          ));
      }
    }

    const rawWifiAirtime = Array.isArray(metrics['wifiAirtime']) ? (metrics['wifiAirtime'] as unknown[]) : [];
    if (rawWifiAirtime.length > 0) {
      const values: { deviceId: string; pluginId: string; channel: number; utilizationPct: number | null; collectedAt: string }[] = [];
      for (const raw of rawWifiAirtime) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const ch = numOrNull(r['channel']);
        if (ch === null) continue; // channel is part of the conflict key
        values.push({ deviceId, pluginId, channel: Math.round(ch), utilizationPct: numOrNull(r['utilizationPct']), collectedAt });
      }
      const airByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        airByKey.set(`${v.deviceId}|${v.pluginId}|${v.channel}`, v);
      }
      if (airByKey.size > 0) {
        await db.insert(schema.wifiChannels).values(Array.from(airByKey.values())).onConflictDoUpdate({
          target: [schema.wifiChannels.deviceId, schema.wifiChannels.pluginId, schema.wifiChannels.channel],
          set: {
            utilizationPct: sql`excluded."utilizationPct"`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenAirtimeChannels = new Set(values.map((v) => v.channel));
      if (seenAirtimeChannels.size > 0) {
        await db.delete(schema.wifiChannels)
          .where(and(
            eq(schema.wifiChannels.deviceId, deviceId),
            eq(schema.wifiChannels.pluginId, pluginId),
            notInArray(schema.wifiChannels.channel, Array.from(seenAirtimeChannels))
          ));
      }
    }

    // Radios — noise floor + bandwidth for the spectrum view. Upserted by ifc;
    // a radio that disappears (e.g. disabled) is dropped with its row.
    const rawWifiRadios = Array.isArray(metrics['wifiRadios']) ? (metrics['wifiRadios'] as unknown[]) : [];
    if (rawWifiRadios.length > 0) {
      const values: {
        deviceId: string; pluginId: string; ifc: string; band: string; channel: number | null;
        bandwidthMhz: number | null; noiseFloorDbm: number | null; collectedAt: string;
      }[] = [];
      for (const raw of rawWifiRadios) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        values.push({
          deviceId,
          pluginId,
          ifc: typeof r['ifc'] === 'string' ? (r['ifc'] as string).trim() : '',
          band: typeof r['band'] === 'string' ? (r['band'] as string).trim() : '',
          channel: numOrNull(r['channel']),
          bandwidthMhz: numOrNull(r['bandwidthMhz']),
          noiseFloorDbm: numOrNull(r['noiseFloorDbm']),
          collectedAt,
        });
      }
      const radioByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        radioByKey.set(`${v.deviceId}|${v.pluginId}|${v.ifc}`, v);
      }
      if (radioByKey.size > 0) {
        await db.insert(schema.wifiRadios).values(Array.from(radioByKey.values())).onConflictDoUpdate({
          target: [schema.wifiRadios.deviceId, schema.wifiRadios.pluginId, schema.wifiRadios.ifc],
          set: {
            band: sql`excluded.band`,
            channel: sql`excluded.channel`,
            bandwidthMhz: sql`excluded."bandwidthMhz"`,
            noiseFloorDbm: sql`excluded."noiseFloorDbm"`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenRadioIfcs = new Set(values.map((v) => v.ifc));
      if (seenRadioIfcs.size > 0) {
        await db.delete(schema.wifiRadios)
          .where(and(
            eq(schema.wifiRadios.deviceId, deviceId),
            eq(schema.wifiRadios.pluginId, pluginId),
            notInArray(schema.wifiRadios.ifc, Array.from(seenRadioIfcs))
          ));
      }
    }

    // Neighbor networks — scanner-style list. Upserted by BSSID; neighbors that
    // left range are dropped each snapshot (the scan table is a live view).
    const rawWifiNeighbors = Array.isArray(metrics['wifiNeighbors']) ? (metrics['wifiNeighbors'] as unknown[]) : [];
    if (rawWifiNeighbors.length > 0) {
      const values: {
        deviceId: string; pluginId: string; bssid: string; ssid: string | null; band: string;
        channel: number | null; signalDbm: number | null; collectedAt: string;
      }[] = [];
      for (const raw of rawWifiNeighbors) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const bssid = typeof r['bssid'] === 'string' ? (r['bssid'] as string).trim().toLowerCase() : '';
        if (!bssid) continue; // BSSID is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          bssid,
          ssid: typeof r['ssid'] === 'string' && (r['ssid'] as string).trim() !== '' ? (r['ssid'] as string).trim() : null,
          band: typeof r['band'] === 'string' ? (r['band'] as string).trim() : '',
          channel: numOrNull(r['channel']),
          signalDbm: numOrNull(r['signalDbm']),
          collectedAt,
        });
      }
      const neighborByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        neighborByKey.set(`${v.deviceId}|${v.pluginId}|${v.bssid}`, v);
      }
      if (neighborByKey.size > 0) {
        await db.insert(schema.wifiNeighbors).values(Array.from(neighborByKey.values())).onConflictDoUpdate({
          target: [schema.wifiNeighbors.deviceId, schema.wifiNeighbors.pluginId, schema.wifiNeighbors.bssid],
          set: {
            ssid: sql`excluded.ssid`,
            band: sql`excluded.band`,
            channel: sql`excluded.channel`,
            signalDbm: sql`excluded."signalDbm"`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenBssids = new Set(values.map((v) => v.bssid));
      if (seenBssids.size > 0) {
        await db.delete(schema.wifiNeighbors)
          .where(and(
            eq(schema.wifiNeighbors.deviceId, deviceId),
            eq(schema.wifiNeighbors.pluginId, pluginId),
            notInArray(schema.wifiNeighbors.bssid, Array.from(seenBssids))
          ));
      }
    }

    // Associated WLAN clients — upserted by MAC (a roaming client keeps its
    // latest SSID/radio). Rows for stations that disappeared are dropped.
    const rawWifiClients = Array.isArray(metrics['wlanClients']) ? (metrics['wlanClients'] as unknown[]) : [];
    if (rawWifiClients.length > 0) {
      const values: {
        deviceId: string; pluginId: string; mac: string; ssid: string | null; ip: string | null;
        hostname: string | null; intf: string | null; signalDbm: number | null;
        txRateMbps: number | null; rxRateMbps: number | null; vlanId: number | null; lastSeenAt: string;
      }[] = [];
      for (const raw of rawWifiClients) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const mac = typeof r['mac'] === 'string' ? (r['mac'] as string).trim().toLowerCase() : '';
        if (!mac) continue; // MAC is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          mac,
          ssid: typeof r['ssid'] === 'string' && (r['ssid'] as string).trim() !== '' ? (r['ssid'] as string).trim() : null,
          ip: typeof r['ip'] === 'string' && (r['ip'] as string).trim() !== '' ? (r['ip'] as string).trim() : null,
          hostname: typeof r['hostname'] === 'string' && (r['hostname'] as string).trim() !== '' ? (r['hostname'] as string) : null,
          intf: typeof r['intf'] === 'string' && (r['intf'] as string).trim() !== '' ? (r['intf'] as string) : null,
          signalDbm: numOrNull(r['signalDbm']),
          txRateMbps: numOrNull(r['txRateMbps']),
          rxRateMbps: numOrNull(r['rxRateMbps']),
          vlanId: numOrNull(r['vlanId']),
          lastSeenAt: collectedAt,
        });
      }
      const clientByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        clientByKey.set(`${v.deviceId}|${v.pluginId}|${v.mac}`, v);
      }
      if (clientByKey.size > 0) {
        await db.insert(schema.wifiClients).values(Array.from(clientByKey.values())).onConflictDoUpdate({
          target: [schema.wifiClients.deviceId, schema.wifiClients.pluginId, schema.wifiClients.mac],
          set: {
            ssid: sql`excluded.ssid`,
            ip: sql`excluded.ip`,
            hostname: sql`excluded.hostname`,
            intf: sql`excluded.intf`,
            signalDbm: sql`excluded."signalDbm"`,
            txRateMbps: sql`excluded."txRateMbps"`,
            rxRateMbps: sql`excluded."rxRateMbps"`,
            vlanId: sql`excluded."vlanId"`,
            lastSeenAt: sql`excluded."lastSeenAt"`,
          },
        });
      }
      const seenClientMacs = new Set(values.map((v) => v.mac));
      if (seenClientMacs.size > 0) {
        await db.delete(schema.wifiClients)
          .where(and(
            eq(schema.wifiClients.deviceId, deviceId),
            eq(schema.wifiClients.pluginId, pluginId),
            notInArray(schema.wifiClients.mac, Array.from(seenClientMacs))
          ));
      }
    }

    // --- ports (network interfaces with live state) -------------------------
    // Ports are CONFIG objects — a removed interface must vanish from the table,
    // not linger until the 24h sweep. Same upsert + delete-on-absent pattern as
    // tunnels: an ABSENT key means "plugin doesn't report ports" (no wipe); a
    // present-but-EMPTY array is authoritative (wipes this device+plugin's rows).
    const rawPorts = Array.isArray(metrics['ports']) ? (metrics['ports'] as unknown[]) : null;
    if (rawPorts !== null) {
      const values: {
        deviceId: string; pluginId: string; name: string; status: string; speed: string | null;
        duplex: string | null; vlanId: number | null; poe: string | null; extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawPorts) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue; // name is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          name,
          status: typeof r['status'] === 'string' && (r['status'] as string).trim() !== '' ? (r['status'] as string).trim().toLowerCase() : 'unknown',
          speed: typeof r['speed'] === 'string' && (r['speed'] as string).trim() !== '' ? (r['speed'] as string).trim() : null,
          duplex: typeof r['duplex'] === 'string' && (r['duplex'] as string).trim() !== '' ? (r['duplex'] as string).trim() : null,
          vlanId: numOrNull(r['vlanId']),
          poe: typeof r['poe'] === 'string' && (r['poe'] as string).trim() !== '' ? (r['poe'] as string).trim() : null,
          extra: r['extra'] && typeof r['extra'] === 'object' ? JSON.stringify(r['extra']) : '{}',
          collectedAt,
        });
      }
      // Same de-dup guard as the other inventory blocks.
      const portByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        portByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}`, v);
      }
      if (portByKey.size > 0) {
        await db.insert(schema.devicePorts).values(Array.from(portByKey.values())).onConflictDoUpdate({
          target: [schema.devicePorts.deviceId, schema.devicePorts.pluginId, schema.devicePorts.name],
          set: {
            status: sql`excluded.status`,
            speed: sql`excluded.speed`,
            duplex: sql`excluded.duplex`,
            vlanId: sql`excluded."vlanId"`,
            poe: sql`excluded.poe`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenPortNames = new Set(values.map((v) => v.name));
      if (seenPortNames.size > 0) {
        await db.delete(schema.devicePorts)
          .where(and(
            eq(schema.devicePorts.deviceId, deviceId),
            eq(schema.devicePorts.pluginId, pluginId),
            notInArray(schema.devicePorts.name, Array.from(seenPortNames))
          ));
      }
    }

    // --- Storage (filesystems/pools/datasets + physical disks) --------------
    // Generic keys — any plugin may emit them:
    //   filesystems[] { name, type?, mountpoint?, sizeBytes?, usedBytes?, freeBytes?, status?, parent?, extra? }
    //   disks[]       { name, model?, serial?, capacityBytes?, rotationRate?, health?, poolName?, extra? }
    // Both are CONFIG objects → upsert-per-poll + delete-on-absent (a removed
    // dataset/disk must vanish from the page, not linger until the 24h sweep).
    // `extra` is a plugin-specific JSON object stored verbatim for the webapp's
    // expandable rows and future config/state endpoints; non-object values are
    // dropped defensively (a corrupt row must not break ingestion).
    const extraOf = (r: Record<string, unknown>): string => {
      const e = r['extra'];
      if (!e || typeof e !== 'object' || Array.isArray(e)) return '{}';
      try {
        return JSON.stringify(e);
      } catch {
        return '{}';
      }
    };
    const rawFilesystems = Array.isArray(metrics['filesystems']) ? (metrics['filesystems'] as unknown[]) : null;
    if (rawFilesystems !== null) {
      const values: {
        deviceId: string; pluginId: string; name: string; type: string; mountpoint: string | null;
        sizeBytes: number | null; usedBytes: number | null; freeBytes: number | null;
        status: string; parent: string | null; extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawFilesystems) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue;
        values.push({
          deviceId,
          pluginId,
          name,
          type: typeof r['type'] === 'string' && (r['type'] as string).trim() !== '' ? (r['type'] as string).trim().toLowerCase() : 'other',
          mountpoint: typeof r['mountpoint'] === 'string' && (r['mountpoint'] as string).trim() !== '' ? (r['mountpoint'] as string).trim() : null,
          sizeBytes: numOrNull(r['sizeBytes']),
          usedBytes: numOrNull(r['usedBytes']),
          freeBytes: numOrNull(r['freeBytes']),
          status: typeof r['status'] === 'string' && (r['status'] as string).trim() !== '' ? (r['status'] as string).trim().toLowerCase() : 'unknown',
          parent: typeof r['parent'] === 'string' && (r['parent'] as string).trim() !== '' ? (r['parent'] as string).trim() : null,
          extra: extraOf(r),
          collectedAt,
        });
      }
      const fsByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        fsByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}`, v);
      }
      if (fsByKey.size > 0) {
        await db.insert(schema.storageFilesystems).values(Array.from(fsByKey.values())).onConflictDoUpdate({
          target: [schema.storageFilesystems.deviceId, schema.storageFilesystems.pluginId, schema.storageFilesystems.name],
          set: {
            type: sql`excluded.type`,
            mountpoint: sql`excluded.mountpoint`,
            sizeBytes: sql`excluded."sizeBytes"`,
            usedBytes: sql`excluded."usedBytes"`,
            freeBytes: sql`excluded."freeBytes"`,
            status: sql`excluded.status`,
            parent: sql`excluded.parent`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenFsNames = new Set(values.map((v) => v.name));
      if (seenFsNames.size > 0) {
        await db.delete(schema.storageFilesystems)
          .where(and(
            eq(schema.storageFilesystems.deviceId, deviceId),
            eq(schema.storageFilesystems.pluginId, pluginId),
            notInArray(schema.storageFilesystems.name, Array.from(seenFsNames))
          ));
      }
    }

    const rawDisks = Array.isArray(metrics['disks']) ? (metrics['disks'] as unknown[]) : null;
    if (rawDisks !== null) {
      const values: {
        deviceId: string; pluginId: string; name: string; model: string | null; serial: string | null;
        capacityBytes: number | null; rotationRate: string; health: string; poolName: string | null;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawDisks) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue;
        values.push({
          deviceId,
          pluginId,
          name,
          model: typeof r['model'] === 'string' && (r['model'] as string).trim() !== '' ? (r['model'] as string).trim() : null,
          serial: typeof r['serial'] === 'string' && (r['serial'] as string).trim() !== '' ? (r['serial'] as string).trim() : null,
          capacityBytes: numOrNull(r['capacityBytes']),
          rotationRate: typeof r['rotationRate'] === 'string' && (r['rotationRate'] as string).trim() !== '' ? (r['rotationRate'] as string).trim().toLowerCase() : 'unknown',
          health: typeof r['health'] === 'string' && (r['health'] as string).trim() !== '' ? (r['health'] as string).trim().toLowerCase() : 'unknown',
          poolName: typeof r['poolName'] === 'string' && (r['poolName'] as string).trim() !== '' ? (r['poolName'] as string).trim() : null,
          extra: extraOf(r),
          collectedAt,
        });
      }
      const diskByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        diskByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}`, v);
      }
      if (diskByKey.size > 0) {
        await db.insert(schema.storageDisks).values(Array.from(diskByKey.values())).onConflictDoUpdate({
          target: [schema.storageDisks.deviceId, schema.storageDisks.pluginId, schema.storageDisks.name],
          set: {
            model: sql`excluded.model`,
            serial: sql`excluded.serial`,
            capacityBytes: sql`excluded."capacityBytes"`,
            rotationRate: sql`excluded."rotationRate"`,
            health: sql`excluded.health`,
            poolName: sql`excluded."poolName"`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenDiskNames = new Set(values.map((v) => v.name));
      if (seenDiskNames.size > 0) {
        await db.delete(schema.storageDisks)
          .where(and(
            eq(schema.storageDisks.deviceId, deviceId),
            eq(schema.storageDisks.pluginId, pluginId),
            notInArray(schema.storageDisks.name, Array.from(seenDiskNames))
          ));
      }
    }

    // --- Shares (SMB/CIFS, NFS, iSCSI, NVMe-oF exports) ---------------------
    // Generic key — any plugin may emit it:
    //   shares[] { name, type?, path?, status?, sessionCount?, extra? }
    // CONFIG objects → upsert-per-poll + delete-on-absent (a share removed on the
    // device must vanish from the Shares page, not linger until the 24h sweep).
    // `type` is part of the conflict key so two protocols sharing a name coexist.
    const rawShares = Array.isArray(metrics['shares']) ? (metrics['shares'] as unknown[]) : null;
    if (rawShares !== null) {
      const values: {
        deviceId: string; pluginId: string; name: string; type: string; path: string | null;
        status: string; sessionCount: number | null; extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawShares) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        const type = typeof r['type'] === 'string' && (r['type'] as string).trim() !== '' ? (r['type'] as string).trim().toLowerCase() : 'other';
        if (!name) continue; // name is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          name,
          type,
          path: typeof r['path'] === 'string' && (r['path'] as string).trim() !== '' ? (r['path'] as string).trim() : null,
          status: typeof r['status'] === 'string' && (r['status'] as string).trim() !== '' ? (r['status'] as string).trim().toLowerCase() : 'unknown',
          sessionCount: numOrNull(r['sessionCount']),
          extra: extraOf(r),
          collectedAt,
        });
      }
      const shareByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        shareByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}|${v.type}`, v);
      }
      if (shareByKey.size > 0) {
        await db.insert(schema.shares).values(Array.from(shareByKey.values())).onConflictDoUpdate({
          target: [schema.shares.deviceId, schema.shares.pluginId, schema.shares.name, schema.shares.type],
          set: {
            path: sql`excluded.path`,
            status: sql`excluded.status`,
            sessionCount: sql`excluded."sessionCount"`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      // A share deleted on the device must vanish — drop rows this snapshot no
      // longer reports (only when the key is present at all).
      const seenShareKeys = new Set(values.map((v) => `${v.name}|${v.type}`));
      if (seenShareKeys.size > 0) {
        await db.delete(schema.shares)
          .where(and(
            eq(schema.shares.deviceId, deviceId),
            eq(schema.shares.pluginId, pluginId),
            notInArray(sql`${schema.shares.name} || '|' || ${schema.shares.type}`, Array.from(seenShareKeys))
          ));
      }
    }

    // --- Share sessions (live CIFS/SMB + NFS client connections) ------------
    // Generic key — any plugin may emit it:
    //   shareSessions[] { type?, shareName, clientAddress?, user?, uptimeSeconds? }
    // LIVE state, not config → REPLACED wholesale per device+plugin each poll
    // (delete-all-then-insert). A session that closed simply does not reappear.
    // An ABSENT key means "plugin doesn't report sessions" (no wipe); a present
    // array — even empty — is authoritative for this device+plugin.
    const rawShareSessions = Array.isArray(metrics['shareSessions']) ? (metrics['shareSessions'] as unknown[]) : null;
    if (rawShareSessions !== null) {
      await db.delete(schema.shareSessions).where(and(
        eq(schema.shareSessions.deviceId, deviceId),
        eq(schema.shareSessions.pluginId, pluginId),
      ));
      const values: {
        deviceId: string; pluginId: string; type: string; shareName: string; clientAddress: string;
        user: string | null; uptimeSeconds: number | null; collectedAt: string;
      }[] = [];
      for (const raw of rawShareSessions) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const shareName = typeof r['shareName'] === 'string' ? (r['shareName'] as string).trim() : '';
        if (!shareName) continue; // shareName is required to be useful
        values.push({
          deviceId,
          pluginId,
          type: typeof r['type'] === 'string' && (r['type'] as string).trim() !== '' ? (r['type'] as string).trim().toLowerCase() : 'smb',
          shareName,
          clientAddress: typeof r['clientAddress'] === 'string' ? (r['clientAddress'] as string).trim() : '',
          user: typeof r['user'] === 'string' && (r['user'] as string).trim() !== '' ? (r['user'] as string).trim() : null,
          uptimeSeconds: numOrNull(r['uptimeSeconds']),
          collectedAt,
        });
      }
      if (values.length > 0) {
        await db.insert(schema.shareSessions).values(values);
      }
    }

    // --- Containers (Apps) --------------------------------------------------
    // Generic key — any plugin may emit it:
    //   containers[] { name, state?, image?, version?, upgradeAvailable?, extra? }
    // CONFIG objects → upsert-per-poll + delete-on-absent (an uninstalled app
    // must vanish from the page, not linger until the 24h sweep). `extra` is a
    // plugin-specific JSON object stored verbatim (networks[], ips[], ports[],
    // per-service detail) — same contract as storage_filesystems.extra.
    //
    // startedAt: the TrueNAS public API exposes NO container start-time, so UNM
    // tracks it from observed state transitions instead. When a row is RUNNING
    // and was NOT RUNNING on the previous poll (a transition, or our first
    // observation of it), we stamp collectedAt; while it stays RUNNING we keep
    // the existing value; when it leaves RUNNING we clear it to NULL. The result
    // is a lower-bound "running since" that resets correctly after restarts and
    // grows toward accuracy for apps UNM started watching mid-run (the UI labels
    // it as UNM-observed, not the container's true start time).
    const rawContainers = Array.isArray(metrics['containers']) ? (metrics['containers'] as unknown[]) : null;
    if (rawContainers !== null) {
      // Previous state + startedAt per app name for THIS device+plugin — needed
      // to detect RUNNING transitions without a second write round-trip.
      const prevRows = await db.query.containers.findMany({
        where: and(eq(schema.containers.deviceId, deviceId), eq(schema.containers.pluginId, pluginId)),
      });
      const prevByName = new Map<string, { state: string; startedAt: string | null }>();
      for (const p of prevRows) prevByName.set(p.name, { state: p.state, startedAt: p.startedAt });

      // Plugin-provided start times (e.g. TrueNAS `docker inspect` over SSH)
      // are the REAL container start — they win over transition tracking.
      const pluginStartedAt = new Map<string, string>();
      for (const raw of rawContainers) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const n = typeof r['name'] === 'string' ? r['name'].trim() : '';
        const s = typeof r['startedAt'] === 'string' && (r['startedAt'] as string).trim() !== '' ? (r['startedAt'] as string) : null;
        if (n && s) pluginStartedAt.set(n, s);
      }

      const values: {
        deviceId: string; pluginId: string; name: string; state: string; image: string | null;
        version: string | null; upgradeAvailable: boolean | null; startedAt: string | null;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawContainers) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue;
        const state = typeof r['state'] === 'string' && (r['state'] as string).trim() !== '' ? (r['state'] as string).trim().toUpperCase() : 'UNKNOWN';
        const prev = prevByName.get(name);
        let startedAt: string | null = null;
        if (state === 'RUNNING') {
          // Priority 1: the plugin's REAL start time (docker inspect over SSH)
          // — authoritative, resets correctly after restarts.
          const realStart = pluginStartedAt.get(name);
          if (realStart) {
            startedAt = realStart;
          } else {
            // Priority 2: transition tracking fallback. Continuous RUNNING with
            // an existing stamp → keep it; a fresh transition or first
            // observation → stamp now.
            startedAt = prev && prev.state === 'RUNNING' && prev.startedAt ? prev.startedAt : collectedAt;
          }
        }
        values.push({
          deviceId,
          pluginId,
          name,
          state,
          image: typeof r['image'] === 'string' && (r['image'] as string).trim() !== '' ? (r['image'] as string).trim() : null,
          version: typeof r['version'] === 'string' && (r['version'] as string).trim() !== '' ? (r['version'] as string).trim() : null,
          upgradeAvailable: typeof r['upgradeAvailable'] === 'boolean' ? (r['upgradeAvailable'] as boolean) : null,
          startedAt,
          extra: extraOf(r),
          collectedAt,
        });
      }
      const contByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        contByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}`, v);
      }
      if (contByKey.size > 0) {
        await db.insert(schema.containers).values(Array.from(contByKey.values())).onConflictDoUpdate({
          target: [schema.containers.deviceId, schema.containers.pluginId, schema.containers.name],
          set: {
            state: sql`excluded.state`,
            image: sql`excluded.image`,
            version: sql`excluded.version`,
            upgradeAvailable: sql`excluded."upgradeAvailable"`,
            startedAt: sql`excluded."startedAt"`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenContNames = new Set(values.map((v) => v.name));
      if (seenContNames.size > 0) {
        await db.delete(schema.containers)
          .where(and(
            eq(schema.containers.deviceId, deviceId),
            eq(schema.containers.pluginId, pluginId),
            notInArray(schema.containers.name, Array.from(seenContNames))
          ));
      } else if (rawContainers.length === 0) {
        // Present-but-EMPTY is the authoritative wipe: delete ALL rows for this
        // device+plugin. (The size>0 guard above must NOT swallow this case —
        // otherwise a plugin that stops reporting containers, e.g. via its
        // "Enable App/Container collection" option off, would leave stale rows.)
        await db.delete(schema.containers)
          .where(and(
            eq(schema.containers.deviceId, deviceId),
            eq(schema.containers.pluginId, pluginId)
          ));
      }
    }

    // --- Docker images ------------------------------------------------------
    // Generic key — any plugin may emit it:
    //   images[] { name, sizeBytes?, createdAt?, updateAvailable?, dangling?, extra? }
    // Same CONFIG-object lifecycle as containers (upsert-per-poll + delete-on-
    // absent, present-but-empty = authoritative wipe): an image removed from the
    // host must vanish from the Containers page's images panel on the next poll.
    const rawImages = Array.isArray(metrics['images']) ? (metrics['images'] as unknown[]) : null;
    if (rawImages !== null) {
      const values: {
        deviceId: string; pluginId: string; name: string; sizeBytes: number | null;
        createdAt: string | null; updateAvailable: boolean | null; dangling: boolean;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawImages) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue; // name is part of the conflict key
        values.push({
          deviceId,
          pluginId,
          name,
          sizeBytes: numOrNull(r['sizeBytes']),
          createdAt: typeof r['createdAt'] === 'string' && (r['createdAt'] as string).trim() !== '' ? (r['createdAt'] as string) : null,
          updateAvailable: typeof r['updateAvailable'] === 'boolean' ? (r['updateAvailable'] as boolean) : null,
          dangling: r['dangling'] === true,
          extra: extraOf(r),
          collectedAt,
        });
      }
      const imgByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        imgByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}`, v);
      }
      if (imgByKey.size > 0) {
        await db.insert(schema.dockerImages).values(Array.from(imgByKey.values())).onConflictDoUpdate({
          target: [schema.dockerImages.deviceId, schema.dockerImages.pluginId, schema.dockerImages.name],
          set: {
            sizeBytes: sql`excluded."sizeBytes"`,
            createdAt: sql`excluded."createdAt"`,
            updateAvailable: sql`excluded."updateAvailable"`,
            dangling: sql`excluded.dangling`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenImgNames = new Set(values.map((v) => v.name));
      if (seenImgNames.size > 0) {
        await db.delete(schema.dockerImages)
          .where(and(
            eq(schema.dockerImages.deviceId, deviceId),
            eq(schema.dockerImages.pluginId, pluginId),
            notInArray(schema.dockerImages.name, Array.from(seenImgNames))
          ));
      } else if (rawImages.length === 0) {
        // Present-but-EMPTY is the authoritative wipe — same contract as containers.
        await db.delete(schema.dockerImages)
          .where(and(
            eq(schema.dockerImages.deviceId, deviceId),
            eq(schema.dockerImages.pluginId, pluginId)
          ));
      }
    }

    // --- VMs -----------------------------------------------------------------
    // Generic key — any plugin may emit it (TrueNAS SCALE today; a future
    // Proxmox or other hypervisor plugin can ingest the same table):
    //   vms[] { name, state?, vcpus?, memoryMiB?, archType?, extra? }
    // Same CONFIG-object lifecycle as containers: upsert-per-poll +
    // delete-on-absent (a deleted VM must vanish from the page), present-but-
    // empty = authoritative wipe. `extra` is a plugin-specific JSON object
    // stored verbatim — nics[] {mac, type?, nicAttach?}, disks[], description,
    // uuid, autostart, ... The NIC MACs are what feed the Hosts page (source
    // 'vm', via the vmHosts key above).
    const rawVms = Array.isArray(metrics['vms']) ? (metrics['vms'] as unknown[]) : null;
    if (rawVms !== null) {
      // Previous state per VM name for THIS device+plugin — needed to track
      // RUNNING transitions the same way containers do.
      const prevVmRows = await db.query.vms.findMany({
        where: and(eq(schema.vms.deviceId, deviceId), eq(schema.vms.pluginId, pluginId)),
      });
      const prevVmByName = new Map<string, { state: string; startedAt: string | null }>();
      for (const p of prevVmRows) prevVmByName.set(p.name, { state: p.state, startedAt: p.startedAt });

      const values: {
        deviceId: string; pluginId: string; name: string; state: string; vcpus: number | null;
        memoryMiB: number | null; archType: string | null; startedAt: string | null;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawVms) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue; // name is part of the conflict key
        const state = typeof r['state'] === 'string' && (r['state'] as string).trim() !== '' ? (r['state'] as string).trim().toUpperCase() : 'UNKNOWN';
        // RUNNING-period tracking — same contract as containers: stamp on a
        // fresh transition / first observation, keep while continuously
        // RUNNING, clear when it leaves RUNNING.
        const prev = prevVmByName.get(name);
        let startedAt: string | null = null;
        if (state === 'RUNNING') {
          startedAt = prev && prev.state === 'RUNNING' && prev.startedAt ? prev.startedAt : collectedAt;
        }
        values.push({
          deviceId,
          pluginId,
          name,
          state,
          vcpus: numOrNull(r['vcpus']),
          memoryMiB: numOrNull(r['memoryMiB']),
          archType: typeof r['archType'] === 'string' && (r['archType'] as string).trim() !== '' ? (r['archType'] as string).trim() : null,
          startedAt,
          extra: extraOf(r),
          collectedAt,
        });
      }
      const vmByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        vmByKey.set(`${v.deviceId}|${v.pluginId}|${v.name}`, v);
      }
      if (vmByKey.size > 0) {
        await db.insert(schema.vms).values(Array.from(vmByKey.values())).onConflictDoUpdate({
          target: [schema.vms.deviceId, schema.vms.pluginId, schema.vms.name],
          set: {
            state: sql`excluded.state`,
            vcpus: sql`excluded.vcpus`,
            memoryMiB: sql`excluded."memoryMiB"`,
            archType: sql`excluded."archType"`,
            startedAt: sql`excluded."startedAt"`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenVmNames = new Set(values.map((v) => v.name));
      if (seenVmNames.size > 0) {
        await db.delete(schema.vms)
          .where(and(
            eq(schema.vms.deviceId, deviceId),
            eq(schema.vms.pluginId, pluginId),
            notInArray(schema.vms.name, Array.from(seenVmNames))
          ));
      } else if (rawVms.length === 0) {
        // Present-but-EMPTY is the authoritative wipe — same contract as containers.
        await db.delete(schema.vms)
          .where(and(
            eq(schema.vms.deviceId, deviceId),
            eq(schema.vms.pluginId, pluginId)
          ));
      }
    }

    // --- GPUs (DeviceDetail GPU cards) --------------------------------------
    // Generic key — any plugin may emit it:
    //   gpus[] { name, vendor?, slot, driver?, driverVersion?, vramBytes?,
    //            utilPercent?, memUtilPercent?, tempCelsius?, powerWatts?,
    //            coreClockMhz?, maxCoreClockMhz?, extra? }
    // Same CONFIG-object lifecycle as containers/vms: upsert-per-poll +
    // delete-on-absent (a removed card must vanish), present-but-empty =
    // authoritative wipe. `slot` (PCI address) is the stable identity and part
    // of the PK; live counters are refreshed in place on every inventory poll.
    const rawGpus = Array.isArray(metrics['gpus']) ? (metrics['gpus'] as unknown[]) : null;
    if (rawGpus !== null) {
      const gpuNumOrNull = (v: unknown): number | null =>
        typeof v === 'number' && Number.isFinite(v) ? v : null;
      const gpuIntOrNull = (v: unknown): number | null =>
        typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : null;
      const values: {
        deviceId: string; pluginId: string; name: string; vendor: string; slot: string;
        driver: string | null; driverVersion: string | null; vramBytes: number | null;
        utilPercent: number | null; memUtilPercent: number | null; tempCelsius: number | null;
        powerWatts: number | null; coreClockMhz: number | null; maxCoreClockMhz: number | null;
        extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawGpus) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        // slot is the stable identity + part of the conflict key — a row without
        // one cannot be upserted or matched, so skip it (defensive: a plugin bug
        // must not wipe this device's GPU rows).
        const slot = typeof r['slot'] === 'string' ? (r['slot'] as string).trim() : '';
        if (!slot) continue;
        values.push({
          deviceId,
          pluginId,
          name: typeof r['name'] === 'string' && (r['name'] as string).trim() !== '' ? (r['name'] as string).trim() : slot,
          vendor: typeof r['vendor'] === 'string' && (r['vendor'] as string).trim() !== '' ? (r['vendor'] as string).trim().toUpperCase() : 'UNKNOWN',
          slot,
          driver: typeof r['driver'] === 'string' && (r['driver'] as string).trim() !== '' ? (r['driver'] as string).trim() : null,
          driverVersion: typeof r['driverVersion'] === 'string' && (r['driverVersion'] as string).trim() !== '' ? (r['driverVersion'] as string).trim() : null,
          vramBytes: gpuNumOrNull(r['vramBytes']),
          utilPercent: gpuIntOrNull(r['utilPercent']),
          memUtilPercent: gpuIntOrNull(r['memUtilPercent']),
          tempCelsius: gpuIntOrNull(r['tempCelsius']),
          powerWatts: gpuNumOrNull(r['powerWatts']),
          coreClockMhz: gpuIntOrNull(r['coreClockMhz']),
          maxCoreClockMhz: gpuIntOrNull(r['maxCoreClockMhz']),
          extra: extraOf(r),
          collectedAt,
        });
      }
      const gpuByKey = new Map<string, typeof values[number]>();
      for (const v of values) {
        gpuByKey.set(`${v.deviceId}|${v.pluginId}|${v.slot}`, v);
      }
      if (gpuByKey.size > 0) {
        await db.insert(schema.gpus).values(Array.from(gpuByKey.values())).onConflictDoUpdate({
          target: [schema.gpus.deviceId, schema.gpus.pluginId, schema.gpus.slot],
          set: {
            name: sql`excluded.name`,
            vendor: sql`excluded.vendor`,
            driver: sql`excluded.driver`,
            "driverVersion": sql`excluded."driverVersion"`,
            "vramBytes": sql`excluded."vramBytes"`,
            "utilPercent": sql`excluded."utilPercent"`,
            "memUtilPercent": sql`excluded."memUtilPercent"`,
            "tempCelsius": sql`excluded."tempCelsius"`,
            "powerWatts": sql`excluded."powerWatts"`,
            "coreClockMhz": sql`excluded."coreClockMhz"`,
            "maxCoreClockMhz": sql`excluded."maxCoreClockMhz"`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
      }
      const seenGpuSlots = new Set(values.map((v) => v.slot));
      if (seenGpuSlots.size > 0) {
        await db.delete(schema.gpus)
          .where(and(
            eq(schema.gpus.deviceId, deviceId),
            eq(schema.gpus.pluginId, pluginId),
            notInArray(schema.gpus.slot, Array.from(seenGpuSlots))
          ));
      } else if (rawGpus.length === 0) {
        // Present-but-EMPTY is the authoritative wipe — same contract as containers.
        await db.delete(schema.gpus)
          .where(and(
            eq(schema.gpus.deviceId, deviceId),
            eq(schema.gpus.pluginId, pluginId)
          ));
      }
    }


    // --- Security checks (Security page) --------------------------------------
    // Generic key — any plugin advertising capability 'securityChecks' may emit it:
    //   securityChecks[] { name, kind, status, detail?, count?, extra? }
    // Same lifecycle as device_updates. Only ACTIONABLE findings persist: rows with
    // status 'ok' are dropped (a clean check is the absence of a row), so the table
    // holds warnings/criticals only and the nav badge counts real issues. A present
    // array — even empty — is authoritative for this device+plugin; an ABSENT key
    // (metrics-only poll, or collection failed) never wipes stored rows.
    const rawSecurityChecks = Array.isArray(metrics['securityChecks']) ? (metrics['securityChecks'] as unknown[]) : null;
    if (rawSecurityChecks !== null) {
      const secNumOrNull = (v: unknown): number | null =>
        typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : null;
      const secExtraOf = (r: Record<string, unknown>): string => {
        const e = r['extra'];
        if (!e || typeof e !== 'object' || Array.isArray(e)) return '{}';
        try {
          return JSON.stringify(e);
        } catch {
          return '{}';
        }
      };
      const values: {
        deviceId: string; pluginId: string; kind: string; name: string;
        status: string; detail: string | null; count: number | null; extra: string; collectedAt: string;
      }[] = [];
      for (const raw of rawSecurityChecks) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        // Only non-'ok' rows persist — 'ok' means "no issue" and is the absence of a row.
        // 'info' covers positive/neutral states worth surfacing (e.g. rate limiting active).
        const status = r['status'];
        if (status !== 'info' && status !== 'warning' && status !== 'critical') continue;
        const name = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
        if (!name) continue; // name is part of the conflict key
        const kind = typeof r['kind'] === 'string' && (r['kind'] as string).trim() !== '' ? (r['kind'] as string).trim() : 'other';
        values.push({
          deviceId,
          pluginId,
          kind,
          name,
          status: status as string,
          detail: typeof r['detail'] === 'string' && (r['detail'] as string).trim() !== '' ? (r['detail'] as string).slice(0, 2_048) : null,
          count: secNumOrNull(r['count']),
          extra: secExtraOf(r),
          collectedAt,
        });
      }
      if (values.length > 0) {
        const byKey = new Map<string, typeof values[number]>();
        for (const v of values) byKey.set(`${v.kind}|${v.name}`, v);
        await db.insert(schema.deviceSecurityChecks).values(Array.from(byKey.values())).onConflictDoUpdate({
          target: [schema.deviceSecurityChecks.deviceId, schema.deviceSecurityChecks.pluginId, schema.deviceSecurityChecks.kind, schema.deviceSecurityChecks.name],
          set: {
            status: sql`excluded."status"`,
            detail: sql`excluded."detail"`,
            count: sql`excluded."count"`,
            extra: sql`excluded.extra`,
            collectedAt: sql`excluded."collectedAt"`,
          },
        });
        const seenKeys = new Set(values.map((v) => `${v.kind}|${v.name}`));
        await db.delete(schema.deviceSecurityChecks)
          .where(and(
            eq(schema.deviceSecurityChecks.deviceId, deviceId),
            eq(schema.deviceSecurityChecks.pluginId, pluginId),
            notInArray(sql`"kind" || '|' || name`, Array.from(seenKeys))
          ));
      } else {
        // Present-but-no-findings is the authoritative wipe — same contract as updates.
        await db.delete(schema.deviceSecurityChecks)
          .where(and(
            eq(schema.deviceSecurityChecks.deviceId, deviceId),
            eq(schema.deviceSecurityChecks.pluginId, pluginId)
          ));
      }
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(
      `[telemetry] inventory ingestion failed for device ${deviceId} via plugin ${pluginId}:`,
      (err as Error).message
    );
  }
}

/**
 * Drops inventory rows not refreshed within INVENTORY_STALE_AFTER_MS so
 * offline devices don't accumulate stale networks/hosts in the cross-device
 * views. ISO-8601 strings compare correctly lexicographically.
 */
async function sweepStaleInventory(inventoryWindowMs: number): Promise<void> {
  // Adaptive cutoff: with a long inventory window (e.g. 12 h) the plain 24 h
  // floor would self-sweep rows of perfectly healthy devices — require at least
  // three full windows of silence before a row counts as stale.
  const staleAfterMs = Math.max(INVENTORY_STALE_AFTER_MS, 3 * inventoryWindowMs);
  const cutoff = new Date(Date.now() - staleAfterMs).toISOString();
  // Disabled devices are intentionally not polled — their inventory rows must
  // survive the stale sweep (re-enabling a device restores its views without
  // waiting for fresh data).
  const disabledIds = (
    await db.query.devices.findMany({ where: eq(schema.devices.enabled, false) })
  ).map((d) => d.id);
  if (disabledIds.length > 0) {
    await db.delete(schema.hosts).where(and(lt(schema.hosts.lastSeenAt, cutoff), notInArray(schema.hosts.deviceId, disabledIds)));
    await db.delete(schema.networks).where(and(lt(schema.networks.collectedAt, cutoff), notInArray(schema.networks.deviceId, disabledIds)));
    await db.delete(schema.devicePorts).where(and(lt(schema.devicePorts.collectedAt, cutoff), notInArray(schema.devicePorts.deviceId, disabledIds)));
    await db.delete(schema.deviceDnsEntries).where(and(lt(schema.deviceDnsEntries.collectedAt, cutoff), notInArray(schema.deviceDnsEntries.deviceId, disabledIds)));
    await db.delete(schema.deviceDhcpNetworks).where(and(lt(schema.deviceDhcpNetworks.collectedAt, cutoff), notInArray(schema.deviceDhcpNetworks.deviceId, disabledIds)));
    await db.delete(schema.deviceDhcpReservations).where(and(lt(schema.deviceDhcpReservations.collectedAt, cutoff), notInArray(schema.deviceDhcpReservations.deviceId, disabledIds)));
  } else {
    await db.delete(schema.hosts).where(lt(schema.hosts.lastSeenAt, cutoff));
    await db.delete(schema.networks).where(lt(schema.networks.collectedAt, cutoff));
    await db.delete(schema.devicePorts).where(lt(schema.devicePorts.collectedAt, cutoff));
    await db.delete(schema.deviceDnsEntries).where(lt(schema.deviceDnsEntries.collectedAt, cutoff));
    await db.delete(schema.deviceDhcpNetworks).where(lt(schema.deviceDhcpNetworks.collectedAt, cutoff));
    await db.delete(schema.deviceDhcpReservations).where(lt(schema.deviceDhcpReservations.collectedAt, cutoff));
  }
  // Tunnels/routes/Wi-Fi rows carry no deviceId — they are only ever refreshed
  // by polling enabled devices, so the plain stale sweep applies to them.
  await db.delete(schema.tunnels).where(lt(schema.tunnels.collectedAt, cutoff));
  await db.delete(schema.routes).where(lt(schema.routes.collectedAt, cutoff));
  await db.delete(schema.deviceServices).where(lt(schema.deviceServices.collectedAt, cutoff));
  await db.delete(schema.firewallRules).where(lt(schema.firewallRules.collectedAt, cutoff));
  await db.delete(schema.certificates).where(lt(schema.certificates.collectedAt, cutoff));
  await db.delete(schema.wifiSsids).where(lt(schema.wifiSsids.collectedAt, cutoff));
  await db.delete(schema.wifiChannels).where(lt(schema.wifiChannels.collectedAt, cutoff));
  await db.delete(schema.wifiRadios).where(lt(schema.wifiRadios.collectedAt, cutoff));
  await db.delete(schema.wifiNeighbors).where(lt(schema.wifiNeighbors.collectedAt, cutoff));
  await db.delete(schema.wifiClients).where(lt(schema.wifiClients.lastSeenAt, cutoff));
  await db.delete(schema.storageFilesystems).where(lt(schema.storageFilesystems.collectedAt, cutoff));
  await db.delete(schema.storageDisks).where(lt(schema.storageDisks.collectedAt, cutoff));
  await db.delete(schema.shares).where(lt(schema.shares.collectedAt, cutoff));
  // Live share sessions age out the same way — a device that stops reporting
  // drops its (stale) session rows after the sweep window.
  await db.delete(schema.shareSessions).where(lt(schema.shareSessions.collectedAt, cutoff));
  await db.delete(schema.containers).where(lt(schema.containers.collectedAt, cutoff));
  // Installed-package inventory (CVE tracking) ages out the same way as containers.
  await db.delete(schema.devicePackages).where(lt(schema.devicePackages.collectedAt, cutoff));
  // Derived CVE matches: swept too so an offline device drops out of the Security
  // page between worker beats (the worker also recomputes them wholesale each cycle).
  await db.delete(schema.deviceCves).where(lt(schema.deviceCves.collectedAt, cutoff));
  await db.delete(schema.dockerImages).where(lt(schema.dockerImages.collectedAt, cutoff));
  await db.delete(schema.vms).where(lt(schema.vms.collectedAt, cutoff));
  await db.delete(schema.gpus).where(lt(schema.gpus.collectedAt, cutoff));
  await db.delete(schema.deviceUpdates).where(lt(schema.deviceUpdates.collectedAt, cutoff));
  await db.delete(schema.deviceSecurityChecks).where(lt(schema.deviceSecurityChecks.collectedAt, cutoff));
  await db.delete(schema.mailDomains).where(lt(schema.mailDomains.collectedAt, cutoff));
  await db.delete(schema.mailMailboxes).where(lt(schema.mailMailboxes.collectedAt, cutoff));
  await db.delete(schema.mailAliases).where(lt(schema.mailAliases.collectedAt, cutoff));
}

/**
 * Overall device status from per-assignment poll outcomes — worst-wins:
 *   any assignment UNREACHABLE → offline (transport failure / dead plugin);
 *   reachable but critical health → critical (device answers, real problem
 *     reported — e.g. a degraded pool; it is NOT offline);
 *   all ok → online; otherwise degraded.
 */
function deriveDeviceStatus(outcomes: PollOutcome[]): string {
  if (outcomes.length === 0) return 'unknown';
  if (outcomes.some((o) => !o.reachable)) return 'offline';
  if (outcomes.some((o) => o.health === 'critical')) return 'critical';
  if (outcomes.every((o) => o.health === 'ok')) return 'online';
  return 'degraded';
}

/** One line of the device's status tooltip — which plugin, why. */
interface DeviceHealthReason {
  pluginId: string;
  /** Plugin display name (resolved at derivation time; null when unknown). */
  pluginName: string | null;
  severity: 'warning' | 'critical';
  message: string;
}

/**
 * Rolls the per-assignment outcomes up into human-readable status reasons —
 * one entry per non-ok assignment, worst first (unreachable → critical →
 * warning). Plugins that report `healthReasons` contribute their own lines;
 * everyone else gets a generic fallback so the tooltip is never empty for a
 * degraded/critical/offline device. Online/unknown devices get no reasons.
 * The map keys are `${deviceId}|${pluginId}` — the plugin id comes from there.
 */
function deriveDeviceHealthReasons(
  byAssignment: Map<string, PollOutcome>,
  pluginNameByPluginId: Map<string, string>
): DeviceHealthReason[] {
  const outcomes = Array.from(byAssignment.values());
  const status = deriveDeviceStatus(outcomes);
  if (status === 'online' || status === 'unknown') return [];

  const rank = (o: PollOutcome): number =>
    !o.reachable ? 0 : o.health === 'critical' ? 1 : o.health === 'warning' ? 2 : 3;

  const reasons: DeviceHealthReason[] = [];
  for (const [key, o] of [...byAssignment.entries()].sort((a, b) => rank(a[1]) - rank(b[1]))) {
    if (o.reachable && o.health === 'ok') continue;
    const pluginId = key.split('|')[1] ?? '';
    const pluginName = pluginNameByPluginId.get(pluginId) ?? null;
    if (!o.reachable) {
      reasons.push({
        pluginId,
        pluginName,
        severity: 'critical',
        message: `Monitoring unreachable${o.error ? ` — ${o.error.slice(0, 200)}` : ''}`,
      });
    } else if (o.healthReasons.length > 0) {
      for (const r of o.healthReasons) {
        reasons.push({ pluginId, pluginName, severity: r.severity, message: r.message });
      }
    } else {
      const generic =
        o.health === 'critical' ? 'Reports a critical problem' : 'Reports degraded health';
      reasons.push({ pluginId, pluginName, severity: o.health === 'critical' ? 'critical' : 'warning', message: generic });
    }
  }
  return reasons.slice(0, 12); // tooltip budget — keep it scannable
}

/**
 * Mirror a device status transition into the notification center.
 *   - degrading (offline/critical/degraded): one live row per condition via a
 *     stable dedupe key — re-emissions while ongoing just bump occurrences,
 *     and the notifications worker auto-resolves it when the device recovers;
 *   - recovering to online: a one-shot info note (unique key, no recurrence).
 * Never throws — notification failures must not break the poll cycle.
 */
async function emitDeviceStatusNotification(deviceId: string, prev: string, next: string): Promise<void> {
  try {
    const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
    const name = device?.name ?? deviceId;

    if (next === 'online' && prev !== 'unknown') {
      await emitNotification({
        severity: 'info',
        source: 'device',
        title: `${name} is back online`,
        message: `Device recovered from ${prev}.`,
        deviceId,
        context: { from: prev, to: next },
      });
      return;
    }

    const severity = statusToSeverity(next);
    if (!severity) return; // unknown/online — nothing to report

    await emitNotification({
      severity,
      source: 'device',
      title:
        next === 'offline'
          ? `${name} is offline`
          : next === 'critical'
            ? `${name} reports a critical problem`
            : `${name} is degraded`,
      message:
        next === 'offline'
          ? `Device stopped responding to monitoring (was ${prev}).`
          : `Health changed from ${prev} to ${next}.`,
      dedupeKey: deviceStatusDedupeKey(deviceId, next),
      deviceId,
      context: { from: prev, to: next },
    });
  } catch {
    // Best-effort by contract.
  }
}

// --- Dispatcher state -------------------------------------------------------

/** Per-assignment scheduling state (in-memory; re-staggered on restart). */
interface TargetState {
  target: AssignmentTarget;
  /** Stable identity `${deviceId}|${pluginId}` — survives roster refreshes. */
  key: string;
  metricsNextDueAt: number;
  inventoryNextDueAt: number;
  /** Effective windows (ms) resolved at the last roster refresh. */
  metricsWindowMs: number;
  inventoryWindowMs: number;
  /** True once this plugin emitted any inventory array in a snapshot. */
  everEmittedInventory: boolean;
  /** Consecutive inventory-due polls that came back without inventory keys. */
  inventoryMissStreak: number;
}

const targetStates = new Map<string, TargetState>();
/** Assignments currently being polled — prevents double-dispatch. */
const inFlightKeys = new Set<string>();
/** Last-known poll outcome per assignment (device status is worst-wins over these). */
const lastOutcomesByDevice = new Map<string, Map<string, PollOutcome>>();
/** In-memory mirror of devices.status (avoids a DB read per poll). */
const lastKnownStatus = new Map<string, string>();
/** In-memory mirror of devices.healthReasons (JSON or null) — lets us skip the
 * DB write when neither status nor reasons changed. */
const lastHealthReasonsJson = new Map<string, string | null>();

// --- Status-transition hysteresis -------------------------------------------
// A single bad poll must not flip a device's status (and thereby emit a
// notification): e.g. one lost ping out of four is 'warning' for 30 s and back
// to ok — without grace that churns "degraded" + "back online" rows every few
// minutes on flaky links. A NEWLY DERIVED status only commits once it has been
// observed continuously for STATUS_TRANSITION_GRACE_MS; the DB keeps showing
// the previous (stable) state until then. Recovery to 'online' gets the same
// grace, so a brief blip never produces a "back online" note at all.
const STATUS_TRANSITION_GRACE_MS = 60_000;
/** deviceId → epoch ms when the current derived status first differed from the committed one (null = matches). */
const pendingStatusSince = new Map<string, number | null>();
/** Plugin display names for status-reason tooltips (refreshed with the roster). */
const pluginNames = new Map<string, string>();
/** Assignment count per device — status is only derived once all are known. */
const assignmentsPerDevice = new Map<string, number>();
let lastRosterRefreshAt = 0;
let lastSweepAt = 0;
/** Global safety net: a wedged dispatcher tick must never stack on itself. */
let dispatcherRunning = false;

/**
 * Effective windows for one assignment. Resolution order (most specific wins):
 *   plugin option @device scope → devices.pollIntervalMs column
 *   → plugin option @global scope → system setting.
 * The device column overrides the metrics window only; the inventory window is
 * then clamped to at least the metrics window (inventory can't refresh faster
 * than the poll itself).
 */
async function resolveWindows(
  target: AssignmentTarget,
  settings: SystemSettings
): Promise<{ metricsWindowMs: number; inventoryWindowMs: number }> {
  const deviceOpts = await getEffectiveSettings(target.pluginId, target.deviceId).catch((): Record<string, unknown> => ({}));
  const globalOpts = await getEffectiveSettings(target.pluginId).catch((): Record<string, unknown> => ({}));

  let metricsWindowMs = toIntOrNull(deviceOpts['pollIntervalMs']);
  if (metricsWindowMs === null) metricsWindowMs = toIntOrNull(target.pollIntervalMs);
  if (metricsWindowMs === null) metricsWindowMs = toIntOrNull(globalOpts['pollIntervalMs']);
  if (metricsWindowMs === null) metricsWindowMs = settings.telemetryPollIntervalMs;
  metricsWindowMs = clampInt(metricsWindowMs, 5_000, 3_600_000);

  let inventoryWindowMs = toIntOrNull(deviceOpts['inventoryWindowMs']);
  if (inventoryWindowMs === null) inventoryWindowMs = toIntOrNull(globalOpts['inventoryWindowMs']);
  if (inventoryWindowMs === null) inventoryWindowMs = settings.telemetryInventoryWindowMs;
  inventoryWindowMs = clampInt(inventoryWindowMs, 30_000, 12 * 60 * 60_000);

  return { metricsWindowMs, inventoryWindowMs: Math.max(inventoryWindowMs, metricsWindowMs) };
}

/**
 * Re-reads enabled devices + assignments and (re)builds the scheduling state.
 * New targets get their first deadline staggered across the window via a stable
 * hash — a fleet boot or bulk import never produces a synchronized burst.
 */
async function refreshRoster(settings: SystemSettings): Promise<void> {
  const startedAt = Date.now();
  // Disabled devices are not polled — their historical data and last metrics
  // stay preserved, and the status column keeps its last derived value.
  const devices = await db.query.devices.findMany({ where: eq(schema.devices.enabled, true) });
  const deviceById = new Map(devices.map((d) => [d.id, d] as const));

  if (devices.length === 0) {
    targetStates.clear();
    lastOutcomesByDevice.clear();
    assignmentsPerDevice.clear();
    pluginNames.clear();
    lastHealthReasonsJson.clear();
    pendingStatusSince.clear();
    recordTelemetryCycle(0, 0, Date.now() - startedAt);
    return;
  }

  // Load every assignment with its plugin endpoint in one pass.
  const assignments = await db.query.devicePlugins.findMany({});
  const pluginsById = new Map((await db.query.plugins.findMany()).map((p) => [p.id, p] as const));

  // Plugin display names — used to attribute status-reason tooltip lines.
  pluginNames.clear();
  for (const p of pluginsById.values()) pluginNames.set(p.id, p.name);

  // Secondary IPs per device (primary is always managementAddress). Batched.
  const deviceIds = devices.map((d) => d.id);
  const secondaryIps =
    deviceIds.length > 0
      ? await db.query.deviceIps.findMany({ where: inArray(schema.deviceIps.deviceId, deviceIds) })
      : [];
  const ipsByDevice = new Map<string, string[]>();
  for (const row of secondaryIps) {
    const list = ipsByDevice.get(row.deviceId) ?? [];
    list.push(row.address);
    ipsByDevice.set(row.deviceId, list);
  }

  const now = Date.now();
  const seenKeys = new Set<string>();
  for (const a of assignments) {
    const device = deviceById.get(a.deviceId);
    const plugin = pluginsById.get(a.pluginId);
    if (!device || !plugin) continue; // stale assignment or unknown plugin: skip
    const key = `${a.deviceId}|${a.pluginId}`;
    seenKeys.add(key);

    const target: AssignmentTarget = {
      deviceId: device.id,
      managementAddress: device.managementAddress,
      ipAddresses: [
        { address: device.managementAddress, isPrimary: true },
        ...(ipsByDevice.get(device.id) ?? []).map((address) => ({ address, isPrimary: false })),
      ],
      pluginId: a.pluginId,
      secretId: a.secretId,
      extraCredentials: parseExtraCredentials(a.extraCredentials),
      endpoint: plugin.endpoint,
      model: device.model ?? null,
      firmwareVersion: device.firmwareVersion ?? null,
      pollIntervalMs: device.pollIntervalMs ?? null,
    };

    const existing = targetStates.get(key);
    if (!existing) {
      // New assignment — stagger first deadlines across their windows.
      const windows = await resolveWindows(target, settings);
      targetStates.set(key, {
        target,
        key,
        metricsNextDueAt: now + (stableHash(key) % Math.max(1, windows.metricsWindowMs)),
        inventoryNextDueAt: now + (stableHash(`${key}:inv`) % Math.max(1, windows.inventoryWindowMs)),
        metricsWindowMs: windows.metricsWindowMs,
        inventoryWindowMs: windows.inventoryWindowMs,
        everEmittedInventory: false,
        inventoryMissStreak: 0,
      });
    } else {
      // Existing — refresh the target (endpoint/credentials may have changed)
      // and re-resolve windows; deadlines stay untouched.
      existing.target = target;
      const windows = await resolveWindows(target, settings);
      existing.metricsWindowMs = windows.metricsWindowMs;
      existing.inventoryWindowMs = windows.inventoryWindowMs;
    }
  }

  // Drop state for assignments that no longer exist (device deleted/disabled).
  for (const key of Array.from(targetStates.keys())) {
    if (!seenKeys.has(key)) targetStates.delete(key);
  }
  const liveDeviceIds = new Set(Array.from(seenKeys).map((k) => k.split('|')[0]));
  for (const deviceId of Array.from(lastOutcomesByDevice.keys())) {
    if (!liveDeviceIds.has(deviceId)) lastOutcomesByDevice.delete(deviceId);
  }
  for (const deviceId of Array.from(lastHealthReasonsJson.keys())) {
    if (!liveDeviceIds.has(deviceId)) lastHealthReasonsJson.delete(deviceId);
  }
  for (const deviceId of Array.from(pendingStatusSince.keys())) {
    if (!liveDeviceIds.has(deviceId)) pendingStatusSince.delete(deviceId);
  }

  // Per-device assignment counts + status mirror for transition detection.
  assignmentsPerDevice.clear();
  for (const state of targetStates.values()) {
    assignmentsPerDevice.set(
      state.target.deviceId,
      (assignmentsPerDevice.get(state.target.deviceId) ?? 0) + 1
    );
  }
  // Seed both mirrors from the DB — a device already non-ok before an API
  // restart must get its reasons persisted on the first poll without a status
  // transition to trigger it.
  for (const d of devices) {
    lastKnownStatus.set(d.id, d.status);
    lastHealthReasonsJson.set(d.id, d.healthReasons ?? null);
  }

  recordTelemetryCycle(devices.length, targetStates.size, Date.now() - startedAt);
}

/** Dispatches one due assignment: poll → reschedule deadlines → update status. */
async function dispatchPoll(state: TargetState, settings: SystemSettings): Promise<void> {
  inFlightKeys.add(state.key);
  telemetryStats.pollsInFlight = inFlightKeys.size;
  const startedAt = Date.now();
  try {
    // Inventory-due? Checked at DISPATCH time — the deadline may have passed
    // while this target waited for a free slot.
    const collectInventory = Date.now() >= state.inventoryNextDueAt;

    const outcome = await pollAssignment(state.target, { collectInventory });
    recordTelemetryPoll(Date.now() - startedAt);

    // Reschedule the metrics deadline from COMPLETION (not dispatch) so a slow
    // device isn't double-polled back-to-back. Jitter decorrelates phases over
    // time so targets never re-synchronize.
    const jitter = 1 + (Math.random() * 2 - 1) * (settings.telemetryJitterPercent / 100);
    state.metricsNextDueAt = Date.now() + Math.max(5_000, state.metricsWindowMs * jitter);

    // Inventory deadline: advance only when the plugin actually delivered
    // inventory this poll — a transient collection failure retries on the next
    // metrics beat instead of waiting a full window. Plugins that never emit
    // inventory (e.g. ICMP) always advance; after 5 consecutive misses we force-
    // advance anyway so a permanently broken collector can't pin every poll to
    // full-collection mode.
    if (collectInventory) {
      const delivered = outcome.reachable && (!state.everEmittedInventory || outcome.inventoryEmitted);
      state.inventoryMissStreak = delivered ? 0 : state.inventoryMissStreak + 1;
      if (delivered || state.inventoryMissStreak >= 5) {
        state.inventoryNextDueAt = Date.now() + Math.max(30_000, state.inventoryWindowMs * jitter);
      }
    }
    if (outcome.inventoryEmitted) state.everEmittedInventory = true;

    await updateDeviceStatus(state.target.deviceId, state.key, outcome);
  } finally {
    inFlightKeys.delete(state.key);
    telemetryStats.pollsInFlight = inFlightKeys.size;
  }
}

/**
 * Device status = worst-wins over the LAST KNOWN outcome of every assignment.
 * With staggered deadlines each assignment polls at its own pace, so we keep a
 * per-assignment outcome cache and only derive once all of the device's
 * assignments have reported at least once (no boot-time flapping).
 */
async function updateDeviceStatus(
  deviceId: string,
  assignmentKey: string,
  outcome: PollOutcome
): Promise<void> {
  let byAssignment = lastOutcomesByDevice.get(deviceId);
  if (!byAssignment) {
    byAssignment = new Map();
    lastOutcomesByDevice.set(deviceId, byAssignment);
  }
  byAssignment.set(assignmentKey, outcome);

  const expected = assignmentsPerDevice.get(deviceId) ?? 1;
  if (byAssignment.size < expected) return; // wait for the full picture

  const derived = deriveDeviceStatus(Array.from(byAssignment.values()));
  const committed = lastKnownStatus.get(deviceId) ?? 'unknown';

  // Hysteresis (see STATUS_TRANSITION_GRACE_MS): a transition only commits once
  // it has been SUSTAINED for the grace window. Until then the device keeps its
  // previous stable status AND reasons — no partial updates, no notification
  // churn from single bad polls (one lost ping out of four must not flip a
  // healthy device to degraded and back within a minute).
  let status = committed;
  if (derived !== committed) {
    const since = pendingStatusSince.get(deviceId);
    if (since === undefined || since === null) {
      pendingStatusSince.set(deviceId, Date.now()); // first observation — start the window
      return; // keep showing the previous stable state for now
    }
    if (Date.now() - since < STATUS_TRANSITION_GRACE_MS) return; // still inside the window
    status = derived; // sustained long enough — commit it
  } else {
    pendingStatusSince.set(deviceId, null); // back to committed state — re-arm for next time
  }

  // Human-readable reasons for the current outcome set (NULL when healthy).
  const healthReasons = deriveDeviceHealthReasons(byAssignment, pluginNames);
  const reasonsJson = healthReasons.length > 0 ? JSON.stringify(healthReasons) : null;

  if (status === committed && (lastHealthReasonsJson.get(deviceId) ?? null) === reasonsJson) return;

  // Mirror the STATUS transition into the notification center. Degrading states
  // carry a stable dedupe key so they upsert while ongoing and are auto-resolved
  // by the notifications worker when the device recovers; recovery emits one-shot.
  if (status !== committed) {
    lastKnownStatus.set(deviceId, status);
    pendingStatusSince.set(deviceId, null); // re-arm for the next transition
    void emitDeviceStatusNotification(deviceId, committed, status);
    // Actions & Schedules — deviceStatus triggers fire on the SETTLED transition
    // (post-hysteresis), never disturbing telemetry bookkeeping.
    void onDeviceStatusTransition(deviceId, committed as DeviceStatus, status as DeviceStatus).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[telemetry] automation device-status hook failed:', err);
    });
  }
  // Persist status + reasons whenever EITHER changed — a device that was already
  // non-ok before an API restart has no transition to trigger the write, so its
  // tooltip would stay empty until this catches up.
  lastHealthReasonsJson.set(deviceId, reasonsJson);
  await db.update(schema.devices).set({
    status,
    healthReasons: reasonsJson,
  }).where(eq(schema.devices.id, deviceId));
}

/** One dispatcher tick: roster/sweeps on their cadences + dispatch due targets. */
async function dispatcherTick(): Promise<void> {
  const settings = await getSystemSettings();

  if (Date.now() - lastRosterRefreshAt >= ROSTER_REFRESH_MS) {
    lastRosterRefreshAt = Date.now();
    try {
      await refreshRoster(settings);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[telemetry] roster refresh failed:', err);
    }
  }

  if (Date.now() - lastSweepAt >= INVENTORY_SWEEP_INTERVAL_MS) {
    lastSweepAt = Date.now();
    void sweepStaleInventory(settings.telemetryInventoryWindowMs).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[telemetry] inventory sweep failed:', err);
    });
  }

  const now = Date.now();
  const budget = Math.max(1, settings.telemetryMaxConcurrency);

  // Due targets (not already in flight), most-overdue first for fair catch-up.
  const due: TargetState[] = [];
  for (const state of targetStates.values()) {
    if (!inFlightKeys.has(state.key) && now >= state.metricsNextDueAt) due.push(state);
  }
  telemetryStats.overdueWaiting = Math.max(0, due.length - (budget - inFlightKeys.size));

  const slots = budget - inFlightKeys.size;
  if (slots <= 0 || due.length === 0) return;
  due.sort((a, b) => a.metricsNextDueAt - b.metricsNextDueAt);
  for (const state of due.slice(0, slots)) {
    void dispatchPoll(state, settings).catch(() => undefined); // dispatchPoll never throws
  }
}

/**
 * Starts the telemetry dispatcher. Each assignment is polled once per metrics
 * window (staggered across the window) and carries a slower inventory deadline;
 * windows + concurrency are re-read from system_settings every tick, so an
 * admin can tune them live from the Workers page without a restart. Returns a
 * stop function.
 */
export function startTelemetryWorker(): () => void {
  initWorker('telemetry', LEADER_KEYS.telemetry);
  // eslint-disable-next-line no-console
  console.log('[telemetry] worker started (window-based staggered dispatcher, 1 s resolution)');

  let stopped = false;
  let timer: NodeJS.Timeout | null = null;

  const tick = async (): Promise<void> => {
    if (stopped) return;
    // Global safety net: a wedged tick must never stack on itself.
    if (!dispatcherRunning) {
      dispatcherRunning = true;
      try {
        await trackBeat('telemetry', () => dispatcherTick());
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error('[telemetry] dispatcher tick failed:', err);
      } finally {
        dispatcherRunning = false;
      }
    } else {
      recordSkippedTelemetryBeat();
    }
    timer = setTimeout(() => void tick(), DISPATCH_TICK_MS);
  };

  // First tick shortly after start (the roster refresh happens inside it).
  timer = setTimeout(() => void tick(), 500);

  return () => {
    stopped = true;
    if (timer) clearTimeout(timer);
  };
}

// --- Forced refresh (manual re-poll) ----------------------------------------

/** Per-device result of a forced refresh. */
export interface ForceRefreshDeviceResult {
  deviceId: string;
  name: string;
  /** True when at least one assignment was polled successfully. */
  ok: boolean;
  /** Number of plugin assignments that were re-polled (0 = none possible). */
  assignmentsPolled: number;
  /** Per-assignment outcomes (plugin id + health, or the transport error). */
  results: { pluginId: string; health: Health; reachable: boolean; error?: string }[];
  /** Device-level problem (unknown device / polling disabled) — no polls ran. */
  error?: string;
}

/**
 * Forces an immediate re-poll of one or more devices, bypassing the staggered
 * scheduling windows entirely. Every assignment is polled with
 * collectInventory=true (full snapshot + inventory ingestion), so BOTH live
 * metrics and the cross-device inventory tables refresh in one shot — this is
 * the diagnostic path for "is this device reachable right now?" and whenever
 * fresh data is essential without waiting up to a full window.
 *
 * The regular deadlines stay untouched: after a forced poll the next scheduled
 * beat still fires at its original time (no double-poll, no re-stagger). A
 * forced poll also does NOT touch in-flight bookkeeping — if the dispatcher
 * happens to be polling the same assignment concurrently, both snapshots are
 * simply appended to telemetry history (last write wins per row key).
 *
 * Devices are processed sequentially (their assignments in parallel) so a big
 * bulk request can't fan out into hundreds of concurrent plugin calls. Unknown
 * ids and disabled devices come back with ok=false + an error, never throw.
 */
export async function forceRefreshDevices(
  deviceIds: string[]
): Promise<ForceRefreshDeviceResult[]> {
  const ids = Array.from(new Set(deviceIds.filter((id) => typeof id === 'string' && id !== '')));
  if (ids.length === 0) return [];

  const devices = await db.query.devices.findMany({ where: inArray(schema.devices.id, ids) });
  const deviceById = new Map(devices.map((d) => [d.id, d] as const));
  const pluginsById = new Map(
    (await db.query.plugins.findMany()).map((p) => [p.id, p] as const)
  );

  // Secondary IPs per requested device (primary is always managementAddress).
  const secondaryIps = await db.query.deviceIps.findMany({ where: inArray(schema.deviceIps.deviceId, ids) });
  const ipsByDevice = new Map<string, string[]>();
  for (const row of secondaryIps) {
    const list = ipsByDevice.get(row.deviceId) ?? [];
    list.push(row.address);
    ipsByDevice.set(row.deviceId, list);
  }

  // Preserve the caller's device order in the response.
  const results: ForceRefreshDeviceResult[] = [];
  for (const id of ids) {
    const device = deviceById.get(id);
    if (!device) {
      results.push({
        deviceId: id,
        name: '',
        ok: false,
        assignmentsPolled: 0,
        results: [],
        error: 'Device not found',
      });
      continue;
    }

    if (device.enabled === false) {
      results.push({
        deviceId: id,
        name: device.name,
        ok: false,
        assignmentsPolled: 0,
        results: [],
        error: 'Device polling is disabled — enable the device first',
      });
      continue;
    }

    const assignments = await db.query.devicePlugins.findMany({ where: eq(schema.devicePlugins.deviceId, id) });
    const targets: AssignmentTarget[] = [];
    for (const a of assignments) {
      const plugin = pluginsById.get(a.pluginId);
      if (!plugin) continue; // stale assignment — skip
      targets.push({
        deviceId: device.id,
        managementAddress: device.managementAddress,
        ipAddresses: [
          { address: device.managementAddress, isPrimary: true },
          ...(ipsByDevice.get(device.id) ?? []).map((address) => ({ address, isPrimary: false })),
        ],
        pluginId: a.pluginId,
        secretId: a.secretId,
        extraCredentials: parseExtraCredentials(a.extraCredentials),
        endpoint: plugin.endpoint,
        model: device.model ?? null,
        firmwareVersion: device.firmwareVersion ?? null,
        pollIntervalMs: device.pollIntervalMs ?? null,
      });
    }

    if (targets.length === 0) {
      results.push({
        deviceId: id,
        name: device.name,
        ok: false,
        assignmentsPolled: 0,
        results: [],
        error: 'Device has no plugin assignment',
      });
      continue;
    }

    // forceUpdateCheck: an explicit "Check now" must not be held back by the
    // plugin's automatic-search cadence (or a zero interval) — it asks for FRESH
    // data right now. The probe itself runs in the background inside the plugin.
    const outcomes = await Promise.all(
      targets.map((target) => pollAssignment(target, { collectInventory: true, forceUpdateCheck: true }))
    );
    results.push({
      deviceId: id,
      name: device.name,
      ok: outcomes.some((o) => o.reachable),
      assignmentsPolled: targets.length,
      results: outcomes.map((o, i) => ({
        pluginId: targets[i].pluginId,
        health: o.health,
        reachable: o.reachable,
        ...(o.error ? { error: o.error } : {}),
      })),
    });
  }
  return results;
}

