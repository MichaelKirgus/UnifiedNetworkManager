import { db, pool } from './db';

/**
 * Runtime-tunable system settings (Workers page → "HA & workers" panel).
 *
 * Values live in the `system_settings` table so they survive restarts and are
 * shared across API replicas. Workers read them through a short-TTL cache on
 * every beat — no restart needed to change poll cadence or concurrency.
 * Env vars remain the deployment-level default; a stored value always wins.
 */

export interface SystemSettings {
  /** Telemetry poll beat in ms (env: TELEMETRY_POLL_INTERVAL_MS, min 5000). */
  telemetryPollIntervalMs: number;
  /** Max concurrent /monitoring calls per cycle (env: TELEMETRY_MAX_CONCURRENCY, min 1). */
  telemetryMaxConcurrency: number;
}

const DEFAULTS: SystemSettings = {
  telemetryPollIntervalMs: Math.max(5_000, Number(process.env.TELEMETRY_POLL_INTERVAL_MS ?? 30_000)),
  telemetryMaxConcurrency: Math.max(1, Number(process.env.TELEMETRY_MAX_CONCURRENCY ?? 64)),
};

const MIN_POLL_INTERVAL_MS = 5_000;
const MAX_POLL_INTERVAL_MS = 3_600_000; // one hour — beyond that it's a different design
const MIN_CONCURRENCY = 1;
const MAX_CONCURRENCY = 2_000;

let cache: { values: SystemSettings; cachedAt: number } | null = null;
const CACHE_TTL_MS = 5_000; // one beat of staleness is fine for cadence knobs

/**
 * Validates + clamps a partial update. Unsent fields keep their CURRENT value
 * (base), so a one-field PUT never resets the other knob to its default.
 * Throws on bad types (route maps to 400).
 */
export function validateSettingsUpdate(body: Partial<SystemSettings>, base?: SystemSettings): SystemSettings {
  const out: SystemSettings = { ...(base ?? currentDefaults()) };
  if (body.telemetryPollIntervalMs !== undefined) {
    const v = Number(body.telemetryPollIntervalMs);
    if (!Number.isFinite(v)) throw new Error('"telemetryPollIntervalMs" must be a number');
    out.telemetryPollIntervalMs = Math.min(MAX_POLL_INTERVAL_MS, Math.max(MIN_POLL_INTERVAL_MS, Math.round(v)));
  }
  if (body.telemetryMaxConcurrency !== undefined) {
    const v = Number(body.telemetryMaxConcurrency);
    if (!Number.isFinite(v)) throw new Error('"telemetryMaxConcurrency" must be a number');
    out.telemetryMaxConcurrency = Math.min(MAX_CONCURRENCY, Math.max(MIN_CONCURRENCY, Math.round(v)));
  }
  return out;
}

function currentDefaults(): SystemSettings {
  return { ...DEFAULTS };
}

/** Effective settings: stored overrides ⊕ env defaults. Cached for CACHE_TTL_MS. */
export async function getSystemSettings(): Promise<SystemSettings> {
  const now = Date.now();
  if (cache && now - cache.cachedAt < CACHE_TTL_MS) return cache.values;

  let values = currentDefaults();
  try {
    const rows = await db.query.systemSettings.findMany();
    for (const row of rows) {
      if (row.key === 'telemetryPollIntervalMs') {
        const v = Number(row.value);
        if (Number.isFinite(v)) values.telemetryPollIntervalMs = Math.min(MAX_POLL_INTERVAL_MS, Math.max(MIN_POLL_INTERVAL_MS, Math.round(v)));
      } else if (row.key === 'telemetryMaxConcurrency') {
        const v = Number(row.value);
        if (Number.isFinite(v)) values.telemetryMaxConcurrency = Math.min(MAX_CONCURRENCY, Math.max(MIN_CONCURRENCY, Math.round(v)));
      }
    }
  } catch {
    // Table missing / DB hiccup — fall back to env defaults rather than failing the beat.
  }

  cache = { values, cachedAt: now };
  return values;
}

/** Persists a full settings object (all-or-nothing) and busts the local cache. */
export async function saveSystemSettings(values: SystemSettings): Promise<SystemSettings> {
  const now = new Date().toISOString();
  const rows: Array<[string, string]> = [
    ['telemetryPollIntervalMs', String(values.telemetryPollIntervalMs)],
    ['telemetryMaxConcurrency', String(values.telemetryMaxConcurrency)],
  ];
  for (const [key, value] of rows) {
    await pool.query(
      `INSERT INTO system_settings ("key", value, "updatedAt") VALUES ($1, $2, $3)
       ON CONFLICT ("key") DO UPDATE SET value = EXCLUDED.value, "updatedAt" = EXCLUDED."updatedAt"`,
      [key, value, now]
    );
  }
  cache = { values, cachedAt: Date.now() };
  return values;
}

/** Drops one (or all) cached settings after a write from ANY replica. */
export function invalidateSystemSettingsCache(): void {
  cache = null;
}

// Re-export for the route's error mapping convenience.
export const SETTINGS_LIMITS = {
  MIN_POLL_INTERVAL_MS,
  MAX_POLL_INTERVAL_MS,
  MIN_CONCURRENCY,
  MAX_CONCURRENCY,
};
