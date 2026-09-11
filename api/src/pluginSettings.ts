import { and, eq, isNull } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { db } from './db';
import * as schema from './db/schema';
import type { PluginOptionDescriptor, StringOption, IntegerOption } from './types/pluginOptions';
import { getPluginGlobalSettings } from './systemSettings';

/**
 * Plugin settings broker.
 *
 * Plugins declare their options (typed descriptors) in `/discover`; the API
 * caches them on the `plugins` row and is the single authority for:
 *   - validation of user-supplied values (`validateOptionValue`)
 *   - persistence of overrides (`plugin_settings` table, global rows)
 *   - resolving effective values (descriptor defaults ⊕ stored overrides)
 *
 * Plugins never store or validate their own settings — they receive the
 * effective values on every API call via the `x-unm-settings` header.
 */

export interface PluginOptionsView {
  pluginId: string;
  options: PluginOptionDescriptor[];
  /** Stored overrides only (key -> value). Empty when nothing was set. */
  values: Record<string, unknown>;
  /** Defaults merged with stored overrides — what the UI should initialize to. */
  effectiveValues: Record<string, unknown>;
}

export interface ValidationError {
  error: string;
  fieldErrors?: Record<string, string>;
}

/** Error carrying per-field validation messages (routes map it to HTTP 400). */
export class SettingsValidationError extends Error {
  fieldErrors: Record<string, string>;
  constructor(fieldErrors: Record<string, string>) {
    super('One or more settings are invalid');
    this.fieldErrors = fieldErrors;
  }
}

function parseDescriptors(raw: string | null): PluginOptionDescriptor[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as PluginOptionDescriptor[]) : [];
  } catch {
    return [];
  }
}

/**
 * Validates a single value against its descriptor. The API is the only place
 * this logic lives — plugins and webapp both rely on it (the webapp mirrors
 * it client-side for instant feedback).
 */
export function validateOptionValue(
  descriptor: PluginOptionDescriptor,
  value: unknown
): string | null {
  switch (descriptor.type) {
    case 'string': {
      if (typeof value !== 'string') return 'Must be a string';
      const s = descriptor as StringOption;
      if (s.minLength !== undefined && value.length < s.minLength) {
        return `Must be at least ${s.minLength} characters`;
      }
      if (s.maxLength !== undefined && value.length > s.maxLength) {
        return `Must be at most ${s.maxLength} characters`;
      }
      if (s.pattern) {
        try {
          if (!new RegExp(s.pattern).test(value)) return 'Does not match the required pattern';
        } catch {
          // Malformed regex in a descriptor must never break validation.
        }
      }
      return null;
    }
    case 'integer': {
      if (typeof value !== 'number' || !Number.isInteger(value)) return 'Must be an integer';
      const s = descriptor as IntegerOption;
      if (s.min !== undefined && value < s.min) return `Must be >= ${s.min}`;
      if (s.max !== undefined && value > s.max) return `Must be <= ${s.max}`;
      return null;
    }
    case 'boolean': {
      if (typeof value !== 'boolean') return 'Must be true or false';
      return null;
    }
    default:
      // Unknown option type (forward-compatible): accept anything, the plugin
      // is responsible for interpreting it.
      return null;
  }
}

/** Loads a plugin row + its descriptors; throws 404-shaped error when missing. */
async function loadPlugin(pluginId: string) {
  const row = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, pluginId),
  });
  if (!row) {
    throw Object.assign(new Error('Plugin not found'), { status: 404 });
  }
  return row;
}

/**
 * Loads stored override rows for one scope as key -> decoded value.
 * `deviceId = null` selects global rows; a device id selects that device's
 * override rows (partial unique indexes guarantee at most one row per key).
 */
async function loadScopedValues(
  pluginId: string,
  deviceId: string | null
): Promise<Record<string, unknown>> {
  const rows = await db.query.pluginSettings.findMany({
    where: and(
      eq(schema.pluginSettings.pluginId, pluginId),
      deviceId === null
        ? isNull(schema.pluginSettings.deviceId)
        : eq(schema.pluginSettings.deviceId, deviceId)
    ),
  });
  const values: Record<string, unknown> = {};
  for (const row of rows) {
    try {
      values[row.optionKey] = JSON.parse(row.value);
    } catch {
      // Corrupt stored value: skip rather than fail the whole view.
    }
  }
  return values;
}

/** 404-shaped error when a plugin is not assigned to a device. */
function assignmentNotFound(): Error {
  return Object.assign(new Error('Plugin is not assigned to this device'), { status: 404 });
}

async function assertAssignment(deviceId: string, pluginId: string): Promise<void> {
  const row = await db.query.devicePlugins.findFirst({
    where: and(
      eq(schema.devicePlugins.deviceId, deviceId),
      eq(schema.devicePlugins.pluginId, pluginId)
    ),
  });
  if (!row) throw assignmentNotFound();
}

/**
 * Descriptors + current overrides + effective values (defaults ⊕ overrides).
 * Works even when the plugin is offline — everything comes from the DB cache.
 */
export async function getPluginOptions(pluginId: string): Promise<PluginOptionsView> {
  const row = await loadPlugin(pluginId);
  const options = parseDescriptors(row.optionDescriptors);
  const values = await loadScopedValues(pluginId, null);

  const effectiveValues: Record<string, unknown> = {};
  for (const opt of options) {
    if (opt.key in values) {
      effectiveValues[opt.key] = values[opt.key];
    } else if (opt.default !== undefined) {
      effectiveValues[opt.key] = opt.default;
    }
  }

  return { pluginId, options, values, effectiveValues };
}

/**
 * Device-scoped view: same descriptors, but `values` holds THIS device's
 * overrides and `effectiveValues` resolves in the order
 *   device override → global override → descriptor default.
 */
export async function getDevicePluginOptions(
  deviceId: string,
  pluginId: string
): Promise<PluginOptionsView> {
  const row = await loadPlugin(pluginId);
  await assertAssignment(deviceId, pluginId);
  const options = parseDescriptors(row.optionDescriptors);

  const [globalValues, deviceValues] = await Promise.all([
    loadScopedValues(pluginId, null),
    loadScopedValues(pluginId, deviceId),
  ]);

  const effectiveValues: Record<string, unknown> = {};
  for (const opt of options) {
    if (opt.key in deviceValues) {
      effectiveValues[opt.key] = deviceValues[opt.key];
    } else if (opt.key in globalValues) {
      effectiveValues[opt.key] = globalValues[opt.key];
    } else if (opt.default !== undefined) {
      effectiveValues[opt.key] = opt.default;
    }
  }

  return { pluginId, options, values: deviceValues, effectiveValues };
}

/**
 * Validates ALL entries first and only then writes — a single invalid value
 * rejects the whole request with per-field errors (no partial saves).
 */
/**
 * Core upsert for one scope. `deviceId = null` writes global rows; a device
 * id writes per-device override rows (inherited from global, overridable).
 */
async function upsertScopedSettings(
  pluginId: string,
  deviceId: string | null,
  settings: Record<string, unknown>
): Promise<void> {
  const row = await loadPlugin(pluginId);
  const options = parseDescriptors(row.optionDescriptors);

  // Validate every entry against its descriptor before touching the DB.
  const fieldErrors: Record<string, string> = {};
  for (const [key, value] of Object.entries(settings)) {
    const descriptor = options.find((o) => o.key === key);
    if (!descriptor) {
      fieldErrors[key] = 'Unknown option';
      continue;
    }
    const problem = validateOptionValue(descriptor, value);
    if (problem) fieldErrors[key] = problem;
  }
  if (Object.keys(fieldErrors).length > 0) {
    throw new SettingsValidationError(fieldErrors);
  }

  // All valid → upsert atomically.
  const now = new Date().toISOString();
  for (const [key, value] of Object.entries(settings)) {
    const existing = await db.query.pluginSettings.findFirst({
      where: and(
        eq(schema.pluginSettings.pluginId, pluginId),
        eq(schema.pluginSettings.optionKey, key),
        deviceId === null
          ? isNull(schema.pluginSettings.deviceId)
          : eq(schema.pluginSettings.deviceId, deviceId)
      ),
    });
    if (existing) {
      await db.update(schema.pluginSettings)
        .set({ value: JSON.stringify(value), updatedAt: now })
        .where(eq(schema.pluginSettings.id, existing.id));
    } else {
      await db.insert(schema.pluginSettings).values({
        id: uuidv4(),
        pluginId,
        deviceId,
        optionKey: key,
        value: JSON.stringify(value),
        updatedAt: now,
      });
    }
  }

  invalidateEffectiveCache(pluginId);
}

/** Global-scope upsert (deviceId = NULL rows). */
export async function upsertPluginSettings(
  pluginId: string,
  settings: Record<string, unknown>
): Promise<void> {
  await upsertScopedSettings(pluginId, null, settings);
}

/** Per-device override upsert; the plugin must be assigned to the device. */
export async function upsertDevicePluginSettings(
  deviceId: string,
  pluginId: string,
  settings: Record<string, unknown>
): Promise<void> {
  await assertAssignment(deviceId, pluginId);
  await upsertScopedSettings(pluginId, deviceId, settings);
}

/** Core reset for one scope (deletes that scope's override rows). */
async function resetScopedSettings(
  pluginId: string,
  deviceId: string | null
): Promise<void> {
  await loadPlugin(pluginId); // 404 when unknown
  const rows = await db.query.pluginSettings.findMany({
    where: and(
      eq(schema.pluginSettings.pluginId, pluginId),
      deviceId === null
        ? isNull(schema.pluginSettings.deviceId)
        : eq(schema.pluginSettings.deviceId, deviceId)
    ),
  });
  for (const row of rows) {
    await db.delete(schema.pluginSettings).where(eq(schema.pluginSettings.id, row.id));
  }
  invalidateEffectiveCache(pluginId);
}

/** Resets a plugin's global settings to defaults. */
export async function resetPluginSettings(pluginId: string): Promise<void> {
  await resetScopedSettings(pluginId, null);
}

/**
 * Resets ONE device's overrides — the values fall back to the global setting
 * (or descriptor default) instead of being wiped entirely.
 */
export async function resetDevicePluginSettings(
  deviceId: string,
  pluginId: string
): Promise<void> {
  await assertAssignment(deviceId, pluginId);
  await resetScopedSettings(pluginId, deviceId);
}

// --- Effective-values cache (for header injection on every plugin call) -----
// The telemetry worker polls /monitoring every beat per device; resolving
// settings from the DB each time would add a query per poll. Writes invalidate
// this cache immediately (invalidateEffectiveCache), so the TTL only bounds how
// long OTHER API replicas keep serving pre-change values after an edit — 60s is
// plenty and, crucially, LONGER than the poll beat: with a 5s TTL vs a 30s beat
// every single poll was a cache miss anyway (hundreds of extra queries/cycle at
// scale for zero benefit).

const EFFECTIVE_CACHE_TTL_MS = 60_000;
const effectiveCache = new Map<string, { values: Record<string, unknown>; cachedAt: number }>();

function cacheKey(pluginId: string, deviceId?: string | null): string {
  return `${pluginId}:${deviceId ?? 'global'}`;
}

/**
 * Invalidates the effective-values cache for a plugin — ALL scopes (global +
 * every device), since a write in one scope can change what another resolves.
 */
export function invalidateEffectiveCache(pluginId?: string): void {
  if (!pluginId) {
    effectiveCache.clear();
    return;
  }
  for (const key of Array.from(effectiveCache.keys())) {
    if (key === pluginId || key.startsWith(`${pluginId}:`)) {
      effectiveCache.delete(key);
    }
  }
}

/**
 * Effective settings for a plugin in one scope, decoded and ready to be
 * serialized into the `x-unm-settings` header. With a `deviceId`, resolution
 * is device override → global override → default. Returns {} when the plugin
 * is unknown or declares no options — callers can always send it.
 */
export async function getEffectiveSettings(
  pluginId: string,
  deviceId?: string | null
): Promise<Record<string, unknown>> {
  const key = cacheKey(pluginId, deviceId);
  const now = Date.now();
  const cached = effectiveCache.get(key);
  if (cached && now - cached.cachedAt < EFFECTIVE_CACHE_TTL_MS) {
    return cached.values;
  }

  let values: Record<string, unknown> = {};
  try {
    const view = deviceId
      ? await getDevicePluginOptions(deviceId, pluginId)
      : await getPluginOptions(pluginId);
    values = view.effectiveValues;
  } catch {
    // Unknown plugin/assignment or DB hiccup: send no settings rather than fail the call.
    return {};
  }

  effectiveCache.set(key, { values, cachedAt: now });
  return values;
}

/**
 * Axios-ready headers carrying the plugin's effective settings as JSON.
 * Spread into any API→plugin call (`headers: await settingsHeaders(id)`).
 * Pass `deviceId` to resolve per-device overrides. Returns {} when there is
 * nothing to send so callers can always include it.
 */
export async function settingsHeaders(
  pluginId: string,
  deviceId?: string | null
): Promise<Record<string, string>> {
  // Per-plugin effective settings (device override → global → default) plus the
  // app-wide global settings flagged exposeToPlugins. Both ride on every call so
  // plugins can read either via readSettings() / readGlobalSettings().
  const [values, globalRaw] = await Promise.all([
    getEffectiveSettings(pluginId, deviceId),
    getPluginGlobalSettings().catch(() => ({})),
  ]);
  // Mutable copy — the pinning block below may add `knownCertificates`.
  const global: Record<string, unknown> = { ...(globalRaw as Record<string, unknown>) };

  // Certificate pinning: in strict mode the plugin must verify a device's
  // certificate/SSH host key against UNM's inventory BEFORE transmitting
  // credentials. The known fingerprints ride in the same global-settings header,
  // keyed "https:<host>:<port>" / "ssh:<host>:<port>" (the certificates table's
  // name/fingerprint columns). Best-effort — a lookup failure must never break
  // dispatch; plugins treat a missing map as "nothing pinned yet" (TOFU).
  if (deviceId && global['certPinningMode'] === 'strict') {
    try {
      const rows = await db.query.certificates.findMany({ where: eq(schema.certificates.deviceId, deviceId) });
      const known: Record<string, { fingerprint: string; commonName?: string | null }> = {};
      for (const r of rows) {
        if (!r.fingerprint || !r.host) continue; // no key recorded yet / unknown host
        // Pin against the TRUSTED fingerprint — the user-accepted key. The observed
        // `fingerprint` auto-updates on every poll, so pinning to it would never
        // detect a re-key (it would just track whatever the endpoint presents).
        // Fall back to observed only when trust has not been seeded yet.
        const trusted = r.trustedFingerprint || r.fingerprint;
        // Lowercase host — the SDK normalizes its lookup keys the same way, so an
        // uppercase hostname in the inventory still matches (otherwise strict mode
        // would silently degrade to TOFU for that endpoint).
        known[`${r.type}:${String(r.host).toLowerCase()}:${r.port ?? (r.type === 'ssh' ? 22 : 443)}`] = {
          fingerprint: trusted,
          commonName: r.commonName || null,
        };
      }
      if (Object.keys(known).length > 0) global['knownCertificates'] = known;
    } catch {
      // DB hiccup — send the header without pins (plugins fall back to TOFU).
    }
  }

  const headers: Record<string, string> = {};
  if (Object.keys(values).length > 0) headers['x-unm-settings'] = JSON.stringify(values);
  if (Object.keys(global).length > 0) headers['x-unm-global-settings'] = JSON.stringify(global);
  return headers;
}
