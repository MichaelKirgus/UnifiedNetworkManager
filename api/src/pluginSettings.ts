import { and, eq } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { db } from './db';
import * as schema from './db/schema';
import type { PluginOptionDescriptor, StringOption, IntegerOption } from './types/pluginOptions';

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

/** Loads stored global overrides for a plugin as key -> decoded value. */
async function loadStoredValues(pluginId: string): Promise<Record<string, unknown>> {
  const rows = await db.query.pluginSettings.findMany({
    where: (settings) => eq(settings.pluginId, pluginId),
  });
  const values: Record<string, unknown> = {};
  for (const row of rows) {
    if (row.deviceId !== null) continue; // global scope only for now
    try {
      values[row.optionKey] = JSON.parse(row.value);
    } catch {
      // Corrupt stored value: skip rather than fail the whole view.
    }
  }
  return values;
}

/**
 * Descriptors + current overrides + effective values (defaults ⊕ overrides).
 * Works even when the plugin is offline — everything comes from the DB cache.
 */
export async function getPluginOptions(pluginId: string): Promise<PluginOptionsView> {
  const row = await loadPlugin(pluginId);
  const options = parseDescriptors(row.optionDescriptors);
  const values = await loadStoredValues(pluginId);

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
 * Validates ALL entries first and only then writes — a single invalid value
 * rejects the whole request with per-field errors (no partial saves).
 */
export async function upsertPluginSettings(
  pluginId: string,
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
        eq(schema.pluginSettings.optionKey, key)
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
        deviceId: null,
        optionKey: key,
        value: JSON.stringify(value),
        updatedAt: now,
      });
    }
  }

  invalidateEffectiveCache(pluginId);
}

/** Resets a plugin's settings to defaults (deletes its global override rows). */
export async function resetPluginSettings(pluginId: string): Promise<void> {
  await loadPlugin(pluginId); // 404 when unknown
  const rows = await db.query.pluginSettings.findMany({
    where: (settings) => eq(settings.pluginId, pluginId),
  });
  for (const row of rows) {
    if (row.deviceId !== null) continue;
    await db.delete(schema.pluginSettings).where(eq(schema.pluginSettings.id, row.id));
  }
  invalidateEffectiveCache(pluginId);
}

// --- Effective-values cache (for header injection on every plugin call) -----
// The telemetry worker polls /monitoring every 30s per device; resolving
// settings from the DB each time would add a query per poll. A short TTL
// cache keeps writes visible within seconds without hammering Postgres.

const EFFECTIVE_CACHE_TTL_MS = 5_000;
const effectiveCache = new Map<string, { values: Record<string, unknown>; cachedAt: number }>();

export function invalidateEffectiveCache(pluginId?: string): void {
  if (pluginId) effectiveCache.delete(pluginId);
  else effectiveCache.clear();
}

/**
 * Effective settings for a plugin (defaults ⊕ overrides), decoded and ready
 * to be serialized into the `x-unm-settings` header. Returns {} when the
 * plugin is unknown or declares no options — callers can always send it.
 */
export async function getEffectiveSettings(pluginId: string): Promise<Record<string, unknown>> {
  const now = Date.now();
  const cached = effectiveCache.get(pluginId);
  if (cached && now - cached.cachedAt < EFFECTIVE_CACHE_TTL_MS) {
    return cached.values;
  }

  let values: Record<string, unknown> = {};
  try {
    const view = await getPluginOptions(pluginId);
    values = view.effectiveValues;
  } catch {
    // Unknown plugin or DB hiccup: send no settings rather than fail the call.
    return {};
  }

  effectiveCache.set(pluginId, { values, cachedAt: now });
  return values;
}

/**
 * Axios-ready headers carrying the plugin's effective settings as JSON.
 * Spread into any API→plugin call (`headers: await settingsHeaders(id)`).
 * Returns {} when there is nothing to send so callers can always include it.
 */
export async function settingsHeaders(pluginId: string): Promise<Record<string, string>> {
  const values = await getEffectiveSettings(pluginId);
  if (Object.keys(values).length === 0) return {};
  return { 'x-unm-settings': JSON.stringify(values) };
}
