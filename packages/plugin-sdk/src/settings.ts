/**
 * Settings + small shared helpers (previously copy-pasted into 5-7 plugins).
 */

import { PluginOptionDescriptor } from './types';

/**
 * Reads the effective settings the API injects on every call (defaults ⊕ user
 * overrides) from the `x-unm-settings` JSON header, merged over this plugin's
 * declared defaults so a missing/malformed header still yields sane values.
 */
export function readSettings(
  req: { headers?: Record<string, unknown> },
  options: PluginOptionDescriptor[] = []
): Record<string, unknown> {
  const defaults: Record<string, unknown> = {};
  for (const opt of options) if (opt.default !== undefined) defaults[opt.key] = opt.default;

  const raw = req.headers?.['x-unm-settings'];
  if (typeof raw !== 'string' || raw.trim() === '') return defaults;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') return { ...defaults, ...(parsed as Record<string, unknown>) };
  } catch {
    // Malformed header: fall back to defaults rather than failing the call.
  }
  return defaults;
}

/**
 * Reads the app-wide GLOBAL settings the API injects on every call from the
 * `x-unm-global-settings` JSON header, merged over the caller's declared
 * fallbacks so a missing/malformed header still yields sane values.
 *
 * These are the system-level knobs that are NOT plugin- or device-specific (e.g.
 * telemetry poll window, plan step timeout) — as opposed to readSettings(),
 * which reads THIS plugin's own options from `x-unm-settings`. The API only
 * sends keys it has flagged for plugins; pass your fallbacks so a key the API
 * does not send still resolves to something sensible.
 */
export function readGlobalSettings(
  req: { headers?: Record<string, unknown> },
  defaults: Record<string, unknown> = {}
): Record<string, unknown> {
  const raw = req.headers?.['x-unm-global-settings'];
  if (typeof raw !== 'string' || raw.trim() === '') return { ...defaults };
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') return { ...defaults, ...(parsed as Record<string, unknown>) };
  } catch {
    // Malformed header: fall back to defaults rather than failing the call.
  }
  return { ...defaults };
}

/** Clamps an unknown value into [min, max]; non-integers fall back. */
export function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  const n = typeof value === 'number' && Number.isInteger(value) ? value : fallback;
  return Math.min(max, Math.max(min, n));
}

/** Extracts a bare host (no scheme/port/brackets) from a management address. */
export function hostFromAddress(address: string): string {
  const trimmed = (address ?? '').trim();
  if (!trimmed) return '';
  try {
    const u = new URL(trimmed.includes('://') ? trimmed : `http://${trimmed}`);
    return u.hostname.replace(/^\[|\]$/g, ''); // strip IPv6 literal brackets
  } catch {
    return trimmed.split('/')[0].split(':')[0];
  }
}

/** Reads the first non-empty string value from an object across candidate keys. */
export function pickString(obj: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'string' && v.trim() !== '') return v;
  }
  return undefined;
}

/** Reads a numeric value from an object across candidate keys (numeric strings coerced). */
export function pickNumber(obj: Record<string, unknown>, keys: string[]): number | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'number' && Number.isFinite(v)) return v;
    if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) return Number(v);
  }
  return undefined;
}
