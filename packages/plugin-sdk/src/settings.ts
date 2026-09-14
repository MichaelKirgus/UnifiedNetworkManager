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

/**
 * Reads a boolean value from an object across candidate keys. Vendors encode
 * booleans inconsistently — real booleans, 1/'1', 0/'0', and yes/no/on/off
 * strings are all accepted (the union of OPNsense's observed encodings).
 */
export function pickBool(obj: Record<string, unknown>, keys: string[]): boolean | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'boolean') return v;
    if (v === 1 || v === '1' || v === true) return true;
    if (v === 0 || v === '0' || v === false) return false;
    if (typeof v === 'string') {
      const s = v.trim().toLowerCase();
      if (s === 'true' || s === 'yes' || s === 'on') return true;
      if (s === 'false' || s === 'no' || s === 'off') return false;
    }
  }
  return undefined;
}

/**
 * Normalizes a MAC address to lowercase colon form (`aa:bb:cc:dd:ee:ff`),
 * accepting hex with/without separators. Returns '' when unparseable — the same
 * contract as @unm/snmp-client's normalizeMac, so non-SNMP plugins (web-UI/API
 * based) get one canonical shape for inventory rows.
 */
export function normalizeMac(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  const hex = raw.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (hex.length === 12) return hex.replace(/([0-9a-f]{2})(?=[0-9a-f])/g, '$1:').slice(0, 17);
  if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(raw.trim().toLowerCase())) return raw.trim().toLowerCase();
  return '';
}

/** The `{creds?, error?}` envelope every plugin's credential resolver returns. */
export interface UserPassCreds {
  username: string;
  password: string;
}
export type ResolveUserPassResult = { creds?: UserPassCreds; error?: string };

/**
 * Extracts a username/password pair from the decrypted `credentials` field map
 * (the flat shape the API injects for a `usernamePassword` secret). This is the
 * shared core of the per-plugin `resolveCredentials()` wrappers that previously
 * each re-implemented the same extraction + validation:
 *   - non-string / missing fields become '' (an EMPTY password is legitimate —
 *     e.g. RouterOS/SwOS default admin has none);
 *   - a username is required only when `requireUsername` is set, else an empty
 *     username is allowed (FRITZ!Box password-only auth stores "none"/empty);
 *   - with `treatNoneAsEmpty`, the literal string "none" (case-insensitive) in
 *     the username field is normalized to '' — FRITZ!Boxes without a configured
 *     user list authenticate PASSWORD-ONLY and store "none" as that placeholder.
 * Pass `missingUsernameError` to keep your plugin's exact error wording.
 */
export function resolveUserPass(
  fields: Record<string, unknown> | undefined,
  opts: { requireUsername?: boolean; missingUsernameError?: string; treatNoneAsEmpty?: boolean } = {}
): ResolveUserPassResult {
  const c = fields && typeof fields === 'object' ? fields : {};
  let username = typeof c.username === 'string' ? c.username : '';
  const password = typeof c.password === 'string' ? c.password : '';
  if (opts.treatNoneAsEmpty && username.trim().toLowerCase() === 'none') username = '';
  if (opts.requireUsername !== false && username === '') {
    return { error: opts.missingUsernameError ?? 'Missing username in the assigned secret.' };
  }
  return { creds: { username, password } };
}
