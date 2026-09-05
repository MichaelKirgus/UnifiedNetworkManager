/**
 * Generic credential-slot contract.
 *
 * A plugin's PRIMARY credential is the single secret bound to a device
 * assignment (`device_plugins.secretId`), typed by the plugin's declared
 * `requiredSecretType`. Some devices need MORE than one distinct credential —
 * e.g. an LCOS router polled via SNMP but backed up/restored through its web
 * UI with a separate user/password. Plugins declare such additional slots in
 * their `/discover` response:
 *
 *   "credentialSlots": [
 *     { "name": "web", "secretType": "usernamePassword",
 *       "required": false, "description": "Web-UI login for config backup/restore" }
 *   ]
 *
 * The API persists the descriptors on the plugin row (only-overwrite-when-
 * present guard, like metrics/options) and validates that a secret bound to a
 * slot matches its declared `secretType`. Workers decrypt every bound slot and
 * pass them through to plugins under `credentials.slots.<name>` — the primary
 * credential stays at the top level of `credentials`, unchanged.
 */

// The descriptor contract lives in @unm/plugin-sdk — re-exported so API modules
// keep their existing imports.
export type { CredentialSlotDescriptor } from '@unm/plugin-sdk';
import { allowedSecretTypes, type CredentialSlotDescriptor } from '@unm/plugin-sdk';

/** Bound secrets for one assignment: slot name → secrets.id (JSON object). */
export type ExtraCredentials = Record<string, string>;

/** Defensively normalizes a raw `credentialSlots` array from /discover.
 *  A slot is valid when it declares at least ONE allowed secret type — either
 *  the legacy single `secretType` or the multi-type `secretTypes` list (which
 *  wins and is also mirrored into `secretType[0]` so older consumers keep working). */
export function normalizeCredentialSlots(raw: unknown): CredentialSlotDescriptor[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const out: CredentialSlotDescriptor[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const e = item as Record<string, unknown>;
    if (typeof e.name !== 'string' || e.name.trim() === '') continue;
    // Collect the allowed types from both declaration forms.
    const types: string[] = [];
    if (Array.isArray(e.secretTypes)) {
      for (const t of e.secretTypes) {
        if (typeof t === 'string' && t.trim() !== '' && !types.includes(t.trim())) types.push(t.trim());
      }
    }
    if (typeof e.secretType === 'string' && e.secretType.trim() !== '' && !types.includes(e.secretType.trim())) {
      types.push(e.secretType.trim());
    }
    if (types.length === 0) continue; // no usable type — skip the slot
    const name = e.name.trim();
    if (seen.has(name)) continue; // first declaration wins — keep it stable
    seen.add(name);
    const slot: CredentialSlotDescriptor = { name, secretType: types[0], secretTypes: types };
    if (typeof e.required === 'boolean') slot.required = e.required;
    if (typeof e.description === 'string' && e.description.trim() !== '') slot.description = e.description.trim();
    out.push(slot);
  }
  return out.length > 0 ? out : undefined;
}

/** True when a secret of `type` may be bound to the given slot. */
export function slotAcceptsType(slot: CredentialSlotDescriptor, type: string): boolean {
  return allowedSecretTypes(slot).includes(type);
}

/** Parses a stored extraCredentials JSON column into a slot map. Never throws. */
export function parseExtraCredentials(raw: string | null | undefined): ExtraCredentials {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const out: ExtraCredentials = {};
      for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof v === 'string' && v.length > 0) out[k] = v;
      }
      return out;
    }
  } catch {
    /* malformed JSON — treat as empty */
  }
  return {};
}
