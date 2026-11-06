/**
 * systemActions — LOCAL mutation actions run by the UNM plan executor itself.
 *
 * The plan engine is device-centric: every step normally dispatches to a plugin's
 * /config endpoint for one of the caller's devices. RADIUS and CA (WiFi EAP-TLS)
 * changes have NO device — they act on UNM's own sidecars (the FreeRADIUS config
 * volume + the step-ca service). To route them through the SAME plan workflow
 * (2FA-gated execution, full audit trail, retryable, schedulable, automatable),
 * this module defines a small set of reserved LOCAL action ids. The executor
 * recognizes them via {@link isLocalMutationAction} and runs them in-process by
 * calling the shared mutation functions — never dispatching to any plugin.
 *
 * A system plan carries the sentinel plugin/device ids (see SYSTEM_PLUGIN_ID /
 * SYSTEM_DEVICE_ID) so it slots into the existing plans/plan_steps tables without
 * schema changes. Each action declares the DOMAIN permission that gates its plan
 * ({@link requiredDomainPermission}) — on top of the global `configs:apply` + 2FA
 * gate every plan already passes through.
 */

import {
  createNasClient,
  updateNasClient,
  deleteNasClient,
  deleteNasClients,
  createProfile,
  updateProfile,
  deleteProfile,
  deleteProfiles,
} from '../radius/mutations';
import { enrollWifiCert, revokeWifiCert, revokeWifiCerts } from '../ca/mutations';

/** Sentinel plugin id for system (device-less) plans. Not a real plugins row. */
export const SYSTEM_PLUGIN_ID = '__unm-system__';
/** Sentinel device id for system plan steps. Not a real devices row. */
export const SYSTEM_DEVICE_ID = '__unm-system__';

// --- Reserved local-mutation action ids --------------------------------------

export const ACTION_RADIUS_NAS_CREATE = 'radius.nas-client.create';
export const ACTION_RADIUS_NAS_UPDATE = 'radius.nas-client.update';
export const ACTION_RADIUS_NAS_DELETE = 'radius.nas-client.delete';
export const ACTION_RADIUS_NAS_BULK_DELETE = 'radius.nas-client.bulk-delete';
export const ACTION_RADIUS_PROFILE_CREATE = 'radius.profile.create';
export const ACTION_RADIUS_PROFILE_UPDATE = 'radius.profile.update';
export const ACTION_RADIUS_PROFILE_DELETE = 'radius.profile.delete';
export const ACTION_RADIUS_PROFILE_BULK_DELETE = 'radius.profile.bulk-delete';
// The certs are EAP-TLS CLIENT certificates — WiFi is one consumer, wired
// 802.1X (and any other EAP-TLS supplicant) uses the same enrollment.
export const ACTION_CA_CLIENT_ENROLL = 'ca.client-cert.enroll';
export const ACTION_CA_CLIENT_REVOKE = 'ca.client-cert.revoke';
export const ACTION_CA_CLIENT_BULK_REVOKE = 'ca.client-cert.bulk-revoke';

const LOCAL_ACTION_IDS: ReadonlySet<string> = new Set([
  ACTION_RADIUS_NAS_CREATE,
  ACTION_RADIUS_NAS_UPDATE,
  ACTION_RADIUS_NAS_DELETE,
  ACTION_RADIUS_NAS_BULK_DELETE,
  ACTION_RADIUS_PROFILE_CREATE,
  ACTION_RADIUS_PROFILE_UPDATE,
  ACTION_RADIUS_PROFILE_DELETE,
  ACTION_RADIUS_PROFILE_BULK_DELETE,
  ACTION_CA_CLIENT_ENROLL,
  ACTION_CA_CLIENT_REVOKE,
  ACTION_CA_CLIENT_BULK_REVOKE,
]);

/** True for reserved local-mutation action ids (executor runs them in-process). */
export function isLocalMutationAction(actionId: string): boolean {
  return LOCAL_ACTION_IDS.has(actionId);
}

/** The domain permission that gates a local-mutation plan (beyond configs:apply + 2FA). */
export function requiredDomainPermission(actionId: string): string | null {
  switch (actionId) {
    case ACTION_RADIUS_NAS_CREATE:
    case ACTION_RADIUS_NAS_UPDATE:
    case ACTION_RADIUS_NAS_DELETE:
    case ACTION_RADIUS_NAS_BULK_DELETE:
    case ACTION_RADIUS_PROFILE_CREATE:
    case ACTION_RADIUS_PROFILE_UPDATE:
    case ACTION_RADIUS_PROFILE_DELETE:
    case ACTION_RADIUS_PROFILE_BULK_DELETE:
      return 'radius:write';
    case ACTION_CA_CLIENT_ENROLL:
    case ACTION_CA_CLIENT_REVOKE:
    case ACTION_CA_CLIENT_BULK_REVOKE:
      return 'ca:manage';
    default:
      return null;
  }
}

/** Human-readable label for the Plans UI (system plans have no real plugin). */
export function systemPlanLabel(actionId: string): string {
  switch (actionId) {
    case ACTION_RADIUS_NAS_CREATE: return 'Add RADIUS NAS client';
    case ACTION_RADIUS_NAS_UPDATE: return 'Update RADIUS NAS client';
    case ACTION_RADIUS_NAS_DELETE: return 'Remove RADIUS NAS client';
    case ACTION_RADIUS_NAS_BULK_DELETE: return 'Remove RADIUS NAS clients (bulk)';
    case ACTION_RADIUS_PROFILE_CREATE: return 'Add RADIUS user profile';
    case ACTION_RADIUS_PROFILE_UPDATE: return 'Update RADIUS user profile';
    case ACTION_RADIUS_PROFILE_DELETE: return 'Remove RADIUS user profile';
    case ACTION_RADIUS_PROFILE_BULK_DELETE: return 'Remove RADIUS user profiles (bulk)';
    case ACTION_CA_CLIENT_ENROLL: return 'Enroll EAP-TLS client certificate';
    case ACTION_CA_CLIENT_REVOKE: return 'Revoke EAP-TLS client certificate';
    case ACTION_CA_CLIENT_BULK_REVOKE: return 'Revoke EAP-TLS client certificates (bulk)';
    default: return actionId;
  }
}

/**
 * Runs one local-mutation step in-process. Returns the result object that is
 * stored on plan_steps.result (and available to later steps via
 * `${steps[N].result.details.*}` tokens). Throws on any failure — the executor
 * records it as a failed step and fails the plan unless the step is bestEffort.
 */
export async function runLocalMutationStep(actionId: string, input: Record<string, unknown>): Promise<Record<string, unknown>> {
  switch (actionId) {
    case ACTION_RADIUS_NAS_CREATE:
      return await createNasClient(input);
    case ACTION_RADIUS_NAS_UPDATE:
      if (typeof input.id !== 'string' || !input.id.trim()) throw new Error('"id" is required');
      return await updateNasClient(input.id.trim(), input);
    case ACTION_RADIUS_NAS_DELETE:
      if (typeof input.id !== 'string' || !input.id.trim()) throw new Error('"id" is required');
      return await deleteNasClient(input.id.trim());
    case ACTION_RADIUS_NAS_BULK_DELETE: {
      const ids = Array.isArray(input.ids) ? (input.ids as unknown[]).filter((x): x is string => typeof x === 'string' && !!x.trim()) : [];
      if (ids.length === 0) throw new Error('"ids" must be a non-empty array of NAS client ids');
      if (ids.length > 500) throw new Error('At most 500 ids per bulk delete');
      return await deleteNasClients(ids);
    }
    case ACTION_RADIUS_PROFILE_CREATE:
      return await createProfile(input);
    case ACTION_RADIUS_PROFILE_UPDATE:
      if (typeof input.id !== 'string' || !input.id.trim()) throw new Error('"id" is required');
      return await updateProfile(input.id.trim(), input);
    case ACTION_RADIUS_PROFILE_DELETE:
      if (typeof input.id !== 'string' || !input.id.trim()) throw new Error('"id" is required');
      return await deleteProfile(input.id.trim());
    case ACTION_RADIUS_PROFILE_BULK_DELETE: {
      const ids = Array.isArray(input.ids) ? (input.ids as unknown[]).filter((x): x is string => typeof x === 'string' && !!x.trim()) : [];
      if (ids.length === 0) throw new Error('"ids" must be a non-empty array of profile ids');
      if (ids.length > 500) throw new Error('At most 500 ids per bulk delete');
      return await deleteProfiles(ids);
    }
    case ACTION_CA_CLIENT_ENROLL:
      return await enrollWifiCert(input);
    case ACTION_CA_CLIENT_REVOKE:
      if (typeof input.serial !== 'string' || !input.serial.trim()) throw new Error('"serial" is required');
      return { serial: input.serial.trim().toLowerCase(), ...(await revokeWifiCert(input.serial)) };
    case ACTION_CA_CLIENT_BULK_REVOKE: {
      const serials = Array.isArray(input.serials) ? (input.serials as unknown[]).filter((x): x is string => typeof x === 'string' && !!x.trim()) : [];
      if (serials.length === 0) throw new Error('"serials" must be a non-empty array of hex certificate serials');
      return await revokeWifiCerts(serials);
    }
    default:
      throw new Error(`Unknown local-mutation action "${actionId}"`);
  }
}
