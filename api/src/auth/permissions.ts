/**
 * Canonical permission catalog for UnifiedNetworkManager.
 *
 * RBAC here is flat: users carry a `permissions` string array in their JWT
 * claims (roles are decorative and never evaluated). This module is the single
 * source of truth for which permissions exist — used by the admin seed, the
 * one-time admin backfill, and the `GET /v1/permissions` catalog endpoint that
 * drives the Users page UI.
 */

/** Permission id → human-readable description (shown in the Users page). */
export const PERMISSION_DESCRIPTIONS: Record<string, string> = {
  'devices:read': 'View devices, their plugins and telemetry',
  'devices:write': 'Create, update and delete devices and plugin assignments',
  'configs:apply': 'Submit configuration jobs to devices (requires 2FA)',
  'plugins:manage': 'Change global plugin settings',
  'secrets:read': 'View secrets (metadata only — values stay encrypted)',
  'secrets:write': 'Create and update secrets',
  'secrets:delete': 'Delete secrets',
  'sites:write': 'Create, update and delete sites',
  'users:read': 'View users and their roles/permissions',
  'users:write': 'Edit user roles/permissions and delete users',
};

/** All known permission ids (stable order — object key insertion order). */
export const ALL_PERMISSIONS: string[] = Object.keys(PERMISSION_DESCRIPTIONS);

/** The admin role is granted every permission. */
export const ADMIN_PERMISSIONS: string[] = [...ALL_PERMISSIONS];

/** Roles the platform knows about (admin = full access by convention). */
export const KNOWN_ROLES: string[] = ['admin'];
