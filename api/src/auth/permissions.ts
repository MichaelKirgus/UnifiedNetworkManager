/**
 * Canonical permission catalog for UnifiedNetworkManager.
 *
 * RBAC is flat at enforcement time: users carry a `permissions` string array
 * in their JWT claims and only that claim is checked by middleware. Roles are
 * DB-backed bundles of permissions (see the `roles` table) whose permissions
 * are unioned into the user's explicit permissions when the JWT is minted —
 * so role changes take effect on the next login, same as explicit grants.
 * This module is the single source of truth for which permissions exist —
 * used by the admin seed, the one-time admin backfills, and the
 * `GET /v1/permissions` catalog endpoint that drives the Users/Roles UIs.
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
  'users:write': 'Edit user roles/permissions, manage roles, and delete users',
  'users:create': 'Create new users with an initial password and TOTP enrollment',
  'users:manage-credentials': "Reset passwords and manage 2FA of other users",
  'users:self-credentials': 'Change own password and manage own 2FA',
};

/** All known permission ids (stable order — object key insertion order). */
export const ALL_PERMISSIONS: string[] = Object.keys(PERMISSION_DESCRIPTIONS);

/** The admin role is granted every permission. */
export const ADMIN_PERMISSIONS: string[] = [...ALL_PERMISSIONS];

/**
 * Roles the platform knows about at bootstrap time (admin = full access by
 * convention). Additional roles are created via `POST /v1/roles` and live in
 * the `roles` table; this list only seeds/falls back for the built-in admin.
 */
export const KNOWN_ROLES: string[] = ['admin'];

/** Username of the initial seeded admin — protected from deletion/demotion. */
export const INITIAL_ADMIN_USERNAME = 'admin';
