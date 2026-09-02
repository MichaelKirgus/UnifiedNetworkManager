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
  // --- Page-scoped read/write pairs -----------------------------------------
  // Every webapp page has a dedicated read permission gating its data routes;
  // write permissions gate the mutating routes of that area. The sidebar hides
  // menu entries whose read permission is missing (see Sidebar.tsx).
  'devices:read': 'View devices, their plugins and telemetry',
  'devices:write': 'Create, update and delete devices and plugin assignments',
  'networks:read': 'View the Networks inventory page (logical networks across devices)',
  'hosts:read': 'View the Hosts inventory page (ARP/NDP/DHCP/WLAN clients)',
  'tunnels:read': 'View the Tunnels page (configured + live tunnel state)',
  'routes:read': 'View the Routes page (static and dynamic routes across devices)',
  'wifi:read': 'View the WiFi page (SSIDs, spectrum and neighbors)',
  'topology:read': 'View the Topology page (physical + logical network graph)',
  'sites:read': 'View sites',
  'config-jobs:read': 'View configuration jobs',
  'plans:read': 'View execution plans and their steps',
  'plugins:read': 'View plugins, their options and self-metrics',
  // Logs can carry critical details (endpoints, error payloads), so they get
  // their own permission instead of riding on devices:read. Gates both the
  // global /logs page and the per-device Logs section in DeviceDetail.
  'logs:read': 'View plugin log entries (device and global)',
  'configs:apply': 'Submit configuration jobs to devices (requires 2FA)',
  'plugins:manage': 'Change global plugin settings',
  'secrets:read': 'View secrets (metadata only — values stay encrypted)',
  'secrets:write': 'Create and update secrets',
  'secrets:delete': 'Delete secrets',
  'sites:write': 'Create, update and delete sites',
  // Topology layer registry (band names/colors/order) — read is open to any
  // authenticated user (the topology page needs it), write is gated.
  'layers:write': 'Add, edit or remove network layers used by the topology view',
  'tokens:manage': "Create, view and revoke your own API tokens",
  'users:read': 'View users and their roles/permissions',
  'users:write': 'Edit user roles/permissions, manage roles, and delete users',
  'users:create': 'Create new users with an initial password and TOTP enrollment',
  'users:manage-credentials': "Reset passwords and manage 2FA of other users",
  'users:self-credentials': 'Change own password and manage own 2FA',
  // Credential policies (required 2nd factor at login + which AMRs satisfy the
  // privileged-action gate) — global default and per-user overrides.
  'auth:policies:write': 'Edit credential policies (2FA requirements and 2FA-gate satisfaction)',
  // System/HA observability + runtime tuning (Workers page): worker leadership,
  // poll-cycle stats, Postgres health, and the admin-tunable HA settings.
  'system:read': 'View system status — workers, leader election, database health',
  'system:write': 'Change runtime worker/HA settings (poll cadence, concurrency)',
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
