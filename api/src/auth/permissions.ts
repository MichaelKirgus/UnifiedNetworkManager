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
  // Device-level access control. ADDITIVE: every existing user/role keeps
  // full device visibility by default (no scope rules = unrestricted), so the
  // permission is granted to everyone at backfill time — removing it from a
  // role/user is what activates their deviceScope restrictions. Carriers of
  // this permission bypass all device-scope checks entirely.
  'devices:all': 'Access every device regardless of device-scope rules',
  'networks:read': 'View the Networks inventory page (logical networks across devices)',
  'hosts:read': 'View the Hosts inventory page (ARP/NDP/DHCP/WLAN clients)',
  // User-maintained host documentation (DNS names, IPs, expected MACs) — a
  // permanent inventory distinct from the live ARP/NDP observations above.
  'documented-hosts:read': 'View documented hosts (the user-maintained host inventory)',
  'documented-hosts:write': 'Create, update and delete documented hosts (incl. CSV import)',
  // User-maintained network documentation (subnets, VLANs, gateways, DNS) — a
  // permanent inventory distinct from the live interface observations above.
  'documented-networks:read': 'View documented networks (the user-maintained network inventory)',
  'documented-networks:write': 'Create, update and delete documented networks (incl. CSV import)',
  'tunnels:read': 'View the Tunnels page (configured + live tunnel state)',
  // Cross-device service inventory — OPNsense rc services, TrueNAS middleware
  // services and generic Linux systemd/OpenRC/runit/SysVinit units. Managed via
  // the plan/config workflow; this read permission only gates viewing the page.
  'services:read': 'View the Services page (systemd/rc/middleware services across devices)',
  'routes:read': 'View the Routes page (static and dynamic routes across devices)',
  'firewall:read': 'View the Firewall page (filter + NAT rules across devices)',
  'certificates:read': 'View the Certificates page (TLS certs + SSH host keys across devices)',
  // Accepting a CHANGED certificate/host key re-pins it for strict pinning — a
  // security-relevant action, so it is gated separately from reading.
  'certificates:write': 'Accept changed certificates / SSH host keys (re-pin endpoints)',
  'wifi:read': 'View the WiFi page (SSIDs, spectrum and neighbors)',
  'storage:read': 'View the Storage page (filesystems, pools/datasets and physical disks across devices)',
  // File-share exports (SMB/CIFS, NFS, iSCSI, NVMe-oF) + live client sessions.
  // Shares are managed through the plan/config workflow (configs:apply), so this
  // read permission only gates viewing the cross-device Shares page.
  'shares:read': 'View the Shares page (SMB/NFS/iSCSI/NVMe-oF shares and active client sessions across devices)',
  // Cross-device clock overview — each device's current time/timezone + drift vs UNM.
  // Time is managed through the plan/config workflow (configs:apply), so this read
  // permission only gates viewing the cross-device Time page.
  'time:read': 'View the Time page (device clocks, timezones and clock drift across devices)',
  'containers:read': 'View the Containers page (Apps/container workloads across devices)',
  'vms:read': 'View the VMs page (virtual machines and their NICs across devices)',
  // Cross-device update center — firmware, OS packages (package manager over SSH)
  // and Docker images/apps available for update. Applying an update is a plan
  // (configs:apply + 2FA); this read permission only gates viewing the page.
  'updates:read': 'View the Updates page (available firmware/package/image updates across devices)',
  'topology:read': 'View the Topology page (physical + logical network graph)',
  'sites:read': 'View sites',
  'config-jobs:read': 'View configuration jobs',
  'plans:read': 'View execution plans and their steps',
  'plugins:read': 'View plugins, their options and self-metrics',
  // Logs can carry critical details (endpoints, error payloads), so they get
  // their own permission instead of riding on devices:read. Gates both the
  // global /logs page and the per-device Logs section in DeviceDetail.
  'logs:read': 'View plugin log entries (device and global)',
  // Notification center — bell badge, dropdown panel and the full Notifications
  // page with filters. Acknowledging/closing is a read-level action (it only
  // affects the user's own view state); changing per-user visibility settings
  // additionally requires notifications:write.
  'notifications:read': 'View the notification center (bell, panel and Notifications page)',
  'notifications:write': 'Change personal notification visibility settings',
  'configs:apply': 'Submit configuration jobs to devices (requires 2FA)',
  'plugins:manage': 'Change global plugin settings',
  'secrets:read': 'View secrets (metadata only — values stay encrypted)',
  'secrets:write': 'Create and update secrets',
  'secrets:delete': 'Delete secrets',
  // Personal secret area: create your OWN secrets (and edit/delete them). Distinct
  // from the global `secrets:write` which manages ALL secrets. A user with only this
  // permission can build their own SSH/SFTP credentials for interactive sessions but
  // cannot touch other users' or shared secrets.
  'secrets:self-write': "Create and manage your own personal secrets (for interactive SSH / file access)",
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
  // Interactive web-UI sign-in. ADDITIVE: every existing user keeps it by
  // default, so removing it is an explicit lockdown for service-only accounts
  // that are only used to mint API tokens / call the API directly. Checked at
  // login (POST /auth/login) — long-lived API tokens are never affected.
  'auth:interactive-login': 'Sign in interactively to the web UI',
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
