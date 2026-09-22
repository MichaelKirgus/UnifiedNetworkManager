/**
 * @unm/plugin-sdk — shared service-inventory contract for plugins.
 *
 * Powers the cross-device "Services" page: every plugin can report, per device,
 * the services it manages and their current state — OPNsense rc services via
 * its core/service API, TrueNAS middleware services via JSON-RPC + a `ps`
 * snapshot over SSH, generic Linux hosts via systemd/OpenRC/runit/SysVinit
 * detection over plain SSH.
 *
 * The contract is deliberately vendor-agnostic: ONE row per service with a
 * normalized status vocabulary and an init-system label so the page can group
 * and badge rows uniformly. `extra` carries vendor-specific details (e.g.
 * systemd sub-state, TrueNAS process match).
 */

/** Known init systems / service frameworks (free-form strings are tolerated —
 *  unknown labels render with a neutral badge instead of breaking the PK). */
export type ServiceType = 'systemd' | 'openrc' | 'runit' | 'sysvinit' | 'freebsd-rc' | 'truenas' | 'openwrt';

/** Normalized service states (plugins report what they can observe). */
export const SERVICE_STATUSES = ['running', 'stopped', 'failed', 'unknown'] as const;
export type ServiceStatus = (typeof SERVICE_STATUSES)[number];

/** One row of the services inventory → `metrics['services']` + device_services. */
export interface ServiceRow {
  /** Service name on the device ("sshd", "smb", "unbound", "nginx.service"…). */
  name: string;
  /** Init system / framework managing it (see ServiceType). */
  type?: ServiceType | string;
  /** running | stopped | failed | unknown — normalized to lowercase at ingest. */
  status?: ServiceStatus | string;
  /** True when the service is enabled to start on boot; null = not observable. */
  enabled?: boolean | null;
  /** Main process id (null when not a live-process metric or stopped). */
  pid?: number | null;
  /** Human description from the vendor ("System Logging", "SMB/CIFS service"…). */
  description?: string | null;
  /** Vendor-specific extras: systemd sub-state, TrueNAS matched process, … */
  extra?: Record<string, unknown>;
}
