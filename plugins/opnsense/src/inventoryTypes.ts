import { TunnelRow } from './tunnels';
import { RouteRow } from './routes';
import { FirewallRuleRow } from './firewall';
import type { CertificateRow, ServiceRow } from '@unm/plugin-sdk';

/**
 * The cached inventory snapshot for one appliance (see getInventory in index.ts).
 * Lives in its own module so both the /monitoring collector and the /state
 * builder can share the shape without a circular import.
 */
export interface InventorySnapshot {
  collectedAt: number;
  hostname?: string;
  version?: string;
  arp: Record<string, unknown>[];
  ndp: Record<string, unknown>[];
  /** Configured networks: one row per interface IP address (see parseNetworkRows). */
  networks: Record<string, unknown>[];
  /** Active DHCP leases normalized across Kea/dnsmasq backends. */
  dhcpLeases: Record<string, unknown>[];
  /** Configured tunnels (WireGuard/OpenVPN/IPsec/PPPoE/GRE) — see collectTunnels. */
  tunnels: TunnelRow[];
  /** Configured static routes — see collectRoutes. */
  routes: RouteRow[];
  /** Firewall rules (filter + NAT kinds), unified shape — see collectFirewallRules.
   * null = collection failed this cycle → /monitoring must NOT emit the key, so a
   * transient failure never wipes previously stored rows (present-but-empty is
   * authoritative on the API side). */
  firewallRules: FirewallRuleRow[] | null;
  /** Configured gateways (routing/settings) — feeds the derived default-route rows. */
  gateways: Record<string, unknown>[];
  /** Storage inventory for the cross-device Storage page (see collectStorage).
   * Empty arrays = appliance has no ZFS/USB storage endpoints (404). */
  filesystems: Record<string, unknown>[];
  disks: Record<string, unknown>[];
  /** Certificate endpoints (management HTTPS cert + SSH host key) for the
   * Certificates page. [] = nothing readable this cycle (e.g. plain-http UI). */
  certificates: CertificateRow[];
  /** rc-managed services with running state (Services page) — see collectServices.
   * null = collection failed this cycle → /monitoring must NOT emit the key, so a
   * transient failure never wipes previously stored rows. */
  services: ServiceRow[] | null;
  /** Static DNS host entries {name, ip} from the active backend (dnsmasq hosts /
   * unbound local-zone overrides) — feeds UNM's cross-device DNS page. Unbound
   * rows carry a native free-text `description` when set; dnsmasq has none.
   * null = collection failed this cycle → /monitoring must NOT emit the key. */
  // `domain` is set only by the unbound backend (bare hostname + separate
  // domain field); dnsmasq rows carry no domain.
  dnsEntries: Array<{ name: string; ip: string; domain?: string; description?: string }> | null;
  /** True when the SSH ZFS enrichment SUCCEEDED for this snapshot (a bound ssh
   * slot answered with a real pool listing). Drives notification mirroring of
   * pool states — false means "no fresh authoritative ZFS data", so live pool
   * alerts are kept rather than wrongly cleared by an API-only poll or a
   * transient SSH failure. */
  zfsSshCollected?: boolean;
}
