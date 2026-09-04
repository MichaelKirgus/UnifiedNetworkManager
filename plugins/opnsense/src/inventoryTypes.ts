import { TunnelRow } from './tunnels';
import { RouteRow } from './routes';
import { FirewallRuleRow } from './firewall';

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
}
