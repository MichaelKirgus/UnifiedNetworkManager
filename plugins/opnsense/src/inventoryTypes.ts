import { TunnelRow } from './tunnels';
import { RouteRow } from './routes';

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
  /** Configured gateways (routing/settings) — feeds the derived default-route rows. */
  gateways: Record<string, unknown>[];
}
