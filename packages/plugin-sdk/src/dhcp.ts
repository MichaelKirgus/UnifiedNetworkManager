/**
 * Cross-device DHCP inventory contract — shared row shapes that router plugins
 * emit in /monitoring metrics so the API can persist them for the DHCP page:
 *
 *   - `dhcpNetworks[]`     — configured DHCP server networks/pools (range, lease time)
 *   - `dhcpReservations[]` — static MAC→IP mappings/reservations
 *
 * Live leases are NOT part of this contract — they already flow through the
 * existing `dhcpLeases[]` metric into the hosts table (source 'dhcp').
 *
 * Emission follows the standard present-vs-absent inventory rule: a PRESENT
 * but empty array is authoritative ("this device has no DHCP networks"), an
 * ABSENT key means "plugin doesn't report this" and must not wipe stored rows.
 */

/** One configured DHCP server network/pool on one device (one row per range). */
export interface DhcpNetworkRow {
  /** Network/scope name as configured, or the serving interface when the vendor has no name. */
  name: string;
  /** Serving interface (e.g. `bridge1`, `lan`). Null when the vendor doesn't expose it. */
  interface?: string | null;
  /** First address of the lease range. */
  rangeStart: string;
  /** Last address of the lease range. */
  rangeEnd: string;
  /** Subnet CIDR covering the range (derived by the plugin when known). Null = unknown. */
  cidr?: string | null;
  /** Lease time in seconds as configured on the device. Null = vendor default / not exposed. */
  leaseTimeSeconds?: number | null;
  /** Gateway address handed out to clients. Null = not exposed. */
  gateway?: string | null;
  /** DNS servers handed out to clients (comma-joined). Null = not exposed. */
  dnsServers?: string | null;
  /** Vendor-side row identity used for deletion (dnsmasq range uuid, Kea subnet id…). Null = no stable handle. */
  refId?: string | null;
}

/** One static DHCP reservation (MAC → fixed IP) on one device. */
export interface DhcpReservationRow {
  /** Client MAC address, lowercase colon form. */
  mac: string;
  /** Fixed IP the client always receives. Null when the vendor exposes a name-only mapping. */
  ip?: string | null;
  /** Hostname bound to the reservation (when the vendor has one). */
  hostname?: string | null;
  /** Serving interface the mapping is scoped to (OPNsense staticmaps are per-interface). Null = not exposed. */
  iface?: string | null;
  /** Vendor-specific row identifier used for deletion (OPNsense uuid, OpenWrt uci key…). Null = delete by MAC. */
  refId?: string | null;
  /**
   * Vendor lease status when exposed (e.g. RouterOS `bound`/`free`). Some vendors
   * keep static bindings and active dynamic leases in ONE table (RouterOS
   * /ip/dhcp-server/lease) — the page uses this + a live-lease join to tell them
   * apart. Null = vendor has no status field (the row is unambiguously static).
   */
  status?: string | null;
}
