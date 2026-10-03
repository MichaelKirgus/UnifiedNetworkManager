import { db } from '../db';
import * as schema from '../db/schema';
import { ipFamily, nextFreeAddressInCidr } from '@unm/plugin-sdk';

/**
 * IP auto-assignment for the fleet rollout wizard.
 *
 * When a rollout carries a CIDR (v4 and/or v6), every device that will get an
 * L3 address needs ONE concrete host address inside it. UNM computes those
 * from its own live inventory — the next free address in the target subnet,
 * skipping everything already observed anywhere in the fleet:
 *   - `networks` rows (per-interface ip + prefix — the primary source),
 *   - `hosts` rows (ARP/NDP/DHCP leases — addresses handed out to clients),
 *   - `device_ips` (management + secondary addresses).
 *
 * Allocation is SEQUENTIAL within one rollout: each address assigned in this
 * batch is reserved for the next device, so a /24 with 5 targets yields .1…/5
 * even though none of them exist in the inventory yet.
 */

/** One device's suggested host addresses (null = subnet exhausted or no CIDR). */
export interface IpSuggestion {
  v4?: string | null;
  v6?: string | null;
}

/** Loads every known address literal from the live inventory into one set. */
export async function loadUsedAddresses(): Promise<Set<string>> {
  const [netRows, hostRows, ipRows] = await Promise.all([
    db.query.networks.findMany(),
    db.query.hosts.findMany(),
    db.query.deviceIps.findMany(),
  ]);
  const used = new Set<string>();
  for (const r of netRows) {
    if (!r.ip || ipFamily(r.ip)) used.add(r.ip);
  }
  for (const r of hostRows) {
    if (ipFamily(r.ip)) used.add(r.ip);
  }
  for (const r of ipRows) {
    if (ipFamily(r.address)) used.add(r.address);
  }
  return used;
}

/**
 * Allocates the next free host address(es) inside the given CIDR(s).
 * `used` is mutated: every allocated address is added to it, so calling this
 * once per device in order yields a sequential, collision-free assignment.
 */
export function allocateAddresses(
  cidrV4: string | null | undefined,
  cidrV6: string | null | undefined,
  used: Set<string>,
): IpSuggestion {
  const out: IpSuggestion = {};
  if (cidrV4) {
    const a = nextFreeAddressInCidr(cidrV4, used);
    if (a !== null) { out.v4 = a; used.add(a); } else out.v4 = null;
  }
  if (cidrV6) {
    const a = nextFreeAddressInCidr(cidrV6, used);
    if (a !== null) { out.v6 = a; used.add(a); } else out.v6 = null;
  }
  return out;
}

/**
 * Per-device IP suggestions for one rollout: `deviceId → {v4?, v6?}`. Only
 * devices with at least one target CIDR get an entry; the caller decides which
 * of them actually receive an L3 address (deployed no-ops and L2-only devices
 * are filtered out by the dialog).
 */
export async function suggestRolloutAddresses(
  deviceIds: string[],
  cidrV4: string | null,
  cidrV6: string | null,
): Promise<Record<string, IpSuggestion>> {
  if (!cidrV4 && !cidrV6) return {};
  const used = await loadUsedAddresses();
  const out: Record<string, IpSuggestion> = {};
  for (const id of deviceIds) {
    out[id] = allocateAddresses(cidrV4, cidrV6, used);
  }
  return out;
}
