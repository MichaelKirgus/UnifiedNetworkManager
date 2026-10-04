/**
 * Flow IP classification — pure, dependency-free (unit-tested in isolation).
 *
 * Decides whether an endpoint IP is `internal`, `internet` or `unknown` for the
 * Flows feature. The internal/external IPv4 range lists are GLOBAL SETTINGS
 * (`flowInternalRanges` / `flowExternalRanges`) so each deployment can define
 * its own "inside" — the defaults are RFC 1918 private space and an empty
 * external list.
 *
 * Precedence (highest first):
 *   1. exact inventory hit (hosts / device_ips / devices.managementAddress) → internal + deviceId
 *   2. special non-routable IPv4 (0/8, link-local, multicast/reserved ≥224) → unknown
 *   3. external range list match → internet — an EXPLICIT carve-out beats the
 *      broad inventoried-network and internal-range matches (e.g. a public or
 *      DMZ subnet living inside an inventoried /16 must still count as egress)
 *   4. inventoried network CIDR match → internal + deviceId
 *   5. internal range list match → internal
 *   6. any other public IPv4 → internet; IPv6 / unparseable → unknown (v1 simplification)
 */

/** One parsed CIDR entry ("a.b.c.d/p" → network + mask). */
export interface CidrEntry {
  net: number;
  mask: number;
  prefixLen: number; // longest-prefix wins on ties
}

/** Parse an IPv4 dotted quad to an unsigned int, or null. */
export function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const octet = Number(m[i]);
    if (octet > 255) return null;
    n = (n << 8) | octet;
  }
  return n >>> 0;
}

/** Prefix network + mask for "a.b.c.d/p" (or bare IP → /32). */
export function ipv4CidrToNetMask(cidr: string): { net: number; mask: number } | null {
  const [ipPart, prefixPart] = cidr.split('/');
  const ip = ipv4ToInt(ipPart.trim());
  if (ip === null) return null;
  const prefix = prefixPart !== undefined ? Number(prefixPart) : 32;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return { net: (ip & mask) >>> 0, mask };
}

/**
 * Parses a comma-separated CIDR list ("10.0.0.0/8, 192.168.0.0/16") into
 * entries. Empty string → []. Throws on any malformed entry (settings
 * validation surfaces it as a 400).
 */
export function parseCidrList(value: string): CidrEntry[] {
  const out: CidrEntry[] = [];
  for (const raw of value.split(',')) {
    const part = raw.trim();
    if (!part) continue; // empty segments are fine ("10.0.0.0/8,,192.168.0.0/16")
    const cm = ipv4CidrToNetMask(part);
    if (!cm) throw new Error(`invalid IPv4 CIDR "${part}"`);
    out.push({ net: cm.net, mask: cm.mask, prefixLen: part.includes('/') ? Number(part.split('/')[1]) : 32 });
  }
  return out;
}

/** Longest-prefix match of an unsigned IPv4 int against a list. */
export function matchCidr<T extends CidrEntry>(n: number, entries: T[]): T | null {
  let best: T | null = null;
  for (const c of entries) {
    // NOTE: `&` yields a SIGNED int32 in JS — normalize both sides with >>> 0.
    if (((n & c.mask) >>> 0) === c.net && (!best || c.prefixLen > best.prefixLen)) best = c;
  }
  return best;
}

/** An inventoried network CIDR with device + display attribution. */
export interface NetworkEntry extends CidrEntry {
  deviceId: string | null;
  /** Interface/network name from the inventory (e.g. "LAN", "NET_ELASTIC"). */
  name?: string | null;
  /** VLAN id when the inventory carries one (null/undefined = untagged or unknown). */
  vlanId?: number | null;
}

export type FlowIpClass = 'internal' | 'internet' | 'unknown';

/** Network display context for an endpoint IP (longest-prefix match, any class). */
export interface NetworkContext {
  name: string | null;
  vlanId: number | null;
}

/**
 * Longest-prefix lookup of the inventoried network containing `ip` — returns
 * its name + VLAN id for display enrichment. Works for ANY ip (internal,
 * internet or unknown) so even external talkers can show which local network
 * they were reached through when one is inventoried. Pure.
 */
export function lookupNetworkContext(ip: string, networkCidrs: NetworkEntry[]): NetworkContext | null {
  const n = ipv4ToInt(ip);
  if (n === null) return null; // v6 — no CIDR match yet
  const hit = matchCidr(n, networkCidrs);
  if (!hit) return null;
  return { name: hit.name ?? null, vlanId: hit.vlanId ?? null };
}

/** The configured range lists (parsed from the two global settings). */
export interface RangeLists {
  internal: CidrEntry[];
  external: CidrEntry[];
}

/**
 * Classifies one endpoint IP. `exactHit` is the deviceId from the exact-IP
 * inventory map (or null); `networkCidrs` are inventoried network entries
 * (with device attribution). Pure — no I/O, no globals.
 */
export function classifyIp(
  ip: string,
  exactHit: string | null,
  networkCidrs: NetworkEntry[],
  ranges: RangeLists
): { cls: FlowIpClass; deviceId: string | null } {
  if (exactHit) return { cls: 'internal', deviceId: exactHit };

  const n = ipv4ToInt(ip);
  if (n !== null) {
    // Special non-routable space is never traffic we can attribute.
    if (((n & 0xffff_0000) >>> 0) === 0xa9fe_0000 || // 169.254/16 link-local (mask = /16!)
        ((n & 0xff00_0000) >>> 0) === 0x0000_0000 || // 0.0.0.0/8
        (n >= 0xe000_0000)) { // 224/4 multicast + 240/4 reserved
      return { cls: 'unknown', deviceId: null };
    }

    // Explicit external carve-outs beat the broad matches below — an operator
    // who lists a range as external means it (e.g. a public/DMZ subnet inside
    // an inventoried /16). Exact inventory hits above still win: a known
    // device is never "internet" traffic just because its address was carved out.
    if (matchCidr(n, ranges.external)) return { cls: 'internet', deviceId: null };

    // Inventoried network → internal + device attribution.
    const net = matchCidr(n, networkCidrs);
    if (net) return { cls: 'internal', deviceId: net.deviceId };

    // Configured internal space (default: RFC 1918).
    if (matchCidr(n, ranges.internal)) return { cls: 'internal', deviceId: null };

    // Any other public IPv4 → internet.
    return { cls: 'internet', deviceId: null };
  }

  // IPv6 or unparseable — v1 simplification (no v6 range lists yet).
  return { cls: 'unknown', deviceId: null };
}
