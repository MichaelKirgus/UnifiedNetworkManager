/**
 * Browser mirror of packages/plugin-sdk/src/ip.ts — keep the two in sync.
 * The SDK copy is canonical (plugins + API import it from @unm/plugin-sdk);
 * this file exists because the webapp bundle must not pull Node-only SDK
 * dependencies into the browser. Same convention as utils/address.ts.
 */

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/** Strips a trailing %zone id ("fe80::1%eth0" → "fe80::1"); trims whitespace. */
export function stripZoneId(addr: string): string {
  return addr.trim().replace(/%[a-zA-Z0-9._-]+$/, '');
}

/** The family of an IP literal ("v4" | "v6"); null when not a valid address. */
export function ipFamily(addr: string): 'v4' | 'v6' | null {
  const v = stripZoneId(addr);
  if (ipv4ToInt(v) !== null) return 'v4';
  if (ipv6ToWords(v) !== null) return 'v6';
  return null;
}

/** IPv4 literal → 32-bit unsigned int, or null when not a valid IPv4 literal. */
export function ipv4ToInt(addr: string): number | null {
  const v = stripZoneId(addr);
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v)) return null;
  let n = 0;
  for (const part of v.split('.')) {
    const o = Number(part);
    if (!Number.isInteger(o) || o > 255) return null;
    n = (n << 8) | o;
  }
  return n >>> 0;
}

/** 32-bit unsigned int → dotted-quad IPv4 literal. */
export function ipv4FromInt(n: number): string {
  const v = n >>> 0;
  return `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`;
}

/**
 * IPv6 literal → its eight 16-bit groups, or null when malformed. Handles '::'
 * compression (at most one), embedded-IPv4 tails ("::ffff:192.0.2.1"), and a
 * trailing %zone id.
 */
export function ipv6ToWords(addr: string): number[] | null {
  const v = stripZoneId(addr);
  if (!v.includes(':')) return null;
  if ((v.match(/::/g) ?? []).length > 1) return null; // at most one "::"
  let left: string[];
  let right: string[];
  if (v.includes('::')) {
    const [l, r] = v.split('::');
    left = l === '' ? [] : l.split(':');
    right = r === '' ? [] : r.split(':');
  } else {
    left = v.split(':');
    right = [];
  }
  const parseGroup = (g: string): number[] | null => {
    if (g.includes('.')) {
      // Embedded IPv4 tail — expands to exactly two 16-bit groups.
      const o = g.split('.').map(Number);
      if (o.length !== 4 || o.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return null;
      return [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
    }
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    return [parseInt(g, 16)];
  };
  const words: number[] = [];
  for (const g of [...left, ...right]) {
    const w = parseGroup(g);
    if (!w) return null;
    words.push(...w);
  }
  if (v.includes('::')) {
    if (words.length >= 8) return null; // "::" must compress at least one group
    const leftWords = left.reduce((n, g) => n + (g.includes('.') ? 2 : 1), 0);
    words.splice(leftWords, 0, ...Array(8 - words.length).fill(0));
  } else if (words.length !== 8) {
    return null;
  }
  return words;
}

/** Eight 16-bit groups → canonical compressed IPv6 literal (RFC 5952: leftmost longest zero run). */
export function ipv6FromWords(words: number[]): string {
  const groups = words.map((w) => w.toString(16));
  let bestStart = -1;
  let bestLen = 0;
  let start = -1;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === '0') {
      if (start === -1) start = i;
      if (i - start + 1 > bestLen) {
        bestLen = i - start + 1;
        bestStart = start;
      }
    } else {
      start = -1;
    }
  }
  if (bestLen >= 2) {
    const head = groups.slice(0, bestStart).join(':');
    const tail = groups.slice(bestStart + bestLen).join(':');
    return `${head}::${tail}`;
  }
  return groups.join(':');
}

/** IPv6 literal → full 128-bit BigInt, or null when not valid IPv6. */
export function ipv6ToBigInt(addr: string): bigint | null {
  const g = ipv6ToWords(addr);
  if (!g) return null;
  let v = 0n;
  for (const x of g) v = (v << 16n) | BigInt(x);
  return v;
}

/** Full 128-bit BigInt → canonical compressed IPv6 literal. */
export function ipv6FromBigInt(v: bigint): string {
  const groups = Array.from({ length: 8 }, (_, i) => Number((v >> BigInt(16 * (7 - i))) & 0xffffn));
  return ipv6FromWords(groups);
}

// ---------------------------------------------------------------------------
// CIDR math
// ---------------------------------------------------------------------------

/** Splits "a.b.c.d/p" into network address + prefix; null when malformed. */
export function splitCidr(cidr: string): { net: string; prefix: number } | null {
  const v = cidr.trim();
  const i = v.indexOf('/');
  if (i < 0) return null; // bare addresses are not network references here
  const net = v.slice(0, i);
  const prefix = Number(v.slice(i + 1));
  const max = net.includes(':') ? 128 : 32;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) return null;
  return { net, prefix };
}

/** True when `addr` is contained in the CIDR network (families must match). */
export function ipInCidr(addr: string, cidr: string): boolean {
  const s = splitCidr(cidr);
  if (!s) return false;
  if (!s.net.includes(':')) {
    const a = ipv4ToInt(addr);
    const n = ipv4ToInt(s.net);
    return a !== null && n !== null && v4PrefixMatch(a, n, s.prefix);
  }
  const a = ipv6ToWords(addr);
  const n = ipv6ToWords(s.net);
  return !!a && !!n && v6PrefixMatch(a, n, s.prefix);
}

/**
 * True when the two CIDR networks intersect (one contains part of the other).
 * Families must match; malformed inputs never overlap. The wider prefix wins:
 * two networks intersect iff the narrower one's network address falls inside
 * the wider one — i.e. they share their top `min(prefixA, prefixB)` bits.
 */
export function cidrsOverlap(a: string, b: string): boolean {
  const sa = splitCidr(a);
  const sb = splitCidr(b);
  if (!sa || !sb) return false;
  const aV4 = !sa.net.includes(':');
  const bV4 = !sb.net.includes(':');
  if (aV4 !== bV4) return false; // different families never intersect
  const wide = sa.prefix <= sb.prefix ? sa : sb;
  const narrow = sa.prefix <= sb.prefix ? sb : sa;
  if (wide.net.includes(':')) {
    const w = ipv6ToWords(wide.net);
    const n = ipv6ToWords(narrow.net);
    return !!w && !!n && v6PrefixMatch(w, n, wide.prefix);
  }
  const w = ipv4ToInt(wide.net);
  const n = ipv4ToInt(narrow.net);
  return w !== null && n !== null && v4PrefixMatch(w, n, wide.prefix);
}

/** True when the two IPv4 ints share their top `prefix` bits. */
export function v4PrefixMatch(a: number, n: number, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (a & mask) === (n & mask);
}

/** True when the two IPv6 word arrays share their top `prefix` bits. */
export function v6PrefixMatch(a: number[], n: number[], prefix: number): boolean {
  const big = ipv6ToBigIntFromWords(a)!;
  const net = ipv6ToBigIntFromWords(n)!;
  const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - prefix)) - 1n);
  return (big & mask) === (net & mask);
}

/** Words → BigInt without re-parsing a literal. */
function ipv6ToBigIntFromWords(words: number[]): bigint {
  let v = 0n;
  for (const x of words) v = (v << 16n) | BigInt(x);
  return v;
}

/**
 * Computes the network prefix ("192.168.1.0/24", "fd00::/64") for an IP
 * literal + prefix length — used to group interface rows into logical networks
 * across devices (several interfaces with addresses in the same subnet are ONE
 * network). Returns null when either part is missing or not a valid IP literal;
 * callers fall back to other grouping keys.
 */
export function subnetOf(ip: string, prefix: number | null): string | null {
  if (!ip || prefix === null) return null;
  const family = ipFamily(ip);
  if (family === 'v4' && Number.isInteger(prefix) && prefix >= 0 && prefix <= 32) {
    const a = ipv4ToInt(ip)!;
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return `${ipv4FromInt(a & mask)}/${prefix}`;
  }
  if (family === 'v6' && Number.isInteger(prefix) && prefix >= 0 && prefix <= 128) {
    const words = ipv6ToWords(ip)!;
    for (let i = 0; i < 8; i++) {
      const bitsInGroup = Math.max(0, Math.min(16, prefix - i * 16));
      if (bitsInGroup === 0) words[i] = 0;
      else if (bitsInGroup < 16) words[i] &= 0xffff << (16 - bitsInGroup);
    }
    return `${ipv6FromWords(words)}/${prefix}`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Scope classification — loopback / link-local / private / multicast / public
// ---------------------------------------------------------------------------

/** The scope of an IP literal (or the network address of a CIDR). */
export type IpScope = 'loopback' | 'link-local' | 'private' | 'public' | 'multicast' | 'reserved';

/** True for RFC 1918 private IPv4 space (10/8, 172.16/12, 192.168/16). */
export function isPrivateIpv4(addr: string): boolean {
  const v = stripZoneId(addr);
  if (!v.includes('.')) return false;
  const o = v.split('.').map(Number);
  if (o.length !== 4 || o.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return false;
  if (o[0] === 10) return true;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  return o[0] === 192 && o[1] === 168;
}

/** True for IPv4 loopback (127/8). */
export function isLoopbackIpv4(addr: string): boolean {
  const v = stripZoneId(addr);
  if (!v.includes('.')) return false;
  const o = v.split('.').map(Number);
  return o.length === 4 && o.every((x) => Number.isInteger(x) && x >= 0 && x <= 255) && o[0] === 127;
}

/** True for IPv4 link-local (APIPA, 169.254/16). */
export function isLinkLocalIpv4(addr: string): boolean {
  const v = stripZoneId(addr);
  if (!v.includes('.')) return false;
  const o = v.split('.').map(Number);
  return o.length === 4 && o.every((x) => Number.isInteger(x) && x >= 0 && x <= 255) && o[0] === 169 && o[1] === 254;
}

/** True for IPv4 multicast (224.0.0.0/4). */
export function isMulticastIpv4(addr: string): boolean {
  const v = stripZoneId(addr);
  if (!v.includes('.')) return false;
  const o = v.split('.').map(Number);
  return o.length === 4 && o.every((x) => Number.isInteger(x) && x >= 0 && x <= 255) && o[0] >= 224 && o[0] <= 239;
}

/** True for IPv6 ULA (fc00::/7). */
export function isUlaIpv6(addr: string): boolean {
  const w = ipv6ToWords(addr);
  return !!w && (w[0] & 0xfe00) === 0xfc00;
}

/** True for IPv6 loopback (::1). */
export function isLoopbackIpv6(addr: string): boolean {
  const v = stripZoneId(addr);
  if (!v.includes(':')) return false;
  // Only the exact loopback literal — "::" (unspecified) is NOT loopback.
  return ipv6ToBigInt(v) === 1n;
}

/** True for IPv6 link-local (fe80::/10). */
export function isLinkLocalIpv6(addr: string): boolean {
  const w = ipv6ToWords(addr);
  return !!w && (w[0] & 0xffc0) === 0xfe80;
}

/** True for IPv6 multicast (ff00::/8). */
export function isMulticastIpv6(addr: string): boolean {
  const w = ipv6ToWords(addr);
  return !!w && (w[0] & 0xff00) === 0xff00;
}

/** True for IPv4 addresses in the reserved space (240.0.0.0/4, incl. 255.255.255.255 broadcast). */
export function isReservedIpv4(addr: string): boolean {
  const v = stripZoneId(addr);
  if (!v.includes('.')) return false;
  const o = v.split('.').map(Number);
  return o.length === 4 && o.every((x) => Number.isInteger(x) && x >= 0 && x <= 255) && o[0] >= 240;
}

/** True for IPv6 documentation space (2001:db8::/32, RFC 3849). */
export function isDocumentationIpv6(addr: string): boolean {
  const w = ipv6ToWords(addr);
  return !!w && w[0] === 0x2001 && w[1] === 0xdb8;
}

/** True for a publicly routable IPv4 address (RFC 1918, loopback, link-local, multicast and reserved space count as internal). */
export function isPublicIpv4(addr: string): boolean {
  if (ipv4ToInt(stripZoneId(addr)) === null) return false;
  if (isLoopbackIpv4(addr) || isLinkLocalIpv4(addr) || isPrivateIpv4(addr)) return false;
  if (isMulticastIpv4(addr) || isReservedIpv4(addr)) return false;
  return true;
}

/** True for a publicly routable IPv6 address — i.e. global unicast (2000::/3), excluding ULA, link-local, loopback, multicast and documentation space. */
export function isPublicIpv6(addr: string): boolean {
  const w = ipv6ToWords(addr);
  if (!w) return false;
  if ((w[0] & 0xe000) !== 0x2000) return false; // must be global unicast (2000::/3)
  if (isDocumentationIpv6(addr)) return false;
  return true;
}

/**
 * Classifies an IP literal or CIDR into its scope. The prefix of a CIDR is
 * ignored — only the network address decides. Null when the value can't be
 * classified at all (DNS names, malformed input).
 */
export function ipScope(value: string): IpScope | null {
  const v = stripZoneId(value);
  if (!v) return null;
  // CIDR: classify the network address only.
  const addrPart = v.split('/')[0];

  if (addrPart.includes('.')) {
    if (ipv4ToInt(addrPart) === null) return null;
    if (isLoopbackIpv4(addrPart)) return 'loopback';
    if (isLinkLocalIpv4(addrPart)) return 'link-local';
    if (isPrivateIpv4(addrPart)) return 'private';
    if (isMulticastIpv4(addrPart)) return 'multicast';
    if (isReservedIpv4(addrPart)) return 'reserved';
    return 'public';
  }

  const w = ipv6ToWords(addrPart);
  if (!w) return null;
  if (ipv6ToBigInt(addrPart) === 1n) return 'loopback'; // ::1
  if ((w[0] & 0xffc0) === 0xfe80) return 'link-local'; // fe80::/10
  if ((w[0] & 0xfe00) === 0xfc00) return 'private'; // fc00::/7 ULA
  if ((w[0] & 0xff00) === 0xff00) return 'multicast'; // ff00::/8
  if (isDocumentationIpv6(addrPart)) return 'reserved'; // 2001:db8::/32
  if ((w[0] & 0xe000) === 0x2000) return 'public'; // 2000::/3 GUA
  return 'reserved'; // unspecified, benchmarking, reserved space…
}

// ---------------------------------------------------------------------------
// Address allocation — next free host address inside a CIDR
// ---------------------------------------------------------------------------

/** Hard cap on candidate scans so a pathological (fully-allocated) subnet can't hang the caller. */
const MAX_ADDRESS_SCAN = 1_000_000;

/**
 * Finds the next free host address in a CIDR, skipping structurally reserved
 * addresses and everything in `used` (zone ids stripped on comparison).
 *
 *   - IPv4: skips the network address and the broadcast. /31 and /32 are fully
 *     usable per RFC 3021 (point-to-point) — no skip there.
 *   - IPv6: skips only the first address of the subnet (the "network" address,
 *     mirroring v4 convention); /127 and /128 are fully usable per RFC 6164.
 *
 * Returns null when the CIDR is malformed or no free candidate exists within
 * the scan cap. Pure — `used` may be any iterable of address literals.
 */
export function nextFreeAddressInCidr(cidr: string, used: Iterable<string>): string | null {
  const s = splitCidr(cidr);
  if (!s) return null;
  const usedSet = new Set(Array.from(used).map((a: string) => stripZoneId(a)));

  if (!s.net.includes(':')) {
    // --- IPv4 (32-bit int math) -------------------------------------------
    const netInt = ipv4ToInt(s.net);
    if (netInt === null) return null;
    const mask = s.prefix === 0 ? 0 : (~0 << (32 - s.prefix)) >>> 0;
    const network = (netInt & mask) >>> 0;
    const size = ((~mask) >>> 0) + 1; // addresses in the block
    // /31, /32: every address is usable (RFC 3021). Otherwise skip network + broadcast.
    let start = s.prefix >= 31 ? network : (network + 1) >>> 0;
    const endExclusive = s.prefix === 32 ? (network + 1) >>> 0 : s.prefix === 31 ? (network + 2) >>> 0 : (network + size - 1) >>> 0; // broadcast addr, exclusive bound
    for (let i = 0; i < MAX_ADDRESS_SCAN && start < endExclusive; i++) {
      const lit = ipv4FromInt(start);
      if (!usedSet.has(lit)) return lit;
      start = (start + 1) >>> 0;
    }
    return null;
  }

  // --- IPv6 (BigInt math) ---------------------------------------------------
  const netBig = ipv6ToBigInt(s.net);
  if (netBig === null) return null;
  const mask = s.prefix === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - s.prefix)) - 1n);
  const network = netBig & mask;
  const size = 1n << BigInt(128 - s.prefix);
  // /127, /128: every address is usable (RFC 6164). Otherwise skip the first address.
  let start = s.prefix >= 127 ? network : network + 1n;
  const endExclusive = network + size;
  for (let i = 0n; i < BigInt(MAX_ADDRESS_SCAN) && start < endExclusive; i += 1n) {
    const lit = ipv6FromBigInt(start);
    if (!usedSet.has(lit)) return lit;
    start += 1n;
  }
  return null;
}
