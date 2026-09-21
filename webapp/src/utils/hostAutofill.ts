/**
 * Client-side auto-fill intelligence for the documented-hosts form.
 *
 * Everything here works against the LIVE inventory — merged `HostRow`s from
 * GET /hosts and merged logical networks from GET /networks — so the user can
 * type a DNS name or an IP address and get reliable pre-fills (MAC, network,
 * site, extra addresses) that they can still override. No server round-trip:
 * both datasets are already cached by react-query on this page.
 *
 * All IP math lives in utils/ip.ts (browser mirror of the SDK's ip.ts) —
 * nothing below re-implements IPv4/IPv6 parsing or CIDR containment.
 */

import { ipFamily, ipv4FromInt, ipv4ToInt, ipv6FromBigInt, ipv6ToBigInt, ipInCidr, splitCidr } from './ip';

// ---------------------------------------------------------------------------
// MAC helpers (mirror of api/src/routes/documentedHosts.ts)
// ---------------------------------------------------------------------------

/** Normalizes a MAC to lowercase colon form ("aa:bb:…"); null when not 12 hex digits. */
export function normalizeMac(value: string): string | null {
  const compact = value.toLowerCase().replace(/[^0-9a-f]/g, '');
  if (compact.length !== 12) return null;
  return compact.replace(/([0-9a-f]{2})(?=[0-9a-f])/g, '$1:');
}

/** Strips separators — the canonical comparison key for MACs. */
export function macKey(value: string): string {
  return value.toLowerCase().replace(/[^0-9a-f]/g, '');
}

// ---------------------------------------------------------------------------
// Live host index
// ---------------------------------------------------------------------------

/** Structural subset of HostRow that the auto-fill logic needs. */
export interface LiveHost {
  mac: string;
  ips: string[];
  hostname?: string | null;
  manufacturer?: string | null;
  devices?: { siteName?: string | null }[];
}

/** Lookup index over live hosts by compact MAC and by every known address. */
export interface LiveIndex {
  all: LiveHost[];
  byMac: Map<string, LiveHost>;
  /** Lowercased address -> observing host(s) (usually one). */
  byIp: Map<string, LiveHost[]>;
}

/** Builds the MAC/address lookup index over the merged live host rows. */
export function buildLiveIndex(hosts: LiveHost[]): LiveIndex {
  const byMac = new Map<string, LiveHost>();
  const byIp = new Map<string, LiveHost[]>();
  for (const h of hosts) {
    if (!h.mac) continue;
    byMac.set(macKey(h.mac), h);
    for (const ip of h.ips ?? []) {
      const a = ip.trim().toLowerCase();
      if (!a) continue;
      let list = byIp.get(a);
      if (!list) {
        list = [];
        byIp.set(a, list);
      }
      list.push(h);
    }
  }
  return { all: hosts, byMac, byIp };
}

// ---------------------------------------------------------------------------
// DNS name suggestions (known hostnames from the live inventory)
// ---------------------------------------------------------------------------

/** A known live host offered as a suggestion for the typed DNS name. */
export interface DnsSuggestion {
  /** The observed hostname to document (lowercase). */
  name: string;
  host: LiveHost;
}

/**
 * Suggests known hostnames for a typed DNS name: hosts whose observed
 * hostname starts with the typed text ("mail.exa" → "mail.example.com") or
 * lives in the typed zone ("example.com" offers "mail.example.com"). Picking
 * one pre-fills the form with reliable data.
 */
export function suggestDnsNames(input: string, index: LiveIndex, limit = 8): DnsSuggestion[] {
  const q = input.trim().toLowerCase();
  if (!q) return [];
  const out: DnsSuggestion[] = [];
  for (const h of index.all) {
    const hn = (h.hostname ?? '').trim().toLowerCase();
    if (!hn || hn === q) continue; // the typed name itself is not a suggestion
    const prefixHit = hn.startsWith(q);
    const zoneHit = q.includes('.') && hn.endsWith(`.${q}`);
    if ((prefixHit || zoneHit) && !out.some((x) => x.name === hn)) out.push({ name: hn, host: h });
  }
  return out.slice(0, limit);
}

// ---------------------------------------------------------------------------
// Network matching (IP address -> logical network)
// ---------------------------------------------------------------------------

/** A known logical network: display label, its subnet CIDRs and (when known) VLAN id. */
export interface NetworkOption {
  label: string;
  cidrs: string[];
  vlanId?: number | null;
}

/** Best (largest) prefix of a CIDR in `opt` that contains `addr`; -1 when none match. */
export function networkMatchScore(opt: NetworkOption, addr: string): number {
  let best = -1;
  for (const c of opt.cidrs) {
    // ipInCidr already enforces family matching — a v4 address never matches a v6 subnet.
    if (!ipInCidr(addr, c)) continue;
    const s = splitCidr(c);
    if (!s || s.prefix <= best) continue;
    best = s.prefix;
  }
  return best;
}

/** All known networks that could contain this address, most specific first. */
export function suggestNetworks(addr: string, options: NetworkOption[]): NetworkOption[] {
  const scored = options
    .map((o) => ({ o, s: networkMatchScore(o, addr) }))
    .filter((x) => x.s >= 0);
  scored.sort((a, b) => (b.s !== a.s ? b.s - a.s : a.o.label.localeCompare(b.o.label)));
  return scored.map((x) => x.o);
}

/** Label of the best-matching known network for an address; null when none match. */
export function bestNetworkLabel(addr: string, options: NetworkOption[]): string | null {
  const n = bestNetwork(addr, options);
  return n ? n.label : null;
}

/** The best-matching known network for an address (most specific subnet); null when none match. */
export function bestNetwork(addr: string, options: NetworkOption[]): NetworkOption | null {
  const matches = suggestNetworks(addr, options);
  return matches.length > 0 ? matches[0] : null;
}

// ---------------------------------------------------------------------------
// Family-aware helpers (shared with the reusable IpCidrInput component)
// ipFamily + ipInCidr come from utils/ip.ts — re-exported so existing import
// sites keep working.
// ---------------------------------------------------------------------------

export { ipFamily, ipInCidr };

/** Validates a bare IP or CIDR string; returns an error message or null. */
export function validateIpCidr(value: string): string | null {
  const v = value.trim();
  if (!v) return null; // emptiness is the caller's concern
  const i = v.indexOf('/');
  const addrPart = i >= 0 ? v.slice(0, i) : v;
  const fam = ipFamily(addrPart);
  if (!fam) return `not a valid IP address: "${addrPart}"`;
  if (i < 0) return null; // bare addresses are fine
  const pfx = Number(v.slice(i + 1));
  const max = fam === 'v4' ? 32 : 128;
  if (!Number.isInteger(pfx) || pfx < 0 || pfx > max) return `prefix must be an integer between 0 and ${max}`;
  return null;
}

// ---------------------------------------------------------------------------
// Network matching result — with the containing subnet of the address family
// ---------------------------------------------------------------------------

/** A known network that contains the address, plus the specific subnet (of the address's family) it lives in. */
export interface NetworkMatch {
  option: NetworkOption;
  /** Most specific subnet of `option` that contains the address — same family as the address. */
  cidr: string;
}

/**
 * Best-matching known network for an address, with the containing subnet of
 * the ADDRESS'S FAMILY (an IPv4 address never matches a v6 subnet and vice
 * versa). Most specific prefix wins; null when no known network contains it.
 */
export function matchNetwork(addr: string, options: NetworkOption[]): NetworkMatch | null {
  const fam = ipFamily(addr);
  if (!fam) return null;
  let best: NetworkMatch | null = null;
  let bestPrefix = -1;
  for (const o of options) {
    for (const c of o.cidrs ?? []) {
      if (c.includes(':') !== (fam === 'v6')) continue; // family must match the address
      const s = splitCidr(c);
      if (!s || !ipInCidr(addr, c)) continue;
      if (s.prefix > bestPrefix) {
        best = { option: o, cidr: c };
        bestPrefix = s.prefix;
      }
    }
  }
  return best;
}

/** All known subnets (CIDRs) of the address's family that contain it, most specific first. */
export function matchingSubnets(addr: string, options: NetworkOption[]): string[] {
  const fam = ipFamily(addr);
  if (!fam) return [];
  const out: { c: string; p: number }[] = [];
  for (const o of options) {
    for (const c of o.cidrs ?? []) {
      if (c.includes(':') !== (fam === 'v6')) continue; // family must match the address
      const s = splitCidr(c);
      if (!s || !ipInCidr(addr, c)) continue;
      out.push({ c, p: s.prefix });
    }
  }
  out.sort((a, b) => (b.p !== a.p ? b.p - a.p : a.c.localeCompare(b.c)));
  return Array.from(new Set(out.map((x) => x.c)));
}

/**
 * Checks whether a stored network label is compatible with an address:
 * true = the known network contains it, false = KNOWN but does NOT contain it
 * (e.g. an IPv4 address in an IPv6-only network), null = not checkable
 * (empty or free-form label that matches no known network).
 */
export function labelContainsAddress(label: string, addr: string, options: NetworkOption[]): boolean | null {
  const l = label.trim();
  if (!l) return null; // no reference — nothing to check
  const fam = ipFamily(addr);
  if (!fam) return null;
  // The label is a bare CIDR.
  if (l.includes('/')) {
    const s = splitCidr(l);
    if (!s) return false;
    if (s.net.includes(':') !== (fam === 'v6')) return false; // family mismatch
    return ipInCidr(addr, l);
  }
  // The label is a known network's display name.
  const opt = options.find((o) => o.label.toLowerCase() === l.toLowerCase());
  if (!opt) return null; // free-form label — not checkable against the inventory
  return (opt.cidrs ?? []).some((c) => c.includes(':') === (fam === 'v6') && ipInCidr(addr, c));
}

// ---------------------------------------------------------------------------
// Free IP suggestion (pick an unused address inside a known network)
// ---------------------------------------------------------------------------

/**
 * Resolves a stored network label — a bare CIDR or the display name of a known
 * logical network — to ONE of its subnets. Dual-stack networks prefer their
 * IPv4 subnet (the common case for new VMs/containers). Null when the label is
 * free-form / unknown, so callers can disable dependent actions.
 */
export function resolveNetworkCidr(networkLabel: string, options: NetworkOption[]): string | null {
  const l = networkLabel.trim();
  if (!l) return null;
  if (l.includes('/')) return splitCidr(l) ? l : null;
  const opt = options.find((o) => o.label.toLowerCase() === l.toLowerCase());
  const subs = opt?.cidrs ?? [];
  for (const c of subs) {
    if (!c.includes(':') && splitCidr(c)) return c; // IPv4 first
  }
  for (const c of subs) {
    if (c.includes(':') && splitCidr(c)) return c;
  }
  return null;
}

/**
 * Suggests the first free IP inside a known network — for documenting a NEW
 * host (VM, container, physical). The FAMILY is controlled by the selected
 * network: an IPv4 subnet yields an IPv4 address, an IPv6-only network an
 * IPv6 one. `taken` must hold every already-used or documented address
 * (lowercase, no zone id) so suggestions never collide with reality.
 */
export function suggestFreeIp(
  networkLabel: string,
  options: NetworkOption[],
  taken: Set<string>
): { address: string; cidr: string } | null {
  const cidr = resolveNetworkCidr(networkLabel, options);
  if (!cidr) return null;

  // --- IPv4: scan from the first usable host (skip network + broadcast).
  if (!cidr.includes(':')) {
    const s = splitCidr(cidr)!;
    if (s.prefix > 30) return null; // /31, /32 are point-to-point — no free pool
    const raw = ipv4ToInt(s.net);
    if (raw === null) return null;
    const mask = s.prefix === 0 ? 0 : (~0 << (32 - s.prefix)) >>> 0;
    const base = raw & mask; // drop stray host bits from the input CIDR
    const size = 1 << (32 - s.prefix);
    for (let i = 1; i < size - 1; i++) {
      const addr = ipv4FromInt(base + i);
      if (!taken.has(addr)) return { address: addr, cidr };
    }
    return null; // subnet exhausted
  }

  // --- IPv6: keep the network prefix bits, increment the host part.
  const s = splitCidr(cidr)!;
  const netBig = ipv6ToBigInt(s.net);
  if (netBig === null) return null;
  const pfx = Math.min(s.prefix, 64); // the host part lives in the last ≤64 bits
  const mask = pfx === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - pfx)) - 1n);
  const prefixBits = netBig & mask;
  const hostBits = Math.min(128 - pfx, 64);
  const maxHost = 1n << BigInt(hostBits);
  for (let host = 1n; host < maxHost; host++) {
    if (host === maxHost - 1n && hostBits === 64) continue; // all-ones multicast id
    const addr = ipv6FromBigInt(prefixBits | host);
    if (!taken.has(addr)) return { address: addr, cidr };
  }
  return null; // pool exhausted
}
