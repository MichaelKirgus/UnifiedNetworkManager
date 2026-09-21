/**
 * Cross-device address resolution for firewall rules (GET /firewall-rules).
 *
 * A rule's source/destination is often an alias name ("LAN", "cameras") or a
 * bare IP — neither tells the operator WHICH network it covers. This module
 * resolves raw rule-address text against the cross-device inventory:
 *   - CIDR tokens are matched to known subnets (networks table) → which
 *     devices/interfaces carry that subnet;
 *   - IP literals and CIDRs are matched to discovered hosts (hosts table,
 *     ARP/NDP/DHCP/WLAN/MAC-table rows) → hostnames, MACs, where seen.
 * Resolution happens at READ time in the API route — no new tables: a rule on
 * device A can match subnets configured on B or hosts learned by C's switch.
 * The inventory index is cached briefly (INDEX_TTL_MS) because rebuilding it
 * from thousands of rows per request would be wasteful; 30 s staleness is
 * invisible for display purposes and the underlying tables refresh every poll.
 */

import { ipScope, subnetOf } from '@unm/plugin-sdk';

/** One discovered host matched by a rule address (merged across devices). */
export interface ResolvedFirewallHost {
  mac: string;
  /** All known addresses of this host, IPv4 first. */
  ips: string[];
  hostname: string | null;
  manufacturer: string | null;
  /** Device names that observed this host (deduped). */
  devices: string[];
}

/** The resolution result for one raw rule-address value ('' = any → never resolved). */
export interface FirewallAddressResolution {
  /** Known subnets the address covers ("192.168.1.0/24"), IPv4 first. */
  subnets: string[];
  /** Interfaces on which those subnets are configured (e.g. "OPNSENSE01: lan"). */
  interfaces: string[];
  /** Number of discovered hosts inside the address (may exceed hosts.length). */
  hostCount: number;
  /** Matched hosts, capped at MAX_HOSTS for payload size. */
  hosts: ResolvedFirewallHost[];
  /** Tokens that are neither IP literals nor CIDRs — alias names we can't expand here. */
  unresolved: string[];
}

/** One host while the index is being built (pre-response shape). */
interface HostEntry {
  mac: string;
  ips: Set<string>;
  hostname: string | null;
  manufacturer: string | null;
  deviceIds: Set<string>;
}

/** The in-memory inventory index used to resolve rule addresses. */
export interface FirewallInventoryIndex {
  /** cidr → interfaces carrying it ("DeviceName: iface", deduped). */
  subnets: Map<string, Set<string>>;
  /** ip literal → set of MACs seen on that address (any device/source). */
  ipToMac: Map<string, Set<string>>;
  /** Pre-parsed form of every known host IP — containment matching is then pure arithmetic. */
  ipParsed: Map<string, { v4: number | null; v6: number[] | null }>;
  /** mac (lowercase) → merged host entry. */
  hosts: Map<string, HostEntry>;
  /** deviceId\u0000ifaceName(lower) → subnets configured on that interface (real ones only). */
  ifaceSubnets: Map<string, Set<string>>;
  /** deviceId\u0000intf(lower) → host mac keys seen on that interface. */
  ifaceHosts: Map<string, Set<string>>;
  /** deviceId → the appliance's own host mac keys (hosts rows with source 'self'). */
  selfHosts: Map<string, Set<string>>;
}

/** Cap on matched hosts per address — a /16 LAN must not bloat the payload. */
const MAX_HOSTS = 50;
/** How long a built index stays fresh for repeated requests (ms). */
const INDEX_TTL_MS = 30_000;

// --- IP math — canonical implementation lives in @unm/plugin-sdk (ip.ts) -------

import { ipv4ToInt, ipv6ToWords } from '@unm/plugin-sdk';

/**
 * True for subnets that do NOT identify a real network — loopback and
 * link-local exist on nearly every interface/host and would match everything.
 * Mirrors the filter used by mergeNetworkRows (api/src/routes/networks.ts).
 */
function isNonNetworkSubnet(subnet: string): boolean {
  const [addr, prefix] = subnet.split('/');
  if (prefix === undefined) return false;
  const scope = ipScope(addr);
  return scope === 'loopback' || scope === 'link-local';
}

/** Pre-parsed form of an IP literal — one of the two is non-null. */
interface ParsedIp {
  v4: number | null;
  v6: number[] | null;
}

/** Parses an IP literal once (v4 int or v6 words); both null when malformed. */
function parseIp(ip: string): ParsedIp {
  const v4 = ipv4ToInt(ip);
  if (v4 !== null) return { v4, v6: null };
  const v6 = ipv6ToWords(ip);
  return { v4: null, v6 };
}

/** Containment test on pre-parsed values — the hot path for host matching. */
function parsedInCidr(ip: ParsedIp, netAddr: string, prefix: number): boolean {
  if (ip.v6 !== null) {
    const netWords = ipv6ToWords(netAddr);
    if (!netWords) return false;
    // IPv6: mask per 16-bit group.
    for (let i = 0; i < 8; i++) {
      const bitsInGroup = Math.max(0, Math.min(16, prefix - i * 16));
      if (bitsInGroup === 0) continue; // rest of the address is free space
      const mask = bitsInGroup === 16 ? 0xffff : 0xffff << (16 - bitsInGroup);
      if ((ip.v6[i] & mask) !== (netWords[i] & mask)) return false;
    }
    return true;
  }
  if (ip.v4 === null) return false;
  const netInt = ipv4ToInt(netAddr);
  if (netInt === null || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ip.v4 & mask) === (netInt & mask);
}

/** True when the IP literal falls inside the CIDR (v4 and v6 supported). */
export function ipInCidr(ip: string, cidr: string): boolean {
  const [netAddr, prefixStr] = cidr.split('/');
  if (!netAddr || prefixStr === undefined) return false; // bare IP — exact match only
  const prefix = Number(prefixStr);
  if (!Number.isInteger(prefix)) return false;
  return parsedInCidr(parseIp(ip), netAddr, prefix);
}

/** Pre-parsed CIDR token (real subnets only — loopback/link-local excluded). */
interface ParsedCidr {
  raw: string;
  netAddr: string;
  prefix: number;
}

/** Parses the real-subnet CIDR tokens of a raw rule-address value. */
function parseCidrTokens(value: string): ParsedCidr[] {
  const out: ParsedCidr[] = [];
  for (const token of splitTokens(value)) {
    if (!token.includes('/')) continue;
    const [netAddr, prefixStr] = token.split('/');
    const prefix = Number(prefixStr);
    if (!Number.isInteger(prefix) || isNonNetworkSubnet(token)) continue;
    out.push({ raw: token, netAddr, prefix });
  }
  return out;
}

// --- Index building -------------------------------------------------------------

/** One stored row of the `networks` table (structural — avoids a schema import cycle). */
export interface NetworkIndexRow {
  deviceId: string;
  name: string;
  ip: string;
  prefix: number | null;
}

/** One stored row of the `hosts` table. */
export interface HostIndexRow {
  deviceId: string;
  mac: string;
  ip: string;
  /** arp | ndp | dhcp | wlan | mac | self — 'self' = the appliance's own interfaces. */
  source: string;
  hostname: string | null;
  manufacturer: string | null;
  intf: string | null;
}

/**
 * Builds the resolution index from raw inventory rows. Loopback/link-local
 * subnets are excluded (they exist on nearly every interface and would match
 * everything); IP-less host rows ('mac' source) still contribute their MAC to
 * the host entries but no ipToMac mapping.
 */
export function buildFirewallInventoryIndex(
  networkRows: NetworkIndexRow[],
  hostRows: HostIndexRow[]
): FirewallInventoryIndex {
  const subnets = new Map<string, Set<string>>();
  const ifaceSubnets = new Map<string, Set<string>>();
  for (const r of networkRows) {
    if (!r.ip || r.prefix === null) continue;
    const cidr = subnetOf(r.ip, r.prefix);
    if (!cidr) continue;
    // Loopback/link-local exist on almost every interface — never useful as a match.
    if (isNonNetworkSubnet(cidr)) continue;
    let set = subnets.get(cidr);
    if (!set) {
      set = new Set();
      subnets.set(cidr, set);
    }
    // The device name is attached by the caller via deviceNameById at match time —
    // we store the raw deviceId here and let enrichFirewallAddress format it.
    set.add(r.deviceId + '\u0000' + r.name);
    // Per-interface view — lets a rule's interface-name token ("lan", "opt26")
    // resolve to the subnets configured on that exact interface of its device.
    const ikey = `${r.deviceId}\u0000${(r.name || '').toLowerCase()}`;
    let iset = ifaceSubnets.get(ikey);
    if (!iset) {
      iset = new Set();
      ifaceSubnets.set(ikey, iset);
    }
    iset.add(cidr);
  }

  const ipToMac = new Map<string, Set<string>>();
  const ipParsed = new Map<string, ParsedIp>();
  const hosts = new Map<string, HostEntry>();
  const ifaceHosts = new Map<string, Set<string>>();
  const selfHosts = new Map<string, Set<string>>();
  for (const r of hostRows) {
    const key = r.mac.toLowerCase();
    let h = hosts.get(key);
    if (!h) {
      h = { mac: r.mac, ips: new Set(), hostname: null, manufacturer: null, deviceIds: new Set() };
      hosts.set(key, h);
    }
    if (r.ip !== '') h.ips.add(r.ip);
    if (!h.hostname && r.hostname) h.hostname = r.hostname;
    if (!h.manufacturer && r.manufacturer) h.manufacturer = r.manufacturer;
    h.deviceIds.add(r.deviceId);
    // Per-interface host view — an interface-name token also matches the hosts
    // learned ON that interface (ARP/NDP rows carry intf).
    if (r.intf) {
      const ikey = `${r.deviceId}\u0000${r.intf.toLowerCase()}`;
      let iset = ifaceHosts.get(ikey);
      if (!iset) {
        iset = new Set();
        ifaceHosts.set(ikey, iset);
      }
      iset.add(key);
    }
    // The appliance's own interfaces (source 'self') — resolves "(self)" tokens.
    if (r.source === 'self') {
      let sset = selfHosts.get(r.deviceId);
      if (!sset) {
        sset = new Set();
        selfHosts.set(r.deviceId, sset);
      }
      sset.add(key);
    }
    if (r.ip !== '') {
      let macs = ipToMac.get(r.ip);
      if (!macs) {
        macs = new Set();
        ipToMac.set(r.ip, macs);
      }
      macs.add(key);
      // Parse each distinct IP once — containment matching is then pure arithmetic.
      if (!ipParsed.has(r.ip)) ipParsed.set(r.ip, parseIp(r.ip));
    }
  }

  return { subnets, ipToMac, ipParsed, hosts, ifaceSubnets, ifaceHosts, selfHosts };
}

// --- Resolution -----------------------------------------------------------------

/** Splits a raw rule-address value into tokens. Comma lists are common in rules;
 * OPNsense alias CONTENT is newline-separated — both must split cleanly. */
function splitTokens(raw: string): string[] {
  return Array.from(new Set(raw.split(/[,;\n]+/).map((t) => t.trim()).filter(Boolean)));
}

/**
 * Resolves one raw rule-address value against the inventory index. Returns null
 * when nothing matched (the caller then omits the field entirely). `deviceNameById`
 * maps deviceId → display name for the interface labels; missing ids fall back to
 * the raw id. `deviceId` is the device the RULE lives on — it lets interface-name
 * tokens ("lan", "opt26") and "(self)" resolve against that device's own inventory.
 */
export function enrichFirewallAddress(
  raw: string,
  index: FirewallInventoryIndex,
  deviceNameById?: Map<string, string>,
  deviceId?: string
): FirewallAddressResolution | null {
  const value = (raw ?? '').trim();
  if (!value || value === 'any' || value === '*') return null;

  const matchedSubnets = new Set<string>();
  const exactIps = new Map<string, ParsedIp>(); // ip literal → parsed form (for subnet containment)
  const unresolved: string[] = [];
  const ifaceTokens: string[] = []; // interface names that exist on the rule's device
  let selfRequested = false; // "(self)" — the appliance itself

  for (const token of splitTokens(value)) {
    if (token.includes('/')) {
      // CIDR — match against known subnets (exact cidr or containment either way).
      const [addr, prefixStr] = token.split('/');
      const tokenPrefix = Number(prefixStr);
      const tokenNet = parseIp(addr);
      let matched = false;
      for (const cidr of index.subnets.keys()) {
        if (cidr === token) {
          matchedSubnets.add(cidr);
          matched = true;
          continue;
        }
        // Does the rule's CIDR sit inside a known subnet, or does it contain one?
        const [netAddr, kPrefixStr] = cidr.split('/');
        const kPrefix = Number(kPrefixStr);
        if (!Number.isInteger(kPrefix)) continue;
        if (parsedInCidr(parseIp(netAddr), addr, tokenPrefix) || parsedInCidr(tokenNet, netAddr, kPrefix)) {
          matchedSubnets.add(cidr);
          matched = true;
        }
      }
      // An unknown network address is still a probe for host containment.
      if (tokenNet.v4 !== null || tokenNet.v6 !== null) exactIps.set(addr, tokenNet);
    } else {
      const lower = token.toLowerCase();
      if (lower === '(self)' || lower === 'self') {
        selfRequested = true; // the appliance itself
        continue;
      }
      const parsed = parseIp(token);
      if (parsed.v4 !== null || parsed.v6 !== null) {
        exactIps.set(token, parsed);
        continue;
      }
      // Interface name on the rule's own device ("lan", "opt26") — resolve it to
      // the subnets configured there and the hosts learned on that interface.
      if (deviceId) {
        const ikey = `${deviceId}\u0000${lower}`;
        const subs = index.ifaceSubnets.get(ikey);
        const hs = index.ifaceHosts.get(ikey);
        if (subs || hs) {
          ifaceTokens.push(token);
          for (const s of subs ?? []) matchedSubnets.add(s);
          continue;
        }
      }
      unresolved.push(token); // alias name / interface group — not expandable here
    }
  }

  // Hosts: exact-IP lookup first, then containment of every known host IP in the
  // rule's CIDR tokens (a /24 rule matches all ARP entries inside it). Both use
  // pre-parsed values — no string re-parsing on the hot path.
  const matchedMacs = new Set<string>();
  for (const ip of exactIps.keys()) {
    for (const mac of index.ipToMac.get(ip) ?? []) matchedMacs.add(mac);
  }
  // Interface-name tokens → hosts learned ON that interface of the rule's device.
  if (deviceId && ifaceTokens.length > 0) {
    for (const t of ifaceTokens) {
      const hs = index.ifaceHosts.get(`${deviceId}\u0000${t.toLowerCase()}`);
      if (hs) for (const m of hs) matchedMacs.add(m);
    }
  }
  // "(self)" → the appliance's own interfaces.
  if (selfRequested && deviceId) {
    const sh = index.selfHosts.get(deviceId);
    if (sh) for (const m of sh) matchedMacs.add(m);
  }
  const cidrTokens = parseCidrTokens(value); // real subnets only — fe80::/10 & co. excluded
  if (cidrTokens.length > 0) {
    for (const [ip, macs] of index.ipToMac) {
      const parsed = index.ipParsed.get(ip);
      if (!parsed) continue;
      if (cidrTokens.some((c) => parsedInCidr(parsed, c.netAddr, c.prefix))) {
        for (const m of macs) matchedMacs.add(m);
      }
    }
  }

  // Subnets containing exact IPs (a bare host IP still reveals its LAN).
  if (exactIps.size > 0) {
    for (const [cidr] of index.subnets) {
      const [netAddr, prefixStr] = cidr.split('/');
      const prefix = Number(prefixStr);
      if (!Number.isInteger(prefix)) continue;
      for (const [ip, parsed] of exactIps) {
        if (parsedInCidr(parsed, netAddr, prefix)) {
          matchedSubnets.add(cidr);
          break; // this subnet is already claimed — no need to test the other IPs
        }
      }
    }
  }

  const hosts: ResolvedFirewallHost[] = [];
  for (const mac of matchedMacs) {
    const h = index.hosts.get(mac);
    if (!h) continue;
    hosts.push({
      mac: h.mac,
      ips: Array.from(h.ips).sort((a, b) => (a.includes(':') ? 1 : 0) - (b.includes(':') ? 1 : 0)),
      hostname: h.hostname,
      manufacturer: h.manufacturer,
      devices: Array.from(h.deviceIds).map((id) => deviceNameById?.get(id) ?? id),
    });
  }
  hosts.sort((a, b) => (a.hostname ?? a.mac).localeCompare(b.hostname ?? b.mac));

  // Interface labels for the matched subnets ("Device: iface").
  const interfaces = new Set<string>();
  for (const cidr of matchedSubnets) {
    for (const entry of index.subnets.get(cidr) ?? []) {
      const [deviceId, name] = entry.split('\u0000');
      interfaces.add(`${deviceNameById?.get(deviceId) ?? deviceId}: ${name}`);
    }
  }

  if (matchedSubnets.size === 0 && matchedMacs.size === 0 && unresolved.length === 0) return null;

  const subnetList = Array.from(matchedSubnets).sort((a, b) => {
    const av = a.includes(':') ? 1 : 0;
    const bv = b.includes(':') ? 1 : 0;
    return av !== bv ? av - bv : a.localeCompare(b);
  });

  return {
    subnets: subnetList,
    interfaces: Array.from(interfaces).sort(),
    hostCount: matchedMacs.size,
    hosts: hosts.slice(0, MAX_HOSTS),
    unresolved,
  };
}

// --- Index cache ------------------------------------------------------------------

interface CacheEntry {
  index: FirewallInventoryIndex;
  builtAt: number;
}
const indexCache = new Map<string, CacheEntry>();
/** In-flight builds — concurrent requests for the same scope share one build. */
const inFlight = new Map<string, Promise<FirewallInventoryIndex>>();

/**
 * Returns a cached inventory index for the given cache key (e.g. `fw:<siteId>`),
 * building it via `build()` when absent or older than INDEX_TTL_MS. Concurrent
 * callers share one build; a failed build is not cached and may be retried next call.
 */
export function getCachedFirewallIndex(
  key: string,
  build: () => Promise<FirewallInventoryIndex>
): Promise<FirewallInventoryIndex> {
  const now = Date.now();
  const hit = indexCache.get(key);
  if (hit && now - hit.builtAt < INDEX_TTL_MS) return Promise.resolve(hit.index);

  const pending = inFlight.get(key);
  if (pending) return pending;

  const p = build()
    .then((index) => {
      indexCache.set(key, { index, builtAt: Date.now() });
      // Opportunistic eviction of other stale entries.
      for (const [k, e] of indexCache) {
        if (Date.now() - e.builtAt >= INDEX_TTL_MS && k !== key) indexCache.delete(k);
      }
      return index;
    })
    .finally(() => inFlight.delete(key));

  inFlight.set(key, p);
  return p;
}
