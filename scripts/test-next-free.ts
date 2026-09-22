/**
 * Standalone verification of the "next free network" algorithm used by the
 * Documented Networks form (webapp/src/pages/DocumentedNetworks.tsx). Mirrors
 * nextFreeNetwork() + cidrsOverlap() exactly — keep in sync.
 */
import { ipFamily, ipv4FromInt, ipv6FromBigInt, splitCidr } from '../packages/plugin-sdk/src/ip';

function isIpLiteral(value: string): boolean {
  const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  if (IPV4.test(value)) return true;
  const v = value.replace(/%[a-zA-Z0-9._-]+$/, '');
  if (!v.includes(':')) return false;
  const parts = v.split('::');
  if (parts.length > 2) return false;
  for (const part of parts) {
    if (part === '') continue;
    for (const group of part.split(':')) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return false;
    }
  }
  return true;
}

function ipv4ToInt(value: string): number | null {
  const o = value.split('.').map(Number);
  if (o.length !== 4 || o.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return null;
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

function ipv6ToBigInt(value: string): bigint | null {
  const v = value.replace(/%[a-zA-Z0-9._-]+$/, '');
  if (!v.includes(':')) return null;
  let halves = v.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] === '' ? [] : halves[0].split(':');
  const right = halves.length === 2 && halves[1] !== '' ? halves[1].split(':') : [];
  let groups: string[];
  if (halves.length === 2) {
    if (left.length + right.length > 7) return null;
    groups = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  } else {
    if (left.length !== 8) return null;
    groups = left;
  }
  let out = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    out = (out << 16n) | BigInt(parseInt(g, 16));
  }
  return out;
}

function cidrsOverlap(a: string, b: string): boolean {
  const sa = a.trim().split('/');
  const sb = b.trim().split('/');
  if (sa.length !== 2 || sb.length !== 2) return false;
  const [na, pa] = sa;
  const [nb, pb] = sb;
  const pfxA = Number(pa);
  const pfxB = Number(pb);
  if (na.includes(':') !== nb.includes(':')) return false;
  if (!na.includes(':')) {
    const ia = ipv4ToInt(na);
    const ib = ipv4ToInt(nb);
    if (ia === null || ib === null) return false;
    const pfx = Math.min(pfxA, pfxB);
    const mask = pfx === 0 ? 0 : (~0 << (32 - pfx)) >>> 0;
    return (ia & mask) === (ib & mask);
  }
  const ia = ipv6ToBigInt(na);
  const ib = ipv6ToBigInt(nb);
  if (ia === null || ib === null) return false;
  const pfx = Math.min(pfxA, pfxB);
  const mask = pfx === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - pfx)) - 1n);
  return (ia & mask) === (ib & mask);
}

function nextFreeNetwork(baseCidrOrIp: string, prefix: number, existingSubnets: string[]): { cidr?: string; error?: string } {
  const base = splitCidr(baseCidrOrIp) ?? (isIpLiteral(baseCidrOrIp.trim()) ? { net: baseCidrOrIp.trim(), prefix: baseCidrOrIp.trim().includes(':') ? 128 : 32 } : null);
  if (!base) return { error: `"${baseCidrOrIp}" is not a valid IP or CIDR.` };
  const family = ipFamily(base.net);
  if (family === 'v4' && prefix > 32) return { error: `Prefix /${prefix} is too large for IPv4 (max /32).` };
  if (family === 'v6' && prefix > 128) return { error: `Prefix /${prefix} is too large for IPv6 (max /128).` };
  const existing = existingSubnets.filter((s) => ipFamily(s.split('/')[0]) === family);

  const MAX_CANDIDATES = 5_000_000;

  if (family === 'v4') {
    const ipInt = ipv4ToInt(base.net);
    if (ipInt === null) return { error: `Invalid IPv4 address "${base.net}".` };
    const v4Mask = (pfx: number): number => (pfx === 0 ? 0 : (~0 << (32 - pfx)) >>> 0);
    let start: number;
    let end: number;
    if (splitCidr(baseCidrOrIp)) {
      const baseNet = ipInt & v4Mask(base.prefix);
      // A numerically LARGER prefix is a SMALLER network — it fits when
      // prefix >= base.prefix; only a bigger block (smaller number) can't fit.
      if (prefix < base.prefix) return { error: `No /${prefix} network fits inside ${base.net}/${base.prefix}.` };
      start = baseNet & v4Mask(prefix);
      // 1 << 32 === 4 in JS (shifts are mod 32) — handle a /0 base explicitly.
      end = baseNet + (base.prefix === 0 ? 0x1_0000_0000 : 1 << (32 - base.prefix));
    } else {
      start = ipInt & v4Mask(prefix);
      end = 0x1_0000_0000; // whole v4 space
    }
    const size = 1 << (32 - prefix);
    let checked = 0;
    for (let c = start; c < end; c += size) {
      if (++checked > MAX_CANDIDATES) return { error: `Search space too large — narrow the base range or use a bigger prefix.` };
      const cidr = `${ipv4FromInt(c)}/${prefix}`;
      if (!existing.some((s) => cidrsOverlap(cidr, s))) return { cidr };
    }
    return { error: `No free /${prefix} network found starting at ${base.net}.` };
  }

  const ipBig = ipv6ToBigInt(base.net);
  if (ipBig === null) return { error: `Invalid IPv6 address "${base.net}".` };
  const FULL128 = (1n << 128n) - 1n;
  let start: bigint;
  let end: bigint;
  if (splitCidr(baseCidrOrIp)) {
    const netMask = base.prefix === 0 ? 0n : FULL128 ^ ((1n << BigInt(128 - base.prefix)) - 1n);
    const baseNet = ipBig & netMask;
    if (prefix < base.prefix) return { error: `No /${prefix} network fits inside ${base.net}/${base.prefix}.` };
    start = baseNet & (FULL128 ^ ((1n << BigInt(128 - prefix)) - 1n));
    end = baseNet + (1n << BigInt(128 - base.prefix));
  } else {
    start = ipBig & (FULL128 ^ ((1n << BigInt(128 - prefix)) - 1n));
    end = 1n << 128n; // whole v6 space
  }
  const size = 1n << BigInt(128 - prefix);
  let checked = 0;
  for (let c = start; c < end; c += size) {
    if (++checked > MAX_CANDIDATES) return { error: `Search space too large — narrow the base range or use a bigger prefix.` };
    const cidr = `${ipv6FromBigInt(c)}/${prefix}`;
    if (!existing.some((s) => cidrsOverlap(cidr, s))) return { cidr };
  }
  return { error: `No free /${prefix} network found starting at ${base.net}.` };
}

// ---------------------------------------------------------------------------
let failures = 0;
function check(label: string, actual: unknown, expected: unknown) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}: got ${JSON.stringify(actual)}${ok ? '' : `, expected ${JSON.stringify(expected)}`}`);
}

// --- IPv4: base range, skip occupied blocks -------------------------------
check('v4 first free in /16', nextFreeNetwork('10.40.0.0/16', 24, []).cidr, '10.40.0.0/24');
check('v4 skips occupied /24', nextFreeNetwork('10.40.0.0/16', 24, ['10.40.0.0/24']).cidr, '10.40.1.0/24');
check('v4 skips contained supernet', nextFreeNetwork('10.40.0.0/16', 24, ['10.40.0.0/23']).cidr, '10.40.2.0/24');
check('v4 skips sub-block overlap', nextFreeNetwork('10.40.0.0/16', 24, ['10.40.0.5/30']).cidr, '10.40.1.0/24');
check('v4 host bits in base are masked', nextFreeNetwork('10.40.7.99/16', 24, []).cidr, '10.40.0.0/24');
check('v4 bare IP base starts at aligned block', nextFreeNetwork('10.40.5.77', 24, []).cidr, '10.40.5.0/24');
check('v4 bare IP skips its own block', nextFreeNetwork('10.40.5.77', 24, ['10.40.5.0/24']).cidr, '10.40.6.0/24');
check('v4 /32 exact fit', nextFreeNetwork('192.168.1.0/30', 32, ['192.168.1.0/31']).cidr, '192.168.1.2/32');
check('v4 no fit → error', nextFreeNetwork('10.40.0.0/24', 24, ['10.40.0.0/24']).error, 'No free /24 network found starting at 10.40.0.0.');
check('v4 prefix bigger than base → error', nextFreeNetwork('10.40.0.0/24', 16, []).error, 'No /16 network fits inside 10.40.0.0/24.');
check('v4 whole space empty', nextFreeNetwork('0.0.0.0/0', 8, []).cidr, '0.0.0.0/8');
check('v4 whole space skips 0/8 + 10/8 (1-9 free)', nextFreeNetwork('0.0.0.0/0', 8, ['0.0.0.0/8', '10.0.0.0/8']).cidr, '1.0.0.0/8');
check('v4 invalid base → error', nextFreeNetwork('not-an-ip', 24, []).error, '"not-an-ip" is not a valid IP or CIDR.');

// --- IPv6: same semantics ---------------------------------------------------
check('v6 first free in /48', nextFreeNetwork('fd00::/48', 64, []).cidr, 'fd00::/64');
check('v6 skips occupied /64', nextFreeNetwork('fd00::/48', 64, ['fd00::/64']).cidr, 'fd00:0:0:1::/64');
// A /56 pins the top 8 bits of group 3 — it covers group 3 ∈ [0x000..0x0ff],
// so the first free /64 is fd00:0:0:100::. 
check('v6 skips contained supernet', nextFreeNetwork('fd00::/48', 64, ['fd00::/56']).cidr, 'fd00:0:0:100::/64');
check('v6 host bits masked', nextFreeNetwork('fd00:0:0:1234:abcd::99/48', 64, []).cidr, 'fd00::/64');
check('v6 bare IP base aligned', nextFreeNetwork('fd00:0:0:5::77', 64, []).cidr, 'fd00:0:0:5::/64');
// A v6 /127 covers exactly two addresses (fd00:: and fd00::1) — next free is fd00::2. 
check('v6 /128 exact fit', nextFreeNetwork('fd00::/126', 128, ['fd00::/127']).cidr, 'fd00::2/128');
check('v6 no fit → error', nextFreeNetwork('fd00::/64', 64, ['fd00::/64']).error, 'No free /64 network found starting at fd00::.');
check('v6 prefix bigger than base → error', nextFreeNetwork('fd00::/64', 48, []).error, 'No /48 network fits inside fd00::/64.');
check('v6 whole space empty', nextFreeNetwork('::/0', 32, []).cidr, '::/32');
// ::/32 = 0:0::/32 — the very next /32 (0:1::) is free. 
check('v6 whole space skips ::/32 + 2001:db8::/32', nextFreeNetwork('::/0', 32, ['::/32', '2001:db8::/32']).cidr, '0:1::/32');
check('v6 family isolation (v4 existing ignored)', nextFreeNetwork('fd00::/48', 64, ['10.0.0.0/8']).cidr, 'fd00::/64');

// --- Cross-family overlap must not block -----------------------------------
check('v4 search ignores v6 rows', nextFreeNetwork('10.40.0.0/16', 24, ['fd00::/64']).cidr, '10.40.0.0/24');

// --- Performance sanity: full /8 in /24s = 16384 candidates -----------------
const t0 = Date.now();
check('v4 dense search (16k candidates)', nextFreeNetwork('10.0.0.0/8', 24, ['10.0.0.0/16']).cidr, '10.1.0.0/24');
console.log(`(dense v4 took ${Date.now() - t0} ms)`);

process.exit(failures === 0 ? 0 : 1);
