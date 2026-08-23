import { isIP } from 'node:net';

/**
 * Device address validation.
 *
 * A device's `managementAddress` (primary) and any secondary addresses in
 * `device_ips` must be a bare network target — an IPv4 literal, an IPv6
 * literal, or a DNS name / FQDN. Schemes (`https://…`) and paths are NOT
 * allowed: choosing the transport scheme is each plugin's responsibility via
 * its own options (see OPNsense `transport`), so we never store one here.
 */

// RFC 1123 label: alphanumeric, may contain interior hyphens, no leading/trailing.
const LABEL = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/;
const MAX_HOSTNAME_LENGTH = 253;

/** True when `value` is a valid IPv4 or IPv6 literal (per node:net). */
function isIpLiteral(value: string): boolean {
  return isIP(value) !== 0;
}

/** True when `value` looks like a DNS name / FQDN (one or more RFC 1123 labels). */
function isDnsName(value: string): boolean {
  if (value.length === 0 || value.length > MAX_HOSTNAME_LENGTH) return false;
  const labels = value.split('.');
  // A trailing dot (absolute name) is tolerated but not required.
  while (labels[labels.length - 1] === '') labels.pop();
  if (labels.length === 0) return false;
  for (const label of labels) {
    if (!LABEL.test(label)) return false;
  }
  return true;
}

/**
 * Validates a device address. Accepts IPv4, IPv6, or DNS names/FQDNs.
 * Rejects empty strings, schemes (`://`), and anything with path characters.
 */
export function isValidAddress(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const v = value.trim();
  if (v.length === 0) return false;
  // Schemes / URLs are owned by plugins, not stored on the device.
  if (v.includes('://')) return false;
  if (isIpLiteral(v)) return true;
  return isDnsName(v);
}

/** Human-readable error for a rejected address, or null when it's valid. */
export function addressError(value: unknown): string | null {
  if (isValidAddress(value)) return null;
  return 'Must be an IPv4 address, IPv6 address, or DNS name (no scheme like https://)';
}

/**
 * Computes the network prefix ("192.168.1.0/24", "fd00::/64") for an IP
 * literal + prefix length — used to group interface rows into logical
 * networks across devices (several interfaces with addresses in the same
 * subnet are ONE network). Returns null when either part is missing or not a
 * valid IP literal; callers fall back to other grouping keys.
 */
export function subnetOf(ip: string, prefix: number | null): string | null {
  if (!ip || prefix === null) return null;
  const family = isIP(ip);
  if (family === 4 && Number.isInteger(prefix) && prefix >= 0 && prefix <= 32) {
    const o = ip.split('.').map(Number);
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    const net = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) & mask;
    return `${(net >>> 24) & 255}.${(net >>> 16) & 255}.${(net >>> 8) & 255}.${net & 255}/${prefix}`;
  }
  if (family === 6 && Number.isInteger(prefix) && prefix >= 0 && prefix <= 128) {
    const words = ipv6ToWords(ip);
    if (!words) return null;
    for (let i = 0; i < 8; i++) {
      const bitsInGroup = Math.max(0, Math.min(16, prefix - i * 16));
      if (bitsInGroup === 0) words[i] = 0;
      else if (bitsInGroup < 16) words[i] &= 0xffff << (16 - bitsInGroup);
    }
    return `${wordsToIpv6(words)}/${prefix}`;
  }
  return null;
}

/** Expands an IPv6 literal to eight 16-bit groups, or null when malformed. */
function ipv6ToWords(ip: string): number[] | null {
  const addr = ip.trim();
  if (!addr.includes(':')) return null;
  if ((addr.match(/::/g) ?? []).length > 1) return null; // at most one "::"
  let left: string[];
  let right: string[];
  if (addr.includes('::')) {
    const [l, r] = addr.split('::');
    left = l === '' ? [] : l.split(':');
    right = r === '' ? [] : r.split(':');
  } else {
    left = addr.split(':');
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
  if (addr.includes('::')) {
    if (words.length >= 8) return null; // "::" must compress at least one group
    const leftWords = left.reduce((n, g) => n + (g.includes('.') ? 2 : 1), 0);
    words.splice(leftWords, 0, ...Array(8 - words.length).fill(0));
  } else if (words.length !== 8) {
    return null;
  }
  return words;
}

/** Renders eight 16-bit groups as a canonical compressed IPv6 literal. */
function wordsToIpv6(words: number[]): string {
  const groups = words.map((w) => w.toString(16));
  // Longest run of zero groups becomes "::" (only when it actually saves).
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
