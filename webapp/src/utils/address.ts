/**
 * Browser mirror of api/src/utils/address.ts (no node:net available here).
 *
 * A device address must be a bare network target — an IPv4 literal, an IPv6
 * literal, or a DNS name / FQDN. Schemes (`https://…`) and paths are NOT
 * allowed: choosing the transport scheme is each plugin's responsibility via
 * its own options (see OPNsense `transport`), so we never store one here.
 */

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/;

// RFC 1123 label: alphanumeric, may contain interior hyphens.
const LABEL = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/;
const MAX_HOSTNAME_LENGTH = 253;

/** True when `value` is an IPv4 or IPv6 literal (structural check). */
export function isIpLiteral(value: string): boolean {
  if (IPV4.test(value)) return true;
  // IPv6: hex groups separated by colons, at most one '::' compression, and
  // an optional trailing %zone id (link-local) which we strip before checking.
  const v = value.replace(/%[a-zA-Z0-9._-]+$/, '');
  if (!v.includes(':')) return false;
  const parts = v.split('::');
  if (parts.length > 2) return false; // more than one '::' is invalid
  for (const part of parts) {
    if (part === '') continue; // empty side of a '::' compression
    for (const group of part.split(':')) {
      if (!HEX_GROUP.test(group)) return false;
    }
  }
  return true;
}

function isDnsName(value: string): boolean {
  if (value.length === 0 || value.length > MAX_HOSTNAME_LENGTH) return false;
  const labels = value.split('.');
  while (labels[labels.length - 1] === '') labels.pop(); // tolerate trailing dot
  if (labels.length === 0) return false;
  for (const label of labels) {
    if (!LABEL.test(label)) return false;
  }
  return true;
}

/** True when `value` is a valid IPv4, IPv6, or DNS name. */
export function isValidAddress(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const v = value.trim();
  if (v.length === 0) return false;
  if (v.includes('://')) return false; // schemes are owned by plugins
  return isIpLiteral(v) || isDnsName(v);
}

/** Human-readable error for a rejected address, or null when valid. */
export function addressError(value: unknown): string | null {
  if (isValidAddress(value)) return null;
  return 'Must be an IPv4 address, IPv6 address, or DNS name (no scheme like https://)';
}
/** Address scope for the Networks/Hosts pages' per-IP badges. */
export type IpScope = 'private' | 'public' | 'ula' | 'gua' | 'link-local';

function ipv4Octets(value: string): number[] {
  return value.split('.').map(Number);
}

/** True for RFC 1918 private IPv4 space (10/8, 172.16/12, 192.168/16). */
function isPrivateIpv4(o: number[]): boolean {
  if (o[0] === 10) return true;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  return o[0] === 192 && o[1] === 168;
}

/** True for IPv4 link-local (APIPA, 169.254/16). */
function isLinkLocalIpv4(o: number[]): boolean {
  return o[0] === 169 && o[1] === 254;
}

/**
 * Classifies an IP literal or CIDR into its scope, or null when it can't be
 * classified (DNS names, loopback, multicast/reserved space, malformed input).
 * The prefix of a CIDR is ignored — only the network address decides.
 *   IPv4: RFC 1918 → private · 169.254/16 → link-local · other routable → public
 *   IPv6: fc00::/7 → ULA · fe80::/10 → link-local · 2000::/3 → GUA (global)
 */
export function ipScope(value: string): IpScope | null {
  const v = value.trim().replace(/%[a-zA-Z0-9._-]+$/, ''); // strip %zone id
  if (!v) return null;

  // CIDR: classify the network address only.
  const addrPart = v.split('/')[0];

  // IPv4 literal?
  if (IPV4.test(addrPart)) {
    const o = ipv4Octets(addrPart);
    if (o[0] === 127) return null; // loopback — no scope badge
    if (isLinkLocalIpv4(o)) return 'link-local';
    if (isPrivateIpv4(o)) return 'private';
    if (o[0] >= 224) return null; // multicast / reserved
    return 'public';
  }

  // IPv6 literal? (addrPart already has the /prefix stripped for CIDRs.)
  if (!addrPart.includes(':')) return null;
  const parts = addrPart.split('::');
  if (parts.length > 2) return null;
  for (const part of parts) {
    if (part === '') continue;
    for (const group of part.split(':')) {
      if (!HEX_GROUP.test(group)) return null; // not a valid IPv6 literal
    }
  }

  // Expand to the full 8 groups. With '::' compression the missing middle is
  // zero-filled; without it all 8 groups are present verbatim.
  const groups: number[] = [];
  if (parts.length === 2) {
    for (const g of parts[0].split(':')) if (g !== '') groups.push(parseInt(g, 16));
    const missing = 8 - groups.length;
    for (let i = 0; i < missing; i++) groups.push(0);
    for (const g of parts[1].split(':')) if (g !== '') groups.push(parseInt(g, 16));
  } else {
    for (const g of addrPart.split(':')) if (g !== '') groups.push(parseInt(g, 16));
  }

  // fc00::/7 ULA — first group's top bit pattern 1111 110x.
  const first = groups[0];
  if ((first & 0xfe00) === 0xfc00) return 'ula';
  // fe80::/10 link-local — first group's top bits 1111 1110.
  if ((first & 0xffc0) === 0xfe80) return 'link-local';
  // ::1 loopback, multicast ff00::/8, reserved 2001:db8::/32 — no badge.
  if (addrPart === '::1') return null;
  if ((first & 0xff00) === 0xff00) return null; // multicast
  if (groups[0] === 0x2001 && groups[1] === 0xdb8) return null; // documentation
  // 2000::/3 global unicast — first group's top bits 001.
  if ((first & 0xe000) === 0x2000) return 'gua';
  return null;
}

/** Coarse scope groups for the grouped display chips (see IpGroupChips). */
export type IpScopeGroup = 'private' | 'public' | 'link-local';

/**
 * Coarse grouping of an IP/CIDR: ULA counts as private and GUA as public, so a
 * dual-stack network collapses into at most three chips (Private / Public /
 * Link-Local). Null when the value can't be classified.
 */
export function ipScopeGroup(value: string): IpScopeGroup | null {
  const s = ipScope(value);
  if (s === 'ula') return 'private';
  if (s === 'gua') return 'public';
  if (s === 'private' || s === 'public' || s === 'link-local') return s;
  return null;
}