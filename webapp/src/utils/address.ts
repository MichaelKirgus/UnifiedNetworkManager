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
function isIpLiteral(value: string): boolean {
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
