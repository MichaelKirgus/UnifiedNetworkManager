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
 *
 * Delegates to the canonical implementation in @unm/plugin-sdk (ip.ts) — this
 * re-export keeps existing import sites working without duplicating the math.
 */
export { subnetOf } from '@unm/plugin-sdk';
