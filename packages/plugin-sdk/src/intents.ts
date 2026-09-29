/**
 * Canonical fleet intents — the cross-vendor abstraction layer for rolling out
 * whole networks (VLANs, optionally with a WLAN SSID) across a site or tag.
 *
 * The idea: one INTENT ("create network XY with VLAN 42 on every router at
 * site H") maps to ONE canonical action id + input schema per vendor plugin.
 * Each plugin implements the intent against its own config surface (LCOS CLI
 * tables, OPNsense staged API, RouterOS API, …) under the SAME id and a
 * COMPATIBLE subset of this schema, so:
 *   - the UNM plan machinery fans the intent out per device unchanged
 *     (POST /plans with devices[] — one step per device),
 *   - the webapp's Network Rollout dialog can target a site/tag once and let
 *     every router plugin that implements the intent pick it up,
 *   - later tunnel intents (WireGuard/IPsec/OpenSSL) reuse the same pattern.
 *
 * A plugin MAY implement only a subset of an intent's optional fields — its
 * catalog entry advertises exactly what it supports via its own inputSchema
 * (validated per-plugin at plan time). The canonical schemas below are the
 * SUPERSET contract; `canonicalIntentIds` is the registry of known intents.
 */

import type { InputSchema } from './types';

/** Canonical intent ids every router plugin SHOULD implement for fleet rollout. */
export const INTENT_NETWORK_CREATE = 'network.create' as const;
export const INTENT_NETWORK_DELETE = 'network.delete' as const;
// Reserved for the tunnel-abstraction round (WireGuard/IPsec/OpenSSL):
//   INTENT_TUNNEL_CREATE = 'tunnel.create', INTENT_TUNNEL_DELETE = 'tunnel.delete'.

/** All canonical intent ids, in rollout order. */
export const CANONICAL_INTENTS: readonly string[] = [INTENT_NETWORK_CREATE, INTENT_NETWORK_DELETE];

/** True when an action id is a canonical fleet intent (plugins implement them). */
export function isCanonicalIntent(id: string): boolean {
  return (CANONICAL_INTENTS as readonly string[]).includes(id);
}

// ---------------------------------------------------------------------------
// network.create — "create Network XY with VLAN ID on all devices" (+ optional SSID)
// ---------------------------------------------------------------------------

/**
 * Canonical input schema for `network.create`. Every field except `name` and
 * `vlanId` is optional so a plugin can advertise the subset it supports:
 *   - LCOS: name, vlanId, cidr|ip+netmask, interface, dhcpPool{start,end}, ssid{name}
 *   - OPNsense: name, vlanId (→ staged vlan.add + reconfigure)
 * `cidr` and `ip`/`netmask` are alternative forms of the same L3 address — a
 * plugin accepts whichever it understands.
 */
export const NETWORK_CREATE_SCHEMA: InputSchema = {
  name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Network name (unique per device)' },
  vlanId: { type: 'number', required: true, min: 1, max: 4094, description: 'VLAN ID to create/attach' },
  cidr: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'L3 address as CIDR (e.g. 10.42.0.1/24) — alternative to ip+netmask' },
  ip: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'L3 address (alternative to cidr)' },
  netmask: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Netmask for `ip`' },
  interface: { type: 'string', maxLength: 64, description: 'Device-local L2 interface to attach the VLAN to (e.g. LAN-1)' },
  dhcpPool: {
    type: 'object',
    description: 'Optional DHCP pool served on this network',
    properties: {
      start: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$' },
      end: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$' },
    },
  },
  ssid: {
    type: 'object',
    description: 'Optional WLAN SSID to expose this network on (devices with local radios only)',
    properties: {
      name: { type: 'string', required: true, minLength: 1, maxLength: 32, description: 'Broadcast SSID name' },
      slot: { type: 'string', description: 'Device-local radio slot to use (vendor-specific; auto-picked when omitted)' },
    },
  },
};

// ---------------------------------------------------------------------------
// network.delete — "remove Network XY from all devices"
// ---------------------------------------------------------------------------

/** Canonical input schema for `network.delete` (name-addressed, idempotent). */
export const NETWORK_DELETE_SCHEMA: InputSchema = {
  name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Network name to remove' },
};

/** Canonical intent → input schema lookup (the superset contract). */
export const CANONICAL_INTENT_SCHEMAS: Record<string, InputSchema> = {
  [INTENT_NETWORK_CREATE]: NETWORK_CREATE_SCHEMA,
  [INTENT_NETWORK_DELETE]: NETWORK_DELETE_SCHEMA,
};
