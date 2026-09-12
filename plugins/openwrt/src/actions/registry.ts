/**
 * Action registry — the single source of truth for everything this plugin can
 * do. Serves three entry points (opnsense pattern):
 *  - /discover → listActions() (the catalog the API persists + validates against)
 *  - /plan     → getAction(intent).provision(...) to request durable credentials
 *  - /config   → getAction(step.actionId).execute(ctx, input) to run one step
 *
 * The multi-device INTENT catalog (listCatalog) lives in ../plan.ts so it can
 * merge single-device actions with the tunnel/back-route intents — mirroring
 * opnsense exactly.
 */

import type { ActionDescriptor } from './types';
import { SYSTEM_ACTIONS } from './system';
import { SNAPSHOT_ACTIONS } from './snapshots';
import { FIREWALL_ACTIONS } from './firewall';
import { WIREGUARD_ACTIONS } from './wireguard';
import { OPENVPN_ACTIONS } from './openvpn';
import { ROUTES_ACTIONS } from './routes';
import { INTERFACE_ACTIONS } from './interfaces';
import { DNS_ACTIONS, DHCP_ACTIONS } from './dnsDhcp';
import { WIRELESS_ACTIONS } from './wireless';

const ALL_ACTIONS: ActionDescriptor[] = [
  ...SYSTEM_ACTIONS,
  ...SNAPSHOT_ACTIONS,
  ...FIREWALL_ACTIONS,
  ...WIREGUARD_ACTIONS,
  ...OPENVPN_ACTIONS,
  ...ROUTES_ACTIONS,
  ...INTERFACE_ACTIONS,
  ...DNS_ACTIONS,
  ...DHCP_ACTIONS,
  ...WIRELESS_ACTIONS,
];

const byId = new Map<string, ActionDescriptor>(ALL_ACTIONS.map((a) => [a.id, a]));

/** Returns the action for an id, or undefined. */
export function getAction(id: string): ActionDescriptor | undefined {
  return byId.get(id);
}

/** All single-device actions (the full catalog). */
export function listActions(): ActionDescriptor[] {
  return ALL_ACTIONS;
}

/** Distinct module names, for catalog grouping in the webapp. */
export function listModules(): string[] {
  return [...new Set(ALL_ACTIONS.map((a) => a.module))];
}
