import { ActionDescriptor } from './types';
import { systemActions } from './system';
import { firewallActions } from './firewall';
import { wireguardActions } from './wireguard';
import { ipsecActions } from './ipsec';
import { openvpnActions } from './openvpn';
import { routeActions } from './routes';
import { interfaceActions } from './interfaces';
import { dnsActions } from './dns';
import { dhcpActions } from './dhcp';
import { trafficshaperActions } from './trafficshaper';
import { ntpdActions, syslogActions, monitActions } from './services';
import { syncActions } from './sync';
import { securityActions } from './security';
import { configBackupActions } from './configBackup';
import { userActions } from './users';
import { l2TopologyAction } from './l2Topology';
import { networkIntentActions } from './networkIntents';
import { dnsIntentActions } from './dnsIntents';

/**
 * The action registry — the single source of truth for everything this plugin
 * can do. It serves three entry points:
 *  - /discover → listActions() (the catalog the API persists + validates against)
 *  - /plan     → getAction(intent).provision(...) to request durable credentials
 *  - /config   → getAction(step.actionId).execute(ctx, input) to run one step
 */

const ALL_ACTIONS: ActionDescriptor[] = [
  ...systemActions,
  ...firewallActions,
  ...wireguardActions,
  ...ipsecActions,
  ...openvpnActions,
  ...routeActions,
  ...interfaceActions,
  ...dnsActions,
  ...dhcpActions,
  ...trafficshaperActions,
  ...ntpdActions,
  ...syslogActions,
  ...monitActions,
  ...syncActions,
  ...securityActions,
  // File-repo config backup + SSH restore (gap fill — snapshots are appliance-local).
  ...configBackupActions,
  // Local user management (version-aware /api/auth/user ↔ /api/core/user).
  ...userActions,
  l2TopologyAction,
  ...networkIntentActions,
  // Canonical DNS intents (dns.set / dns.delete) — fan-out via plan workflow.
  ...dnsIntentActions,
];

const byId = new Map<string, ActionDescriptor>(ALL_ACTIONS.map((a) => [a.id, a]));

/** Returns the action for an id, or undefined. */
export function getAction(id: string): ActionDescriptor | undefined {
  return byId.get(id);
}

/** All actions (the full catalog). */
export function listActions(): ActionDescriptor[] {
  return ALL_ACTIONS;
}

/**
 * The subset of the catalog executable on a given edition. BE-only actions are
 * dropped for CE devices unless they declare a ceFallback (in which case the
 * planner substitutes the fallback action id instead).
 */
export function listActionsForEdition(edition: 'ce' | 'be'): ActionDescriptor[] {
  if (edition === 'be') return ALL_ACTIONS;
  return ALL_ACTIONS.filter((a) => !a.beOnly || a.ceFallback);
}

/** Resolves the effective action id for an edition (applies ceFallback). */
export function resolveActionForEdition(id: string, edition: 'ce' | 'be'): ActionDescriptor | undefined {
  const action = byId.get(id);
  if (!action) return undefined;
  if (edition === 'ce' && action.beOnly) {
    return action.ceFallback ? byId.get(action.ceFallback) : undefined;
  }
  return action;
}

/** Distinct module names, for catalog grouping in the webapp. */
export function listModules(): string[] {
  return [...new Set(ALL_ACTIONS.map((a) => a.module))];
}
