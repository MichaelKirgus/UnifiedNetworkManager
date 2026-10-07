/**
 * Action registry — the single source of truth for everything this plugin can
 * do. Serves three entry points (openwrt pattern):
 *  - /discover → listCatalog() (the catalog the API persists + validates against)
 *  - /plan     → getAction(intent).provision(...) to request durable credentials
 *  - /config   → getAction(step.actionId).execute(ctx, input) to run one step
 *
 * The multi-device INTENT catalog (listCatalogWithIntents) lives in ../plan.ts
 * so it can merge single-device actions with the tunnel intent.
 */

import { createRegistry } from '@unm/plugin-sdk';
import type { ActionDescriptor as SdkActionDescriptor, CatalogEntry } from '@unm/plugin-sdk';
import type { ActionContext } from './types';
import { SYSTEM_ACTIONS } from './system';
import { ROUTES_ACTIONS } from './routes';
import { SNAPSHOT_ACTIONS } from './backup';
import { WIREGUARD_ACTIONS } from './wireguard';
import { PACKAGES_ACTIONS } from './packages';
import { SECURITY_ACTIONS } from './security';
import { DOCKER_ACTIONS } from './docker';
import { FIREWALL_LOG_ACTIONS } from './firewallLog';
import { networkIntentActions } from './networkIntents';

const ALL_ACTIONS: SdkActionDescriptor<ActionContext>[] = [
  ...SYSTEM_ACTIONS,
  ...ROUTES_ACTIONS,
  ...SNAPSHOT_ACTIONS,
  ...WIREGUARD_ACTIONS,
  ...PACKAGES_ACTIONS,
  ...SECURITY_ACTIONS,
  // Kernel firewall drop logging (Firewall Events page) — behavior-preserving
  // nftables log twins on existing DROP/REJECT rules.
  ...FIREWALL_LOG_ACTIONS,
  // Docker / Compose (Containers page) — only meaningful on hosts that run a
  // docker daemon; the actions degrade to clear errors elsewhere.
  ...DOCKER_ACTIONS,
  // Canonical fleet intents (network.create / network.delete / l2.topology.read).
  ...networkIntentActions,
];

export const registry = createRegistry<ActionContext>(ALL_ACTIONS);

/** Returns the action for an id, or undefined. */
export function getAction(id: string): SdkActionDescriptor<ActionContext> | undefined {
  return registry.getAction(id);
}

/** All single-device actions (the full catalog). */
export function listActions(): SdkActionDescriptor<ActionContext>[] {
  return registry.listActions();
}

/** Single-device action catalog entries. */
export function listCatalog(): CatalogEntry[] {
  return registry.listCatalog();
}
