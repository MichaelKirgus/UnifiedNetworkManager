import { ActionDescriptor } from './types';
import { l2TopologyAction } from './l2Topology';
import { networkIntentActions } from './networkIntents';
import { clockSyncAction } from './clock';

/**
 * The action registry — the single source of truth for everything this plugin
 * can do. It serves three entry points:
 *  - /discover → listActions() (the catalog the API persists + validates against)
 *  - /plan     → buildPlan() to fan out intents across a device batch
 *  - /config   → getAction(step.actionId).execute(ctx, input) to run one step
 */

const ALL_ACTIONS: ActionDescriptor[] = [
  l2TopologyAction,
  ...networkIntentActions,
  clockSyncAction,
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

/** The catalog as advertised in /discover — the API persists it and validates
 * plan inputs against its inputSchema. deviceCount is reported as 'N' for
 * EVERY entry on purpose: buildPlan() fans out each action to one step per
 * device (there are no fixed-count multi-device intents here), so a numeric
 * count would make the API reject legitimate multi-device plans. */
export function listCatalog() {
  return ALL_ACTIONS.map((a) => ({
    id: a.id,
    label: a.label,
    description: a.description,
    module: a.module,
    riskLevel: a.riskLevel,
    deviceCount: 'N' as const,
    timeoutMs: a.timeoutMs,
    retryOnDispatchFailure: a.retryOnDispatchFailure,
    inputSchema: a.inputSchema,
  }));
}

/** Module names present in the catalog (grouping hint for /discover). */
export function listModules(): string[] {
  return Array.from(new Set(ALL_ACTIONS.map((a) => a.module)));
}
