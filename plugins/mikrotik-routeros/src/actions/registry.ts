import { ActionDescriptor } from './types';
import { l2TopologyAction } from './l2Topology';
import { networkIntentActions } from './networkIntents';

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
