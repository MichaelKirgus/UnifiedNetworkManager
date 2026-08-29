/**
 * Action registry core types for the SwOS plugin — same contract as the other
 * UNM plugins so the API treats them identically:
 *  - /discover advertises the catalog (API persists + validates against it),
 *  - /plan composes steps from single-device actions,
 *  - /config dispatches one step to its executor.
 *
 * The shared contract types (schemas, plan shapes, catalog entries) + the
 * canonical input validator come from @unm/plugin-sdk — re-exported here so
 * sibling files keep their existing imports.
 */

import { SwosClient } from '../swosClient';
import { SwosPlatform } from '../platform';
import type { ActionDescriptor as SdkActionDescriptor } from '@unm/plugin-sdk';
import { isValidInput, validateInput } from '@unm/plugin-sdk';
import type {
  ActionResult,
  CatalogEntry,
  DeviceCount,
  InputSchema,
  InputSchemaProperty,
  Plan,
  PlanStep,
  ProvisionRequest,
  RiskLevel,
} from '@unm/plugin-sdk';

// Shared contract types + canonical validator (superset semantics).
export type {
  ActionResult,
  CatalogEntry,
  DeviceCount,
  InputSchema,
  InputSchemaProperty,
  Plan,
  PlanStep,
  ProvisionRequest,
  RiskLevel,
};
export { isValidInput, validateInput };

/** Everything an action executor needs to run against one switch. */
export interface ActionContext {
  client: SwosClient;
  /** Resolved platform (field map + feature flags) for this device. */
  platform: SwosPlatform;
  host: string;
  deviceId?: string;
}

/** A fully-described action — the SDK descriptor bound to SwOS's executor context. */
export type ActionDescriptor = SdkActionDescriptor<ActionContext>;

// --- Input validation ---------------------------------------------------------------
// The canonical validator (superset semantics incl. minLength/maxLength) lives
// in @unm/plugin-sdk and is re-exported above.

