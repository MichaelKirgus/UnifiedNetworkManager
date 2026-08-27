import { SnmpCredentials, TransportOptions } from '@unm/snmp-client';
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

/**
 * Action registry core types for the LANCOM SX-Series switch plugin.
 *
 * An "action" is one unit of work the plugin can perform against a switch,
 * described declaratively so that:
 *  - /discover advertises the full catalog (the API persists it and validates
 *    job actions against it; the webapp renders only what exists),
 *  - /plan composes multi-device intents from single-device actions,
 *  - /config dispatches a single step to its executor.
 *
 * One registry serves all three entry points — the API never interprets
 * payloads, it validates `actionId` and propagates. All writes go over SNMP
 * SET with the primary `snmp` credential; v1 has no extra credential slots.
 *
 * The shared contract types (schemas, plan shapes, catalog entries) + the
 * canonical input validator come from @unm/plugin-sdk — re-exported here so
 * sibling files keep their existing imports.
 */

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

/** Merged credentials for one step — the primary SNMP secret's fields. */
export interface StepCredentials {
  /** Primary credential — the decrypted `snmp` secret fields. */
  snmp: SnmpCredentials;
  [key: string]: unknown;
}

/** Everything an action executor needs to run against one switch. */
export interface ActionContext {
  /** Bare host (no scheme/port) for SNMP calls. */
  host: string;
  /** Full management address as given by the API (may carry scheme/port). */
  address: string;
  deviceId?: string;
  credentials: StepCredentials;
  /** Effective transport options (timeout/retries/mibDir). */
  opts: TransportOptions;
}

/** Declares what durable credentials a multi-device intent needs (called by the planner). */
export type ProvisionFn = (inputs: Record<string, unknown>, deviceCount: number) => ProvisionRequest[];

/** A fully-described action — the SDK descriptor + an optional provision hook. */
export interface ActionDescriptor extends SdkActionDescriptor<ActionContext> {
  /** Declares durable credentials a multi-device intent needs (unused in v1). */
  provision?: ProvisionFn;
}

// --- Input validation ---------------------------------------------------------------
// The canonical validator (superset semantics incl. minLength/maxLength) lives
// in @unm/plugin-sdk and is re-exported above.
