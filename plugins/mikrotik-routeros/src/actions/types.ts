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
import type { RouterOsClient } from '../routerosClient';

/**
 * Action registry core types for the MikroTik RouterOS plugin.
 *
 * An "action" is one unit of work the plugin can perform against a router,
 * described declaratively so that:
 *  - /discover advertises the full catalog (the API persists it and validates
 *    job actions against it; the webapp renders only what exists),
 *  - /plan composes multi-device intents from single-device actions,
 *  - /config dispatches a single step to its executor.
 *
 * One registry serves all three entry points — the API never interprets
 * payloads, it validates `actionId` and propagates.
 *
 * Transport: everything rides the RouterOS REST API (`/rest`) with HTTP Basic
 * auth using the primary username/password secret — the SAME credential set as
 * monitoring (RouterOS shares one login across REST + SSH). Writes apply
 * IMMEDIATELY (no staged/reconfigure model like OPNsense).
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

/** Merged credentials for one step: the primary username/password secret's fields. */
export interface StepCredentials {
  username: string;
  password: string;
  /** Additional namespaced secrets (e.g. `slots.ssh`) — passed through as-is. */
  [key: string]: unknown;
}

/** Everything an action executor needs to run against one router. */
export interface ActionContext {
  client: RouterOsClient;
  /** Full management address as given by the API (may carry scheme/port). */
  address: string;
  deviceId?: string;
  deviceName?: string;
  credentials: StepCredentials;
}

/** A fully-described action — the SDK descriptor. */
export interface ActionDescriptor extends SdkActionDescriptor<ActionContext> {}
