import { AxiosInstance } from 'axios';
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
import type { OpnsenseEdition, SyncClass } from '../client/editions';
import type { DnsBackend } from '../client/dns';
import type { DhcpBackend } from '../client/dhcp';

/**
 * Action registry core types.
 *
 * An "action" is one unit of work the plugin can perform against an appliance,
 * described declaratively so that:
 *  - /discover advertises the full catalog (the API persists it and validates
 *    job actions against it; the webapp renders only what exists),
 *  - /plan composes multi-device intents from single-device actions,
 *  - /config dispatches a single step to its executor.
 *
 * One registry serves all three entry points — the API never interprets
 * payloads, it validates `actionId` and propagates.
 *
 * The shared contract types (schemas, plan shapes, catalog entries) + the
 * canonical input validator come from @unm/plugin-sdk — re-exported here so
 * sibling files keep their existing imports. OPNsense-specific extensions
 * (staged/beOnly/ceFallback/provision) are layered on top of the SDK descriptor.
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

/** Merged credentials for one step: the device apiKey/secret plus any generated material. */
export interface StepCredentials {
  apiKey: string;
  apiSecret: string;
  /** Additional namespaced secrets (e.g. `wireguard`, `peer`, `psk`). */
  [key: string]: unknown;
}

/** Everything an action executor needs to run against one appliance. */
export interface ActionContext {
  client: AxiosInstance;
  host: string;
  deviceId?: string;
  /** UNM's device display name (sent by the API on /config) — labels artifacts like config backups. */
  deviceName?: string;
  credentials: StepCredentials;
  transport?: 'auto' | 'http' | 'https';
  edition: OpnsenseEdition;
  /** BE sync classes (empty on CE). */
  syncClasses?: SyncClass[];
  dnsBackend: DnsBackend;
  dhcpBackend: DhcpBackend;
  /** Free-form context the planner attached to this step. */
  extra?: Record<string, unknown>;
}

/** Declares what durable credentials a multi-device intent needs (called by the planner). */
export type ProvisionFn = (inputs: Record<string, unknown>, deviceCount: number) => ProvisionRequest[];

/** A fully-described action — the SDK descriptor + OPNsense-specific extensions. */
export interface ActionDescriptor extends SdkActionDescriptor<ActionContext> {
  /** True when the action stages a change that needs an explicit apply/reconfigure to activate. */
  staged?: boolean;
  /** Only executable on Business Edition. */
  beOnly?: boolean;
  /** Action id to run instead when the appliance is CE (for beOnly actions). */
  ceFallback?: string;
  /** Declares durable credentials a multi-device intent needs (unused by single-device actions). */
  provision?: ProvisionFn;
}

// --- Input validation ---------------------------------------------------------------
// The canonical validator (superset semantics incl. minLength/maxLength) lives
// in @unm/plugin-sdk and is re-exported above.
