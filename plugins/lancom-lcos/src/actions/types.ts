import { SnmpCredentials, TransportOptions } from '@unm/snmp-client';
import type { ActionDescriptor as SdkActionDescriptor, TerminalPool } from '@unm/plugin-sdk';
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
 * Action registry core types for the LANCOM LCOS router plugin.
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
 * Transports: config writes go over SNMP SET (primary credential); the web-UI
 * backup/restore actions use the optional `web` credential slot
 * (`usernamePassword`) passed under `credentials.slots.web`.
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

/**
 * Merged credentials for one step: the primary SNMP secret's fields plus any
 * bound credential slots (the API passes them under `slots.<name>`) and any
 * provisioned material namespaced by ref.
 */
export interface StepCredentials {
  /** Primary credential — the decrypted `snmp` secret fields. */
  snmp: SnmpCredentials;
  /** Bound extra credential slots, e.g. `{ web: { username, password } }`. */
  slots?: Record<string, Record<string, string>>;
  [key: string]: unknown;
}

/** Everything an action executor needs to run against one router. */
export interface ActionContext {
  /** Bare host (no scheme/port) for SNMP calls. */
  host: string;
  /** Full management address as given by the API (may carry scheme/port) — used by web-UI actions. */
  address: string;
  deviceId?: string;
  /** UNM's device display name (sent by the API on /config) — labels artifacts like config backups. */
  deviceName?: string;
  credentials: StepCredentials;
  /** Effective transport options (timeout/retries/port). */
  opts: TransportOptions;
  /** Web-UI transport preference ('auto' | 'http' | 'https'). */
  webTransport: 'auto' | 'http' | 'https';
  /** Configured backup endpoint path (see the `backupPath` option) — legacy web fallback only. */
  backupPath: string;
  /** Configured HTTPS management port (default 443) — used by web-UI actions. */
  httpsPort?: number;
  /** Configured plain-HTTP management port (default 80) — used by web-UI fallbacks. */
  httpPort?: number;
  /** Process-wide SFTP pool (SDK createSftpPool) — config backup/restore over the LCOS virtual `/config` file. */
  sftpPool: import('@unm/plugin-sdk').SftpPool;
  /** Process-wide terminal pool (SDK createTerminalPool) — interactive CLI actions (`set`, `readconfig`). */
  terminalPool: TerminalPool;
  /** Configured SSH port (default 22) — used by the SFTP/CLI transports. */
  sshPort?: number;
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
