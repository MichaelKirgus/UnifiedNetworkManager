import { SnmpCredentials, TransportOptions } from '@unm/snmp-client';

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
 */

/** How risky an action is. The API gates `dangerous` behind 2FA + explicit confirm. */
export type RiskLevel = 'read' | 'write' | 'dangerous';

/** Whether the action targets one device or fans out across many (multi-device intent). */
export type DeviceCount = 1 | 'N';

/**
 * A single input property schema — a small JSON-Schema subset deliberately
 * mirroring the shape the API's plugin-options validator already understands,
 * so ONE validator can check both plugin options and action inputs later.
 */
export interface InputSchemaProperty {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  label?: string;
  description?: string;
  required?: boolean;
  default?: unknown;
  /** Regex the string value must match. */
  pattern?: string;
  min?: number;
  max?: number;
  enum?: (string | number)[];
  /** For type 'array': schema of each element. */
  items?: InputSchemaProperty;
  /** For type 'object': nested property schemas. */
  properties?: Record<string, InputSchemaProperty>;
}

/** The action's input contract: a map of property name → schema. */
export type InputSchema = Record<string, InputSchemaProperty>;

/** A request for durable credentials the API must create before steps run. */
export interface ProvisionRequest {
  /** Stable ref within this plan; steps reference it via secretRefs. */
  ref: string;
  /** Secret type to create (must be a type the secrets provider serves). */
  type: string;
  /** Non-secret context fields (labels, CN/SANs...). Never private material. */
  fields?: Record<string, unknown>;
  label?: string;
}

/** A single step in an execution plan. */
export interface PlanStep {
  stepIndex: number;
  deviceId: string;
  actionId: string;
  input: Record<string, unknown>;
  /** Indices of steps that must succeed before this one runs. */
  dependsOn?: number[];
  /** Provisioned secrets to merge into this step's credentials (namespaced by ref). */
  secretRefs?: string[];
  /**
   * True for best-effort steps (e.g. the auto-prepended config.backup.download
   * rollback point): a failure here is recorded but does NOT abort the plan,
   * because the router may simply not have a web-UI slot bound.
   */
  bestEffort?: boolean;
}

/** The output of /plan: ordered, dependency-aware steps + credential requests. */
export interface Plan {
  id: string;
  createdAt: string;
  intentActionId: string;
  provisionRequests: ProvisionRequest[];
  steps: PlanStep[];
}

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
  credentials: StepCredentials;
  /** Effective transport options (timeout/retries/mibDir). */
  opts: TransportOptions;
  /** Web-UI transport preference ('auto' | 'http' | 'https'). */
  webTransport: 'auto' | 'http' | 'https';
  /** Configured backup endpoint path (see the `backupPath` option). */
  backupPath: string;
}

/** The result an action executor returns. `verified` = plugin re-read state post-apply. */
export interface ActionResult {
  success: boolean;
  applied?: boolean;
  verified?: boolean;
  details?: Record<string, unknown>;
  error?: string;
}

/** Declares what durable credentials a multi-device intent needs (called by the planner). */
export type ProvisionFn = (inputs: Record<string, unknown>, deviceCount: number) => ProvisionRequest[];

/** A fully-described action. */
export interface ActionDescriptor {
  id: string;
  label: string;
  description?: string;
  /** Module grouping for catalog display (e.g. "System", "Network"). */
  module: string;
  riskLevel: RiskLevel;
  deviceCount: DeviceCount;
  /** Per-action timeout override (ms) for long-running ops (backup download...). */
  timeoutMs?: number;
  inputSchema: InputSchema;
  provision?: ProvisionFn;
  execute: (ctx: ActionContext, input: Record<string, unknown>) => Promise<ActionResult>;
}

// --- Input validation ---------------------------------------------------------------

export interface ValidationIssue {
  path: string;
  message: string;
}

/**
 * Validates an action's input object against its schema. Returns a list of
 * issues (empty = valid). Mirrors the API plugin-options validator semantics so
 * the same logic can be shared later.
 */
export function validateInput(schema: InputSchema, value: Record<string, unknown>): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  for (const [name, prop] of Object.entries(schema)) {
    const v = value[name];

    if (v === undefined || v === null) {
      if (prop.required) issues.push({ path: name, message: `${name} is required` });
      continue;
    }

    switch (prop.type) {
      case 'string':
        if (typeof v !== 'string') {
          issues.push({ path: name, message: `${name} must be a string` });
          break;
        }
        if (prop.pattern && !new RegExp(prop.pattern).test(v)) {
          issues.push({ path: name, message: `${name} does not match the required pattern` });
        }
        if (prop.enum && !prop.enum.includes(v as string | number)) {
          issues.push({ path: name, message: `${name} must be one of: ${prop.enum.join(', ')}` });
        }
        break;
      case 'number':
        if (typeof v !== 'number' || Number.isNaN(v)) {
          issues.push({ path: name, message: `${name} must be a number` });
          break;
        }
        if (prop.min !== undefined && v < prop.min) issues.push({ path: name, message: `${name} must be >= ${prop.min}` });
        if (prop.max !== undefined && v > prop.max) issues.push({ path: name, message: `${name} must be <= ${prop.max}` });
        break;
      case 'boolean':
        if (typeof v !== 'boolean') issues.push({ path: name, message: `${name} must be a boolean` });
        break;
      case 'array':
        if (!Array.isArray(v)) {
          issues.push({ path: name, message: `${name} must be an array` });
          break;
        }
        if (prop.items) for (const [i, item] of v.entries()) issues.push(...validateInput({ [String(i)]: prop.items }, { [String(i)]: item }).map((x) => ({ ...x, path: `${name}[${i}]` })));
        break;
      case 'object':
        if (typeof v !== 'object' || Array.isArray(v)) {
          issues.push({ path: name, message: `${name} must be an object` });
          break;
        }
        if (prop.properties) for (const issue of validateInput(prop.properties, v as Record<string, unknown>)) issues.push({ ...issue, path: `${name}.${issue.path}` });
        break;
    }
  }

  return issues;
}

/** Convenience: true when the input passes validation. */
export function isValidInput(schema: InputSchema, value: Record<string, unknown>): boolean {
  return validateInput(schema, value).length === 0;
}
