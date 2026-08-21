import { AxiosInstance } from 'axios';
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
   * True for best-effort steps (e.g. the auto-prepended snapshot.create
   * rollback point): a failure here is recorded but does NOT abort the plan,
   * because the appliance may simply not support snapshots.
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
  /** Module grouping for catalog display (e.g. "Firewall", "WireGuard"). */
  module: string;
  riskLevel: RiskLevel;
  /** True when the action stages a change that needs an explicit apply/reconfigure to activate. */
  staged?: boolean;
  deviceCount: DeviceCount;
  /** Per-action timeout override (ms) for long-running ops (reboot, firmware...). */
  timeoutMs?: number;
  /** Only executable on Business Edition. */
  beOnly?: boolean;
  /** Action id to run instead when the appliance is CE (for beOnly actions). */
  ceFallback?: string;
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
