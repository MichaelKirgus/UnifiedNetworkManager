/**
 * Action registry core types for the SwOS plugin — same contract as the
 * OPNsense plugin's registry so the API treats both identically:
 *  - /discover advertises the catalog (API persists + validates against it),
 *  - /plan composes steps from single-device actions,
 *  - /config dispatches one step to its executor.
 */

import { SwosClient } from '../swosClient';
import { SwosPlatform } from '../platform';

/** How risky an action is. The API gates `dangerous` behind 2FA + explicit confirm. */
export type RiskLevel = 'read' | 'write' | 'dangerous';

/** A single input property schema — a small JSON-Schema subset mirroring the
 * shape the webapp's SchemaForm renders (string/number/boolean/array/object,
 * enum → select). */
export interface InputSchemaProperty {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  label?: string;
  description?: string;
  required?: boolean;
  default?: unknown;
  /** Regex the string value must match. */
  pattern?: string;
  minLength?: number;
  maxLength?: number;
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

/** A single step in an execution plan (plugin-side shape). */
export interface PlanStep {
  stepIndex: number;
  deviceId: string;
  actionId: string;
  input: Record<string, unknown>;
  /** Indices of steps that must succeed before this one runs. */
  dependsOn?: number[];
  /** Provisioned secrets to merge into credentials (namespaced by ref). */
  secretRefs?: string[];
  /** Best-effort step — failure is recorded but does not abort the plan. */
  bestEffort?: boolean;
}

/** The output of /plan: ordered, dependency-aware steps. */
export interface Plan {
  id: string;
  createdAt: string;
  intentActionId: string;
  provisionRequests: unknown[]; // SwOS v1 never provisions secrets — always []
  steps: PlanStep[];
}

/** Everything an action executor needs to run against one switch. */
export interface ActionContext {
  client: SwosClient;
  /** Resolved platform (field map + feature flags) for this device. */
  platform: SwosPlatform;
  host: string;
  deviceId?: string;
}

/** The result an action executor returns. `verified` = re-read state post-apply. */
export interface ActionResult {
  success: boolean;
  applied?: boolean;
  verified?: boolean;
  details?: Record<string, unknown>;
  error?: string;
}

/** A fully-described action. */
export interface ActionDescriptor {
  id: string;
  label: string;
  description?: string;
  /** Module grouping for catalog display (Ports, PoE, LAG, VLANs, SNMP, System). */
  module: string;
  riskLevel: RiskLevel;
  deviceCount: 1;
  /** Per-action timeout override (ms) for long-running ops. */
  timeoutMs?: number;
  inputSchema: InputSchema;
  execute: (ctx: ActionContext, input: Record<string, unknown>) => Promise<ActionResult>;
}

// --- Input validation ---------------------------------------------------------------

export interface ValidationIssue {
  path: string;
  message: string;
}

/** Validates an action's input object against its schema (empty list = valid). */
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
        if (prop.items) {
          for (let i = 0; i < v.length; i++) {
            const item = v[i];
            if (prop.items.type === 'object' && prop.items.properties) {
              issues.push(
                ...validateInput(prop.items.properties, (item ?? {}) as Record<string, unknown>).map((x) => ({ ...x, path: `${name}[${i}].${x.path}` }))
              );
            } else if (typeof item === 'string' && prop.items.enum && !prop.items.enum.includes(item)) {
              issues.push({ path: `${name}[${i}]`, message: `must be one of: ${prop.items.enum.join(', ')}` });
            }
          }
        }
        break;
      case 'object':
        if (typeof v !== 'object' || Array.isArray(v)) {
          issues.push({ path: name, message: `${name} must be an object` });
          break;
        }
        if (prop.properties) {
          for (const issue of validateInput(prop.properties, v as Record<string, unknown>)) issues.push({ ...issue, path: `${name}.${issue.path}` });
        }
        break;
    }
  }

  return issues;
}
