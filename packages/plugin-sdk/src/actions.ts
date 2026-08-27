/**
 * Action registry core — canonical input validation + the registry factory
 * (previously copy-pasted into 4 plugins: opnsense, swos, lancom-sx, lancom-lcos).
 */

import { ActionResult, CatalogEntry, InputSchema, InputSchemaProperty } from './types';

export interface ValidationIssue {
  path: string;
  message: string;
}

/**
 * Validates an action's input object against its schema. Returns a list of
 * issues (empty = valid). This is the PLUGIN-side validator — it encodes the
 * superset semantics all four plugin copies agreed on (swos's minLength/
 * maxLength included). The API keeps its own lighter validator for plan-edit
 * time; authoritative validation always happens in the plugin's /config.
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
        if (prop.minLength !== undefined && v.length < prop.minLength) {
          issues.push({ path: name, message: `${name} must be at least ${prop.minLength} characters` });
        }
        if (prop.maxLength !== undefined && v.length > prop.maxLength) {
          issues.push({ path: name, message: `${name} must be at most ${prop.maxLength} characters` });
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

/** Convenience: true when the input passes validation. */
export function isValidInput(schema: InputSchema, value: Record<string, unknown>): boolean {
  return validateInput(schema, value).length === 0;
}

// ---------------------------------------------------------------------------
// Registry factory
// ---------------------------------------------------------------------------

/**
 * A fully-described action. `Context` is the plugin-specific executor context
 * (client + credentials + runtime info) — intentionally generic so each plugin
 * keeps its own shape while sharing the registry machinery.
 */
export interface ActionDescriptor<Context = unknown> {
  id: string;
  label: string;
  description?: string;
  /** Module grouping for catalog display (e.g. "Ports", "Firewall"). */
  module: string;
  riskLevel: 'read' | 'write' | 'dangerous';
  deviceCount: 1 | 'N';
  /** Per-action timeout override (ms) for long-running ops. */
  timeoutMs?: number;
  inputSchema: InputSchema;
  execute: (ctx: Context, input: Record<string, unknown>) => Promise<ActionResult>;
}

/** The registry factory — replaces the ALL_ACTIONS/byId/getAction/listActions/listModules boilerplate. */
export interface ActionRegistry<Context = unknown> {
  /** All actions (the full catalog). */
  listActions(): ActionDescriptor<Context>[];
  getAction(id: string): ActionDescriptor<Context> | undefined;
  /** Distinct module names, for catalog grouping in the webapp. */
  listModules(): string[];
  /** The /discover `actions` array (single-device actions only). */
  listCatalog(): CatalogEntry[];
}

export function createRegistry<Context = unknown>(actions: ActionDescriptor<Context>[]): ActionRegistry<Context> {
  const byId = new Map<string, ActionDescriptor<Context>>(actions.map((a) => [a.id, a]));
  return {
    listActions: () => actions,
    getAction: (id) => byId.get(id),
    listModules: () => [...new Set(actions.map((a) => a.module))],
    listCatalog: () =>
      actions.map((a) => ({
        id: a.id,
        label: a.label,
        description: a.description,
        module: a.module,
        riskLevel: a.riskLevel,
        deviceCount: 1 as const,
        timeoutMs: a.timeoutMs,
        inputSchema: a.inputSchema,
      })),
  };
}
