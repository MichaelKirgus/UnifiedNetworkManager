/**
 * Action input schemas — the JSON-Schema subset a plugin's action catalog
 * declares in /discover (`inputSchema` on each CatalogEntry). The shape
 * deliberately mirrors `InputSchemaProperty` in plugins/opnsense so ONE set of
 * semantics validates both plugin options and plan step inputs. The API does a
 * light check at plan-edit time; the authoritative validation still happens in
 * the plugin's /config handler (which re-validates against its own schema).
 *
 * The contract types come from @unm/plugin-sdk — re-exported here so callers
 * keep their existing imports. This module keeps its OWN validator runtime:
 * it is deliberately lighter than the SDK's (plan-edit-time checks only, e.g.
 * numeric-string coercion for enums), while authoritative validation always
 * happens in the plugin.
 */

import type { InputSchemaProperty as SdkInputSchemaProperty } from '@unm/plugin-sdk';

/** The API-side property schema — the SDK contract minus minLength/maxLength,
 * which only the plugin's /config validator enforces. */
export interface InputSchemaProperty extends Omit<SdkInputSchemaProperty, 'minLength' | 'maxLength'> {}

/** A map of property name → schema (the catalog's `inputSchema`). */
export type InputSchema = Record<string, InputSchemaProperty>;

export interface ValidationIssue {
  path: string;
  message: string;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Validates a value against one schema property. Returns a list of issues
 * (empty = valid). Mirrors the plugin's validateInput semantics.
 */
export function validateAgainstProperty(
  prop: InputSchemaProperty,
  value: unknown,
  path: string
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  if (value === undefined || value === null) {
    return issues; // presence is checked by the caller for required props
  }

  switch (prop.type) {
    case 'string': {
      if (typeof value !== 'string') {
        issues.push({ path, message: `expected a string` });
        break;
      }
      if (prop.pattern && !new RegExp(prop.pattern).test(value)) {
        issues.push({ path, message: `does not match pattern ${prop.pattern}` });
      }
      break;
    }
    case 'number': {
      const n = typeof value === 'string' ? Number(value) : value;
      if (typeof n !== 'number' || !Number.isFinite(n)) {
        issues.push({ path, message: `expected a number` });
        break;
      }
      if (typeof prop.min === 'number' && n < prop.min) {
        issues.push({ path, message: `must be >= ${prop.min}` });
      }
      if (typeof prop.max === 'number' && n > prop.max) {
        issues.push({ path, message: `must be <= ${prop.max}` });
      }
      break;
    }
    case 'boolean': {
      if (typeof value !== 'boolean') {
        issues.push({ path, message: `expected a boolean` });
      }
      break;
    }
    case 'array': {
      if (!Array.isArray(value)) {
        issues.push({ path, message: `expected an array` });
        break;
      }
      if (prop.items) {
        value.forEach((item, i) => {
          issues.push(...validateAgainstProperty(prop.items!, item, `${path}[${i}]`));
        });
      }
      break;
    }
    case 'object': {
      if (!isPlainObject(value)) {
        issues.push({ path, message: `expected an object` });
        break;
      }
      for (const [key, sub] of Object.entries(prop.properties ?? {})) {
        const childPath = `${path}.${key}`;
        const present = value[key] !== undefined && value[key] !== null;
        if (!present) {
          if (sub.required) issues.push({ path: childPath, message: 'is required' });
          continue;
        }
        issues.push(...validateAgainstProperty(sub, value[key], childPath));
      }
      break;
    }
  }

  // enum applies to any type that produced a concrete value.
  if (prop.enum && prop.enum.length > 0) {
    const ok = prop.enum.some(
      (e) => e === value || (typeof e === 'number' && typeof value === 'string' && Number(value) === e)
    );
    if (!ok) issues.push({ path, message: `must be one of: ${prop.enum.join(', ')}` });
  }

  return issues;
}

/** Validates a full input object against an InputSchema (property map). */
export function validateInput(schema: InputSchema, value: Record<string, unknown>): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  for (const [key, prop] of Object.entries(schema)) {
    const present = value[key] !== undefined && value[key] !== null;
    if (!present) {
      if (prop.required) issues.push({ path: key, message: 'is required' });
      continue;
    }
    issues.push(...validateAgainstProperty(prop, value[key], key));
  }
  return issues;
}

/** True when the input has no validation issues. */
export function isValidInput(schema: InputSchema, value: Record<string, unknown>): boolean {
  return validateInput(schema, value).length === 0;
}
