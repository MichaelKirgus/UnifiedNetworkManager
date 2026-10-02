import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Dispatcher } from 'undici';
import YAML from 'yaml';
import { z, ZodTypeAny } from 'zod';
import { apiDispatcher, isTransportError, mtlsLive } from './mcpMtls.js';

/**
 * OpenAPI → MCP tool generation.
 *
 * The UNM API is fully described by `openapi/unified-network-manager.openapi.yaml`
 * (express-openapi-validator enforces it), so this module turns every operation
 * into an MCP tool: parameters + request body become the zod input schema, and
 * execution is a plain fetch against the API with the caller's bearer token.
 * New API operations appear as tools automatically — no per-tool code.
 *
 * Excluded on purpose:
 *   - /auth/* endpoints (login/2FA are interactive; agents use long-lived tokens)
 *   - operations marked `x-2fa-required` (tokens can never carry a TOTP claim)
 */

interface OpenApiSpec {
  paths?: Record<string, Record<string, unknown>>;
  components?: { schemas?: Record<string, unknown> };
}

export interface GeneratedTool {
  name: string;
  description: string;
  /** Zod raw shape for the MCP input schema. */
  inputSchema: Record<string, ZodTypeAny>;
  method: string;
  pathTemplate: string;
  execute: (args: Record<string, unknown>) => Promise<{ status: number; bodyText: string }>;
}

const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const;

/** One-time marker so the "first mTLS call" log line doesn't repeat per request. */
let loggedMtlsUse = false;

/** Resolves the OpenAPI spec file (env override → walk up to the repo root). */
export function resolveSpecPath(): string {
  if (process.env.UNM_OPENAPI_SPEC) return path.resolve(process.env.UNM_OPENAPI_SPEC);
  // Works from both src/ (tsx dev) and dist/src/ (built): walk upward until the
  // spec file is found.
  let dir = path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 8; i++) {
    const candidate = path.join(dir, 'openapi', 'unified-network-manager.openapi.yaml');
    try {
      if (readFileSync(candidate).length > 0) return candidate;
    } catch {
      /* keep walking up */
    }
    dir = path.dirname(dir);
  }
  throw new Error('Could not locate openapi/unified-network-manager.openapi.yaml — set UNM_OPENAPI_SPEC');
}

/** Deterministic tool name: `get_devices_deviceId_plugins_pluginId`. */
function toolName(method: string, templatePath: string): string {
  const segments = templatePath
    .split('/')
    .filter(Boolean)
    .map((s) => s.replace(/[{}]/g, ''));
  return `${method}_${segments.join('_')}`;
}

/** Recursively converts an OpenAPI JSON schema into a zod type (cycle-safe). */
function toZod(schema: unknown, spec: OpenApiSpec, seen = new Set<unknown>()): ZodTypeAny {
  if (!schema || typeof schema !== 'object') return z.unknown();

  const s = schema as Record<string, unknown>;

  // $ref → components/schemas/<Name>
  if (typeof s.$ref === 'string') {
    const name = s.$ref.split('/').pop() ?? '';
    const target = spec.components?.schemas?.[name];
    if (!target) return z.unknown();
    if (seen.has(target)) return z.unknown(); // cycle guard
    seen.add(target);
    return toZod(target, spec, seen);
  }

  // Nullable union: type: [string, 'null']
  const types = Array.isArray(s.type) ? s.type : [s.type];
  const nullable = (types as string[]).includes('null');
  const baseTypes = (types as string[]).filter((t) => t !== 'null');

  const build = (): ZodTypeAny => {
    if (baseTypes.length === 0) return z.unknown();
    switch (baseTypes[0]) {
      case 'string':
        return typeof s.enum !== 'undefined' ? z.enum(s.enum as [string, ...string[]]) : z.string();
      case 'integer':
        return z.number().int();
      case 'number':
        return z.number();
      case 'boolean':
        return z.boolean();
      case 'array': {
        const items = (s.items as Record<string, unknown>) ?? {};
        return z.array(toZod(items, spec, new Set(seen)));
      }
      case 'object': {
        if (s.additionalProperties && typeof s.additionalProperties === 'object') {
          return z.record(z.string(), toZod(s.additionalProperties, spec, new Set(seen)));
        }
        const props = (s.properties ?? {}) as Record<string, unknown>;
        const required = Array.isArray(s.required) ? (s.required as string[]) : [];
        const shape: Record<string, ZodTypeAny> = {};
        for (const [key, value] of Object.entries(props)) {
          let field = toZod(value, spec, new Set(seen));
          if (!required.includes(key)) field = field.optional();
          // Preserve the description on object fields.
          const desc = typeof (value as Record<string, unknown>)?.description === 'string' ? ((value as Record<string, unknown>).description as string) : undefined;
          shape[key] = desc ? field.describe(desc) : field;
        }
        return z.object(shape);
      }
      default:
        return z.unknown();
    }
  };

  const built = build();
  return nullable ? (built as ZodTypeAny).nullable() : built;
}

/** Builds the tool input schema from parameters + requestBody. */
function buildInputSchema(
  operation: Record<string, unknown>,
  spec: OpenApiSpec
): Record<string, ZodTypeAny> {
  const shape: Record<string, ZodTypeAny> = {};

  for (const param of (operation.parameters ?? []) as Array<Record<string, unknown>>) {
    if (!param || typeof param.name !== 'string') continue;
    let field = toZod((param.schema as Record<string, unknown>) ?? {}, spec);
    const desc = typeof param.description === 'string' ? param.description : undefined;
    if (desc) field = field.describe(desc);
    if (param.required !== true) field = field.optional();
    shape[param.name] = field;
  }

  const body = operation.requestBody as Record<string, unknown> | undefined;
  const jsonContent = (body?.content ?? {}) as Record<string, unknown>;
  const media = jsonContent['application/json'] as Record<string, unknown> | undefined;
  if (media?.schema) {
    const objSchema = toZod(media.schema, spec);
    // Unwrap: the body object's properties become top-level tool arguments.
    if (objSchema instanceof z.ZodObject) {
      for (const [key, value] of Object.entries(objSchema.shape)) shape[key] = value as ZodTypeAny;
    } else {
      shape.body = objSchema;
    }
  }

  return shape;
}

/** Splits the input schema into path/query params and the request body. */
function splitArgs(
  args: Record<string, unknown>,
  operation: Record<string, unknown>
): { pathParams: Record<string, string>; queryParams: Record<string, string>; body?: unknown } {
  const paramNames = new Set(
    ((operation.parameters ?? []) as Array<Record<string, unknown>>)
      .map((p) => p?.name)
      .filter((n): n is string => typeof n === 'string')
  );

  const pathParams: Record<string, string> = {};
  const queryParams: Record<string, string> = {};
  for (const [key, value] of Object.entries(args)) {
    if (!paramNames.has(key) || value === undefined || value === null) continue;
    // Path params are always present in the template → path; others → query.
    const isPathParam = (operation.pathTemplate as string | undefined)?.includes(`{${key}}`) === true;
    if (isPathParam) pathParams[key] = String(value);
    else queryParams[key] = String(value);
  }

  // Body: everything that was NOT a declared parameter.
  const bodyObj: Record<string, unknown> = {};
  let hasBody = false;
  for (const [key, value] of Object.entries(args)) {
    if (!paramNames.has(key) && value !== undefined) {
      bodyObj[key] = value;
      hasBody = true;
    }
  }

  return { pathParams, queryParams, body: hasBody ? bodyObj : undefined };
}

/** Generates one MCP tool per spec operation (auth + 2FA-gated excluded). */
export function generateTools(specPath: string): GeneratedTool[] {
  const raw = readFileSync(specPath, 'utf8');
  const spec = YAML.parse(raw) as OpenApiSpec;
  const tools: GeneratedTool[] = [];

  for (const [templatePath, pathItem] of Object.entries(spec.paths ?? {})) {
    if (!pathItem || typeof pathItem !== 'object') continue;
    for (const method of HTTP_METHODS) {
      const operation = pathItem[method];
      if (!operation || typeof operation !== 'object') continue;

      // Interactive auth flows and 2FA-gated operations are out of scope:
      // agents authenticate with long-lived tokens, which can never carry a TOTP claim.
      if (templatePath.startsWith('/auth/')) continue;
      if ((operation as Record<string, unknown>)['x-2fa-required'] === true) continue;

      const op = operation as Record<string, unknown> & { pathTemplate?: string };
      op.pathTemplate = templatePath;

      const name = toolName(method, templatePath);
      const summary = typeof op.summary === 'string' ? op.summary : `${method.toUpperCase()} ${templatePath}`;
      const descriptionParts = [summary];
      if (typeof op.description === 'string') descriptionParts.push(op.description.trim());
      // Surface the documented permission requirement when present in prose.
      const permMatch = /`([a-z-]+:[a-z-]+)`/.exec(typeof op.description === 'string' ? op.description : '');
      if (permMatch) descriptionParts.push(`(requires permission ${permMatch[1]})`);

      tools.push({
        name,
        description: descriptionParts.join(' — '),
        inputSchema: buildInputSchema(op, spec),
        method,
        pathTemplate: templatePath,
        execute: async (args) => {
          // mTLS Stage 2: once the MCP's own leaf is live, prefer the API's
          // :8443 mTLS listener (client cert + UNM root trust via undici).
          const plainBase = process.env.UNM_API_BASE ?? 'http://localhost:3000/v1';
          const tlsBase = (process.env.UNM_API_TLS_BASE ?? plainBase.replace(/^http/i, 'https')).replace(/\/$/, '');
          const token = process.env.UNM_API_TOKEN;
          if (!token) throw new Error('UNM_API_TOKEN is not set');

          const { pathParams, queryParams, body } = splitArgs(args, op);
          let urlPath = templatePath;
          for (const [key, value] of Object.entries(pathParams)) {
            urlPath = urlPath.replace(`{${key}}`, encodeURIComponent(value));
          }
          const qs = new URLSearchParams();
          for (const [key, value] of Object.entries(queryParams)) qs.set(key, value);
          const suffix = qs.toString() ? `?${qs.toString()}` : '';

          if (mtlsLive()) {
            try {
              const result = await doFetch(`${tlsBase}${urlPath}${suffix}`, apiDispatcher());
              if (!loggedMtlsUse) {
                loggedMtlsUse = true;
                console.log(`[unm-mcp] first API call served over mTLS (${tlsBase})`);
              }
              return result;
            } catch (err) {
              // The API's mTLS listener may not be up yet (it enrolls on its own
              // 30s loop too) — fall back to plain HTTP once.
              if (!isTransportError(err)) throw err;
              console.warn(`[unm-mcp] mTLS fetch failed (${(err as Error).message}) — falling back to plain HTTP`);
            }
          }
          return await doFetch(`${plainBase.replace(/\/$/, '')}${urlPath}${suffix}`);

          async function doFetch(url: string, dispatcher?: Dispatcher): Promise<{ status: number; bodyText: string }> {
            const res = await fetch(url, {
              method: method.toUpperCase(),
              headers: {
                Authorization: `Bearer ${token}`,
                ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
              },
              body: body !== undefined ? JSON.stringify(body) : undefined,
              ...(dispatcher ? { dispatcher } : {}),
            });

            const text = await res.text();
            return { status: res.status, bodyText: text || '(empty response)' };
          }
        },
      });
    }
  }

  return tools;
}
