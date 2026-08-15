import fs from 'fs';
import path from 'path';
import YAML from 'yaml';

/**
 * Resolves the absolute path of the OpenAPI spec file. This works whether the
 * process is started via ts-node-dev (src/) or the compiled build (dist/src/)
 * by walking up from this file's directory until an `openapi/` sibling folder
 * is found, rather than hardcoding a relative depth that differs between the
 * two run modes.
 */
export function resolveOpenApiPath(): string {
  if (process.env.OPENAPI_SPEC_PATH) {
    return path.resolve(process.env.OPENAPI_SPEC_PATH);
  }

  let dir = __dirname;
  for (let i = 0; i < 6; i += 1) {
    const candidate = path.join(dir, 'openapi', 'unified-network-manager.openapi.yaml');
    if (fs.existsSync(candidate)) {
      return candidate;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  throw new Error('Unable to locate openapi/unified-network-manager.openapi.yaml');
}

export const OPENAPI_PATH = resolveOpenApiPath();

/**
 * Loads and parses the OpenAPI specification that drives route registration,
 * request validation, and (indirectly) the shape of the web app's API client.
 */
export function loadOpenApiSpec(): Record<string, unknown> {
  const raw = fs.readFileSync(OPENAPI_PATH, 'utf8');
  return YAML.parse(raw);
}
