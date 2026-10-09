/**
 * Plugin identity resolution — the multi-instance convention shared by all
 * plugins (previously ~20 lines of copy-pasted constants per plugin).
 *
 * Env vars:
 *   PORT                  container port (default 4080 — one conventional
 *                         internal port for ALL plugins; compose maps distinct
 *                         HOST ports to it)
 *   ADVERTISED_ENDPOINT   full URL the API should call back (defaults to
 *                         http://localhost:<port>)
 *   PLUGIN_INSTANCE_ID    multi-instance: advertised uuid becomes
 *                         `<uuid>:<instanceId>` and the name gains " (id)"
 *   PLUGIN_DISPLAY_NAME   optional explicit display-name override
 *   UNM_BUILD_TAG         image build tag baked in by CI (branch or release
 *                         tag); surfaced via /discover so the Plugins page can
 *                         show which build is running. Empty = local/dev.
 */

import { PluginCapability } from './types';

export interface PluginIdentity {
  /** Base UUID declared by the plugin (stable across instances). */
  uuid: string;
  /** Advertised identity — `<uuid>:<instanceId>` when instanced. */
  effectiveUuid: string;
  /** Advertised display name. */
  displayName: string;
  version: string;
  vendors: string[];
  capabilities: PluginCapability[];
  /** 'none' | 'token' (free text, never enforced by the API). */
  authType: string;
  port: number;
  endpoint: string;
  /** Image build tag (UNM_BUILD_TAG env) — '' when not baked in (local/dev). */
  buildTag: string;
}

/** The conventional internal port every UNM plugin listens on. */
export const DEFAULT_PLUGIN_PORT = 4080;

export interface PluginIdentityInput {
  uuid: string;
  name: string;
  version: string;
  vendors: string[];
  capabilities: PluginCapability[];
  authType?: string;
}

/** Resolves the effective identity from env + declared constants. */
export function resolvePluginIdentity(input: PluginIdentityInput): PluginIdentity {
  const instanceId = process.env.PLUGIN_INSTANCE_ID?.trim() ?? '';
  const effectiveUuid = instanceId ? `${input.uuid}:${instanceId}` : input.uuid;
  const displayName =
    process.env.PLUGIN_DISPLAY_NAME?.trim() || (instanceId ? `${input.name} (${instanceId})` : input.name);
  const port = Number(process.env.PORT ?? DEFAULT_PLUGIN_PORT);
  return {
    uuid: input.uuid,
    effectiveUuid,
    displayName,
    version: input.version,
    vendors: input.vendors,
    capabilities: input.capabilities,
    authType: input.authType ?? 'none',
    port,
    endpoint: process.env.ADVERTISED_ENDPOINT ?? `http://localhost:${port}`,
    buildTag: process.env.UNM_BUILD_TAG?.trim() ?? '',
  };
}
