/**
 * createPluginServer — the pre-wired express app every plugin used to build by
 * hand (cors + json + /healthz + /discover + static icons + mDNS advertising).
 * Plugins register their own routes on the returned `app`.
 */

import path from 'path';
import cors from 'cors';
import express, { Express, Request, Response } from 'express';
import { Bonjour } from 'bonjour-service';
import { PluginIdentity } from './identity';
import {
  CatalogEntry,
  CredentialSlotDescriptor,
  DeviceModelEntry,
  MetricDescriptor,
  PluginOptionDescriptor,
} from './types';

/** Extra /discover fields beyond the identity core (all optional). */
export interface DiscoveryExtras {
  /** Secret type this plugin expects for device credentials (null = none). Re-fetched live by the API — never persisted. */
  requiredSecretType?: string | null;
  metrics?: MetricDescriptor[];
  options?: PluginOptionDescriptor[];
  actions?: CatalogEntry[];
  modules?: string[];
  iconUrl?: string;
  deviceModels?: DeviceModelEntry[];
  credentialSlots?: CredentialSlotDescriptor[];
  /** Identity-provider plugins (basic-auth): flow + optional redirectUrl. */
  identityProvider?: { flow: string; redirectUrl?: string };
  /** Secrets-provider plugins: algorithm + the secret types served. */
  secretsProvider?: Record<string, unknown>;
}

export interface PluginServerOptions {
  identity: PluginIdentity;
  /** Log tag for console output (e.g. "icmp-plugin"). Defaults to the display name. */
  logTag?: string;
  /** JSON body limit — plugins carrying base64 config backups need '32mb'. Default '100kb' (express default). */
  jsonLimit?: string;
  /** Serve static icon assets at /icons from this directory (plugin-root relative path, e.g. path.join(__dirname, '../../icons')). */
  iconsDir?: string;
  /** Extra /discover fields (see DiscoveryExtras). May be a function for dynamic catalogs. */
  discovery?: DiscoveryExtras | (() => DiscoveryExtras);
}

export interface PluginServer {
  app: Express;
  identity: PluginIdentity;
  /** Starts listening + mDNS advertising. Returns the bound port. */
  listen(): Promise<number>;
}

/** Builds the /discover response body from identity + extras (single source for HTTP + mDNS TXT). */
export function buildDiscoverPayload(identity: PluginIdentity, extras?: DiscoveryExtras | (() => DiscoveryExtras)): Record<string, unknown> {
  const e = typeof extras === 'function' ? extras() : extras ?? {};
  return {
    uuid: identity.effectiveUuid,
    name: identity.displayName,
    version: identity.version,
    vendors: identity.vendors,
    capabilities: identity.capabilities,
    endpoint: identity.endpoint,
    authType: identity.authType,
    ...(e.requiredSecretType !== undefined ? { requiredSecretType: e.requiredSecretType } : {}),
    ...(e.metrics !== undefined ? { metrics: e.metrics } : {}),
    ...(e.options !== undefined ? { options: e.options } : {}),
    ...(e.actions !== undefined ? { actions: e.actions } : {}),
    ...(e.modules !== undefined ? { modules: e.modules } : {}),
    ...(e.iconUrl !== undefined ? { iconUrl: e.iconUrl } : {}),
    ...(e.deviceModels !== undefined ? { deviceModels: e.deviceModels } : {}),
    ...(e.credentialSlots !== undefined ? { credentialSlots: e.credentialSlots } : {}),
    ...(e.identityProvider !== undefined ? { identityProvider: e.identityProvider } : {}),
    ...(e.secretsProvider !== undefined ? { secretsProvider: e.secretsProvider } : {}),
  };
}

/** Advertises the plugin over mDNS/DNS-SD (service type `_unm-plugin._tcp`). Best-effort. */
function startMdnsAdvertising(identity: PluginIdentity, logTag: string): void {
  try {
    const bonjour = new Bonjour();
    bonjour.publish({
      name: identity.displayName,
      type: 'unm-plugin',
      port: identity.port,
      txt: {
        uuid: identity.effectiveUuid,
        name: identity.displayName,
        version: identity.version,
        vendors: identity.vendors.join(','),
        capabilities: identity.capabilities.join(','),
        endpoint: identity.endpoint,
        authType: identity.authType,
      },
    });
    console.log(`[${logTag}] advertising via mDNS as "${identity.displayName}" (${identity.effectiveUuid})`);
  } catch (err) {
    console.warn(`[${logTag}] mDNS advertising unavailable, falling back to polling discovery only:`, (err as Error).message);
  }
}

/** Creates the pre-wired plugin app. */
export function createPluginServer(opts: PluginServerOptions): PluginServer {
  const identity = opts.identity;
  const logTag = opts.logTag ?? identity.displayName.toLowerCase().replace(/\s+/g, '-');

  const app = express();
  app.use(cors());
  app.use(express.json({ limit: opts.jsonLimit }));

  if (opts.iconsDir) {
    // dist/src/../../icons = <plugin root>/icons (plugins compile with rootDir ".").
    app.use('/icons', express.static(path.join(opts.iconsDir)));
  }

  app.get('/healthz', (_req: Request, res: Response) => {
    res.status(200).json({ status: 'ok' });
  });

  app.get('/discover', (_req: Request, res: Response) => {
    res.status(200).json(buildDiscoverPayload(identity, opts.discovery));
  });

  return {
    app,
    identity,
    listen() {
      return new Promise<number>((resolve) => {
        const server = app.listen(identity.port, () => {
          console.log(`[${logTag}] listening on port ${identity.port}`);
          startMdnsAdvertising(identity, logTag);
          resolve(identity.port);
        });
        // Keep a reference so the process stays alive and tests can close it.
        (app as unknown as { __server?: typeof server }).__server = server;
      });
    },
  };
}

/**
 * Middleware authenticating the calling UNM API via the shared `x-plugin-api-key`
 * (used by basic-auth + secrets-provider). Skipped when PLUGIN_API_KEY is unset,
 * matching the API's own dev behavior.
 */
export function requirePluginKey(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const expected = process.env.PLUGIN_API_KEY;
  const provided = req.headers['x-plugin-api-key'];
  if (expected && provided !== expected) {
    res.status(403).json({ error: 'Forbidden: Invalid plugin API key' });
    return;
  }
  next();
}
