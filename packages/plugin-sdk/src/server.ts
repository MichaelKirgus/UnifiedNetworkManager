/**
 * createPluginServer — the pre-wired express app every plugin used to build by
 * hand (cors + json + /healthz + /discover + static icons + mDNS advertising).
 * Plugins register their own routes on the returned `app`.
 */

import path from 'path';
import http from 'http';
import tls from 'tls';
import type { IncomingMessage } from 'http';
import type { Duplex } from 'stream';
import cors from 'cors';
import express, { Express, Request, Response } from 'express';
import { Bonjour } from 'bonjour-service';
import { PluginIdentity } from './identity';
import { ensureTlsIdentity, resolveTlsIdentifiers, scheduleTlsRenewal, TlsIdentity } from './tlsIdentity';
import { createSelfMetrics } from './selfMetrics';
import {
  CatalogEntry,
  CredentialSlotDescriptor,
  DeviceModelEntry,
  DeviceStateResponse,
  FilesystemRequestBody,
  FilesystemResponseBody,
  MetricDescriptor,
  PluginOptionDescriptor,
  ProbeRequestBody,
  QuickAction,
  QuickActionRequestBody,
  QuickActionResponseBody,
  ProbeResponseBody,
  StateRequestBody,
} from './types';
import { DeviceSupport } from './deviceSupport';

/** Extra /discover fields beyond the identity core (all optional). */
export interface DiscoveryExtras {
  /** Secret type this plugin expects for device credentials (null = none). Re-fetched live by the API — never persisted. */
  requiredSecretType?: string | null;
  /** Multiple acceptable secret types for the PRIMARY credential (e.g. a plugin
   *  that accepts both usernamePassword and sshKeyPair logins). Wins over
   *  `requiredSecretType` when present; older consumers fall back to the single
   *  type, so declare BOTH whenever you use this field. */
  requiredSecretTypes?: string[];
  metrics?: MetricDescriptor[];
  options?: PluginOptionDescriptor[];
  actions?: CatalogEntry[];
  /** Quick actions for the Devices page "Device Actions" column (see types.ts). */
  quickActions?: QuickAction[];
  modules?: string[];
  iconUrl?: string;
  deviceModels?: DeviceModelEntry[];
  credentialSlots?: CredentialSlotDescriptor[];
  /** Device support metadata — license, help URL, built-in markdown docs path,
   *  and the standardized supported-device matrix (profiles → capabilities +
   *  intents with gating conditions). See deviceSupport.ts. */
  deviceSupport?: DeviceSupport;
  /** Identity-provider plugins (basic-auth): flow + optional redirectUrl. */
  identityProvider?: { flow: string; redirectUrl?: string };
  /** Secrets-provider plugins: algorithm + the secret types served. */
  secretsProvider?: Record<string, unknown>;
  /** File-repo storage backends: backend kind (e.g. 'local-filesystem'). The API
   *  broker only needs the `fileRepo` capability on /discover; this field is
   *  informational for the webapp's repo picker. */
  fileRepo?: Record<string, unknown>;
}

export interface PluginServerOptions {
  identity: PluginIdentity;
  /** Log tag for console output (e.g. "icmp-plugin"). Defaults to the display name. */
  logTag?: string;
  /** JSON body limit — plugins carrying base64 config backups need '32mb'. Default '100kb' (express default). */
  jsonLimit?: string;
  /** Serve static icon assets at /icons from this directory (plugin-root relative path, e.g. path.join(__dirname, '../../icons')). */
  iconsDir?: string;
  /** Serve static text assets (LICENSE.md, docs/*.md) at /assets from this
   *  directory — the plugin root by default. The API's asset proxy fetches
   *  these for the webapp's license/documentation viewers; only files under
   *  this dir are reachable (express.static containment). */
  assetsDir?: string;
  /** Extra /discover fields (see DiscoveryExtras). May be a function for dynamic catalogs. */
  discovery?: DiscoveryExtras | (() => DiscoveryExtras);
  /** Extra custom self-metrics gauges, merged into GET /metrics (see createSelfMetrics). */
  selfMetricsExtra?: Record<string, number> | (() => Record<string, number>);
  /** Optional WebSocket upgrade handler (e.g. makeConsoleUpgrade for the SSH console,
   *  capability 'sshConsole'). Attached to BOTH the plain and TLS servers on
   *  listen(); non-matching paths are dropped by the handler itself. */
  wsUpgrade?: (req: IncomingMessage, socket: Duplex, head: Buffer) => void;
  /**
   * Enable mTLS (ACME enrollment against UNM's step-ca). Defaults to
   * `process.env.UNM_TLS === '1'`. When enabled the server starts on plain
   * HTTP immediately and swaps in-place to a TLS listener once enrollment
   * succeeds (retries every 60s until it does — the fleet stays reachable on
   * plain HTTP if the CA is down). The API's pluginHttp factory tries https
   * first, so no advertised-endpoint change is needed.
   */
  tlsEnabled?: boolean;
}

export interface PluginServer {
  app: Express;
  identity: PluginIdentity;
  /** True once the TLS listener is live (mTLS). False while plain HTTP only. */
  readonly tlsLive: boolean;
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
    ...(Array.isArray(e.requiredSecretTypes) && e.requiredSecretTypes.length > 0 ? { requiredSecretTypes: e.requiredSecretTypes } : {}),
    ...(e.metrics !== undefined ? { metrics: e.metrics } : {}),
    ...(e.options !== undefined ? { options: e.options } : {}),
    ...(e.actions !== undefined ? { actions: e.actions } : {}),
    ...(Array.isArray(e.quickActions) && e.quickActions.length > 0 ? { quickActions: e.quickActions } : {}),
    ...(e.modules !== undefined ? { modules: e.modules } : {}),
    ...(e.iconUrl !== undefined ? { iconUrl: e.iconUrl } : {}),
    ...(e.deviceModels !== undefined ? { deviceModels: e.deviceModels } : {}),
    ...(e.credentialSlots !== undefined ? { credentialSlots: e.credentialSlots } : {}),
    ...(e.deviceSupport !== undefined ? { deviceSupport: e.deviceSupport } : {}),
    ...(e.identityProvider !== undefined ? { identityProvider: e.identityProvider } : {}),
    ...(e.secretsProvider !== undefined ? { secretsProvider: e.secretsProvider } : {}),
    ...(e.fileRepo !== undefined ? { fileRepo: e.fileRepo } : {}),
  };
}

/** Closes a listener, draining idle keep-alives first; force-kills after 5s. */
function closeServer(server: http.Server | tls.Server): Promise<void> {
  return new Promise((resolve) => {
    let done = false;
    const finish = (): void => {
      if (!done) {
        done = true;
        resolve();
      }
    };
    server.close(finish);
    (server as unknown as { closeIdleConnections?: () => void }).closeIdleConnections?.();
    const t = setTimeout(() => {
      // Stuck active connections — destroy them so the port frees up.
      (server as unknown as { closeAllConnections?: () => void }).closeAllConnections?.();
      finish();
    }, 5000);
    (t as unknown as { unref?: () => void }).unref?.();
  });
}

/**
 * Background mTLS enrollment loop. Starts plain HTTP; on each successful
 * ensureTlsIdentity() closes the current listener and re-opens it as a TLS
 * server (requestCert + rejectUnauthorized — full mTLS). Retries every 60s
 * while enrollment fails, so a downed CA never takes the plugin offline.
 */
function startTlsEnrollment(
  app: Express,
  port: number,
  logTag: string,
  wsUpgrade?: (req: IncomingMessage, socket: Duplex, head: Buffer) => void,
  onLiveChange?: (live: boolean) => void,
): { isLive(): boolean } {
  let live = false;
  let currentServer: http.Server | tls.Server | null = null;
  let stopRenewal: (() => void) | null = null;
  let loadedKeyPem: string | null = null;
  let loadedCertPem: string | null = null;
  // Joined identifier set the currently-live leaf was enrolled for — used to
  // detect an endpoint rename (ADVERTISED_ENDPOINT host change) at runtime.
  let servedFor = '';

  const attachUpgrade = (s: http.Server | tls.Server): void => {
    if (wsUpgrade) s.on('upgrade', wsUpgrade);
  };

  const swapToTls = async (identity: TlsIdentity): Promise<void> => {
    if (currentServer) await closeServer(currentServer);
    // tls.Server emits 'request' exactly like an http.Server — mount the same
    // express app on it. The cast is type-level only; runtime behavior is
    // identical to `app.listen()` over TLS.
    const server = tls.createServer({
      key: identity.keyPem,
      cert: identity.certChainPem,
      ca: [identity.caBundlePem],
      requestCert: true,
      rejectUnauthorized: true,
    });
    (server as unknown as http.Server).on('request', app);
    attachUpgrade(server);
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, () => resolve());
    });
    currentServer = server;
    live = true;
    loadedKeyPem = identity.keyPem;
    loadedCertPem = identity.certChainPem;
    onLiveChange?.(true);
    console.log(`[${logTag}] mTLS listener live on :${port} (leaf valid to ${identity.notAfter.toISOString()})`);
  };

  const enrollOnce = async (): Promise<void> => {
    try {
      // Resolve the desired identifiers fresh each pass so an endpoint rename
      // (ADVERTISED_ENDPOINT host change) is picked up without a restart: if the
      // new name isn't covered by the existing leaf, ensureTlsIdentity re-enrolls.
      const ids = resolveTlsIdentifiers();
      const identity = await ensureTlsIdentity({ identity: logTag, identifiers: ids });
      const idKey = ids.join('\u0000');
      // Swap when the TLS listener isn't up yet OR the on-disk material changed.
      if (!live || identity.keyPem !== loadedKeyPem || identity.certChainPem !== loadedCertPem) {
        await swapToTls(identity);
        stopRenewal?.();
        stopRenewal = scheduleTlsRenewal(identity, () => void enrollOnce(), (m) => console.log(`[${logTag}] [tls] ${m}`));
      } else if (servedFor !== idKey) {
        // Identifiers changed but the existing leaf already covers them — no cert
        // swap needed; log so endpoint drift is visible.
        console.log(`[${logTag}] [tls] identifiers now [${ids.join(', ')}] (existing leaf still valid)`);
      }
      servedFor = idKey;
    } catch (err) {
      console.warn(`[${logTag}] mTLS enrollment failed (staying on plain HTTP):`, (err as Error).message);
    }
  };

  void enrollOnce().then(() => {
    // If the first pass left us plain (CA down), keep retrying every 60s — and
    // re-check whenever the desired identifier set drifts from what we serve.
    const timer = setInterval(() => {
      if (!live || servedFor !== resolveTlsIdentifiers().join('\u0000')) void enrollOnce();
    }, 60_000);
    (timer as unknown as { unref?: () => void }).unref?.();
  });

  return { isLive: () => live };
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
  const tlsEnabled = opts.tlsEnabled ?? process.env.UNM_TLS === '1';

  // Live TLS state — surfaced in /discover so the API's pluginHttp factory can
  // prefer https without probing. Updated by startTlsEnrollment on swap.
  const tlsState: { live: boolean } = { live: false };
  const discoveryWrapped: DiscoveryExtras | (() => DiscoveryExtras) = () => ({
    ...(typeof opts.discovery === 'function' ? opts.discovery() : (opts.discovery ?? {})),
    ...(tlsEnabled ? { tlsLive: tlsState.live } : {}),
  });

  const app = express();
  app.use(cors());
  app.use(express.json({ limit: opts.jsonLimit }));

  if (opts.iconsDir) {
    // dist/src/../../icons = <plugin root>/icons (plugins compile with rootDir ".").
    app.use('/icons', express.static(path.join(opts.iconsDir)));
  }

  if (opts.assetsDir) {
    // Static text assets (LICENSE.md, docs/*.md) — proxied by the API's
    // GET /plugins/:id/asset route for the webapp's markdown viewers.
    app.use('/assets', express.static(path.join(opts.assetsDir), { index: false }));
  }

  // Self-metrics: the UNM API polls GET /metrics per plugin and persists the
  // samples for the webapp's per-plugin health view. Mounted automatically —
  // plugins need zero code for CPU/memory/lag/poll-duration visibility.
  // The plugin logger (if any) registers its queue depth with the self-metrics
  // module itself — no wiring needed here.
  const selfMetrics = createSelfMetrics({
    extra: opts.selfMetricsExtra,
  });

  app.get('/healthz', (_req: Request, res: Response) => {
    res.status(200).json({ status: 'ok' });
  });

  app.get('/discover', (_req: Request, res: Response) => {
    res.status(200).json(buildDiscoverPayload(identity, discoveryWrapped));
  });

  // Track work requests (/monitoring, /config, /plan): in-flight count,
  // duration + success of the last N. Must be registered BEFORE the routes.
  app.use(selfMetrics.trackMiddleware);
  app.get('/metrics', selfMetrics.handler);

  return {
    app,
    identity,
    get tlsLive(): boolean {
      return tlsState.live;
    },
    listen() {
      return new Promise<number>((resolve) => {
        const server = app.listen(identity.port, () => {
          console.log(`[${logTag}] listening on port ${identity.port}${tlsEnabled ? ' (mTLS enrollment in progress)' : ''}`);
          startMdnsAdvertising(identity, logTag);
          resolve(identity.port);
        });
        // WebSocket support (SSH console): the handler decides per-path whether to
        // take the upgrade; everything else is dropped so plain HTTP is unaffected.
        if (opts.wsUpgrade) {
          server.on('upgrade', opts.wsUpgrade);
        }
        // Keep a reference so the process stays alive and tests can close it.
        (app as unknown as { __server?: typeof server }).__server = server;

        if (tlsEnabled) {
          startTlsEnrollment(app, identity.port, logTag, opts.wsUpgrade, (live) => {
            tlsState.live = live;
          });
        }
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

/**
 * Express-4-safe handler factory for the GET /state endpoint (capability
 * 'deviceState'). Express 4 does NOT catch rejections from async handlers — an
 * unhandled rejection crashes the process, so this wraps the plugin's state
 * function in a try/catch and answers with a JSON error envelope instead.
 *
 * The callback receives BOTH the parsed body (deviceId/managementAddress/
 * credentials) AND the raw request — plugins need `req` to read per-device
 * settings from the `x-unm-settings` header via readSettings().
 *
 * Success: 200 + DeviceStateResponse ({ collectedAt, sections }).
 * Failure: 502 + { error } (device unreachable / not recognized / auth failure).
 */
export function stateHandler(
  fn: (body: StateRequestBody, req: express.Request) => Promise<DeviceStateResponse>,
  logTag?: string
): express.RequestHandler {
  return async (req, res) => {
    try {
      const body = req.body as StateRequestBody;
      if (!body || typeof body.managementAddress !== 'string' || !body.credentials) {
        res.status(400).json({ error: 'Invalid state request: managementAddress + credentials required' });
        return;
      }
      const state = await fn(body, req);
      res.status(200).json(state);
    } catch (err) {
      console.error(`[${logTag ?? 'plugin'}] /state failed:`, err instanceof Error ? err.message : err);
      res.status(502).json({ error: err instanceof Error ? err.message : String(err) });
    }
  };
}

/**
 * Express-4-safe handler factory for the POST /probe endpoint (capability
 * 'probe'). Same contract as stateHandler but for SHORT-CYCLE live telemetry:
 * the webapp polls on demand (1–5 s) through the API's generic broker. The
 * callback receives the parsed body (deviceId/managementAddress/credentials +
 * `keys` — which probe keys the caller wants) AND the raw request (for
 * readSettings()). Keep it CHEAP: reuse cached connections, one read-only
 * command, no long walks — a page may poll every few seconds.
 *
 * Success: 200 + ProbeResponseBody ({ collectedAt, metrics }).
 * Failure: 502 + { error } (device unreachable / auth failure / key unsupported).
 */
export function probeHandler(
  fn: (body: ProbeRequestBody, req: express.Request) => Promise<ProbeResponseBody>,
  logTag?: string
): express.RequestHandler {
  return async (req, res) => {
    try {
      const body = req.body as ProbeRequestBody;
      if (!body || typeof body.managementAddress !== 'string' || !body.credentials) {
        res.status(400).json({ error: 'Invalid probe request: managementAddress + credentials required' });
        return;
      }
      const result = await fn(body, req);
      res.status(200).json(result);
    } catch (err) {
      console.error(`[${logTag ?? 'plugin'}] /probe failed:`, err instanceof Error ? err.message : err);
      res.status(502).json({ error: err instanceof Error ? err.message : String(err) });
    }
  };
}

/**
 * Express-4-safe handler factory for the POST /quick-action endpoint (capability
 * 'quickActions'). The API brokers a click on one of this plugin's advertised
 * quick actions: it resolves kind:'url' entries into the device's management web-UI
 * URL. The PLUGIN owns all URL knowledge — scheme, path and the configured web-UI
 * port (read via readSettings() from the `x-unm-settings` header) — so the API and
 * webapp never assemble appliance URLs themselves.
 *
 * The callback receives the parsed body (deviceId/managementAddress/actionId) AND the
 * raw request. It must look up `actionId` in its own quickActions list, build the URL
 * with buildWebUiUrl() and return { url }. Unknown ids or non-url kinds → throw.
 *
 * Success: 200 + QuickActionResponseBody ({ url }).
 * Failure: 502 + { error } (unknown action / bad address).
 */
export function quickActionHandler(
  fn: (body: QuickActionRequestBody, req: express.Request) => Promise<QuickActionResponseBody>,
  logTag?: string
): express.RequestHandler {
  return async (req, res) => {
    try {
      const body = req.body as QuickActionRequestBody;
      if (!body || typeof body.managementAddress !== 'string' || !body.actionId) {
        res.status(400).json({ error: 'Invalid quick-action request: managementAddress + actionId required' });
        return;
      }
      const result = await fn(body, req);
      if (!result || typeof result.url !== 'string' || !/^https?:\/\//i.test(result.url)) {
        res.status(502).json({ error: 'Plugin returned an invalid URL for the quick action' });
        return;
      }
      res.status(200).json(result);
    } catch (err) {
      console.error(`[${logTag ?? 'plugin'}] /quick-action failed:`, err instanceof Error ? err.message : err);
      res.status(502).json({ error: err instanceof Error ? err.message : String(err) });
    }
  };
}

/**
 * Express-4-safe handler factory for the POST /filesystem endpoint (capability
 * 'filesystem'). Same contract as probeHandler but for a generic, root-scoped file
 * manager over SFTP: the webapp's Storage page (dataset contents) and Containers
 * page (volume mounts) drive it through the API broker. The callback receives the
 * parsed body (deviceId/managementAddress/credentials + op/path/context) AND the raw
 * request (for readSettings()). The plugin maps `context` onto an SFTP root and confines
 * every path to it — see sftp.ts resolvePath().
 *
 * Success: 200 + FilesystemResponseBody ({ collectedAt, … }).
 * Failure: 502 + { error } (device unreachable / auth failure / bad context).
 */
export function filesystemHandler(
  fn: (body: FilesystemRequestBody, req: express.Request) => Promise<FilesystemResponseBody>,
  logTag?: string
): express.RequestHandler {
  return async (req, res) => {
    try {
      const body = req.body as FilesystemRequestBody;
      if (!body || typeof body.managementAddress !== 'string' || !body.credentials || typeof body.op !== 'string') {
        res.status(400).json({ error: 'Invalid filesystem request: managementAddress + credentials + op required' });
        return;
      }
      const result = await fn(body, req);
      res.status(200).json(result);
    } catch (err) {
      console.error(`[${logTag ?? 'plugin'}] /filesystem failed:`, err instanceof Error ? err.message : err);
      res.status(502).json({ error: err instanceof Error ? err.message : String(err) });
    }
  };
}
