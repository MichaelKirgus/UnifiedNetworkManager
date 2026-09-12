import path from 'path';
import { Request, Response } from 'express';
import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  INVENTORY_INTERVAL_MS,
  clampInt,
  createNotifier,
  createPluginLogger,
  createPluginServer,
  gaugeMetric,
  pickNumber,
  pickString,
  readSettings,
  resolvePluginIdentity,
  stateHandler,
  probeHandler,
  filesystemHandler,
  type FilesystemRequestBody,
  type FilesystemResponseBody,
  createSftpPool,
  textMetric,
  validateInput,
  PortRow,
  PlanRequest,
  StateRequestBody,
  ProbeRequestBody,
  resolveSshCredentials,
  makeConsoleUpgrade,
  createTerminalPool,
  createPinningGuard,
  dynamicSshHostVerifier,
  resolveHttpsPort,
  resolveHttpPort,
  resolveSshPort,
  TtlCache,
  collectDeviceCertificates,
  parseProbeTarget,
  CertificateRow,
  type SshCredentials,
  type SshTerminalSession,
} from '@unm/plugin-sdk';
import { TruenasClient, TruenasCredentials, TruenasRpcError, TruenasTransport } from './client/truenasClient';
import {
  collectProbeStates,
  collectProbeStats,
  collectProbeVmStates,
  ensureEnrichment,
  ensureVmEnrichment,
  getEnrichment,
  getVmEnrichment,
  monitoringInFlight,
  normalizeVmDevice,
  setHostSshPort,
  serviceNetDetails,
  sshHostOf,
  sshPool,
  type ContainerStat,
  type ContainerVolume,
  type DockerContainerInfo,
  type ProbeContainerState,
  type ProbeContainerStat,
  type ProbeVmState,
  type ServiceNetDetail,
} from './enrich';
import { alertDedupeKey, registry as actionRegistry, TruenasActionContext } from './actions';
import { buildTruenasState } from './state';
import { buildPlan, PlanningError } from './plan';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000009';
export const PLUGIN_NAME = 'TrueNAS Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:instanceId`) so the API registers them as separate plugins.
 * `PLUGIN_DISPLAY_NAME` optionally overrides the advertised name; without it,
 * the instance id is appended: "TrueNAS Plugin (site-a)". Unset = single-instance behavior.
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  // 0.5.0 — live PROBE endpoint (POST /probe, capability 'probe'): short-cycle
  // per-container CPU/RAM/I-O for the Containers page's on-demand polling
  // (1–5 s), served from ONE `docker stats --no-stream` over the shared SSH
  // pool. On top of 0.4.0 VM collection + the 0.3.0 SSH data path.
  // 0.6.0 — app-store actions: catalog.templates.list + template.details.read
  // (read-only, drive the Containers page's Create-app dialog) and
  // containers.install (app.create job — catalog template or custom compose).
  // 0.6.1 — template.details.read also returns a `groups` section layout
  // (TrueNAS question groups + dict sub-forms as their own sections) so the
  // dialog can render long config forms as collapsible sections.
  // 0.6.2 — compose.config.read now answers for CATALOG apps too: instead of an
  // error it returns catalog_app/train/values (the saved template config), which
  // drives the Create-app dialog's duplicate/clone flow.
  // 0.6.3 — containers.logs.read: per-container log output via `docker logs` over
  // the shared SSH pool (TrueNAS 26 has NO app/container-log RPC — verified
  // against the full core.get_methods catalog). Requires a bound ssh slot.
  // 0.6.4 — probe key `containerStates` now reports REAL per-container docker
  // states (`docker ps -a`) instead of just the running set, and honors an
  // optional `names` selection so a page can watch specific containers at a
  // tighter cadence (e.g. right after start/stop).
  // 0.7.0 — VM lifecycle + NIC actions for the VMs page: vms.start / stop /
  // kill / restart / suspend / resume / delete (vm.* RPC, names resolved via
  // vm.query, idempotent per-name outcomes) plus vms.nic-choices (read-only
  // bridge/MACVLAN list), vms.nic-attach and vms.nic-detach. GENERIC contract:
  // any future hypervisor plugin implementing the same action ids gets the
  // webapp's VM row/bulk actions for free.
  // 0.8.0 — Storage lifecycle actions for the Storage page: storage.scrub
  // (pool.scrub), storage.snapshot (pool.snapshot.create + optional retention
  // cleanup of prior `unm-*` snapshots), storage.quota-set (pool.dataset.update
  // quota), storage.mount / storage.unmount (pool.dataset.mount/unmount) and
  // storage.delete (pool.dataset.delete, destructive). GENERIC contract: any
  // future storage plugin implementing these ids gets the webapp's row + bulk
  // actions for free.
  // 0.8.1 — pool.dataset.query (Storage-page dataset inventory) now runs with a
  // dedicated 20 s per-call timeout: on slow/degraded appliances it can exceed
  // the default 5 s and previously timed out, silently dropping ALL datasets of
  // that device from the Storage page (pools showed no children).
  // 0.9.0 — filesystem browser (POST /filesystem, capability 'filesystem'): a
  // generic, root-scoped SFTP file manager for the webapp's Storage page (browse
  // dataset contents) and Containers page (browse container volume mounts). Ops:
  // list/read/stat/write/mkdir/rmdir/unlink/rename. Paths are confined to the
  // scoped root (a dataset mountpoint or a volume's host source) — requires a
  // bound ssh slot. GENERIC contract: any future plugin serving /filesystem gets
  // the webapp's file browser for free.
  // 0.10.0 — interactive SSH console (/console WebSocket, capability 'sshConsole'):
  // a full xterm.js terminal in the web UI that talks to the appliance like PuTTY
  // would (TrueNAS' own web console does exactly this). Two attach modes via the
  // plugin-owned `context`: { kind: 'host' } = login shell on the host, and
  // { kind: 'container', name?, service? } = `docker exec -it` into a container
  // (the docker name is resolved live from `docker ps`). Requires a bound ssh slot.
  // GENERIC contract: any future plugin serving /console with the SDK's
  // makeConsoleUpgrade gets the webapp's Shell button + container consoles for free.
  version: '0.10.0',
  vendors: ['truenas'],
  capabilities: ['monitoring', 'configuration', 'planning', 'deviceState', 'ssh', 'probe', 'filesystem', 'sshConsole'],
});

/**
 * The options this plugin exposes for configuration. Declared in /discover so
 * the API can persist + validate user-set values and the webapp can render a
 * generic form — this plugin never stores settings itself; it receives them on
 * every call via the `x-unm-settings` header (see readSettings()).
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'transport',
    label: 'Transport',
    type: 'string' as const,
    default: 'auto',
    pattern: '^(auto|http|https)$',
    description:
      'How to reach the appliance. auto = HTTPS with self-signed certificates accepted (default — TrueNAS ships a self-signed cert out of the box). https = force TLS. http = plaintext HTTP.',
  },
  {
    key: 'httpsPort',
    label: 'HTTPS port',
    type: 'integer' as const,
    default: 443,
    min: 1,
    max: 65535,
    description:
      "TCP port of the appliance's HTTPS management UI / WebSocket API. Used when the management address carries no explicit port (an explicit https://host:<port> always wins). Also the port certificate pinning verifies against.",
  },
  {
    key: 'httpPort',
    label: 'HTTP port',
    type: 'integer' as const,
    default: 80,
    min: 1,
    max: 65535,
    description: "TCP port of the appliance's plain-HTTP management UI (used when transport is http or auto falls back to it).",
  },
  {
    key: 'sshPort',
    label: 'SSH port',
    type: 'integer' as const,
    default: 22,
    min: 1,
    max: 65535,
    description:
      "TCP port of the appliance's SSH daemon. Used for container/VM enrichment, live probes, the filesystem browser and the interactive console when the management address carries no explicit port.",
  },
  {
    key: 'timeoutMs',
    label: 'Request timeout (ms)',
    type: 'integer' as const,
    default: 5000,
    min: 500,
    max: 60000,
    description: 'Per-request timeout for TrueNAS API calls. The whole poll must fit the API\'s ~30 s monitoring budget (slow inventory RPCs like pool.dataset.query get a dedicated 20 s per-call timeout).',
  },
  {
    key: 'apiKeyUsername',
    label: 'API key owner username',
    type: 'string' as const,
    default: 'root',
    description:
      "Username that owns the bound API key. TrueNAS 26+ requires it for API-key login (auth.login_ex API_KEY_PLAIN). Only used when an API key slot is bound.",
  },
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (poll failures, auth errors) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
  },
  {
    key: 'notifyAlerts',
    label: 'Mirror alerts to notification center',
    type: 'boolean' as const,
    default: true,
    description:
      'Push active TrueNAS alerts (alert.list) into the UNM notification center. Alerts that disappear are auto-resolved.',
  },
  {
    key: 'collectApps',
    label: 'Enable App/Container collection',
    type: 'boolean' as const,
    default: true,
    description:
      'Collect installed Apps (app.query) and their containers for the Containers page — including background enrichment (per-app static IPs via app.config, real MACs/IPs/start times via docker inspect over SSH). Disable on hosts whose containers are monitored by another plugin (e.g. the generic Docker plugin): no container RPC traffic is sent to the appliance and previously collected rows are cleared.',
  },
  {
    key: 'collectVms',
    label: 'Enable VM collection',
    type: 'boolean' as const,
    default: true,
    description:
      'Collect virtual machines (vm.query) for the VMs page — including their NIC MAC addresses (inserted into the Hosts page with source "VM") and live guest IPs via `virsh domifaddr` over SSH when an ssh slot is bound. Disable on hosts whose VMs are monitored by another plugin: no vm.query RPC traffic is sent to the appliance and previously collected rows are cleared.',
  },
];

// ---------------------------------------------------------------------------
// Metric descriptors — static part advertised in /discover. The webapp renders
// from these; dynamic ones (pools table rows, error text) are echoed per poll.
// ---------------------------------------------------------------------------

const POOL_TABLE_COLUMNS = ['name', 'status', 'size', 'used', 'free', 'scrub'];

function buildMetricDescriptors(): MetricDescriptor[] {
  return [
    gaugeMetric('system.cpuLoad', 'CPU Load (1-min avg)', { unit: '%', min: 0, max: 100, group: 'System', summary: true }),
    { key: 'system.memoryTotal', label: 'Memory Total', type: 'number', visualization: 'text', unit: 'bytes', format: 'bytes', group: 'System' },
    gaugeMetric('storage.poolUsedPct', 'Pool Usage (all pools)', { unit: '%', min: 0, max: 100, group: 'Storage', summary: true }),
    textMetric('system.version', 'Version', { group: 'System', intervalMs: INVENTORY_INTERVAL_MS }),
    textMetric('system.hostname', 'Hostname', { group: 'System', intervalMs: INVENTORY_INTERVAL_MS }),
    textMetric('system.model', 'Model', { group: 'System', intervalMs: INVENTORY_INTERVAL_MS }),
    textMetric('system.serialNumber', 'Serial Number', { group: 'System', intervalMs: INVENTORY_INTERVAL_MS }),
    { key: 'system.uptime', label: 'Uptime', type: 'number', visualization: 'text', unit: 's', format: 'duration', group: 'System', intervalMs: INVENTORY_INTERVAL_MS },
  ];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Human-readable byte size ("8.0 TB") for pre-formatted table cells. */
function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

/** Seconds → "15d 4h" / "3h 12m" / "45s" (duration format the webapp understands). */
function formatUptime(totalSeconds: number): string {
  if (!Number.isFinite(totalSeconds) || totalSeconds < 0) return '—';
  const d = Math.floor(totalSeconds / 86400);
  const h = Math.floor((totalSeconds % 86400) / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${Math.floor(totalSeconds)}s`;
}

/** Extracts the effective transport option from injected settings. */
function transportOf(settings: Record<string, unknown>): TruenasTransport {
  const t = settings.transport;
  return typeof t === 'string' && ['auto', 'http', 'https'].includes(t) ? (t as TruenasTransport) : 'auto';
}

/** Extracts the configured endpoint ports from injected settings (defaults 443/80). */
function portsOf(settings: Record<string, unknown>): { httpsPort?: number; httpPort?: number } {
  const hp = resolveHttpsPort(settings.httpsPort);
  const tp = resolveHttpPort(settings.httpPort);
  return { httpsPort: hp !== 443 ? hp : undefined, httpPort: tp !== 80 ? tp : undefined };
}

/** Extracts the configured SSH port from injected settings (default 22). */
function sshPortOf(settings: Record<string, unknown>): number {
  return resolveSshPort(settings.sshPort);
}

/**
 * Per-host client cache — the WebSocket transport keeps ONE authenticated
 * socket per appliance, so we must NOT create a fresh client (and thus a new
 * handshake + login exchange) on every 30 s poll. Keyed by host+transport+port.
 */
const clientCache = new Map<string, TruenasClient>();

// --- Certificates (capability: cross-device Certificates page) -----------------
// Certificate rows are probed on a slower cadence than the inventory RPCs — they
// change rarely and each probe opens fresh TLS/SSH connections to the appliance.
const CERT_TTL_MS = 10 * 60_000;
const certCache = new TtlCache<CertificateRow[]>({ isFresh: (v) => Array.isArray(v) });

// Certificate pinning — one process-wide guard for every credential-bearing
// entry point. Strict mode + a known fingerprint MISMATCH throws before any
// credentials are transmitted; unknown endpoints are TOFU-accepted and land in
// UNM's inventory via the `certificates` metric.
const assertPinned = createPinningGuard();

/** TEMP DEBUG (log-once): hosts+methods whose storage-extra outcome was already logged. */
const storageDebugLogged = new Set<string>();

function getClient(
  host: string,
  transport: TruenasTransport,
  timeoutMs: number,
  ports?: { httpsPort?: number; httpPort?: number }
): TruenasClient {
  const key = `${host}|${transport}|${ports?.httpsPort ?? ''}|${ports?.httpPort ?? ''}`;
  let c = clientCache.get(key);
  if (!c) {
    c = new TruenasClient(host, transport, timeoutMs, ports);
    clientCache.set(key, c);
  }
  return c;
}

/** Human-readable message from an unknown rejection reason. */
function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

/**
 * Resolves the credentials for one poll. The assignment's primary secret is a
 * `usernamePassword` type (fields at top level of `credentials`); an optional
 * bound credential slot named `apiKey` (secret type `apiKey`) takes precedence
 * when set — TrueNAS API keys are the vendor-recommended integration credential
 * and avoid storing appliance passwords. TrueNAS 26+ requires the key's owner
 * username for API-key login; it comes from the `apiKeyUsername` option.
 */
function resolveCredentials(
  creds: Record<string, unknown> | undefined,
  apiKeyUsername: string
): { creds?: TruenasCredentials; error?: string } {
  const c = creds && typeof creds === 'object' ? creds : {};
  // Optional API-key slot (decrypted fields arrive under credentials.slots.apiKey).
  const slots = c['slots'] as Record<string, Record<string, string>> | undefined;
  const keySlot = slots?.['apiKey'];
  if (keySlot && typeof keySlot === 'object') {
    const apiKey = pickString(keySlot, ['apiKey']);
    if (apiKey) return { creds: { kind: 'apiKey', username: apiKeyUsername || undefined, apiKey } };
  }
  // Primary username/password secret.
  const username = pickString(c, ['username']);
  const password = pickString(c, ['password']);
  if (username && password) return { creds: { kind: 'password', username, password } };
  return { error: 'No credentials — assign a Username/Password secret (or an API key slot) to this device' };
}

// ---------------------------------------------------------------------------
// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled().
// ---------------------------------------------------------------------------
const logger = createPluginLogger(identity);

// Notification-center pushes for appliance-level events (alert.list diffing).
// Gated per call by the `notifyAlerts` option, same pattern as logging.
const notifier = createNotifier(identity);

/**
 * Per-host snapshot of the last-seen ACTIVE alerts — used to diff alert.list
 * across polls so each alert notifies ONCE (dedupeKey upsert keeps it live)
 * and is resolved when it disappears. Keyed by host; values are dedupe keys.
 */
const knownAlertsByHost = new Map<string, Set<string>>();

// ---------------------------------------------------------------------------
// Interactive SSH console (/console WebSocket, capability 'sshConsole').
// The webapp's DeviceDetail "Shell" button and the Containers page per-container
// consoles drive this: a full xterm.js terminal that talks to the appliance like
// PuTTY would. Two attach modes via the plugin-owned `context`:
//   { kind: 'host' }                        → login shell on the host (openShell)
//   { kind: 'container', name?, service? }  → docker exec -it into a container;
//                                             the docker NAME is resolved live from
//                                             `docker ps` against candidate names
//                                             (the webapp knows compose service
//                                             names, not necessarily docker names).
// Requires a bound ssh slot. The SDK's makeConsoleUpgrade handles the WS protocol
// (binary = raw I/O, text = control JSON); this plugin only maps context → session.
// ---------------------------------------------------------------------------

/** Process-wide terminal connection pool — one authenticated SSH conn per host+user,
 *  shared by ALL concurrent consoles to that appliance (each console opens its own channel). */
const termPool = createTerminalPool();
process.on('SIGTERM', () => termPool.closeAll());
process.on('SIGINT', () => termPool.closeAll());

/** Opens an interactive session for one console hello frame. */
async function openConsoleSession(
  host: string,
  sshCreds: SshCredentials,
  context: Record<string, unknown> | undefined,
  sshPort = 22
): Promise<SshTerminalSession> {
  // UNM certificate pinning — resolves the freshest trusted fingerprint at
  // handshake time (pooled sessions outlive single requests). A mismatch
  // rejects the handshake BEFORE any auth message is sent.
  const conn = await termPool.get(host, sshPort, sshCreds, { hostKeyVerifier: dynamicSshHostVerifier(host, sshPort) });
  const ctx: Record<string, unknown> = context ?? {};
  const kind = typeof ctx['kind'] === 'string' ? (ctx['kind'] as string) : '';

  if (kind === 'container') {
    // Candidate docker names: explicit `name` first, then the compose service name
    // and the `<app>-<service>` convention TrueNAS uses for multi-container apps.
    const candidates = [pickString(ctx, ['name']), pickString(ctx, ['service'])].filter((c): c is string => !!c);
    const svc = pickString(ctx, ['service']);
    if (svc) {
      // The webapp sends the app name too when it differs — try `<app>-<svc>` as well.
      const app = pickString(ctx, ['app']);
      if (app && app !== svc) candidates.push(`${app}-${svc}`);
    }

    // Resolve the real docker name with ONE `docker ps -a` over the plugin's shared
    // (non-PTY) exec pool — clean output, no terminal artifacts. The dynamic host-key
    // verifier pins the SSH handshake against UNM's inventory before auth.
    const probeClient = await sshPool.get(host, sshPort, sshCreds, { hostKeyVerifier: dynamicSshHostVerifier(host, sshPort) });
    const listingRes = await probeClient.exec(`docker ps -a --format '{{.Names}}' 2>/dev/null`, sshCreds);
    const names = new Set(listingRes.stdout.split('\n').map((l) => l.trim()).filter(Boolean));
    const dockerName = candidates.find((c) => names.has(c)) ?? null;
    if (!dockerName) {
      throw new Error(`Container not found on the appliance (tried: ${candidates.join(', ') || 'no name given'})`);
    }

    // `docker exec -it <name> /bin/sh` — the outer SSH PTY is what makes docker's
    // `-t` work; resize propagates through both layers. /bin/sh exists in (nearly)
    // every image that ships a shell at all; images without one surface docker's
    // own error on the terminal, which is the honest answer.
    return conn.openExec(`docker exec -it ${dockerName} /bin/sh`, sshCreds);
  }

  // Default (and kind: 'host') — a plain login shell on the appliance.
  return conn.openShell(sshCreds);
}

/** The WebSocket upgrade handler createPluginServer attaches to its HTTP server. */
const consoleUpgrade = makeConsoleUpgrade({
  expectedApiKey: () => process.env.PLUGIN_API_KEY ?? null,
  path: '/console',
  onOpen: async (hello) => {
    const host = sshHostOf(hello.managementAddress);
    if (!host) throw new Error('Missing management address');
    // Only the bound ssh slot counts — the primary username/password must NOT be reused.
    const sshCreds = resolveSshCredentials(hello.credentials as Record<string, unknown> | undefined, { slotOnly: true });
    if (!sshCreds) throw new Error('No SSH credential bound — console unavailable');
    // Configured SSH port (plugin option `sshPort`, default 22) — delivered by
    // the API in the console hello frame so a per-device override is honored.
    const sshPort = resolveSshPort(hello.settings?.['sshPort']);
    setHostSshPort(host, sshPort);
    return openConsoleSession(host, sshCreds, hello.context, sshPort);
  },
});

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'ix-truenas-plugin',
  // Interactive SSH console (capability 'sshConsole') — WS upgrades for /console.
  wsUpgrade: consoleUpgrade,
  // Filesystem writes (POST /filesystem op=write) carry base64 file contents —
  // allow up to ~10 MiB of inbound JSON so a user can upload files that size.
  jsonLimit: '12mb',
  // Static icon assets, advertised in /discover and fetched by the API's icon proxy.
  iconsDir: path.join(__dirname, '../../icons'),
  discovery: {
    // Primary secret type for device credentials (username/password login).
    requiredSecretType: 'usernamePassword',
    // Optional second credential: a TrueNAS API key used INSTEAD of the
    // username/password when bound to this slot. The webapp renders slot
    // selectors automatically from this descriptor.
    credentialSlots: [
      {
        name: 'apiKey',
        secretType: 'apiKey',
        required: false,
        description:
          'Optional TrueNAS API key — used instead of username/password when set (recommended). TrueNAS 26+ also needs the owner username from the "API key owner username" option.',
      },
      {
        name: 'ssh',
        secretTypes: ['usernamePassword', 'sshKeyPair'],
        required: false,
        description:
          'Optional SSH access for per-container details (real MAC addresses, live IPs and start times via docker inspect), the filesystem browser (browse/edit dataset contents + container volume mounts over SFTP) AND the interactive web console (a full shell on the host or inside a container — like TrueNAS\' own web terminal). Unbound = containers keep showing compose-config data only and the Browse/Shell buttons stay hidden.',
      },
    ],
    metrics: buildMetricDescriptors(),
    options: PLUGIN_OPTIONS,
    // The full action catalog (single-device actions) — persisted by the API
    // and validated against /config dispatches + state action refs.
    actions: actionRegistry.listCatalog(),
    modules: actionRegistry.listModules(),
    iconUrl: '/icons/truenas.svg',
  },
});
const app = server.app;

// ---------------------------------------------------------------------------
// POST /monitoring — the telemetry worker polls every ~30 s (10 s budget).
// Three CORE documented calls in parallel: system.info (CPU load, memory total,
// inventory text) + pool.query (pools table + aggregate usage)
// + alert.list (active alerts drive health). Plus best-effort extras that never
// affect health: interface.query (networks inventory), staticroute.query
// (routes inventory; per-interface `static_routes` fallback on older releases)
// and system.dmidecode_info (board serial/model). All fields are taken from the
// appliance's own API docs — no undocumented surfaces.
// ---------------------------------------------------------------------------

interface PoolRow {
  name: string;
  status: string;
  sizeBytes?: number;
  usedBytes?: number;
  freeBytes?: number;
  scrubState?: string;
}

/** Maps one raw pool.query entry to a normalized row (defensive field reads). */
function parsePool(p: Record<string, unknown>): PoolRow {
  const name = pickString(p, ['name']) ?? 'unknown';
  const statusRaw = pickString(p, ['status', 'state']);
  const sizeBytes = pickNumber(p, ['size', 'size_bytes']);
  const allocBytes = pickNumber(p, ['allocated', 'alloc', 'used', 'used_bytes']);
  const freeBytes = pickNumber(p, ['free', 'available', 'free_bytes']);
  // Scrub/scan state: v26 pool.query returns a `scan` object ({function, state,
  // percentage, ...}); older releases used a string `scrub_state`. Handle both.
  let scrubState: string | undefined;
  const scan = p['scan'];
  if (scan && typeof scan === 'object') {
    const s = pickString(scan as Record<string, unknown>, ['state']);
    const fn = pickString(scan as Record<string, unknown>, ['function']);
    scrubState = s ? `${fn ?? ''} ${s}`.trim() : undefined;
  } else if (typeof p['scrub_state'] === 'string') {
    scrubState = p['scrub_state'];
  }

  return {
    name,
    status: statusRaw ? statusRaw.toUpperCase() : 'UNKNOWN',
    sizeBytes,
    usedBytes: allocBytes ?? (sizeBytes !== undefined && freeBytes !== undefined ? sizeBytes - freeBytes : undefined),
    freeBytes,
    scrubState,
  };
}

/** Maps one raw alert.list entry to its severity (INFO/WARNING/CRITICAL). */
function parseAlertSeverity(a: Record<string, unknown>): string {
  const sev = pickString(a, ['severity', 'level']);
  return sev ? sev.toUpperCase() : 'INFO';
}

// ---------------------------------------------------------------------------
// Storage inventory (cross-device Storage page): `filesystems[]` + `disks[]`
// metrics. Pools come from pool.query (already polled); datasets + zvols from
// pool.dataset.query; physical disks from disk.query (+ boot-pool members via
// boot.get_disks, legacy system.datastore fallback). All three extras are
// best-effort — their failure does NOT count toward health.
// ---------------------------------------------------------------------------

/** One row of the filesystems inventory (shape consumed by the API's ingestInventory). */
interface FsRow {
  name: string;
  type: 'zfs-pool' | 'zfs-dataset' | 'zfs-zvol' | 'usb' | 'other';
  mountpoint?: string | null;
  sizeBytes?: number | null;
  usedBytes?: number | null;
  freeBytes?: number | null;
  status?: string;
  parent?: string | null;
  /** Plugin-specific details (ZFS dataset props, ...) — stored in the API's
   * `extra` JSON column for expandable rows + future config/state endpoints. */
  extra?: Record<string, unknown>;
}

/** One row of the disks inventory (shape consumed by the API's ingestInventory). */
interface DiskRow {
  name: string;
  model?: string | null;
  serial?: string | null;
  capacityBytes?: number | null;
  rotationRate: 'hdd' | 'ssd' | 'flash' | 'unknown';
  health?: string;
  poolName?: string | null;
  /** Plugin-specific details (temperature, power state) — stored in the API's
   * `extra` JSON column for later config/state use. */
  extra?: Record<string, unknown>;
}

/** ZFS dataset properties worth propagating for the Storage page's expandable
 * rows and later config/state endpoints (quota management, mount control, ...). */
const DATASET_EXTRA_PROPS = [
  'used', 'referenced', 'usedbydataset', 'usedbychildren', 'usedbysnapshots',
  'quota', 'reservation', 'volsize',
  'compression', 'compressratio',
  'mounted', 'readonly', 'atime', 'sync', 'xattr',
  'creation', 'origin',
] as const;

/** True for system-managed datasets the UI hides from users (boot pool,
 * sysdataset, apps/container internals) — mirrors middleware's INTERNAL_DATASETS. */
function isInternalDataset(name: string): boolean {
  if (name === '.system' || name.startsWith('.system/')) return true;
  for (const p of ['ix-applications', 'ix-apps']) {
    if (name === p || name.startsWith(`${p}/`) || name.includes(`/${p}`)) return true;
  }
  // Boot pool: `boot-pool` on modern releases, `freenas-boot` on legacy ones.
  for (const bp of ['boot-pool', 'freenas-boot']) {
    if (name === bp || name.startsWith(`${bp}/`)) return true;
  }
  return false;
}

/** Reads one ZFS property from a pool.dataset.query entry. Modern TrueNAS
 * (25.10+/26) FLATTENS properties to top-level keys; older releases nest them
 * under `properties`. Both shapes are handled: {value, parsed?, rawvalue?}
 * objects and plain scalars. Returns the canonical value (`value`) plus a
 * distinct human-readable variant (`parsed`) when one exists — for size props
 * that is bytes + "5 GB", which downstream stores as extra[key] / extra[key+'Parsed']. */
function propOf(d: Record<string, unknown>, key: string): { value?: unknown; parsed?: unknown } | undefined {
  const nested = (d['properties'] as Record<string, unknown> | undefined)?.[key];
  if (nested !== undefined) {
    // Legacy shape — property lives under `properties`. Either an object
    // ({value, parsed?}) or a plain scalar (e.g. mountpoint string).
    if (typeof nested === 'object' && nested !== null) {
      const n = nested as Record<string, unknown>;
      return { value: n['value'], parsed: n['parsed'] };
    }
    return { value: nested };
  }
  const flat = d[key];
  if (flat !== undefined) {
    // Flattened shape — size props carry bytes in `parsed`, human text as the field.
    if (typeof flat === 'object' && flat !== null) {
      const f = flat as Record<string, unknown>;
      const v = f['value'];
      const p = f['parsed'];
      // Canonical value: prefer an explicit numeric `value`, else bytes in `parsed`.
      if (typeof v === 'number') return { value: v, parsed: typeof p === 'string' ? p : undefined };
      if (typeof p === 'number') return { value: p, parsed: typeof v === 'string' ? v : undefined };
      return { value: v ?? p, parsed: typeof p === 'string' && p !== v ? p : undefined };
    }
    // Plain scalar (e.g. mountpoint string, compression "lz4", readonly bool).
    return { value: flat };
  }
  return undefined;
}

/** Numeric bytes from a property (prefers `parsed` — the real number). */
function propBytes(d: Record<string, unknown>, key: string): number | null {
  const p = propOf(d, key);
  if (!p) return null;
  for (const v of [p.parsed, p.value]) {
    if (typeof v === 'number' && Number.isFinite(v)) return v;
  }
  return null;
}

/** Maps one raw pool.dataset.query entry to a filesystem row. Pools themselves,
 * snapshots and system-managed datasets are excluded — pools already have their
 * own rows from pool.query (same natural key → an upsert would clobber the type).
 * Both FILESYSTEMS and VOLUMES (zvols) are kept: zvols are block devices that
 * hold data (VM disks, iSCSI LUNs) and belong on the Storage page. */
function parseDataset(d: Record<string, unknown>): FsRow | null {
  const name = pickString(d, ['name']);
  if (!name) return null;
  // Top-level entries ARE the pools — already represented by pool.query rows.
  if (!name.includes('/')) return null;
  if (isInternalDataset(name)) return null;
  // Snapshots are per-dataset point-in-time copies — not mountable storage.
  const dsType = typeof d['type'] === 'string' ? (d['type'] as string).toLowerCase() : '';
  if (dsType !== 'filesystem' && dsType !== 'volume') return null;

  // Mountpoint: modern shape is a plain top-level STRING; legacy nests it.
  const mp = propOf(d, 'mountpoint');
  let mountpoint: string | null = null;
  const mpVal = mp?.value ?? (typeof d['mountpoint'] === 'string' ? d['mountpoint'] : undefined);
  if (typeof mpVal === 'string' && mpVal !== 'legacy' && mpVal !== 'unmounted') mountpoint = mpVal;

  // ZFS space accounting — differs by type:
  //   FILESYSTEM: `referenced` = space this dataset itself consumes (the "used"
  //     the UI shows); `used` also includes children. Capacity = quota if set,
  //     else reservation, else null (unlimited → no bar). free = cap - used.
  //   VOLUME:     `volsize` = provisioned size; `used` = space actually written.
  const isVol = dsType === 'volume';
  const referenced = propBytes(d, 'referenced');
  const usedTotal = propBytes(d, 'used');
  const volsize = propBytes(d, 'volsize');
  const quota = propBytes(d, 'quota');
  const reservation = propBytes(d, 'reservation');

  let sizeBytes: number | null;
  let usedBytes: number | null;
  if (isVol) {
    sizeBytes = volsize;
    usedBytes = usedTotal ?? referenced;
  } else {
    sizeBytes = quota ?? reservation; // capacity ceiling (null = unlimited)
    usedBytes = referenced ?? usedTotal;
  }
  const freeBytes =
    sizeBytes !== null && usedBytes !== null ? Math.max(0, sizeBytes - usedBytes) : null;

  // Detailed props for the expandable row + future config/state endpoints.
  // `parsed` variants are included when present (e.g. quota "10 GB" → value is
  // bytes, parsed is the human string) — both are useful downstream.
  const extra: Record<string, unknown> = {};
  for (const key of DATASET_EXTRA_PROPS) {
    const p = propOf(d, key);
    if (!p) continue;
    const v = p.value ?? p.parsed;
    if (v === undefined || v === null) continue;
    extra[key] = v;
    if (typeof p.parsed === 'string' && p.parsed !== '') extra[`${key}Parsed`] = p.parsed;
  }

  return {
    name,
    type: isVol ? 'zfs-zvol' : 'zfs-dataset',
    mountpoint,
    sizeBytes,
    usedBytes,
    freeBytes,
    status: typeof d['state'] === 'string' ? (d['state'] as string).toUpperCase() : undefined,
    // IMMEDIATE parent — the Storage page nests hierarchically (datasets under
    // datasets, zvols under their dataset), not flat-under-pool.
    parent: name.slice(0, name.lastIndexOf('/')) || null,
    extra: Object.keys(extra).length > 0 ? extra : undefined,
  };
}

/** Maps one raw hardware.disk.query entry to a disk row. */
function parseDisk(d: Record<string, unknown>): DiskRow | null {
  const name = pickString(d, ['name', 'identifier']);
  if (!name) return null;
  const modelRaw = pickString(d, ['model', 'description']);
  const serial = pickString(d, ['serial', 'serial_number']);
  const capacityBytes = pickNumber(d, ['size', 'capacity_bytes']);
  // Media type: modern TrueNAS (24.10+) disk.query returns `type` ('HDD'|'SSD')
  // and an integer `rotationrate` (RPM; null for SSDs). Older releases used a
  // boolean `rotation_rate` (true = spinning media) — keep both shapes working.
  let rotationRate: DiskRow['rotationRate'] = 'unknown';
  const typeRaw = pickString(d, ['type']);
  if (typeRaw === 'SSD') rotationRate = 'ssd';
  else if (typeRaw === 'HDD') rotationRate = 'hdd';
  else {
    const rr = d['rotationrate'];
    if (typeof rr === 'number' && rr > 0) rotationRate = 'hdd';
    else if (rr === null) rotationRate = 'ssd';
    else if (d['rotation_rate'] === true) rotationRate = 'hdd';
    else if (d['rotation_rate'] === false) rotationRate = 'ssd';
  }
  const healthRaw = pickString(d, ['health', 'state']);
  return {
    name,
    model: isPlaceholder(modelRaw ?? '') ? null : modelRaw,
    serial: isPlaceholder(serial ?? '') ? null : serial,
    capacityBytes,
    rotationRate,
    health: healthRaw ? healthRaw.toLowerCase() : undefined,
  };
}

/**
 * Maps active SMART alerts to the disks they describe. TrueNAS 25.10+ REMOVED
 * the public SMART API (disk.smart_test is private/cron-only) — but the built-in
 * SMART checker runs every 90 min and surfaces problems as alert.list entries,
 * each carrying the bare disk name in args: WARNING = uncorrected errors /
 * failed selftest, CRITICAL = low spare-block reserve / high erase count.
 * No active alert for a disk ⇒ its last check found nothing ⇒ healthy.
 */
const SMART_ALERT_CLASSES = new Set([
  'SMARTUncorrectedErrorsAlert',
  'SMARTFailedSelfTestAlert',
  'SMARTSpareBlockCountAlert',
  'SMARTEraseCycleCountAlert',
]);

function smartAlertsOf(rawAlerts: Record<string, unknown>[]): Map<string, { level: string; text: string }> {
  const map = new Map<string, { level: string; text: string }>();
  for (const a of rawAlerts) {
    if (a['dismissed'] === true) continue; // operator-acknowledged — not an active problem
    const klass = pickString(a, ['klass']);
    if (!klass || !SMART_ALERT_CLASSES.has(klass)) continue;
    const args = (a['args'] ?? {}) as Record<string, unknown>;
    const name = bareDiskName(pickString(args, ['name']) ?? '');
    if (!name) continue;
    map.set(name, { level: parseAlertSeverity(a), text: pickString(a, ['text']) ?? '' });
  }
  return map;
}

/** Disk details worth keeping for later config/state use (temperature, power). */
function diskExtra(d: Record<string, unknown>): Record<string, unknown> | undefined {
  const extra: Record<string, unknown> = {};
  const temp = pickNumber(d, ['temperature', 'temp_celsius']);
  if (typeof temp === 'number') extra.temperatureC = temp;
  const powerState = pickString(d, ['power_state', 'standby']);
  if (powerState) extra.powerState = powerState.toLowerCase();
  return Object.keys(extra).length > 0 ? extra : undefined;
}

/** Strips a device prefix so `/dev/sda` and `sda` both match disk.query names. */
function bareDiskName(raw: string): string {
  const m = raw.match(/\/dev\/([A-Za-z0-9]+)$/);
  return m ? m[1] : raw;
}

/**
 * Walks a pool's vdev tree and returns the disk names it contains. TrueNAS
 * `pool.query` returns topology as a DICT of vdev categories ({data, log,
 * cache, spares, special, dedup}) — older releases used a plain array under
 * `vdevs`. Each vdev is {type, path?, disk?, children[]}; leaf disks carry the
 * name in `disk` (bare) or `path` (`/dev/sda`). Both shapes are handled.
 */
function collectPoolDisks(topology: unknown): Set<string> {
  const found = new Set<string>();
  const walk = (node: unknown): void => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const v of node) walk(v);
      return;
    }
    const n = node as Record<string, unknown>;
    // Category dict ({data:[...], log:[...]}) — descend into the lists.
    if (!n['type'] && !n['path']) {
      for (const key of ['data', 'log', 'cache', 'spares', 'special', 'dedup']) {
        const v = n[key];
        if (Array.isArray(v)) walk(v);
      }
      return;
    }
    // Vdev node — leaf disks carry `disk` (bare name) or `path` (/dev/...).
    for (const key of ['disk', 'path']) {
      const v = pickString(n, [key]);
      if (v) found.add(bareDiskName(v));
    }
    const children = n['children'];
    if (Array.isArray(children)) for (const c of children) walk(c);
  };
  walk(topology);
  return found;
}

/** Boot media from system.datastore — the disk TrueNAS itself runs on. */
function parseBootDisk(datastore: Record<string, unknown>): DiskRow | null {
  const name = pickString(datastore, ['disk', 'boot_disk']);
  if (!name) return null;
  return { name, rotationRate: 'unknown', health: undefined };
}

/** One row of the networks inventory (shape consumed by the API's ingestInventory). */
interface NetworkRow {
  name: string;
  ip: string;
  prefix: number | null;
  version: '4' | '6';
  vlanId: number | null;
  mac: string | null;
  status: string | null;
}

/**
 * Maps interface.query rows to networks-inventory rows — one row per IP alias.
 * v26 encodes each alias as a JSON STRING inside the `aliases` array
 * ({"type":"INET","address":"10.25.0.10","netmask":16}); older releases used
 * plain objects — both are handled. Interfaces without IPs contribute nothing
 * (the inventory is about addressable networks, not raw NICs).
 */
function parseNetworks(ifaces: Record<string, unknown>[]): NetworkRow[] {
  const rows: NetworkRow[] = [];
  for (const i of ifaces) {
    const state = (i['state'] ?? {}) as Record<string, unknown>;
    // Prefer the human description ("NET_MANAGEMENT") over the kernel name.
    const name = pickString(i, ['description']) || pickString(i, ['name']) || '';
    if (!name) continue;
    const aliasesRaw = i['aliases'];
    if (!Array.isArray(aliasesRaw)) continue;
    const mac = typeof state['link_address'] === 'string' ? (state['link_address'] as string).toLowerCase() : null;
    const status = state['link_state'] === 'LINK_STATE_UP' ? 'up' : 'down';
    const vlanId = pickNumber(i, ['vlan_tag']);
    for (const a of aliasesRaw) {
      let alias: Record<string, unknown> | undefined;
      if (typeof a === 'string') {
        try { alias = JSON.parse(a) as Record<string, unknown>; } catch { continue; }
      } else if (a && typeof a === 'object') {
        alias = a as Record<string, unknown>;
      }
      if (!alias) continue;
      const ip = pickString(alias, ['address']);
      if (!ip) continue;
      rows.push({
        name,
        ip,
        prefix: pickNumber(alias, ['netmask', 'prefixlen']) ?? null,
        version: pickString(alias, ['type']) === 'INET6' ? '6' : '4',
        vlanId: vlanId ?? null,
        mac,
        status,
      });
    }
  }
  return rows;
}

/** One row of the hosts inventory for THIS appliance's own interfaces. */
interface OwnHostRow {
  mac: string;
  ip: string;
  hostname: string;
  intf?: string;
}

/**
 * Maps interface.query rows to host-inventory rows for the appliance's OWN
 * interfaces — one row per (MAC, IP alias), carrying the system hostname.
 * The API merges host rows by MAC across devices, so these 'self' rows merge
 * with ARP/NDP entries other appliances see for this box and supply the name
 * that neighbor tables never carry. Interfaces without IPs contribute nothing.
 */
function parseOwnHosts(ifaces: Record<string, unknown>[], hostname: string): OwnHostRow[] {
  const rows: OwnHostRow[] = [];
  if (!hostname) return rows;
  for (const i of ifaces) {
    const state = (i['state'] ?? {}) as Record<string, unknown>;
    const macRaw = typeof state['link_address'] === 'string' ? (state['link_address'] as string).toLowerCase() : '';
    if (!macRaw || !/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(macRaw)) continue; // no real MAC → nothing to merge on
    const aliasesRaw = i['aliases'];
    if (!Array.isArray(aliasesRaw) || aliasesRaw.length === 0) continue;
    const intf = pickString(i, ['description']) || pickString(i, ['name']) || '';
    for (const a of aliasesRaw) {
      let alias: Record<string, unknown> | undefined;
      if (typeof a === 'string') {
        try { alias = JSON.parse(a) as Record<string, unknown>; } catch { continue; }
      } else if (a && typeof a === 'object') {
        alias = a as Record<string, unknown>;
      }
      if (!alias) continue;
      const ip = pickString(alias, ['address']);
      if (!ip) continue;
      rows.push({ mac: macRaw, ip, hostname, intf: intf || undefined });
    }
  }
  return rows;
}

/** One row of the routes inventory (shape consumed by the API's ingestInventory). */
interface RouteRow {
  destination: string;
  gateway: string;
  protocol: 'static';
  status: string;
  extra?: Record<string, unknown>;
}

/**
 * Maps `staticroute.query` entries (TrueNAS v26+ documented CRUD namespace) to
 * route-inventory rows. Each entry is {id, destination: "CIDR", gateway: "IP",
 * description}; `extra.peer` carries the human label so the Routes page can show it.
 */
function parseStaticRoutes(entries: Record<string, unknown>[]): RouteRow[] {
  const rows: RouteRow[] = [];
  for (const e of entries) {
    const destination = pickString(e, ['destination']);
    if (!destination) continue;
    const description = pickString(e, ['description']) ?? '';
    rows.push({
      destination,
      gateway: pickString(e, ['gateway']) ?? '',
      protocol: 'static',
      status: 'active', // configured static routes are applied by TrueNAS with the interface config
      extra: description ? { peer: description } : undefined,
    });
  }
  return rows;
}

/**
 * Fallback for older releases WITHOUT the `staticroute.*` namespace: each
 * interface's documented `static_routes` array of {destination, gateway} entries.
 */
function parseRoutes(ifaces: Record<string, unknown>[]): RouteRow[] {
  const rows: RouteRow[] = [];
  for (const i of ifaces) {
    const sr = i['static_routes'];
    if (!Array.isArray(sr)) continue;
    // Prefer the human description ("NET_MONITORING") over the kernel name.
    const label = pickString(i, ['description']) || pickString(i, ['name']) || '';
    for (const r of sr) {
      let entry: Record<string, unknown> | undefined;
      if (typeof r === 'string') {
        try { entry = JSON.parse(r) as Record<string, unknown>; } catch { continue; }
      } else if (r && typeof r === 'object') {
        entry = r as Record<string, unknown>;
      }
      if (!entry) continue;
      const destination = pickString(entry, ['destination']);
      if (!destination) continue;
      rows.push({
        destination,
        gateway: pickString(entry, ['gateway']) ?? '',
        protocol: 'static',
        status: 'active', // configured static routes are applied by TrueNAS with the interface config
        extra: label ? { peer: label } : undefined,
      });
    }
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Containers inventory (cross-device Containers page): `containers[]` metric.
// Apps on TrueNAS SCALE are docker/k8s workloads exposed via app.query; their
// network placement + static IPs come from the per-app compose config
// (app.config) and the docker networks (docker.network.query). The public API
// exposes NO per-container CPU/mem/IO stats or start times — this inventory is
// about identity, state and network footprint only.
// ---------------------------------------------------------------------------

/** One row of the containers inventory (shape consumed by the API's ingestInventory). */
interface ContainerRow {
  name: string;
  // RUNNING | STOPPED | ... (app-level state, uppercased at emit).
  state: string;
  image?: string | null;
  version?: string | null;
  upgradeAvailable?: boolean;
  /** Real container start time (ISO) from `docker inspect` over SSH — only for
   *  single-container apps whose container is running. The API prefers this
   *  over its own transition tracking when present. */
  startedAt?: string | null;
  /** Structured details — stored in the API's `extra` JSON column:
   *  networks[] {name, driver?, subnets?}, ips[], ports[], containerCount,
   *  containers[] (per-service detail incl. mac/ip/startedAt when SSH-bound,
   *  volumes[] from compose config), app-level volumeMounts[], customApp?. */
  extra?: Record<string, unknown>;
}

// ServiceNetDetail + serviceNetDetails now live in ./enrich (shared with the
// background app.config wave) — imported at the top of this file.

/** Maps raw docker.network.query entries to name → {driver, subnets[]} for tooltips. */
function parseDockerNetworks(nets: Record<string, unknown>[]): Map<string, { driver: string; subnets: string[] }> {
  const map = new Map<string, { driver: string; subnets: string[] }>();
  for (const n of nets) {
    const name = pickString(n, ['name']);
    if (!name) continue;
    const ipam = (n['ipam'] ?? {}) as Record<string, unknown>;
    const config = Array.isArray(ipam['config']) ? (ipam['config'] as Record<string, unknown>[]) : [];
    const subnets: string[] = [];
    for (const c of config) {
      const s = pickString(c, ['subnet']);
      if (s) subnets.push(s);
    }
    map.set(name, { driver: pickString(n, ['driver']) ?? 'unknown', subnets });
  }
  return map;
}

/**
 * Maps app.query rows (+ cached enrichment) to container inventory rows — one
 * row PER APP (the page's granularity). Multi-container apps carry their
 * per-service detail in extra.containers. Enrichment sources, in priority order:
 *   1. docker inspect over SSH (when an ssh slot is bound): REAL MACs + live IPs
 *      + start times — the public API exposes none of these.
 *   2. app.config compose wave (background cache): static IPs + hostnames for
 *      containers without a usable SSH observation.
 */
function buildContainerRows(
  apps: Record<string, unknown>[],
  serviceDetailsByApp: Map<string, ServiceNetDetail[]>,
  dockerNets: Map<string, { driver: string; subnets: string[] }>,
  dockerInfo?: DockerContainerInfo[] | null,
  dockerStats?: Map<string, ContainerStat>
): ContainerRow[] {
  // Index the SSH observations by container id (and by name as a fallback).
  const infoById = new Map<string, DockerContainerInfo>();
  const infoByName = new Map<string, DockerContainerInfo>();
  for (const d of dockerInfo ?? []) {
    if (!infoById.has(d.id)) infoById.set(d.id, d);
    if (d.name && !infoByName.has(d.name)) infoByName.set(d.name, d);
  }

  const rows: ContainerRow[] = [];
  for (const a of apps) {
    const name = pickString(a, ['name', 'id']);
    if (!name) continue;
    const aw = (a['active_workloads'] ?? {}) as Record<string, unknown>;
    const details = Array.isArray(aw['container_details']) ? (aw['container_details'] as Record<string, unknown>[]) : [];

    // Networks: app-level `networks` array first, then the compose config's per-service networks.
    const networkNames = new Set<string>();
    if (Array.isArray(aw['networks'])) {
      for (const n of aw['networks']) {
        const s = typeof n === 'string' ? n : pickString((n ?? {}) as Record<string, unknown>, ['name']);
        if (s) networkNames.add(s);
      }
    }

    // Static IPs + per-service networks from the compose config (cached wave).
    const svcDetails = serviceDetailsByApp.get(name) ?? [];
    const ips = new Set<string>();
    for (const d of svcDetails) {
      for (const ip of d.ips) ips.add(ip);
      for (const net of d.networks) networkNames.add(net);
    }

    // Per-service detail for the expandable row — enriched with SSH facts when
    // available (real MAC + live IP beat the compose static config).
    const containers: {
      service?: string; image?: string | null; state?: string; mac?: string; ip?: string;
      startedAt?: string; volumes?: ContainerVolume[];
      cpuPct?: number; memUsedBytes?: number; memLimitBytes?: number;
      netRxRate?: number; netTxRate?: number; blkReadRate?: number; blkWriteRate?: number;
    }[] = [];
    for (const d of details) {
      const cid = pickString(d, ['id']);
      const svcName = pickString(d, ['service_name']) ?? '';
      const info = (cid ? infoById.get(cid) : undefined) ?? (svcName ? infoByName.get(svcName) : undefined);
      // Live stats (SSH docker stats) are keyed by container NAME — the service
      // name first, then the observed docker name as fallback.
      let stat: ContainerStat | undefined;
      if (dockerStats && (svcName || info?.name)) {
        stat = svcName ? dockerStats.get(svcName) : undefined;
        if (!stat && info?.name) stat = dockerStats.get(info.name);
      }
      // Compose detail for this service (hostname + static IPs + declared volumes).
      const svc = svcDetails.find((s) => s.hostname === svcName || s.hostname === name);
      let mac: string | undefined;
      let ip: string | undefined;
      if (info && info.nets.length > 0) {
        // Prefer the first network with a real IP, else the first entry.
        const primary = info.nets.find((n) => n.ip) ?? info.nets[0];
        mac = primary.mac;
        ip = primary.ip || undefined;
      } else if (svc && svc.ips.length > 0) {
        ip = svc.ips[0]; // static compose IP — no MAC available without SSH
      }
      containers.push({
        service: svcName || undefined,
        image: pickString(d, ['image']),
        state: pickString(d, ['state']) ?? undefined,
        ...(mac ? { mac } : {}),
        ...(ip ? { ip } : {}),
        ...(info?.startedAt && info.state === 'running' ? { startedAt: info.startedAt } : {}),
        ...(svc && svc.volumes.length > 0 ? { volumes: svc.volumes } : {}),
        // Live CPU/RAM + average I/O rates (absent until the first SSH cycle).
        ...(stat?.cpuPct !== undefined ? { cpuPct: stat.cpuPct } : {}),
        ...(stat?.memUsedBytes !== undefined ? { memUsedBytes: stat.memUsedBytes } : {}),
        ...(stat?.memLimitBytes !== undefined ? { memLimitBytes: stat.memLimitBytes } : {}),
        ...(stat?.netRxRate !== undefined ? { netRxRate: stat.netRxRate } : {}),
        ...(stat?.netTxRate !== undefined ? { netTxRate: stat.netTxRate } : {}),
        ...(stat?.blkReadRate !== undefined ? { blkReadRate: stat.blkReadRate } : {}),
        ...(stat?.blkWriteRate !== undefined ? { blkWriteRate: stat.blkWriteRate } : {}),
      });
    }

    // App-level live stats — aggregate across this app's containers: RAM and
    // I/O rates summed, CPU = the busiest container (multi-core sums would be
    // misleading). Absent until the first successful SSH enrichment cycle.
    let appStats: Record<string, number> | null = null;
    const statRows = containers.filter((c) => c.cpuPct !== undefined || c.memUsedBytes !== undefined);
    if (statRows.length > 0) {
      const s: Record<string, number> = {};
      for (const c of statRows) {
        if (c.cpuPct !== undefined) s['cpuMax'] = Math.max(s['cpuMax'] ?? 0, c.cpuPct);
        if (c.memUsedBytes !== undefined) s['memUsedBytes'] = (s['memUsedBytes'] ?? 0) + c.memUsedBytes;
        for (const k of ['netRxRate', 'netTxRate', 'blkReadRate', 'blkWriteRate'] as const) {
          if (c[k] !== undefined) s[k] = (s[k] ?? 0) + (c[k] as number);
        }
      }
      appStats = s;
    }

    // SSH live IPs join the app-level IP set (real addresses beat compose-only).
    for (const d of dockerInfo ?? []) {
      const cid = details.find((x) => pickString(x, ['id']) === d.id);
      if (!cid) continue; // not a container of THIS app
      for (const n of d.nets) if (n.ip) ips.add(n.ip);
    }

    // Enrich each network name with its driver + subnets from docker.network.query.
    const networks: { name: string; driver?: string; subnets?: string[] }[] = Array.from(networkNames).sort().map((n) => {
      const meta = dockerNets.get(n);
      return meta ? { name: n, driver: meta.driver, subnets: meta.subnets.length > 0 ? meta.subnets : undefined } : { name: n };
    });

    // Published host ports (app-level used_ports; entries are numbers or "host:container" strings).
    const ports: number[] = [];
    if (Array.isArray(aw['used_ports'])) {
      for (const p of aw['used_ports']) {
        if (typeof p === 'number') ports.push(p);
        else if (typeof p === 'string') {
          const m = p.match(/^(\d+)(?::)/);
          if (m) ports.push(Number(m[1]));
        }
      }
    }

    // Volume mounts (deduped by source path).
    const volumes = Array.isArray(aw['volumes']) ? (aw['volumes'] as Record<string, unknown>[]) : [];
    const volumeMounts = Array.from(new Set(volumes.map((v) => pickString(v, ['source']) ?? '').filter(Boolean))).sort();

    // Real start time for single-container apps (SSH only — the API has none).
    let startedAt: string | null | undefined;
    if (details.length === 1) {
      const cid = pickString(details[0], ['id']);
      const info = (cid ? infoById.get(cid) : undefined);
      if (info?.startedAt && info.state === 'running') startedAt = info.startedAt;
    }

    rows.push({
      name,
      state: (pickString(a, ['state']) ?? 'UNKNOWN').toUpperCase(),
      image: details.length === 1 ? pickString(details[0], ['image']) : null,
      version: pickString(a, ['human_version', 'version']),
      upgradeAvailable: a['upgrade_available'] === true || a['image_updates_available'] === true ? true : undefined,
      ...(startedAt !== undefined ? { startedAt } : {}),
      extra: {
        networks,
        ips: Array.from(ips).sort(),
        ports: ports.sort((x, y) => x - y),
        containerCount: details.length,
        ...(containers.length > 0 ? { containers } : {}),
        ...(appStats ? { stats: appStats } : {}),
        ...(volumeMounts.length > 0 ? { volumeMounts } : {}),
        customApp: a['custom_app'] === true ? true : undefined,
      },
    });
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Docker image inventory (Containers page → collapsible images panel): the
// generic `images[]` metric. Source is app.image.query — TrueNAS SCALE's view
// of the local docker image store (one entry per image, with all its tags).
// Same upsert + delete-on-absent lifecycle as containers at ingest.
// ---------------------------------------------------------------------------

/** One row of the images inventory (shape consumed by the API's ingestInventory). */
interface ImageRow {
  name: string;
  sizeBytes?: number | null;
  createdAt?: string | null;
  updateAvailable?: boolean | null;
  dangling?: boolean;
  extra?: Record<string, unknown>;
}

const NONE_TAG = '<none>:<none>';

/** Maps raw app.image.query entries to UNM image rows: one row per IMAGE (not
 * per tag) — the first real tag is the name, all tags/digests ride in `extra`.
 * An image whose only tag is <none>:<none> is dangling and named by its short id. */
function buildImageRows(appImages: Record<string, unknown>[]): ImageRow[] {
  const rows: ImageRow[] = [];
  for (const img of appImages) {
    if (!img || typeof img !== 'object') continue;
    const tagsRaw = Array.isArray(img['repo_tags']) ? (img['repo_tags'] as unknown[]) : [];
    const tags = tagsRaw.filter((t): t is string => typeof t === 'string' && t.length > 0);
    const realTags = tags.filter((t) => t !== NONE_TAG);
    const dangling = img['dangling'] === true || realTags.length === 0;

    const id = pickString(img, ['id']) ?? '';

    let name: string;
    if (!dangling) {
      name = realTags[0];
    } else {
      // Untagged image — identify by short id so the row is stable + readable.
      name = id ? `sha256:${id.slice(0, 12)}` : 'unknown';
    }

    rows.push({
      name,
      sizeBytes: pickNumber(img, ['size']),
      createdAt: pickString(img, ['created']),
      updateAvailable: typeof img['update_available'] === 'boolean' ? (img['update_available'] as boolean) : null,
      dangling,
      extra: {
        // The appliance image id — the `images.delete` action matches on this.
        ...(id ? { id } : {}),
        ...(realTags.length > 1 ? { tags: realTags } : {}),
        ...(Array.isArray(img['repo_digests']) && (img['repo_digests'] as unknown[]).length > 0 ? { digests: img['repo_digests'] } : {}),
      },
    });
  }
  return rows.sort((a, b) => a.name.localeCompare(b.name));
}

// ---------------------------------------------------------------------------
// VM inventory (VMs page): the generic `vms[]` metric. Source is vm.query —
// TrueNAS SCALE's view of its libvirt guests (one entry per VM with devices[],
// status.state, vcpus, memory in MiB). Same upsert + delete-on-absent
// lifecycle as containers at ingest. The NIC MACs are what feed the Hosts page
// (source 'vm', via the vmHosts key) — TrueNAS assigns every VM NIC a real
// 00:a0:98:* MAC, so guests merge by MAC with ARP/NDP entries other devices
// report for them. Live guest IPs are NOT in the public API; when an ssh slot
// is bound they come from `virsh domifaddr` over SSH (background enrichment).
// ---------------------------------------------------------------------------

/** One row of the VMs inventory (shape consumed by the API's ingestInventory). */
interface VmRow {
  name: string;
  state?: string;
  vcpus?: number | null;
  memoryMiB?: number | null;
  archType?: string | null;
  extra?: Record<string, unknown>;
}

/** One attached device of a VM — NIC, disk, display, CD-ROM, PCIe passthrough,
 * or any other dtype the appliance reports. GENERIC shape so ANY hypervisor
 * plugin (TrueNAS today, Proxmox later) can emit the same list: `dtype` is the
 * appliance's native type string; `label`/`detail` are pre-formatted for display
 * so the webapp never has to know a specific appliance's attribute schema. */
interface VmDevice {
  dtype: string;
  label?: string;
  detail?: string;
}

/** Formats ONE normalized VM device into a generic display entry. Known TrueNAS
 * dtypes get tailored labels (MAC, disk path, display resolution…); unknown ones
 * fall back to `dtype` + a compact dump of their scalar attributes so no data is
 * ever silently dropped when a new dtype appears on a future release. */
function formatVmDevice(dev: { dtype: string; attrs: Record<string, unknown> }): VmDevice {
  const a = dev.attrs;
  const s = (k: string): string | undefined => {
    const v = a[k];
    if (typeof v === 'string' && v !== '') return v;
    if (typeof v === 'number') return String(v);
    return undefined;
  };
  switch (dev.dtype) {
    case 'NIC': {
      const mac = s('mac');
      const parts: string[] = [];
      if (s('type')) parts.push(s('type') as string);
      if (s('nic_attach')) parts.push(`→ ${s('nic_attach')}`);
      return { dtype: 'NIC', label: mac ?? 'no MAC assigned', detail: parts.join(' ') || undefined };
    }
    case 'DISK':
    case 'RAW': {
      const path = s('path');
      return { dtype: dev.dtype, label: path ?? 'disk', detail: s('type') };
    }
    case 'CDROM': {
      const path = s('path');
      return { dtype: 'CDROM', label: path && path !== '' ? path : 'CD-ROM drive', detail: s('type') };
    }
    case 'DISPLAY': {
      const type = s('type');
      const parts: string[] = [];
      if (s('resolution')) parts.push(s('resolution') as string);
      if (s('port')) parts.push(`:${s('port')}`);
      return { dtype: 'DISPLAY', label: `Display${type ? ` (${type})` : ''}`, detail: parts.join(' ') || undefined };
    }
    case 'PCI': {
      const hostdev = s('hostdev');
      return { dtype: 'PCI', label: hostdev ?? 'PCI passthrough', detail: s('rombar') ? `rombar=${a['rombar']}` : undefined };
    }
    default: {
      // Unknown / future dtype — surface it generically so nothing is lost.
      const interesting = Object.entries(a)
        .filter(([k, v]) => k !== 'dtype' && (typeof v === 'string' || typeof v === 'number') && v !== '' && v !== null)
        .slice(0, 4);
      return { dtype: dev.dtype, label: dev.dtype.toLowerCase(), detail: interesting.map(([k, v]) => `${k}=${v}`).join(' ') || undefined };
    }
  }
}

/** Maps raw vm.query entries to UNM VM rows. EVERY attached device (NICs with
 * their MACs, disks, displays, CD-ROMs, PCIe passthrough…) rides in `extra.devices`
 * — the webapp renders each as a child row under the collapsed parent. */
function buildVmRows(vms: Record<string, unknown>[]): VmRow[] {
  const rows: VmRow[] = [];
  for (const v of vms) {
    if (!v || typeof v !== 'object') continue;
    const name = pickString(v, ['name']);
    if (!name) continue;

    // status.state — RUNNING | STOPPED | SUSPENDED | PAUSED | ... (libvirt).
    const status = (v['status'] ?? {}) as Record<string, unknown>;
    const state = typeof status['state'] === 'string' && (status['state'] as string) !== '' ? (status['state'] as string).toUpperCase() : 'UNKNOWN';

    // Every attached device → one generic display entry (any dtype is kept).
    const devices: VmDevice[] = [];
    const devicesRaw = Array.isArray(v['devices']) ? (v['devices'] as Record<string, unknown>[]) : [];
    for (const d of devicesRaw) {
      const dev = normalizeVmDevice(d);
      if (!dev) continue;
      devices.push(formatVmDevice(dev));
    }

    rows.push({
      name,
      state,
      vcpus: pickNumber(v, ['vcpus']),
      memoryMiB: pickNumber(v, ['memory']), // TrueNAS reports MiB
      archType: pickString(v, ['arch_type']) ?? pickString(v, ['machine_type']) ?? null,
      extra: {
        devices,
        ...(pickString(v, ['description']) && (v['description'] as string) !== '' ? { description: v['description'] } : {}),
        ...(pickString(v, ['uuid']) ? { uuid: v['uuid'] } : {}),
        autostart: typeof v['autostart'] === 'boolean' ? (v['autostart'] as boolean) : undefined,
      },
    });
  }
  return rows.sort((a, b) => a.name.localeCompare(b.name));
}

/** True for DMI placeholder values ("To Be Filled By O.E.M.") — not real data. */
function isPlaceholder(s: string | undefined): boolean {
  return !s || /to be filled/i.test(s);
}

app.post('/monitoring', async (req, res) => {
  // Track in-flight polls per host — the background app.config wave must not
  // overlap a live poll on the shared WebSocket (the appliance's socket closes
  // under overlapping bursts; measured ~4 calls/s ceiling).
  const body = req.body ?? {};
  const hostForGuard = applianceHost(body.managementAddress);
  if (hostForGuard) monitoringInFlight.add(hostForGuard);
  try {
    await handleMonitoring(req, res);
  } catch (err) {
    // Safety net: Express 4 does NOT catch rejections from async handlers —
    // an unhandled one would crash the plugin process. Always answer 200 with
    // health=critical so the API records a failed poll instead of losing us.
    logger.error(`Monitoring poll crashed: ${errMsg(err)}`, {
      deviceId: typeof body.deviceId === 'string' ? body.deviceId : undefined,
      context: { host: typeof body.managementAddress === 'string' ? body.managementAddress : '' },
    });
    res.status(200).json({
      deviceId: typeof body.deviceId === 'string' ? body.deviceId : null,
      collectedAt: new Date().toISOString(),
      health: 'critical',
      metrics: { 'system.error': errMsg(err) },
      metricDescriptors: [textMetric('system.error', 'Error', { group: 'System' })],
    });
  } finally {
    if (hostForGuard) monitoringInFlight.delete(hostForGuard);
  }
});

async function handleMonitoring(req: Request, res: Response): Promise<void> {
  const body = req.body ?? {};
  const deviceId: string | undefined = typeof body.deviceId === 'string' ? body.deviceId : undefined;
  // Full address (host[:port]) — the WebSocket URL resolver needs the port.
  const host = applianceHost(body.managementAddress);

  // Effective settings injected by the API (defaults ⊕ user overrides).
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  notifier.setEnabled(settings.notifyAlerts === true);
  const transport = transportOf(settings);
  const ports = portsOf(settings);
  // Register the configured SSH port for this host — every internal sshPool.get()
  // (enrichment, probes) reads it via hostSshPort() without a threaded parameter.
  setHostSshPort(host, sshPortOf(settings));

  // Certificate pinning — verify the appliance's TLS cert against UNM's
  // inventory BEFORE any credentials are transmitted (throws on mismatch;
  // the /monitoring wrapper turns it into a health=critical poll result).
  await assertPinned(req, body.managementAddress, transport, ports);

  const timeoutMs = clampInt(settings.timeoutMs, 500, 60000, 5000);
  // App/Container collection toggle — off = skip app.query/docker.network + all
  // enrichment and emit empty containers[]/dockerHosts[] to clear stale rows.
  const collectApps = settings.collectApps !== false;
  // VM collection toggle — off = skip vm.query + the SSH virsh enrichment and
  // emit empty vms[]/vmHosts[] to clear stale rows (same contract as apps).
  const collectVms = settings.collectVms !== false;
  // Window-based scheduling: the API sends collectInventory=false on metrics-only
  // polls. The health trio (system.info / pool.query / alert.list) ALWAYS runs so
  // device status stays live; the slow inventory RPCs + their metric keys are
  // skipped until the next inventory-due poll. Absent = full collection.
  const collectInventory = body.collectInventory !== false;

  // Credentials: API-key slot (if bound) takes precedence over username/password.
  const apiKeyUsername = typeof settings.apiKeyUsername === 'string' ? settings.apiKeyUsername.trim() : '';
  const { creds, error: credError } = resolveCredentials(body.credentials as Record<string, unknown> | undefined, apiKeyUsername);
  if (!creds || !host) {
    res.status(200).json({
      deviceId: deviceId ?? null,
      collectedAt: new Date().toISOString(),
      health: 'critical',
      metrics: { 'system.error': credError ?? 'Missing managementAddress' },
      metricDescriptors: [textMetric('system.error', 'Error', { group: 'System' })],
    });
    return;
  }

  const client = getClient(host, transport, timeoutMs, ports);
  const metrics: Record<string, unknown> = {};
  let failures = 0;
  let firstError = '';

  // Core calls in parallel (the API's monitoring budget is ~30 s; the slowest
  // call dominates). allSettled (NOT all): a failed login (unreachable host /
  // bad credentials) must be handled per section, not reject the whole poll
  // before error handling. The last three are best-effort extras (networks
  // inventory + static routes + board serial/model) — their failure does NOT
  // count toward health.
  const [sysInfoRes, poolsRes, alertsRes, ifacesRes, dmiRes, staticRoutesRes, datasetsRes, disksRes, datastoreRes, bootDisksRes, appsRes, dockerNetsRes, appImagesRes, vmsRes] = await Promise.allSettled([
    client.call<Record<string, unknown>>('system.info', [], creds),
    client.call<Record<string, unknown>[]>('pool.query', [], creds),
    client.call<Record<string, unknown>[]>('alert.list', [], creds),
    // Inventory RPCs — skipped on metrics-only polls (collectInventory=false).
    collectInventory ? client.call<Record<string, unknown>[]>('interface.query', [], creds) : Promise.resolve(undefined),
    collectInventory ? client.call<Record<string, unknown>>('system.dmidecode_info', [], creds) : Promise.resolve(undefined),
    collectInventory ? client.call<Record<string, unknown>[]>('staticroute.query', [], creds) : Promise.resolve(undefined),
    // Storage-page extras (best-effort — never count toward health). Method
    // names verified against truenas/middleware: pool.dataset.query (datasets,
    // all releases), disk.query (physical disks incl. USB/NVMe), boot.get_disks
    // (boot-pool members; 25.10+/26) with system.datastore as the legacy
    // fallback for older releases.
    // pool.dataset.query reads EVERY dataset's full property set — on slow or
    // degraded appliances it can exceed the default per-call timeout and time
    // out, silently dropping ALL of that device's datasets from the Storage
    // page (pools with no children). Give it a dedicated 20 s budget; the API
    // worker's /monitoring timeout (30 s) covers it.
    collectInventory ? client.call<Record<string, unknown>[]>('pool.dataset.query', [], creds, 20_000) : Promise.resolve(undefined),
    collectInventory ? client.call<Record<string, unknown>[]>('disk.query', [], creds) : Promise.resolve(undefined),
    collectInventory ? client.call<Record<string, unknown>>('system.datastore', [], creds) : Promise.resolve(undefined),
    collectInventory ? client.call<string[]>('boot.get_disks', [], creds) : Promise.resolve(undefined),
    // Containers-page extras (best-effort — never count toward health).
    // app.query = one row per installed App (k8s workload); docker.network.query
    // = the docker networks (macvlan/bridge) with their subnets; app.image.query
    // = the local docker image inventory (tags, sizes, dangling flag) for the
    // Containers page's images panel. Per-app static IPs come from app.config(name)
    // below (sequential, after this batch).
    // Skipped entirely when the `collectApps` option is off — no container RPC
    // traffic to the appliance at all.
    collectApps ? client.call<Record<string, unknown>[]>('app.query', [], creds) : Promise.resolve(undefined),
    collectApps ? client.call<Record<string, unknown>[]>('docker.network.query', [], creds) : Promise.resolve(undefined),
    collectApps ? client.call<Record<string, unknown>[]>('app.image.query', [], creds) : Promise.resolve(undefined),
    // VMs-page extra (best-effort — never count toward health). vm.query = one
    // row per libvirt guest with devices[] (NIC MACs!) + status.state. Skipped
    // entirely when the `collectVms` option is off — no VM RPC traffic at all.
    collectVms ? client.call<Record<string, unknown>[]>('vm.query', [], creds) : Promise.resolve(undefined),
  ]);

  // TEMP DEBUG (log-once per host): the storage extras are best-effort — their
  // failures never count toward health. Log each method's outcome ONCE so a
  // wrong/renamed RPC surfaces in container logs without spamming every poll.
  for (const [label, r] of [
    ['pool.dataset.query', datasetsRes],
    ['disk.query', disksRes],
    ['system.datastore', datastoreRes],
    ['boot.get_disks', bootDisksRes],
    ['app.query', appsRes],
    ['docker.network.query', dockerNetsRes],
    ['app.image.query', appImagesRes],
    ['vm.query', vmsRes],
  ] as const) {
    // Not called when collection is disabled — don't log their "outcome".
    if (!collectApps && (label === 'app.query' || label === 'docker.network.query' || label === 'app.image.query')) continue;
    if (!collectVms && label === 'vm.query') continue;
    if (!collectInventory && ['interface.query', 'system.dmidecode_info', 'staticroute.query', 'pool.dataset.query', 'disk.query', 'system.datastore', 'boot.get_disks'].includes(label)) continue;
    if (storageDebugLogged.has(`${host}|${label}`)) continue;
    storageDebugLogged.add(`${host}|${label}`);
    if (r.status === 'rejected') {
      console.warn(`[storage-debug] ${label} failed: ${errMsg(r.reason)}`);
    } else if (!Array.isArray(r.value) && label !== 'system.datastore') {
      console.warn(`[storage-debug] ${label} returned non-array: ${JSON.stringify(r.value).slice(0, 200)}`);
    } else {
      const n = Array.isArray(r.value) ? r.value.length : Object.keys((r.value ?? {}) as object).length;
      console.log(`[storage-debug] ${label} ok (${n} entries)`);
    }
  }

  // --- system.info: CPU load (loadavg/cores) + memory total + inventory text ---
  let sysInfoOk = false;
  if (sysInfoRes.status === 'rejected') {
    failures++;
    firstError ||= `system.info: ${errMsg(sysInfoRes.reason)}`;
  } else {
    const si = sysInfoRes.value as Record<string, unknown>;
    if (si && typeof si === 'object') {
      // CPU load % from the documented 1-minute load average vs core count.
      const cores = pickNumber(si, ['cores', 'core_count']);
      const loadavg = Array.isArray(si['loadavg']) ? (si['loadavg'] as unknown[])[0] : undefined;
      if (typeof loadavg === 'number' && typeof cores === 'number' && cores > 0) {
        metrics['system.cpuLoad'] = Math.max(0, Math.min(100, Math.round((loadavg / cores) * 1000) / 10));
      }
      const memTotal = pickNumber(si, ['physmem', 'mem_total']);
      if (typeof memTotal === 'number' && memTotal > 0) metrics['system.memoryTotal'] = memTotal;
      // Inventory text (changes rarely — cheap to re-read every poll).
      const version = pickString(si, ['version']);
      if (version) metrics['system.version'] = version;
      const hostname = pickString(si, ['hostname']);
      if (hostname) metrics['system.hostname'] = hostname;
      const model = pickString(si, ['model', 'cpu_model']);
      if (model) metrics['system.model'] = model;
      const serial = pickString(si, ['system_serial', 'serial', 'serial_number']);
      if (!isPlaceholder(serial)) metrics['system.serialNumber'] = serial;
      const up = pickNumber(si, ['uptime_seconds', 'uptime']);
      if (typeof up === 'number') metrics['system.uptime'] = formatUptime(up);
      sysInfoOk = true;
    } else {
      failures++;
      firstError ||= 'system.info returned no data';
    }
  }

  // --- pool.query: per-pool table + aggregate usage gauge ------------------
  let poolsOk = false;
  const rawPools: Record<string, unknown>[] =
    poolsRes.status === 'fulfilled' && Array.isArray(poolsRes.value) ? (poolsRes.value as Record<string, unknown>[]) : [];
  const poolRows: PoolRow[] = rawPools.map(parsePool); // [] when the call failed
  if (poolsRes.status === 'rejected') {
    failures++;
    firstError ||= `pool.query: ${errMsg(poolsRes.reason)}`;
  } else {
    if (Array.isArray(poolsRes.value)) {
      const rows = poolRows;
      let totalSize = 0;
      let totalUsed = 0;
      let haveSizes = false;
      for (const r of rows) {
        if (typeof r.sizeBytes === 'number' && r.sizeBytes > 0) {
          totalSize += r.sizeBytes;
          if (typeof r.usedBytes === 'number') totalUsed += r.usedBytes;
          haveSizes = true;
        }
      }
      metrics['pools'] = rows.map((r) => ({
        name: r.name,
        status: r.status,
        size: formatBytes(r.sizeBytes ?? 0),
        used: formatBytes(r.usedBytes ?? 0),
        free: formatBytes(r.freeBytes ?? 0),
        scrub: r.scrubState ? r.scrubState.toLowerCase() : '—',
      }));
      if (haveSizes && totalSize > 0) {
        metrics['storage.poolUsedPct'] = Math.max(0, Math.min(100, Math.round((totalUsed / totalSize) * 1000) / 10));
      }
      poolsOk = true;
    } else {
      failures++;
      firstError ||= 'pool.query returned no data';
    }

    if (collectInventory) {
    // --- Storage inventory: filesystems[] (pools + datasets) + disks[] ------
    // Emitted even when EMPTY so removed datasets/disks vanish from the page
    // on the next poll (present-but-empty = authoritative; absent = no wipe).
    const fsRows: FsRow[] = poolRows.map((r) => ({
      name: r.name,
      type: 'zfs-pool' as const,
      mountpoint: null,
      sizeBytes: r.sizeBytes ?? null,
      usedBytes: r.usedBytes ?? null,
      freeBytes: r.freeBytes ?? null,
      status: r.status.toLowerCase(),
    }));
    if (datasetsRes.status === 'fulfilled' && Array.isArray(datasetsRes.value)) {
      for (const d of datasetsRes.value as Record<string, unknown>[]) {
        const row = parseDataset(d);
        if (row) fsRows.push(row);
      }
    }
    metrics['filesystems'] = fsRows;

    const diskRows: DiskRow[] = [];
    // Pool membership: walk each pool's vdev tree and tag its disks.
    const disksByPool = new Map<string, Set<string>>();
    for (const p of rawPools) {
      const poolName = pickString(p, ['name']);
      if (!poolName) continue;
      disksByPool.set(poolName, collectPoolDisks(p['topology'] ?? p['vdevs']));
    }
    // SMART health: active SMART alerts (alert.list is already polled above).
    const smartAlerts = alertsRes.status === 'fulfilled' && Array.isArray(alertsRes.value)
      ? smartAlertsOf(alertsRes.value as Record<string, unknown>[])
      : new Map<string, { level: string; text: string }>();
    if (disksRes.status === 'fulfilled' && Array.isArray(disksRes.value)) {
      for (const d of disksRes.value as Record<string, unknown>[]) {
        const row = parseDisk(d);
        if (!row) continue;
        for (const [poolName, names] of disksByPool) {
          if (names.has(row.name)) { row.poolName = poolName; break; }
        }
        // SMART state from active alerts: CRITICAL → failed, WARNING → degraded.
        // No alert ⇒ the 90-min SMART check found nothing ⇒ healthy.
        const smart = smartAlerts.get(row.name);
        if (smart) {
          row.health = smart.level === 'CRITICAL' ? 'failed' : 'degraded';
          row.extra ??= {};
          row.extra['smart'] = smart.text;
        } else {
          row.health = 'healthy';
        }
        // Detailed props (temperature, power state) for later config/state use.
        const extra = diskExtra(d);
        if (extra) Object.assign(row.extra ??= {}, extra);
        diskRows.push(row);
      }
    }
    // Boot media — the disks TrueNAS itself runs on (often a USB stick/SSD).
    // 25.10+/26: boot.get_disks returns the boot pool's member names directly.
    if (bootDisksRes.status === 'fulfilled' && Array.isArray(bootDisksRes.value)) {
      for (const name of bootDisksRes.value as string[]) {
        const existing = diskRows.find((r) => r.name === name);
        if (existing) { existing.poolName ??= 'boot-pool'; continue; }
        diskRows.push({ name, rotationRate: 'unknown', poolName: 'boot-pool' });
      }
    } else if (datastoreRes.status === 'fulfilled' && datastoreRes.value && typeof datastoreRes.value === 'object') {
      // Legacy fallback for older releases without boot.get_disks.
      const boot = parseBootDisk(datastoreRes.value as Record<string, unknown>);
      if (boot && !diskRows.some((r) => r.name === boot.name)) diskRows.push(boot);
    }
    metrics['disks'] = diskRows;
    }
  }

  // --- alert.list: active alerts drive health (CRITICAL/WARNING levels) ---
  let alertsOk = false;
  if (alertsRes.status === 'rejected') {
    failures++;
    firstError ||= `alert.list: ${errMsg(alertsRes.reason)}`;
  } else {
    const rawAlerts = Array.isArray(alertsRes.value) ? (alertsRes.value as Record<string, unknown>[]) : [];
    // Dismissed alerts are acknowledged by the operator — they must not drive health.
    const active = rawAlerts.filter((a) => a['dismissed'] !== true);
    if (active.length > 0) {
      metrics['alerts.active'] = active.length;
      for (const a of active) {
        const sev = parseAlertSeverity(a);
        if (sev === 'CRITICAL') metrics['health.alertCritical'] = true;
        else if (sev === 'WARNING' && !metrics['health.alertWarning']) metrics['health.alertWarning'] = true;
      }
    }
    alertsOk = true;

    // Mirror active alerts into the UNM notification center. Each alert gets a
    // stable dedupe key (class + args) so re-polls upsert instead of flooding,
    // and keys that vanished from this snapshot are resolved below.
    if (settings.notifyAlerts !== false) {
      const seen = new Set<string>();
      for (const a of active) {
        const klass = pickString(a, ['klass']) ?? 'Unknown';
        // Shared with the alerts.dismiss action — keeps UNM rows and appliance
        // alerts matched by the same stable key across polls.
        const key = alertDedupeKey(klass, a['args']);
        seen.add(key);
        // The subject is the tail of the shared key (alert:<klass>:<subject>).
        const subject = key.slice(`alert:${klass}:`.length);

        const sev = parseAlertSeverity(a);
        const text = pickString(a, ['text']) ?? klass;
        const hostname = pickString(metrics, ['system.hostname']) ?? host;
        notifier.notify({
          severity: sev === 'CRITICAL' ? 'critical' : sev === 'WARNING' ? 'warning' : 'info',
          title: `${hostname}: ${klass.replace(/Alert$/, '')}${subject ? ` (${subject})` : ''}`,
          message: text.slice(0, 500),
          dedupeKey: key,
          deviceId,
          context: { klass, subject: subject || null, severity: sev },
        });
      }

      // Alerts that disappeared since the last poll → resolve their rows.
      const prev = knownAlertsByHost.get(host) ?? new Set<string>();
      const gone = Array.from(prev).filter((k) => !seen.has(k));
      if (gone.length > 0) notifier.resolve(gone);
      knownAlertsByHost.set(host, seen);
    }
  }

  // --- interface.query: networks inventory + own-interface host rows -------
  // Networks: one row per IP alias. Hosts: the appliance's OWN interfaces as
  // 'self' rows carrying system.hostname — merged by MAC with ARP/NDP entries
  // other devices report for this box (neighbor tables never carry names).
  if (collectInventory && ifacesRes.status === 'fulfilled' && Array.isArray(ifacesRes.value)) {
    const ifaces = ifacesRes.value as Record<string, unknown>[];
    const rows = parseNetworks(ifaces);
    if (rows.length > 0) metrics['networks'] = rows;
    // system.hostname was parsed from system.info in the section above.
    const hostname = pickString(metrics, ['system.hostname']) ?? '';
    const ownHosts = parseOwnHosts(ifaces, hostname);
    if (ownHosts.length > 0) metrics['hosts'] = ownHosts;

    // ports[] → device_ports table (per-device Config page + cross-device views).
    // One row per interface with its live link state; MAC + first IP alias ride
    // in extra so the API can answer "which devices are on this port".
    const portRows: PortRow[] = [];
    for (const i of ifaces) {
      const name = pickString(i, ['description']) || pickString(i, ['name']);
      if (!name) continue;
      const state = (i['state'] ?? {}) as Record<string, unknown>;
      const linkUp = state['link_state'] === 'LINK_STATE_UP';
      const macRaw = typeof state['link_address'] === 'string' ? (state['link_address'] as string).toLowerCase() : null;
      const vlanId = pickNumber(i, ['vlan_tag']);
      let firstIp: string | undefined;
      const aliasesRaw = i['aliases'];
      if (Array.isArray(aliasesRaw)) {
        for (const a of aliasesRaw) {
          let alias: Record<string, unknown> | undefined;
          if (typeof a === 'string') { try { alias = JSON.parse(a) as Record<string, unknown>; } catch { continue; } }
          else if (a && typeof a === 'object') alias = a as Record<string, unknown>;
          const ip = pickString(alias ?? {}, ['address']);
          if (ip) { firstIp = ip; break; }
        }
      }
      portRows.push({
        name,
        status: linkUp ? 'up' : 'down',
        vlanId: vlanId && vlanId > 0 ? vlanId : null,
        extra: {
          ...(macRaw ? { mac: macRaw } : {}),
          ...(firstIp ? { ip: firstIp } : {}),
        },
      });
    }
    if (portRows.length > 0) metrics['ports'] = portRows;
  }

  // --- staticroute.query: routes inventory ---------------------------------
  // v26+ has a dedicated documented CRUD namespace (`staticroute.*`); older
  // releases carry per-interface `static_routes` in interface.query — fall
  // back to that when the method doesn't exist (-32601). Emitted even when
  // EMPTY so a route removed on the appliance vanishes from the Routes page
  // on the next poll (the API treats a present-but-empty array as
  // authoritative; an absent key would not wipe).
  let routes: RouteRow[] | undefined;
  if (staticRoutesRes.status === 'fulfilled' && Array.isArray(staticRoutesRes.value)) {
    routes = parseStaticRoutes(staticRoutesRes.value as Record<string, unknown>[]);
  } else if (
    staticRoutesRes.status === 'rejected' &&
    staticRoutesRes.reason instanceof TruenasRpcError &&
    staticRoutesRes.reason.code === -32601 &&
    ifacesRes.status === 'fulfilled' && Array.isArray(ifacesRes.value)
  ) {
    routes = parseRoutes(ifacesRes.value as Record<string, unknown>[]);
  }
  if (collectInventory && routes !== undefined) metrics['routes'] = routes;

  // --- Certificates (normalized for the cross-device Certificates page) ----
  // Management HTTPS cert + SSH host key on port 22. Both probes are
  // credential-free and best-effort; a failure simply contributes no row.
  if (collectInventory) {
    const cachedCerts = certCache.get(host, CERT_TTL_MS) ?? null;
    let certRows: CertificateRow[] | null = cachedCerts;
    if (!certRows) {
      // TrueNAS defaults to an HTTPS management UI — probe TLS on the address's
      // port (configured httpsPort, default 443; no row for plain-http).
      const target = parseProbeTarget(host, ports.httpsPort ?? 443);
      certRows =
        target && transport !== 'http'
          ? await collectDeviceCertificates({
              host: target.host,
              httpsPort: target.port,
              servername: target.host,
              sshEnabled: true,
              sshPort: sshPortOf(settings),
              timeoutMs: 5_000,
            })
          : [];
      certCache.set(host, certRows);
    }
    if (certRows.length > 0) metrics['certificates'] = certRows;
  }

  // --- app.query (+ docker.network.query): containers inventory --------------
  // Best-effort extra — never counts toward health. Emitted even when EMPTY so
  // an uninstalled app vanishes from the Containers page on the next poll
  // (present-but-empty is authoritative; absent key would not wipe).
  //
  // Enrichment (static IPs via app.config, real MACs/IPs/start times via SSH)
  // runs in the BACKGROUND with a 15-min cache — this handler only SCHEDULES
  // stale parts and reads whatever cached state exists right now. The poll
  // itself stays within its budget no matter how many apps are installed.
  if (!collectApps) {
    // Collection disabled by option — emit EMPTY arrays so previously collected
    // apps/containers (and their docker host rows) are wiped on this poll: an
    // ABSENT key would never clear stale rows, present-but-empty is the
    // authoritative wipe. No app.query/docker.network RPCs were sent and no
    // enrichment (app.config wave / SSH inspect) is scheduled while disabled.
    metrics['containers'] = [];
    metrics['dockerHosts'] = [];
  } else if (collectInventory && appsRes.status === 'fulfilled' && Array.isArray(appsRes.value)) {
    const apps = appsRes.value as Record<string, unknown>[];

    // Optional SSH slot — the plugin's PRIMARY is a username/password that must
    // NOT be reused for SSH, so only an explicitly bound ssh slot counts.
    const sshCreds = resolveSshCredentials(body.credentials as Record<string, unknown> | undefined, { slotOnly: true });

    ensureEnrichment({
      host,
      client,
      creds,
      sshCreds,
      apps,
      log: (level, message) => (level === 'warn' ? logger.warn(message, { deviceId }) : logger.info(message, { deviceId })),
    });

    const enrichment = getEnrichment(host);
    const serviceDetailsByApp = enrichment?.serviceDetails ?? new Map<string, ServiceNetDetail[]>();
    const dockerInfo = enrichment?.dockerInfo; // undefined until the first SSH cycle completes

    const dockerNets =
      dockerNetsRes.status === 'fulfilled' && Array.isArray(dockerNetsRes.value)
        ? parseDockerNetworks(dockerNetsRes.value as Record<string, unknown>[])
        : new Map<string, { driver: string; subnets: string[] }>();
    metrics['containers'] = buildContainerRows(apps, serviceDetailsByApp, dockerNets, dockerInfo, enrichment?.dockerStats);

    // Host inventory (source 'docker'): one row per container with a REAL MAC —
    // only possible via `docker inspect` over SSH (the public API exposes no
    // per-container MAC anywhere). Rows carry mac + ip + hostname so the API's
    // merge-by-MAC joins them with ARP/NDP entries other devices report. When
    // no ssh slot is bound (or before the first successful cycle) this stays
    // empty — containers without a known MAC are NOT stored as host rows.
    const dockerHosts: { mac: string; ip: string; hostname?: string }[] = [];
    if (dockerInfo && Array.isArray(dockerInfo)) {
      // Map container id → app name for the hostname label.
      const appNameById = new Map<string, string>();
      for (const a of apps) {
        const aw = (a['active_workloads'] ?? {}) as Record<string, unknown>;
        const details = Array.isArray(aw['container_details']) ? (aw['container_details'] as Record<string, unknown>[]) : [];
        for (const d of details) {
          const id = pickString(d, ['id']);
          if (id && !appNameById.has(id)) appNameById.set(id, pickString(a, ['name', 'id']) ?? '');
        }
      }
      const seenMacIps = new Set<string>();
      for (const d of dockerInfo) {
        if (d.state !== 'running') continue; // stopped containers have no live address
        for (const n of d.nets) {
          if (!n.ip || n.ip === '0.0.0.0' || n.ip === '::') continue;
          const key = `${n.mac}|${n.ip}`;
          if (seenMacIps.has(key)) continue;
          seenMacIps.add(key);
          dockerHosts.push({ mac: n.mac, ip: n.ip, hostname: appNameById.get(d.id) || d.name });
        }
      }
    }
    metrics['dockerHosts'] = dockerHosts;
  }

  // --- app.image.query: image inventory (Containers page → images panel) -----
  // Best-effort extra — never counts toward health. Independent of the app.query
  // outcome above (the two RPCs are separate). Emitted even when EMPTY so a
  // removed image vanishes from the page on the next poll (present-but-empty is
  // authoritative; an absent key would not wipe). Skipped while collectApps is
  // off — no image RPC traffic to the appliance at all.
  if (!collectApps) {
    metrics['images'] = [];
  } else if (collectInventory && appImagesRes.status === 'fulfilled' && Array.isArray(appImagesRes.value)) {
    metrics['images'] = buildImageRows(appImagesRes.value as Record<string, unknown>[]);
  }

  // --- vm.query: VMs inventory ---------------------------------------------
  // Best-effort extra — never counts toward health. Emitted even when EMPTY so
  // a deleted VM vanishes from the VMs page on the next poll (present-but-
  // empty is authoritative; an absent key would not wipe). Skipped while
  // collectVms is off — no vm.query RPC traffic to the appliance at all.
  if (!collectVms) {
    metrics['vms'] = [];
    metrics['vmHosts'] = [];
  } else if (collectInventory && vmsRes.status === 'fulfilled' && Array.isArray(vmsRes.value)) {
    const rawVms = vmsRes.value as Record<string, unknown>[];

    // Schedule the background SSH enrichment for live guest IPs — /monitoring
    // never blocks on it; reads whatever cached state exists right now.
    ensureVmEnrichment({
      host,
      sshCreds: resolveSshCredentials(body.credentials as Record<string, unknown> | undefined, { slotOnly: true }),
      vms: rawVms,
      log: (level, message) => (level === 'warn' ? logger.warn(message, { deviceId }) : logger.info(message, { deviceId })),
    });

    const vmIps = getVmEnrichment(host)?.ipsByMac ?? new Map<string, string>();
    metrics['vms'] = buildVmRows(rawVms);

    // Host inventory (source 'vm'): one row per VM NIC with a REAL MAC. TrueNAS
    // assigns every VM NIC a real 00:a0:98:* MAC at creation time — no SSH
    // needed for the MAC itself. The live IP comes from `virsh domifaddr` over
    // SSH (cached); without it the row is emitted with an empty IP and the API
    // merges it by MAC once any device's ARP/NDP table reports the address.
    const vmHosts: { mac: string; ip?: string; hostname?: string }[] = [];
    for (const v of rawVms) {
      if (!v || typeof v !== 'object') continue;
      const name = pickString(v, ['name']);
      if (!name) continue;
      const status = (v['status'] ?? {}) as Record<string, unknown>;
      // Stopped VMs have no live address — their NIC MACs are still valid host
      // rows (the guest exists on the network fabric), but only RUNNING guests
      // get an IP attached.
      const running = status['state'] === 'RUNNING';
      const devicesRaw = Array.isArray(v['devices']) ? (v['devices'] as Record<string, unknown>[]) : [];
      for (const d of devicesRaw) {
        const dev = normalizeVmDevice(d);
        if (!dev || dev.dtype !== 'NIC') continue;
        const mac = pickString(dev.attrs, ['mac']);
        if (!mac) continue; // no MAC assigned yet — nothing to insert into hosts
        vmHosts.push({
          mac: mac.toLowerCase(),
          ...(running && vmIps.get(mac.toLowerCase()) ? { ip: vmIps.get(mac.toLowerCase()) as string } : {}),
          hostname: name,
        });
      }
    }
    metrics['vmHosts'] = vmHosts;
  }

  // --- system.dmidecode_info: board serial + real hardware model fallback ---
  // system.info's `model` is the CPU; the baseboard product name is the actual
  // appliance model. Serial: DMI values are often placeholders — skip those.
  if (dmiRes.status === 'fulfilled' && dmiRes.value && typeof dmiRes.value === 'object') {
    const dmi = dmiRes.value as Record<string, unknown>;
    const boardModel = pickString(dmi, ['baseboard-product-name', 'system-product-name']);
    if (!isPlaceholder(boardModel)) metrics['system.model'] = boardModel;
    const boardSerial = pickString(dmi, ['system-serial-number', 'baseboard-serial-number']);
    if (!isPlaceholder(boardSerial) && !metrics['system.serialNumber']) {
      metrics['system.serialNumber'] = boardSerial;
    }
  }

  // --- Health mapping (only the three CORE calls count — networks/dmidecode
  // are best-effort extras and never affect health) ---
  let health: Health;
  if (failures === 3) {
    health = 'critical';
    metrics['system.error'] = firstError || 'All TrueNAS API calls failed';
  } else {
    const poolRows = metrics['pools'] as { status?: string }[] | undefined;
    const offlinePool = poolRows?.some((r) => r.status === 'OFFLINE');
    const degradedPool = poolRows?.some((r) => r.status === 'DEGRADED' || r.status === 'FAULTED');
    if (offlinePool || metrics['health.alertCritical']) health = 'critical';
    else if (degradedPool || metrics['health.alertWarning'] || failures > 0) health = 'warning';
    else health = sysInfoOk && poolsOk ? 'ok' : 'warning';
  }

  // Internal flags are not user-facing metrics.
  delete metrics['health.alertCritical'];
  delete metrics['health.alertWarning'];

  if (health !== 'ok') {
    logger.warn(`Monitoring poll for ${host} returned health=${health}${firstError ? ` (${firstError})` : ''}`, { deviceId, context: { host } });
  }

  res.status(200).json({
    deviceId: deviceId ?? null,
    collectedAt: new Date().toISOString(),
    health,
    metrics,
    metricDescriptors: descriptorsFromMetrics(metrics),
    // Echo of the effective settings — proof the API→plugin injection loop works.
    activeSettings: { transport, timeoutMs, logToApi: settings.logToApi === true, notifyAlerts: settings.notifyAlerts === true },
  });
}

/**
 * Descriptors generated DYNAMICALLY from the metrics actually collected, so the
 * UI always matches the data (works across TrueNAS versions). Mirrors the
 * OPNsense plugin's approach; static /discover descriptors cover the rest.
 */
function descriptorsFromMetrics(metrics: Record<string, unknown>): MetricDescriptor[] {
  const out: MetricDescriptor[] = [];
  if ('system.cpuLoad' in metrics) out.push(gaugeMetric('system.cpuLoad', 'CPU Load (1-min avg)', { unit: '%', min: 0, max: 100, group: 'System', summary: true }));
  if ('system.memoryTotal' in metrics)
    out.push({ key: 'system.memoryTotal', label: 'Memory Total', type: 'number', visualization: 'text', unit: 'bytes', format: 'bytes', group: 'System' });
  if ('storage.poolUsedPct' in metrics) out.push(gaugeMetric('storage.poolUsedPct', 'Pool Usage (all pools)', { unit: '%', min: 0, max: 100, group: 'Storage', summary: true }));
  for (const key of ['system.version', 'system.hostname', 'system.model', 'system.serialNumber'] as const) {
    if (key in metrics) out.push(textMetric(key, key.split('.')[1] ?? key, { group: 'System' }));
  }
  if ('system.uptime' in metrics)
    out.push({ key: 'system.uptime', label: 'Uptime', type: 'number', visualization: 'text', unit: 's', format: 'duration', group: 'System' });
  if ('alerts.active' in metrics) out.push(gaugeMetric('alerts.active', 'Active Alerts', { min: 0, group: 'Storage' }));
  if (Array.isArray(metrics['networks'])) {
    const rows = metrics['networks'] as Record<string, unknown>[];
    out.push({
      key: 'networks',
      label: 'Network Configuration',
      type: 'string',
      visualization: 'table',
      columns: ['name', 'ip', 'prefix', 'version', 'vlanId', 'mac', 'status'],
      group: 'Storage',
    });
  }
  if (Array.isArray(metrics['pools'])) {
    const rows = metrics['pools'] as Record<string, unknown>[];
    out.push({
      key: 'pools',
      label: 'Pools',
      type: 'string',
      visualization: 'table',
      columns: POOL_TABLE_COLUMNS,
      rows: rows.map((r) => String(r['name'] ?? '')),
      group: 'Storage',
    });
  }
  if (Array.isArray(metrics['routes']) && (metrics['routes'] as unknown[]).length > 0) {
    out.push({
      key: 'routes',
      label: 'Static Routes',
      type: 'string',
      visualization: 'table',
      columns: ['destination', 'gateway', 'protocol', 'status'],
      group: 'Storage',
    });
  }
  if (Array.isArray(metrics['filesystems']) && (metrics['filesystems'] as unknown[]).length > 0) {
    out.push({
      key: 'filesystems',
      label: 'Filesystems',
      type: 'string',
      visualization: 'table',
      columns: ['name', 'type', 'mountpoint', 'sizeBytes', 'usedBytes', 'freeBytes', 'status'],
      group: 'Storage',
    });
  }
  if (Array.isArray(metrics['disks']) && (metrics['disks'] as unknown[]).length > 0) {
    out.push({
      key: 'disks',
      label: 'Physical Disks',
      type: 'string',
      visualization: 'table',
      columns: ['name', 'model', 'serial', 'capacityBytes', 'rotationRate', 'health', 'poolName'],
      group: 'Storage',
    });
  }
  if (Array.isArray(metrics['containers']) && (metrics['containers'] as unknown[]).length > 0) {
    out.push({
      key: 'containers',
      label: 'Containers (Apps)',
      type: 'string',
      visualization: 'table',
      columns: ['name', 'state', 'image', 'version'],
      group: 'Storage',
    });
  }
  if (Array.isArray(metrics['images']) && (metrics['images'] as unknown[]).length > 0) {
    out.push({
      key: 'images',
      label: 'Docker Images',
      type: 'string',
      visualization: 'table',
      columns: ['name', 'sizeBytes', 'createdAt', 'updateAvailable'],
      group: 'Storage',
    });
  }
  if ('system.error' in metrics) out.push(textMetric('system.error', 'Error', { group: 'System' }));
  return out;
}

// ---------------------------------------------------------------------------
// POST /config — executes ONE action step against one appliance. The API's
// config-job worker dispatches here with {actionId, input, credentials}; the
// plugin owns ALL logic (schema validation + JSON-RPC call). Same contract as
// the other plugins: 200 + { success, result } on every path.
// ---------------------------------------------------------------------------
/**
 * Resolves the appliance address for a client. Unlike hostFromAddress (which
 * strips ports — fine for the conventional 443/80 case), the WebSocket URL
 * resolver needs the FULL host:port, so we pass the trimmed management address
 * through as-is (an explicit http(s) scheme is converted to ws(s) by the client).
 */
function applianceHost(managementAddress: unknown): string {
  return typeof managementAddress === 'string' ? managementAddress.trim() : '';
}

app.post('/config', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const host = applianceHost(body.managementAddress);

  // Registry shape preferred; legacy `{action, payload}` maps onto it.
  const actionId: string | undefined = typeof body.actionId === 'string' ? body.actionId : (typeof body.action === 'string' ? body.action : undefined);
  const input: Record<string, unknown> =
    body.input && typeof body.input === 'object'
      ? (body.input as Record<string, unknown>)
      : body.payload && typeof body.payload === 'object'
        ? (body.payload as Record<string, unknown>)
        : {};

  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  const transport = transportOf(settings);
  const ports = portsOf(settings);
  setHostSshPort(host, sshPortOf(settings));
  const timeoutMs = clampInt(settings.timeoutMs, 500, 60000, 5000);

  if (!actionId) {
    res.status(400).json({ success: false, result: { error: 'Missing actionId (or legacy "action")' } });
    return;
  }
  if (!host) {
    res.status(400).json({ success: false, result: { error: 'Missing managementAddress' } });
    return;
  }

  const action = actionRegistry.getAction(actionId);
  if (!action) {
    res.status(400).json({ success: false, result: { error: `Unknown action "${actionId}"` } });
    return;
  }

  // Credentials: API-key slot (if bound) takes precedence over username/password.
  const apiKeyUsername = typeof settings.apiKeyUsername === 'string' ? settings.apiKeyUsername.trim() : '';
  const { creds, error: credError } = resolveCredentials(body.credentials as Record<string, unknown> | undefined, apiKeyUsername);
  if (!creds) {
    res.status(200).json({ success: false, result: { error: credError ?? 'Missing credentials' } });
    return;
  }

  // Validate input against the action's declared schema — the plugin is the
  // authority on what it accepts; the API only checks that the id exists.
  const issues = validateInput(action.inputSchema, input);
  if (issues.length > 0) {
    res.status(200).json({ success: false, result: { error: `Invalid input for ${actionId}: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}` } });
    return;
  }

  try {
    // Certificate pinning — a config action transmits real credentials; refuse
    // the connection when the appliance's key differs from UNM's inventory.
    await assertPinned(req, host, transport, ports);

    // host + rawCredentials let slot-based actions (e.g. containers.logs.read over SSH)
    // reach the appliance on a different channel than the RPC socket.
    const ctx: TruenasActionContext = { client: getClient(host, transport, timeoutMs, ports), creds, host, rawCredentials: body.credentials as Record<string, unknown> | null };
    const result = await action.execute(ctx, input);
    res.status(200).json({ success: result.success, result });
  } catch (err) {
    logger.error(`Config action ${actionId} failed for ${host}: ${errMsg(err)}`, { deviceId, context: { host, actionId } });
    res.status(200).json({ success: false, result: { error: errMsg(err) } });
  }
});

// ---------------------------------------------------------------------------
// POST /state — dynamic device-state document for the UNM Config page. The API
// broker (api/src/deviceState.ts) calls this with fresh credentials + injected
// settings and returns the response verbatim to the webapp. All three reads are
// best-effort: a failing endpoint yields an empty section, not an error.
// ---------------------------------------------------------------------------
app.post('/state', stateHandler(async (body: StateRequestBody, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  const transport = transportOf(settings);
  const ports = portsOf(settings);
  const timeoutMs = clampInt(settings.timeoutMs, 500, 60000, 5000);

  const host = applianceHost(body.managementAddress);
  if (!host) throw new Error('Missing managementAddress');

  const apiKeyUsername = typeof settings.apiKeyUsername === 'string' ? settings.apiKeyUsername.trim() : '';
  const { creds, error: credError } = resolveCredentials(body.credentials as Record<string, unknown> | undefined, apiKeyUsername);
  if (!creds) throw new Error(credError ?? 'Missing credentials');

  // Certificate pinning — /state reads live data with credentials; verify first.
  await assertPinned(req, host, transport, ports);

  const client = getClient(host, transport, timeoutMs, ports);
  const [sysInfoRes, poolsRes, ifacesRes] = await Promise.allSettled([
    client.call<Record<string, unknown>>('system.info', [], creds),
    client.call<Record<string, unknown>[]>('pool.query', [], creds),
    client.call<Record<string, unknown>[]>('interface.query', [], creds),
  ]);

  return buildTruenasState({
    sysInfo: sysInfoRes.status === 'fulfilled' ? sysInfoRes.value : undefined,
    pools: poolsRes.status === 'fulfilled' && Array.isArray(poolsRes.value) ? poolsRes.value : [],
    ifaces: ifacesRes.status === 'fulfilled' && Array.isArray(ifacesRes.value) ? ifacesRes.value : [],
  });
}, 'ix-truenas-plugin'));

// ---------------------------------------------------------------------------
// POST /probe — SHORT-CYCLE live telemetry (capability 'probe'). The webapp's
// Containers page polls this every few seconds through the API broker.
// Requires a bound ssh slot — without one this throws and the webapp falls back
// to the slower enrichment data in the inventory rows.
// Probe keys:
//   - 'containerStats' (default): per-container CPU/RAM/I-O from ONE
//     `docker stats --no-stream` over the shared SSH pool (connection reused);
//     rates come from dedicated probe trackers so fast cycles don't disturb the
//     15-min enrichment baselines.
//   - 'containerStates': the live state of ALL containers from one cheap
//     `docker ps -a` (sub-second, zero TrueNAS API load) — real docker states
//     ('running', 'exited', …), so a caller can watch specific containers
//     through a start/stop transition. The optional `names` request field
//     restricts the result to a subset of container names. An EMPTY map is
//     valid (no containers at all) and distinct from failure (null → 502).
//   - 'vmStates': the live state of ALL VM guests from one cheap `virsh list`
//     over SSH — real libvirt states ('running', 'shut off', …), so the VMs
//     page can watch specific guests through a start/stop transition. Same
//     `names` selection + empty-map semantics as containerStates.
// Unknown keys are ignored; an empty/absent list means "the default set".
// ---------------------------------------------------------------------------
const PROBE_KEYS = new Set(['containerStats', 'containerStates', 'vmStates']);

app.post('/probe', probeHandler(async (body: ProbeRequestBody, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  const host = applianceHost(body.managementAddress);
  if (!host) throw new Error('Missing managementAddress');

  // Only the ssh slot counts — the primary username/password must NOT be reused.
  const sshCreds = resolveSshCredentials(body.credentials as Record<string, unknown> | undefined, { slotOnly: true });
  if (!sshCreds) throw new Error('No SSH credential bound — live probe data unavailable');

  // Register the configured SSH port for this host — the probe collectors read it.
  setHostSshPort(host, sshPortOf(settings));

  // Certificate pinning — the probe transmits SSH credentials; verify first.
  await assertPinned(req, host, transportOf(settings), portsOf(settings));

  // Which keys did the caller ask for? Absent/empty = default set. Unknown keys ignored.
  const requested = Array.isArray(body.keys) && body.keys.length > 0 ? body.keys : ['containerStats'];
  const wanted = new Set(requested.filter((k) => PROBE_KEYS.has(k)));
  if (wanted.size === 0) throw new Error(`No supported probe keys in [${requested.join(', ')}]`);

  // Both collectors share the pooled SSH session; run them in parallel when both
  // are requested (two exec channels on one connection).
  const logFn = (level: 'info' | 'warn', message: string) =>
    level === 'warn' ? logger.warn(message, { deviceId: body.deviceId }) : logger.info(message, { deviceId: body.deviceId });
  // Optional container-name selection (state-style keys only — stats always
  // cover everything running). Absent/empty = full collection.
  const nameSel = Array.isArray(body.names) && body.names.length > 0 ? body.names : undefined;

  const [stats, states, vmStates] = await Promise.all([
    wanted.has('containerStats') ? collectProbeStats(host, sshCreds, logFn) : Promise.resolve(null),
    wanted.has('containerStates') ? collectProbeStates(host, sshCreds, logFn, nameSel) : Promise.resolve(null),
    wanted.has('vmStates') ? collectProbeVmStates(host, sshCreds, logFn, nameSel) : Promise.resolve(null),
  ]);

  const metrics: Record<string, unknown> = {};
  if (wanted.has('containerStats')) {
    if (!stats || stats.size === 0) throw new Error('SSH docker stats probe returned no data');
    // Flat map keyed by container NAME — the webapp joins it onto its rows.
    const flat: Record<string, ProbeContainerStat> = {};
    for (const [name, s] of stats) flat[name] = s;
    metrics['containerStats'] = flat;
  }
  if (wanted.has('containerStates')) {
    // null = SSH failure → 502 (webapp keeps last good data); an EMPTY map is a
    // valid answer (all containers stopped) and must reach the caller.
    if (!states) throw new Error('SSH docker ps probe returned no data');
    const flat: Record<string, ProbeContainerState> = {};
    for (const [name, s] of states) flat[name] = s;
    metrics['containerStates'] = flat;
  }
  if (wanted.has('vmStates')) {
    // Same semantics as containerStates — null → 502, empty map is valid.
    if (!vmStates) throw new Error('SSH virsh list probe returned no data');
    const flat: Record<string, ProbeVmState> = {};
    for (const [name, s] of vmStates) flat[name] = s;
    metrics['vmStates'] = flat;
  }

  return { collectedAt: new Date().toISOString(), metrics };
}, 'ix-truenas-plugin'));

// ---------------------------------------------------------------------------
// POST /filesystem — generic, root-scoped SFTP file manager (capability
// 'filesystem'). The webapp's Storage page browses a dataset's contents and the
// Containers page browses a container volume mount; both drive this ONE endpoint
// through the API broker. The caller passes `context` describing WHAT to browse:
//   { kind: 'dataset', name }            → root = that dataset's live mountpoint
//                                         (resolved via pool.dataset.query)
//   { kind: 'container-volume', source, target? }
//                                        → root = the volume's HOST path (a bind
//                                          mount's source, or a named docker
//                                          volume under /var/lib/docker/volumes)
// Every subsequent `path` is resolved RELATIVE to that root and confined to it —
// a webapp-supplied relative path can never walk out of the scoped tree (the SDK
// rejects `..` traversal + root escape). Requires a bound ssh slot.
// Ops: list | read | stat | write | mkdir | rmdir | unlink | rename.
// ---------------------------------------------------------------------------

/** Process-wide SFTP session pool — one connection per host+root, reused across requests. */
const fsSftpPool = createSftpPool();
process.on('SIGTERM', () => fsSftpPool.closeAll());
process.on('SIGINT', () => fsSftpPool.closeAll());

/** Resolves a dataset's live mountpoint via pool.dataset.query (handles both the
 * flattened and legacy property shapes). Returns null when the dataset is not found. */
async function resolveDatasetMountpoint(
  client: TruenasClient,
  creds: TruenasCredentials,
  name: string
): Promise<string | null> {
  // No server-side filter — reuse the exact call shape the monitoring poll already
  // uses successfully (filter formats are version-sensitive), then match by name.
  const rows = await client.call<Record<string, unknown>[]>('pool.dataset.query', [], creds, 20_000);
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const d = rows.find((r) => pickString(r, ['name']) === name) ?? null;
  if (!d) return null;
  // A zvol is a block device — not browsable as a directory tree.
  const dsType = typeof d['type'] === 'string' ? (d['type'] as string).toLowerCase() : '';
  if (dsType === 'volume') return null;
  const mp = propOf(d, 'mountpoint');
  const mpVal = mp?.value ?? (typeof d['mountpoint'] === 'string' ? d['mountpoint'] : undefined);
  if (typeof mpVal === 'string' && mpVal !== 'legacy' && mpVal !== 'unmounted') return mpVal;
  return null; // unmounted / no mountpoint — nothing to browse
}

/** Maps a container-volume context onto the HOST path that holds its data. */
function volumeHostPath(source: string): string {
  if (!source) throw new Error('container-volume context requires a non-empty source');
  // Named docker volumes live under /var/lib/docker/volumes/<name>/_data; bind
  // mounts are already absolute host paths (or relative to the compose dir — we
  // only accept absolute sources, which is what `docker inspect` reports).
  if (source.startsWith('/')) return source;
  return `/var/lib/docker/volumes/${source}/_data`;
}

app.post(
  '/filesystem',
  filesystemHandler(async (body: FilesystemRequestBody, req): Promise<FilesystemResponseBody> => {
    const settings = readSettings(req, PLUGIN_OPTIONS);
    logger.setEnabled(settings.logToApi === true);

    const host = sshHostOf(body.managementAddress);
    if (!host) throw new Error('Missing managementAddress');

    // Only the bound ssh slot counts — the primary username/password must NOT be reused.
    const sshCreds = resolveSshCredentials(body.credentials as Record<string, unknown> | undefined, { slotOnly: true });
    if (!sshCreds) throw new Error('No SSH credential bound — filesystem browsing unavailable');

    // Register the configured SSH port for this host (the SFTP session below uses it).
    setHostSshPort(host, sshPortOf(settings));

    // Certificate pinning — SFTP transmits credentials; verify first.
    await assertPinned(req, body.managementAddress, transportOf(settings), portsOf(settings));

    // Resolve the SFTP root from the caller's context (what to browse).
    const ctx = body.context ?? {};
    let root: string;
    const kind = typeof ctx['kind'] === 'string' ? (ctx['kind'] as string) : '';
    if (kind === 'dataset') {
      const name = pickString(ctx, ['name']);
      if (!name) throw new Error('dataset context requires a "name"');
      // The mountpoint is resolved over the appliance's RPC socket — that uses the
      // PRIMARY credential (username/password or API key), NOT the ssh slot.
      const apiKeyUsername = typeof settings.apiKeyUsername === 'string' ? settings.apiKeyUsername.trim() : '';
      const { creds, error: credError } = resolveCredentials(body.credentials as Record<string, unknown> | undefined, apiKeyUsername);
      if (!creds) throw new Error(credError ?? 'Missing appliance credentials');
      const client = getClient(host, transportOf(settings), 5000, portsOf(settings));
      const mp = await resolveDatasetMountpoint(client, creds, name);
      if (!mp) throw new Error(`Dataset "${name}" is not mounted (or is a zvol) — nothing to browse`);
      root = mp;
    } else if (kind === 'container-volume') {
      const source = pickString(ctx, ['source']);
      root = volumeHostPath(source ?? '');
    } else {
      throw new Error(`Unsupported filesystem context kind "${kind || '(none)'}" — expected "dataset" or "container-volume"`);
    }

    // One pooled SFTP session per host+root; every path is confined to `root`.
    // The dynamic host-key verifier pins the SSH handshake against UNM's inventory.
    const fsPort = resolveSshPort(settings.sshPort);
    const session = await fsSftpPool.get(host, fsPort, sshCreds, { root, timeoutMs: 30_000, hostKeyVerifier: dynamicSshHostVerifier(host, fsPort) });
    const op = body.op;
    const relPath = typeof body.path === 'string' ? body.path : '';

    switch (op) {
      case 'list': {
        const abs = session.resolve(relPath);
        const r = await session.list(abs, sshCreds);
        return { collectedAt: new Date().toISOString(), path: r.path, entries: r.entries.map((e) => ({ name: e.name, isDirectory: e.isDirectory, sizeBytes: e.sizeBytes, mtimeMs: e.mtimeMs })) };
      }
      case 'stat': {
        const abs = session.resolve(relPath);
        const s = await session.stat(abs, sshCreds);
        return { collectedAt: new Date().toISOString(), path: abs, isDirectory: s.isDirectory, sizeBytes: s.sizeBytes, mtimeMs: s.mtimeMs };
      }
      case 'read': {
        const abs = session.resolve(relPath);
        const buf = await session.readFile(abs, sshCreds);
        return { collectedAt: new Date().toISOString(), path: abs, contentBase64: buf.toString('base64'), sizeBytes: buf.length };
      }
      case 'write': {
        if (typeof body.contentBase64 !== 'string') throw new Error('write requires contentBase64');
        const abs = session.resolve(relPath);
        await session.writeFile(abs, Buffer.from(body.contentBase64, 'base64'), sshCreds);
        return { collectedAt: new Date().toISOString(), path: abs };
      }
      case 'mkdir': {
        if (!relPath) throw new Error('mkdir requires a path');
        const abs = session.resolve(relPath);
        await session.mkdir(abs, sshCreds, body.parents === true);
        return { collectedAt: new Date().toISOString(), path: abs };
      }
      case 'rmdir': {
        if (!relPath) throw new Error('rmdir requires a path');
        const abs = session.resolve(relPath);
        await session.rmdir(abs, sshCreds);
        return { collectedAt: new Date().toISOString(), path: abs };
      }
      case 'unlink': {
        if (!relPath) throw new Error('unlink requires a path');
        const abs = session.resolve(relPath);
        await session.unlink(abs, sshCreds);
        return { collectedAt: new Date().toISOString(), path: abs };
      }
      case 'rename': {
        if (!relPath || typeof body.targetPath !== 'string' || !body.targetPath) throw new Error('rename requires path + targetPath');
        const from = session.resolve(relPath);
        const to = session.resolve(body.targetPath);
        await session.rename(from, to, sshCreds);
        return { collectedAt: new Date().toISOString(), path: to };
      }
      default:
        throw new Error(`Unsupported filesystem op "${op}"`);
    }
  }, 'ix-truenas-plugin')
);

// ---------------------------------------------------------------------------
// POST /plan — builds an execution plan for an intent across a device batch.
// v1 has no multi-device intents: single-device actions fan out to one step
// per device. The API persists the returned steps + provisionRequests and the
// plan executor dispatches each step to /config.
// ---------------------------------------------------------------------------
app.post('/plan', async (req, res) => {
  const body = req.body ?? {};
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);

  const planReq: PlanRequest = {
    intent: {
      actionId: typeof body.intent?.actionId === 'string' ? body.intent.actionId : '',
      inputs: (body.intent?.inputs && typeof body.intent.inputs === 'object' ? body.intent.inputs : {}) as Record<string, unknown>,
    },
    devices: Array.isArray(body.devices)
      ? (body.devices as PlanRequest['devices']).map((d) => ({
          deviceId: String(d.deviceId),
          managementAddress: String(d.managementAddress ?? ''),
          credentials: d.credentials,
        }))
      : [],
  };

  try {
    const plan = await buildPlan(planReq);
    res.status(200).json({ plan });
  } catch (err) {
    if (err instanceof PlanningError) {
      logger.error(`Planning ${planReq.intent.actionId} failed: ${err.message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
      res.status(400).json({ error: err.message });
      return;
    }
    const message = errMsg(err);
    logger.error(`Planning ${planReq.intent.actionId} failed unexpectedly: ${message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
    res.status(500).json({ error: message });
  }
});

// ---------------------------------------------------------------------------
// Startup — bind the port + start mDNS advertising (SDK handles both).
// ---------------------------------------------------------------------------
server.listen();
