/**
 * UnifiedNetworkManager — generic Docker monitoring plugin.
 *
 * Monitors any Docker host through the Docker Engine REST API and emits the
 * GENERIC `containers[]` metric (docs/PLUGIN-DEVELOPMENT.md §5) — so containers
 * appear on the existing Containers page (App → Container → Volumes tree,
 * Image/Tag columns) with zero API or webapp changes. One UNM device = one
 * Docker endpoint; compose projects group into "Apps", standalone containers
 * become single-container rows.
 *
 * Transports (per-device `transport` option): tcp://2375 (trusted LANs),
 * tls://2376 with client certs from a bound `dockerTls` secret slot, or the
 * local unix socket when UNM runs on the same host (socket mounted into this
 * container). See src/client.ts.
 */

import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  PlanRequest,
  ProbeRequestBody,
  StateItem,
  StateRequestBody,
  StateSection,
  clampInt,
  isTransientTransportError,
  collectGpuRows,
  createNotifier,
  createPluginLogger,
  createPluginServer,
  errorDescriptor,
  gaugeMetric,
  probeHandler,
  readSettings,
  resolvePluginIdentity,
  resolveSshCredentials,
  stateHandler,
  textMetric,
  validateInput,
} from '@unm/plugin-sdk';
import { DOCKER_DEVICE_SUPPORT } from './deviceSupport';
import path from 'node:path';

import { DockerClientOptions, DockerTlsMaterial, engineVersion, listContainers, listImages } from './client';
import { buildContainerRows, buildImageRows, ComposeProjectSummary, ContainerRow as UnmContainerRow, DockerContainerRaw, DockerImageRaw, ImageRow, summarizeComposeProjects } from './inventory';
import { registry as actionRegistry, sshPool, DockerActionContext } from './actions';
import { buildPlan, PlanningError } from './plan';
import { collectProbeStats, collectProbeStates, ProbeContainerStat, ProbeContainerState } from './probe';
import { mirrorDockerContainers, ContainerCondition } from './notifications';

// --- Identity -----------------------------------------------------------------
export const PLUGIN_UUID = '00000000-0000-4000-8000-00000000000b';
export const PLUGIN_NAME = 'Docker Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run
 * several instances of the same plugin type — each advertises a distinct
 * identity so the API registers them as separate plugins.
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  // 0.4.0 — containers.deploy-compose deploys a NEW compose stack on the host
  // (docker compose up -d via an optional ssh slot; the Engine API has no
  // classic compose endpoint), powering the Containers page's Create-app dialog.
  // On top of 0.3.0 (per-container start/stop/restart/delete-one) and 0.2.0
  // (app-level actions + image delete via the Engine API, short-cycle POST /probe).
  // 0.4.1 — clone support: rows carry extra.portMappings (full host→container
  // mappings) and containers.run-image accepts optional volumes[] + network,
  // so the webapp can duplicate a single-container app with new mounts/network.
  // 0.5.0 — containers.logs.read: per-container log output via the Engine API
  // (GET /containers/{id}/logs, multiplexed stream demuxed in-process) — no SSH needed.
  // 0.5.1 — probe key `containerStates` now reports REAL per-container docker
  // states (/containers/json?all=true) instead of just the running set, and
  // honors an optional `names` selection so a page can watch specific
  // containers at a tighter cadence (e.g. right after start/stop).
  // 0.6.0 — image management for the Containers page image panel: images.pull
  // {refs[]} (POST /images/create), images.update {refs[], restart?} (re-pull +
  // optionally restart every running container using one of those refs) and
  // images.prune {all?} (POST /images/prune). Same generic contract as the
  // Generic SSH plugin — the webapp's image buttons are catalog-gated.
  // 0.7.0 — notification-center mirroring: non-running containers (exited /
  // dead / paused / created) push a stable per-container bell entry that clears
  // automatically when the container recovers or disappears, gated by the new
  // `notifyAlerts` option. The self-healing 'restarting' state is NOT mirrored
  // so deploys don't flap the center; metrics-only polls pass null (anti-flap).
  // 0.7.1 — docker.containers.running/stopped now count REAL containers and are
  // emitted on EVERY poll: a cheap /containers/json?all=true runs each cycle
  // (the probe already does this every few seconds), so the device page's gauge
  // cards no longer read 0/0 between inventory polls. Previously they counted
  // APP ROWS (compose projects) and were absent on metrics-only polls — a host
  // with one big stack showed "1 running" at best, "0" most of the time. Row +
  // image building stays deferred to inventory-due polls only.
  // 0.8.0 — compose project gauges: docker.compose.projects / .running count
  // distinct com.docker.compose.project labels and docker.compose.projects.list
  // renders a per-project status line ("name running (27/29)"). Pure in-memory
  // grouping over the container list already fetched every poll — no extra
  // Engine API calls, so it is as cheap as the v0.7.1 container gauges.
  // 0.9.0 — GPU inventory + live metrics: emits the generic `gpus[]` metric at
  // the inventory cadence via a shared SDK probe script (PCI enumeration catches
  // NVIDIA/AMD/Intel incl. enabled iGPUs; nvidia-smi / rocm-smi add util, VRAM,
  // temp, power and core clocks) run over an OPTIONAL bound ssh slot — the Engine
  // API exposes no host-GPU endpoint. Gated by the new `collectGpus` option,
  // DEFAULT OFF: most Docker hosts are GPU-less servers/VMs, so off = zero SSH
  // traffic and the key is omitted entirely (no wipe).
  version: '0.9.0',
  vendors: ['generic'],
  capabilities: ['monitoring', 'configuration', 'planning', 'deviceState', 'probe'],
});

// --- Options --------------------------------------------------------------------
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'transport',
    label: 'Transport',
    type: 'string' as const,
    default: 'auto',
    enumOptions: ['auto', 'tcp', 'tls', 'socket'],
    description:
      "How to reach the Docker daemon. auto = try plain TCP (port below), then TLS 2376 when a dockerTls secret is bound. tcp = unauthenticated TCP (trusted networks only). tls = client-cert TLS on port 2376 (bind a 'Docker TLS Client Certificates' secret to the device). socket = unix socket of the daemon running on THIS host (mount /var/run/docker.sock into the plugin container).",
  },
  {
    key: 'port',
    label: 'TCP port',
    type: 'integer' as const,
    default: 2375,
    min: 1,
    max: 65535,
    description: 'Port for the tcp transport (Docker default 2375). TLS uses 2376 unless the device address already carries an explicit port.',
  },
  {
    key: 'localSocketPath',
    label: 'Local socket path',
    type: 'string' as const,
    default: '/var/run/docker.sock',
    description: "Unix socket used by the `socket` transport — inside this plugin container. Only relevant when transport=socket.",
  },
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (poll failures) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
  },
  {
    key: 'notifyAlerts',
    label: 'Mirror stopped containers to notification center',
    type: 'boolean' as const,
    default: true,
    description:
      "Push non-running containers (exited / dead / paused / created) into UNM's notification center. Entries clear automatically when the container recovers or disappears. The transient 'restarting' state is never mirrored.",
  },
  {
    key: 'collectGpus',
    label: 'Collect GPU data (requires SSH slot)',
    type: 'boolean' as const,
    default: false,
    description:
      "Enumerate the host's GPUs (NVIDIA / AMD / Intel, incl. enabled iGPUs) and read live counters via nvidia-smi / rocm-smi during inventory polls — over an OPTIONAL bound ssh slot, since the Engine API has no host-GPU endpoint. OFF by default: most Docker hosts are GPU-less servers/VMs; off = zero SSH traffic.",
  },
];

// --- Metric descriptors -----------------------------------------------------------
const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  gaugeMetric('docker.containers.running', 'Containers running', { group: 'Docker', min: 0, summary: true }),
  gaugeMetric('docker.containers.stopped', 'Containers stopped', { group: 'Docker', min: 0 }),
  gaugeMetric('docker.compose.projects', 'Compose projects', { group: 'Docker', min: 0 }),
  gaugeMetric('docker.compose.projects.running', 'Projects running', { group: 'Docker', min: 0 }),
  textMetric('docker.compose.projects.list', 'Compose project status', { group: 'Docker' }),
  textMetric('docker.version', 'Engine version', { group: 'Docker' }),
];

// --- Pre-wired server ---------------------------------------------------------------
const server = createPluginServer({
  identity,
  logTag: 'docker-plugin',
  // Static doc/license assets served at /assets/* (proxied by the API's
  // GET /plugins/:id/asset) — referenced from discovery.deviceSupport.
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    // Plain TCP needs no secret; TLS material arrives via the optional slot.
    requiredSecretType: null,
    credentialSlots: [
      {
        name: 'dockerTls',
        secretTypes: ['dockerTls'],
        required: false,
        description:
          "Docker TLS client certificates (CA + cert + key) for the tls transport / auto fallback. Unbound = plain TCP only.",
      },
      {
        name: 'ssh',
        secretTypes: ['usernamePassword', 'sshKeyPair'],
        required: false,
        description:
          'Optional SSH access to the host — needed by containers.deploy-compose (runs `docker compose up -d` on the box; the Engine API has no classic compose endpoint). Unbound = deploy action unavailable.',
      },
    ],
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
    actions: actionRegistry.listCatalog(), // config-capable — /config + /plan below
    deviceModels: [{ vendor: 'generic', model: 'Docker Host' }],
    // License/help/docs metadata for UNM's Plugins page (see ./deviceSupport.ts).
    deviceSupport: DOCKER_DEVICE_SUPPORT,
  },
});
const app = server.app;

// --- Structured logging ---------------------------------------------------------------
const logger = createPluginLogger(identity);

// Notification-center mirroring (SDK fire-and-forget notifier) — enabled/disabled
// per poll from the `notifyAlerts` option, same pattern as logToApi.
const notifier = createNotifier(identity);

// --- /monitoring helpers ----------------------------------------------------------------

/** Reads the optional `dockerTls` slot from the decrypted credentials body. */
function tlsMaterialFromCredentials(credentials: unknown): DockerTlsMaterial | undefined {
  if (!credentials || typeof credentials !== 'object') return undefined;
  const slots = (credentials as Record<string, unknown>)['slots'];
  if (!slots || typeof slots !== 'object') return undefined;
  const slot = (slots as Record<string, unknown>)['dockerTls'];
  if (!slot || typeof slot !== 'object') return undefined;
  const s = slot as Record<string, unknown>;
  const pick = (k: string): string | undefined => (typeof s[k] === 'string' && (s[k] as string).trim() ? (s[k] as string) : undefined);
  const ca = pick('ca');
  const cert = pick('cert');
  const key = pick('key');
  if (!ca && !cert && !key) return undefined;
  return { ca, cert, key };
}

/**
 * Builds a DockerClientOptions from effective settings + the request's
 * management address + decrypted credentials. Shared by /monitoring, /config,
 * /state and /probe so all four resolve transport/port/socket/TLS identically.
 */
function clientOptsFrom(
  req: { body?: unknown },
  settings: Record<string, unknown>,
): DockerClientOptions {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';
  const transport = String(settings.transport ?? 'auto');
  const port = clampInt(Number(settings.port ?? 2375), 1, 65535, 2375);
  return {
    host: managementAddress,
    transport: transport as DockerClientOptions['transport'],
    tcpPort: port,
    tlsPort: 2376,
    localSocketPath: String(settings.localSocketPath || '/var/run/docker.sock'),
    tls: tlsMaterialFromCredentials(body.credentials),
  };
}

/** One full collection: version + container list (+ image inventory on full polls) → UNM rows. */
/**
 * Window-based scheduling: `full=false` on metrics-only polls — the cheap
 * engine liveness/version call AND one /containers/json?all=true run (so the
 * running/stopped gauges stay fresh every cycle and the notification mirror has
 * an authoritative snapshot); row building + image listing (the slow part) are
 * skipped until the next inventory-due poll. The container list is deliberately
 * NOT deferred: it is one cheap call the probe already makes every few seconds,
 * while deferring it made the device page's gauge cards read 0/0 for ~15 min at
 * a time and (previously) miscounted APP ROWS instead of containers.
 */
async function collect(opts: DockerClientOptions, full = true): Promise<{
  health: Health;
  error?: string;
  rows: UnmContainerRow[];
  /** null = not collected (key omitted from metrics — no wipe). */
  images: ImageRow[] | null;
  running: number;
  stopped: number;
  compose: ComposeProjectSummary;
  engineVersionText: string | null;
  /** Non-running containers for notification mirroring. `null` when this poll
   * did NOT take an authoritative container snapshot (a failed /containers/json
   * read) — the mirror must leave its known-set alone. */
  conditions: ContainerCondition[] | null;
}> {
  const version = await engineVersion(opts);
  if (!version.ok) {
    return { health: 'critical', error: `Docker Engine unreachable via ${version.transportUsed ?? opts.transport}: ${version.error || `HTTP ${version.status}`}`, rows: [], images: null, running: 0, stopped: 0, compose: { total: 0, running: 0, entries: [] }, engineVersionText: null, conditions: null };
  }

  // Version + container list in parallel (both cheap). On a full poll the image
  // inventory joins them — it is a best-effort extra whose failure must not fail
  // the poll or wipe previously seen rows.
  const [list, imagesRes] = await Promise.all([
    listContainers(opts),
    full ? listImages(opts) : Promise.resolve(null),
  ]);

  if (!list.ok) {
    // A failed container read is authoritative for NOTHING: gauges are emitted
    // as 0/0 (the daemon answered /_ping, so the host is up — we just couldn't
    // list containers this cycle) and `conditions` stays null so the mirror's
    // known-set is untouched. On a full poll it additionally fails the inventory
    // (rows are not emitted → no wipe of stored rows).
    const engineVersionText = version.data?.Version ? `Docker ${version.data.Version}` : null;
    if (!full) {
      return { health: 'ok', rows: [], images: null, running: 0, stopped: 0, compose: { total: 0, running: 0, entries: [] }, engineVersionText, conditions: null };
    }
    return { health: 'critical', error: `/containers/json failed (HTTP ${list.status}): ${JSON.stringify(list.data ?? '').slice(0, 200)}`, rows: [], images: null, running: 0, stopped: 0, compose: { total: 0, running: 0, entries: [] }, engineVersionText, conditions: null };
  }

  const raw = Array.isArray(list.data) ? (list.data as DockerContainerRaw[]) : [];

  // REAL container counts for the gauge cards — every poll, not app rows.
  let running = 0;
  let stopped = 0;
  for (const c of raw) {
    const state = typeof c?.State === 'string' ? c.State.toLowerCase() : '';
    if (state === 'running') running++;
    else stopped++;
  }

  // Non-running containers worth a bell entry — straight from the raw list so we
  // keep the exit code (the UNM row shape doesn't carry it). 'running' and the
  // self-healing 'restarting' transition are excluded by the mirror itself.
  const conditions: ContainerCondition[] = [];
  for (const c of raw) {
    if (!c || typeof c !== 'object') continue;
    const state = typeof c.State === 'string' ? c.State.toLowerCase() : '';
    if (!state || state === 'running' || state === 'restarting') continue;
    const name = Array.isArray(c.Names) && c.Names.length > 0 ? String(c.Names[0]).replace(/^\/+/, '') : '';
    if (!name) continue;
    conditions.push({ name, state, exitCode: typeof c.ExitCode === 'number' ? c.ExitCode : null });
  }

  // Compose project summary for the device-page gauges — every poll, pure
  // in-memory grouping over the raw list (no extra Engine API calls).
  const compose = summarizeComposeProjects(raw);

  // UNM rows (App → Container tree) only on inventory-due polls — they are the
  // slow part and feed the cross-device `containers` table.
  const rows = full ? buildContainerRows(raw) : [];

  let images: ImageRow[] | null = null;
  if (full && imagesRes?.ok && Array.isArray(imagesRes.data)) {
    images = buildImageRows(imagesRes.data as DockerImageRaw[]);
  }

  return {
    health: 'ok',
    rows,
    images,
    running,
    stopped,
    compose,
    engineVersionText: version.data?.Version ? `Docker ${version.data.Version}` : null,
    conditions,
  };
}

// --- POST /monitoring -----------------------------------------------------------------
/**
 * The API polls this every ~30 s with a HARD 10 s budget. Body (decrypted by
 * the API before forwarding): { deviceId, managementAddress, credentials, model?, firmwareVersion? }.
 * Respond 200 ALWAYS — health problems are reported via `health`, not HTTP errors.
 */
app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  // Effective settings: declared defaults ⊕ user overrides from the header.
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  notifier.setEnabled(settings.notifyAlerts !== false);
  const transport = String(settings.transport ?? 'auto');
  const port = clampInt(Number(settings.port ?? 2375), 1, 65535, 2375);
  const localSocketPath = String(settings.localSocketPath || '/var/run/docker.sock');

  const fail = (health: Health, error: string) => {
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics: { 'system.error': error },
      metricDescriptors: [errorDescriptor()],
      error,
    });
  };

  if (!managementAddress.trim() && transport !== 'socket') {
    return fail('critical', 'No target address — set the device management address (or use transport=socket for a local daemon).');
  }

  // Window-based scheduling: the API sends collectInventory=false on
  // metrics-only polls → liveness + version only, no container/image listing.
  const full = body.collectInventory !== false;

  try {
    const result = await collect({
      host: managementAddress,
      transport: transport as DockerClientOptions['transport'],
      tcpPort: port,
      tlsPort: 2376,
      localSocketPath,
      tls: tlsMaterialFromCredentials(body.credentials),
    }, full);

    if (result.error) {
      logger.warn(`Docker poll for ${managementAddress} failed: ${result.error}`, { deviceId, context: { host: managementAddress } });
      return fail(result.health, result.error);
    }

    const metrics: Record<string, unknown> = {};
    // Real container counts on EVERY poll — the device page renders its gauge
    // cards from the latest telemetry row, so deferring these to inventory polls
    // made them read 0/0 for ~15 min at a time.
    metrics['docker.containers.running'] = result.running;
    metrics['docker.containers.stopped'] = result.stopped;
    // Compose project gauges — same every-poll contract as the container
    // counts above. The list line is "name running (27/29)" per project, so a
    // partially-down stack stays visible at a glance.
    metrics['docker.compose.projects'] = result.compose.total;
    metrics['docker.compose.projects.running'] = result.compose.running;
    metrics['docker.compose.projects.list'] = result.compose.entries.length > 0
      ? result.compose.entries.map((e) => `${e.name} ${e.state.toLowerCase()} (${e.runningContainers}/${e.containers})`).join(', ')
      : '';
    if (full) {
      // The generic containers[] key — ingested by the API's telemetry worker
      // into the cross-device `containers` table. Emitted even when empty so a
      // host that loses all containers clears its rows (authoritative wipe);
      // omitted on metrics-only polls (absent = keep stored rows).
      metrics['containers'] = result.rows;
    }
    // GPUs — the Engine API has NO host-GPU endpoint, so this runs over an
    // OPTIONAL bound ssh slot using the shared SDK probe script (PCI + vendor
    // tools in one round-trip). Gated by `collectGpus` (DEFAULT OFF) and on
    // inventory-due polls only. null = exec failed → omit the key (no wipe);
    // an empty array is authoritative (host genuinely has no GPUs).
    if (full && settings.collectGpus === true) {
      const gpuCreds = resolveSshCredentials(body.credentials as Record<string, unknown> | undefined, { slotOnly: true });
      if (gpuCreds) {
        try {
          const sshHost = managementAddress.trim().replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
          const c = await sshPool.get(sshHost, 22, gpuCreds);
          // Hard cap well under the API's 30 s /monitoring budget — a slow host
          // simply yields no GPU rows this cycle (the pooled session stays open).
          const gpus = await Promise.race([
            collectGpuRows({ exec: (cmd, t) => c.exec(cmd, gpuCreds, t) }),
            new Promise<null>((resolve) => setTimeout(() => resolve(null), 8_000).unref()),
          ]);
          // null = probe failed/timed out → omit (no wipe); an EMPTY array is
          // authoritative — the host genuinely has no GPUs and stale rows clear.
          if (gpus !== null) metrics['gpus'] = gpus;
        } catch {
          /* best-effort — a failed GPU probe must never sink the poll */
        }
      }
    }
    if (result.engineVersionText) metrics['docker.version'] = result.engineVersionText;
    // The generic images[] key — ingested into the cross-device `docker_images`
    // table (Containers page → collapsible images panel). Emitted even when
    // empty so a host that removes all images clears its rows; omitted entirely
    // when the /images/json call itself failed (no wipe on transport errors).
    if (result.images !== null) metrics['images'] = result.images;

    // Notification-center mirroring (gated by `notifyAlerts`): non-running
    // containers get a stable per-container bell entry that clears when the
    // container recovers or disappears. `result.conditions` is null on every
    // non-authoritative path (metrics-only poll, failed read) → the mirror's
    // known-set is left untouched (anti-flap contract).
    if (notifier.enabled && result.conditions !== null) {
      mirrorDockerContainers(notifier, managementAddress || 'local', deviceId, result.conditions);
    }

    // The gpus table descriptor is only advertised when rows exist — the
    // static catalog covers everything else.
    const descriptors = Array.isArray(metrics['gpus']) && (metrics['gpus'] as unknown[]).length > 0
      ? [...METRIC_DESCRIPTORS, { key: 'gpus', label: 'GPUs', type: 'string' as const, visualization: 'table' as const, columns: ['name', 'vendor', 'slot', 'driver', 'driverVersion', 'vramBytes', 'utilPercent', 'tempCelsius'], group: 'GPU' }]
      : METRIC_DESCRIPTORS;

    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health: result.health,
      metrics,
      metricDescriptors: descriptors,
      // Echo back the effective settings we received — proof that the
      // API→plugin settings injection loop works end to end.
      activeSettings: {
        transport,
        port,
        localSocketPath,
        logToApi: settings.logToApi === true,
        notifyAlerts: settings.notifyAlerts !== false,
      },
    });
  } catch (err) {
    logger.error(`Monitoring poll for ${managementAddress} failed: ${(err as Error).message}`, { deviceId, context: { host: managementAddress } });
    return fail('critical', `Monitoring failed: ${(err as Error).message}`);
  }
});

// ---------------------------------------------------------------------------
// POST /config — executes ONE action step against one Docker host. The API's
// config-job worker dispatches here with {actionId, input}; the plugin owns ALL
// logic (schema validation + Engine API call). Same contract as the other
// plugins: 200 + { success, result } on every path.
// ---------------------------------------------------------------------------
app.post('/config', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;

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

  if (!actionId) {
    res.status(400).json({ success: false, result: { error: 'Missing actionId (or legacy "action")' } });
    return;
  }

  const action = actionRegistry.getAction(actionId);
  if (!action) {
    res.status(400).json({ success: false, result: { error: `Unknown action "${actionId}"` } });
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
    const opts = clientOptsFrom(req, settings);
    if (!opts.host.trim() && opts.transport !== 'socket') {
      res.status(200).json({ success: false, result: { error: 'No target address — set the device management address (or use transport=socket for a local daemon).' } });
      return;
    }
    // credentials ride along for SSH-based actions (deploy-compose) — the
    // Engine-API-only actions ignore it.
    const ctx: DockerActionContext = { opts, credentials: body.credentials as Record<string, unknown> | null };
    const result = await action.execute(ctx, input);
    res.status(200).json({ success: result.success, result });
  } catch (err) {
    logger.error(`Config action ${actionId} failed: ${(err as Error).message}`, { deviceId, context: { actionId } });
    // Transport-level failures (daemon unreachable / not ready yet) are
    // transient — the plan executor re-dispatches them per the plan's retry
    // policy. Engine-API errors already come back as ok:false results.
    const retryable = isTransientTransportError(err);
    res.status(200).json({ success: false, result: { error: (err as Error).message, ...(retryable ? { retryable: true } : {}) } });
  }
});

// ---------------------------------------------------------------------------
// POST /plan — builds an execution plan for an intent across a device batch.
// v1 has no multi-device intents: single-device actions fan out to one step per
// device. The API persists the returned steps and the plan executor dispatches
// each step to /config.
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
    const message = (err as Error).message;
    logger.error(`Planning ${planReq.intent.actionId} failed unexpectedly: ${message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
    res.status(500).json({ error: message });
  }
});

// ---------------------------------------------------------------------------
// POST /state — dynamic device-state document for the UNM Config page. The API
// broker calls this with fresh credentials + injected settings and returns the
// response verbatim to the webapp. Best-effort reads: a failing endpoint yields
// an empty section, not an error.
// ---------------------------------------------------------------------------
app.post('/state', stateHandler(async (body: StateRequestBody, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  const opts = clientOptsFrom({ body }, settings);
  if (!opts.host.trim() && opts.transport !== 'socket') throw new Error('Missing managementAddress');

  // Engine version + a container summary. Both best-effort — a failure yields an
  // empty section rather than failing the whole state document.
  const [versionRes, listRes] = await Promise.allSettled([engineVersion(opts), listContainers(opts)]);

  const sections: StateSection[] = [];

  if (versionRes.status === 'fulfilled' && versionRes.value.ok) {
    const v = versionRes.value.data ?? {};
    sections.push({
      id: 'engine',
      label: 'Docker Engine',
      items: [
        { key: 'version', title: `Docker ${v.Version ?? '?'}`, fields: { Version: v.Version ?? null, ApiVersion: v.ApiVersion ?? null, Os: v.Os ?? null, Arch: v.Arch ?? null } },
      ],
    });
  }

  if (listRes.status === 'fulfilled' && listRes.value.ok && Array.isArray(listRes.value.data)) {
    const rows = listRes.value.data as Array<{ Names?: string[]; State?: string; Image?: string }>;
    let running = 0;
    for (const r of rows) if (String(r.State ?? '').toLowerCase() === 'running') running++;
    sections.push({
      id: 'containers',
      label: `Containers (${rows.length} total, ${running} running)`,
      items: rows.slice(0, 200).map((r, i) => {
        const name = Array.isArray(r.Names) && r.Names.length > 0 ? String(r.Names[0]).replace(/^\/+/, '') : `container-${i}`;
        return { key: name, title: name, status: String(r.State ?? 'unknown').toLowerCase(), fields: { Image: r.Image ?? null } };
      }),
    });
  }

  return { collectedAt: new Date().toISOString(), sections };
}, 'docker-plugin'));

// ---------------------------------------------------------------------------
// POST /probe — SHORT-CYCLE live telemetry (capability 'probe'). The webapp's
// Containers page polls this every few seconds through the API broker. Served
// straight from the Engine REST API (no SSH needed):
//   - 'containerStats' (default): per-container CPU/RAM/I-O from a bounded
//     fan-out of /containers/{id}/stats?stream=false; rates come from dedicated
//     probe trackers so fast cycles yield fresh averages.
//   - 'containerStates': the live state of ALL containers from ONE cheap
//     /containers/json?all=true (sub-second) — real docker states ('running',
//     'exited', …), so a caller can watch specific containers through a
//     start/stop transition. The optional `names` request field restricts the
//     result to a subset of container names. An EMPTY map is valid (no
//     containers at all) and distinct from failure (null → 502).
// Unknown keys are ignored; an empty/absent list means "the default set".
// ---------------------------------------------------------------------------
const PROBE_KEYS = new Set(['containerStats', 'containerStates']);

app.post('/probe', probeHandler(async (body: ProbeRequestBody, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  const opts = clientOptsFrom(req, settings);
  if (!opts.host.trim() && opts.transport !== 'socket') throw new Error('Missing managementAddress');

  // Which keys did the caller ask for? Absent/empty = default set. Unknown ignored.
  const requested = Array.isArray(body.keys) && body.keys.length > 0 ? body.keys : ['containerStats'];
  const wanted = new Set(requested.filter((k) => PROBE_KEYS.has(k)));
  if (wanted.size === 0) throw new Error(`No supported probe keys in [${requested.join(', ')}]`);

  // Both collectors share the same transport; run them in parallel when both are
  // requested.
  const logFn = (level: 'info' | 'warn', message: string) =>
    level === 'warn' ? logger.warn(message, { deviceId: body.deviceId }) : logger.info(message, { deviceId: body.deviceId });

  // Optional container-name selection (state-style keys only — stats always
  // cover everything running). Absent/empty = full collection.
  const nameSel = Array.isArray(body.names) && body.names.length > 0 ? body.names : undefined;

  const [stats, states] = await Promise.all([
    wanted.has('containerStats') ? collectProbeStats(opts, logFn) : Promise.resolve(null),
    wanted.has('containerStates') ? collectProbeStates(opts, logFn, nameSel) : Promise.resolve(null),
  ]);

  const metrics: Record<string, unknown> = {};
  if (wanted.has('containerStats')) {
    // null = transport failure → 502 (webapp keeps last good data); an EMPTY map
    // is a valid answer (nothing running) and must reach the caller.
    if (!stats) throw new Error('Docker stats probe returned no data');
    const flat: Record<string, ProbeContainerStat> = {};
    for (const [name, s] of stats) flat[name] = s;
    metrics['containerStats'] = flat;
  }
  if (wanted.has('containerStates')) {
    if (!states) throw new Error('Docker /containers/json probe returned no data');
    const flat: Record<string, ProbeContainerState> = {};
    for (const [name, s] of states) flat[name] = s;
    metrics['containerStates'] = flat;
  }

  return { collectedAt: new Date().toISOString(), metrics };
}, 'docker-plugin'));

// listen() binds the conventional plugin port (4080 by default; override with
// the PORT env var) and starts mDNS advertising — both handled by the SDK.
server.listen().catch((err) => {
  console.error('[docker-plugin] fatal startup error:', err);
  process.exit(1);
});
