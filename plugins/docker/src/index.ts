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
  clampInt,
  createPluginLogger,
  createPluginServer,
  errorDescriptor,
  gaugeMetric,
  readSettings,
  resolvePluginIdentity,
  textMetric,
} from '@unm/plugin-sdk';

import { DockerClientOptions, DockerTlsMaterial, engineVersion, listContainers, listImages } from './client';
import { buildContainerRows, buildImageRows, ContainerRow as UnmContainerRow, DockerContainerRaw, DockerImageRaw, ImageRow } from './rows';

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
  version: '0.1.0',
  vendors: ['generic'],
  capabilities: ['monitoring'],
});

// --- Options --------------------------------------------------------------------
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'transport',
    label: 'Transport',
    type: 'string' as const,
    default: 'auto',
    pattern: '^(auto|tcp|tls|socket)$',
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
];

// --- Metric descriptors -----------------------------------------------------------
const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  gaugeMetric('docker.containers.running', 'Containers running', { group: 'Docker', min: 0, summary: true }),
  gaugeMetric('docker.containers.stopped', 'Containers stopped', { group: 'Docker', min: 0 }),
  textMetric('docker.version', 'Engine version', { group: 'Docker' }),
];

// --- Pre-wired server ---------------------------------------------------------------
const server = createPluginServer({
  identity,
  logTag: 'docker-plugin',
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
    ],
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
    deviceModels: [{ vendor: 'generic', model: 'Docker Host' }],
  },
});
const app = server.app;

// --- Structured logging ---------------------------------------------------------------
const logger = createPluginLogger(identity);

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

/** One full collection: version + container list + image inventory → UNM rows. */
async function collect(opts: DockerClientOptions): Promise<{
  health: Health;
  error?: string;
  rows: UnmContainerRow[];
  /** null = the /images/json call failed (key omitted from metrics — no wipe). */
  images: ImageRow[] | null;
  running: number;
  stopped: number;
  engineVersionText: string | null;
}> {
  const version = await engineVersion(opts);
  if (!version.ok) {
    return { health: 'critical', error: `Docker Engine unreachable via ${version.transportUsed ?? opts.transport}: ${version.error || `HTTP ${version.status}`}`, rows: [], images: null, running: 0, stopped: 0, engineVersionText: null };
  }

  // Containers are the core of this plugin; the image inventory is a best-
  // effort extra (a failure must not fail the poll or wipe previously seen rows).
  const [list, imagesRes] = await Promise.all([listContainers(opts), listImages(opts)]);
  if (!list.ok) {
    return { health: 'critical', error: `/containers/json failed (HTTP ${list.status}): ${JSON.stringify(list.data ?? '').slice(0, 200)}`, rows: [], images: null, running: 0, stopped: 0, engineVersionText: version.data?.Version ?? null };
  }

  const raw = Array.isArray(list.data) ? (list.data as DockerContainerRaw[]) : [];
  const rows = buildContainerRows(raw);
  let running = 0;
  let stopped = 0;
  for (const r of rows) {
    if (r.state === 'RUNNING') running++;
    else stopped++;
  }

  let images: ImageRow[] | null = null;
  if (imagesRes.ok && Array.isArray(imagesRes.data)) {
    images = buildImageRows(imagesRes.data as DockerImageRaw[]);
  }

  return {
    health: 'ok',
    rows,
    images,
    running,
    stopped,
    engineVersionText: version.data?.Version ? `Docker ${version.data.Version}` : null,
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

  try {
    const result = await collect({
      host: managementAddress,
      transport: transport as DockerClientOptions['transport'],
      tcpPort: port,
      tlsPort: 2376,
      localSocketPath,
      tls: tlsMaterialFromCredentials(body.credentials),
    });

    if (result.error) {
      logger.warn(`Docker poll for ${managementAddress} failed: ${result.error}`, { deviceId, context: { host: managementAddress } });
      return fail(result.health, result.error);
    }

    const metrics: Record<string, unknown> = {
      // The generic containers[] key — ingested by the API's telemetry worker
      // into the cross-device `containers` table. Emitted even when empty so a
      // host that loses all containers clears its rows (authoritative wipe).
      containers: result.rows,
      'docker.containers.running': result.running,
      'docker.containers.stopped': result.stopped,
    };
    if (result.engineVersionText) metrics['docker.version'] = result.engineVersionText;
    // The generic images[] key — ingested into the cross-device `docker_images`
    // table (Containers page → collapsible images panel). Emitted even when
    // empty so a host that removes all images clears its rows; omitted entirely
    // when the /images/json call itself failed (no wipe on transport errors).
    if (result.images !== null) metrics['images'] = result.images;

    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health: result.health,
      metrics,
      metricDescriptors: METRIC_DESCRIPTORS,
    });
  } catch (err) {
    logger.error(`Monitoring poll for ${managementAddress} failed: ${(err as Error).message}`, { deviceId, context: { host: managementAddress } });
    return fail('critical', `Monitoring failed: ${(err as Error).message}`);
  }
});

// listen() binds the conventional plugin port (4080 by default; override with
// the PORT env var) and starts mDNS advertising — both handled by the SDK.
server.listen().catch((err) => {
  console.error('[docker-plugin] fatal startup error:', err);
  process.exit(1);
});
