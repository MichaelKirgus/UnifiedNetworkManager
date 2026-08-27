/**
 * UnifiedNetworkManager plugin TEMPLATE — a minimal, complete monitoring plugin.
 *
 * Copy this folder to `plugins/<your-plugin>/`, rename the package in
 * package.json + Dockerfile, then follow docs/PLUGIN-DEVELOPMENT.md:
 *   1. Give it a real UUID (crypto.randomUUID()) and name below.
 *   2. Implement collect() against your device's API.
 *   3. Register it in docker-compose.yml (+ the api's PLUGIN_POLL_ENDPOINTS).
 *
 * Everything boring — identity/multi-instance resolution, the express app with
 * /healthz + /discover, mDNS advertising, settings-header parsing, metric
 * descriptor factories, input validation, plan finalization, counter-rate
 * tracking and TTL caching — comes from @unm/plugin-sdk. This file only
 * declares WHAT the plugin is and registers its own routes.
 */

import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  clampInt,
  createPluginLogger,
  createPluginServer,
  errorDescriptor,
  readSettings,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';

// --- Identity -----------------------------------------------------------------
// The UUID is the plugin's primary key in the API — generate ONE and never
// change it (crypto.randomUUID()). Multi-instance support (PLUGIN_INSTANCE_ID /
// PLUGIN_DISPLAY_NAME) is handled by resolvePluginIdentity.
const identity = resolvePluginIdentity({
  uuid: '00000000-0000-4000-8000-0000000000ff', // ← REPLACE with a real UUID
  name: 'Template Plugin', // ← REPLACE
  version: '0.1.0',
  vendors: ['generic'], // ← REPLACE — must match deviceModels[].vendor
  capabilities: ['monitoring'], // add 'inventory' | 'configuration' | 'planning' as implemented
});

// --- Options --------------------------------------------------------------------
// Declared in /discover so the API persists user-set values and injects them
// back via the `x-unm-settings` header on every call — the plugin never stores
// settings itself (see readSettings()).
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'pollIntervalSeconds',
    label: 'Poll interval (seconds)',
    type: 'integer' as const,
    default: 30,
    min: 5,
    max: 600,
    description: 'How often the plugin re-collects from the device.',
  },
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (poll failures, config/plan errors) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
  },
];

// --- Metric descriptors -----------------------------------------------------------
// The webapp renders metrics FROM these — no per-plugin UI code is needed.
const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  { key: 'system.example', label: 'Example metric', type: 'number', visualization: 'gauge', group: 'System', min: 0, max: 100 },
];

// --- Pre-wired server ---------------------------------------------------------------
// cors + json + /healthz + /discover (+ static icons at /icons if you add an
// iconsDir) come from the SDK; mDNS advertising starts on listen(). The API
// discovers this plugin via mDNS or by polling its endpoint.
const server = createPluginServer({
  identity,
  logTag: 'template-plugin', // console prefix
  jsonLimit: '100kb', // raise to e.g. '32mb' if /config results carry base64 backups
  // iconsDir: path.join(__dirname, '../../icons'), // uncomment + add an icons/ folder
  discovery: {
    // Secret type this plugin expects for device credentials (null = none).
    requiredSecretType: null,
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
    // actions: listCatalog(),   // only when implementing /config + a registry
    // modules: listModules(),   // optional grouping hint
    // iconUrl: '/icons/template.svg',
    // deviceModels: DEVICE_MODELS, // optional Model/Firmware dropdown catalog
  },
});
const app = server.app;

// --- Structured logging ---------------------------------------------------------------
// createPluginLogger batches entries in memory and POSTs them to the API's
// internal POST /plugin/logs endpoint (fire-and-forget, drop-on-failure —
// logging never breaks a poll). Emission is gated per call by the `logToApi`
// option via setEnabled() below; it flows through the settings loop, so it
// works globally and per-device with zero extra plumbing. See docs/PLUGIN-DEVELOPMENT.md.
const logger = createPluginLogger(identity);

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
  const pollIntervalSeconds = clampInt(settings.pollIntervalSeconds, 5, 600, 30);

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

  if (!managementAddress.trim()) return fail('critical', 'No target address — set the device management address.');

  try {
    // TODO: replace with a real collection against your device.
    const metrics: Record<string, unknown> = {
      'system.example': 42,
      // Inventory propagation (optional): the API ingests these keys into its
      // Networks/Hosts pages — see docs/PLUGIN-DEVELOPMENT.md for the row shapes.
      // networks: [{ name, ip, vlanId?, status? }],
      // macTable: [{ mac, intf }],
    };

    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health: 'ok',
      metrics,
      metricDescriptors: METRIC_DESCRIPTORS,
      // Echo back the effective settings — proof of the API→plugin loop.
      activeSettings: { pollIntervalSeconds },
    });
  } catch (err) {
    // Log to the API AND keep console output for container logs.
    logger.error(`Monitoring poll for ${managementAddress} failed: ${(err as Error).message}`, { deviceId, context: { host: managementAddress } });
    return fail('critical', `Monitoring failed: ${(err as Error).message}`);
  }
});

// listen() binds the conventional plugin port (4080 by default; override with
// the PORT env var) and starts mDNS advertising — both handled by the SDK.
server.listen().catch((err) => {
  console.error('[template-plugin] fatal startup error:', err);
  process.exit(1);
});
