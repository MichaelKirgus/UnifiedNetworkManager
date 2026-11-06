/**
 * UNM FreeRADIUS management plugin (capability `radius`).
 *
 * Companion to the `unm-radius` sidecar service (FreeRADIUS 3.x for WiFi
 * EAP-TLS). The sidecar itself is driven entirely by the API — which renders
 * clients/eap/sql/site config into a shared volume and SIGHUPs radiusd on
 * change — so this plugin deliberately adds NO control surface of its own:
 * no reload/restart/test-auth actions, no new network endpoints beyond the
 * SDK's standard /healthz + /discover. Its job is to ADVERTISE capability
 * `radius`: the Certificates page gates its "WiFi (EAP-TLS) client
 * certificates" section on at least one loaded plugin advertising this
 * capability, and the CA enrollment flow issues client certs that only make
 * sense when a RADIUS server exists on the instance.
 *
 * Why no sidecar liveness probe: a RADIUS server IGNORES requests from any
 * source IP not in its clients.conf allowlist (verified live — radiusd logs
 * "Ignoring request … from unknown client" and sends NO reply). The plugin's
 * container is not an authorized NAS, so a UDP :1812 probe can never receive
 * a response and would report a healthy sidecar as unreachable forever.
 * Process liveness of the sidecar is covered by its compose healthcheck
 * (pgrep freeradius) + docker restart policy; config correctness by the API's
 * render path (which validates before writing). If operational tooling later
 * needs reload/test-auth, that requires an authenticated control channel in
 * the sidecar — a deliberate follow-up, not something to bolt on here.
 */

import path from 'node:path';
import type { Health } from '@unm/plugin-sdk';
import { FREERADIUS_DEVICE_SUPPORT } from './deviceSupport';
import { createPluginLogger, createPluginServer, resolvePluginIdentity } from '@unm/plugin-sdk';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000017';
export const PLUGIN_NAME = 'FreeRADIUS (WiFi EAP-TLS)';

const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  description:
    "Companion to the unm-radius sidecar — advertises RADIUS support for WiFi EAP-TLS client certificates issued by UNM's CA.",
  version: '0.1.0',
  vendors: ['unm'],
  capabilities: ['radius'],
});

const server = createPluginServer({
  identity,
  logTag: 'freeradius-plugin',
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    requiredSecretType: null, // global service — no device credentials
    metrics: [],
    options: [],
    deviceSupport: FREERADIUS_DEVICE_SUPPORT,
  },
});

// Structured logs shipped to the API (boot errors). Kept for future actions.
const logger = createPluginLogger(identity);

/** POST /monitoring — no device-facing work; reports this service's health. */
server.app.post('/monitoring', (_req, res) => {
  const health: Health = 'ok';
  res.status(200).json({
    collectedAt: new Date().toISOString(),
    health,
    metrics: {},
    metricDescriptors: [],
  });
});

server.listen().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('[freeradius-plugin] failed to start HTTP server:', err.message);
  process.exit(1);
});
