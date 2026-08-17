import express from 'express';
import cors from 'cors';
import { Bonjour } from 'bonjour-service';
import { getSystemStatus, getInterfaces, applyConfig } from './opnsenseClient';

export const PLUGIN_UUID = 'b0e6c8a2-4f1e-4a3d-9c7b-1a2b3c4d5e6f';
export const PLUGIN_NAME = 'OPNsense Plugin';
export const PLUGIN_VERSION = '0.1.0';
export const PLUGIN_VENDORS = ['opnsense'];
export const PLUGIN_CAPABILITIES = ['monitoring', 'configuration', 'inventory'];
export const PLUGIN_AUTH_TYPE = 'none';

const PORT = Number(process.env.PORT ?? 4001);
const ADVERTISED_ENDPOINT = process.env.ADVERTISED_ENDPOINT ?? `http://localhost:${PORT}`;

const app = express();
app.use(cors());
app.use(express.json());

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

/**
 * Plugin identity endpoint. The UnifiedNetworkManager API can poll this
 * endpoint (as a fallback to mDNS discovery) to discover and upsert this
 * plugin. Returns the full, self-describing identity of this plugin.
 */
app.get('/discover', (_req, res) => {
  res.status(200).json({
    uuid: PLUGIN_UUID,
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    vendors: PLUGIN_VENDORS,
    capabilities: PLUGIN_CAPABILITIES,
    endpoint: ADVERTISED_ENDPOINT,
    authType: PLUGIN_AUTH_TYPE,
    // The secret type this plugin expects for device credentials. The API
    // broker reads this to filter which secrets/providers are applicable to
    // devices managed by this plugin.
    requiredSecretType: 'apiKey',
  });
});

type Health = 'ok' | 'warning' | 'critical' | 'unknown';

/**
 * Flattens numeric-looking fields from an arbitrary OPNsense API payload into
 * a flat metrics map, matching the UnifiedNetworkManager TelemetrySnapshot
 * `metrics: { [key: string]: number }` shape. Non-numeric fields are ignored.
 */
function extractMetrics(data: unknown, prefix = ''): Record<string, number> {
  const metrics: Record<string, number> = {};
  if (data === null || typeof data !== 'object') {
    return metrics;
  }

  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    const metricKey = prefix ? `${prefix}.${key}` : key;
    if (typeof value === 'number') {
      metrics[metricKey] = value;
    } else if (typeof value === 'string' && value.trim() !== '' && !Number.isNaN(Number(value))) {
      metrics[metricKey] = Number(value);
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      Object.assign(metrics, extractMetrics(value, metricKey));
    }
  }

  return metrics;
}

app.post('/monitoring', async (req, res) => {
  const { deviceId, apiKey, apiSecret, managementAddress } = req.body ?? {};

  try {
    const status = await getSystemStatus(managementAddress, apiKey, apiSecret);

    let health: Health = 'unknown';
    if (status.ok) {
      health = 'ok';
    } else if (status.status >= 500 || status.status === 0) {
      health = 'critical';
    } else {
      health = 'warning';
    }

    const metrics = extractMetrics(status.data);

    res.status(200).json({
      deviceId: deviceId ?? null,
      collectedAt: new Date().toISOString(),
      health,
      metrics,
    });
  } catch (err) {
    res.status(200).json({
      deviceId: deviceId ?? null,
      collectedAt: new Date().toISOString(),
      health: 'critical',
      metrics: {},
      error: (err as Error).message,
    });
  }
});

app.post('/config', async (req, res) => {
  const { action, payload, apiKey, apiSecret, managementAddress } = req.body ?? {};

  try {
    const result = await applyConfig({ action, payload }, managementAddress, apiKey, apiSecret);
    res.status(200).json({
      success: result.ok,
      result: { status: result.status, data: result.data },
    });
  } catch (err) {
    res.status(200).json({
      success: false,
      result: { error: (err as Error).message },
    });
  }
});

app.get('/inventory', async (req, res) => {
  const { apiKey, apiSecret, managementAddress } = req.query ?? {};

  try {
    const mAddress = typeof managementAddress === 'string' ? managementAddress : '';
    const mApiKey = typeof apiKey === 'string' ? apiKey : '';
    const mApiSecret = typeof apiSecret === 'string' ? apiSecret : '';

    const interfaces = await getInterfaces(mAddress, mApiKey, mApiSecret);
    const items = interfaces.data && typeof interfaces.data === 'object' ? interfaces.data : {};

    res.status(200).json({
      capability: 'inventory',
      collectedAt: new Date().toISOString(),
      interfaces: Object.entries(items as Record<string, unknown>).map(([name, details]) => ({
        name,
        details,
      })),
    });
  } catch (err) {
    res.status(200).json({
      capability: 'inventory',
      collectedAt: new Date().toISOString(),
      interfaces: [],
      error: (err as Error).message,
    });
  }
});

/**
 * Advertises this plugin over mDNS/DNS-SD so the UnifiedNetworkManager API
 * can discover it automatically. Uses service type `_unm-plugin._tcp`.
 *
 * mDNS multicast may be isolated by Docker bridge networks, so this is a
 * best-effort advertisement; the API also polls known plugin endpoints as a
 * fallback.
 */
function startMdnsAdvertising(): void {
  try {
    const bonjour = new Bonjour();
    bonjour.publish({
      name: PLUGIN_NAME,
      type: 'unm-plugin',
      port: PORT,
      txt: {
        uuid: PLUGIN_UUID,
        name: PLUGIN_NAME,
        version: PLUGIN_VERSION,
        vendors: PLUGIN_VENDORS.join(','),
        capabilities: PLUGIN_CAPABILITIES.join(','),
        endpoint: ADVERTISED_ENDPOINT,
        authType: PLUGIN_AUTH_TYPE,
      },
    });
    // eslint-disable-next-line no-console
    console.log(`[opnsense-plugin] advertising via mDNS as "${PLUGIN_NAME}" (${PLUGIN_UUID})`);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[opnsense-plugin] mDNS advertising unavailable, falling back to polling discovery only:', (err as Error).message);
  }
}

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[opnsense-plugin] listening on port ${PORT}`);
  startMdnsAdvertising();
});