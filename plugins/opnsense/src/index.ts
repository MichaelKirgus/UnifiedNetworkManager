import express from 'express';
import cors from 'cors';
import { getSystemStatus, getInterfaces, applyConfig } from './opnsenseClient';

const PORT = Number(process.env.PORT ?? 4001);

const app = express();
app.use(cors());
app.use(express.json());

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok' });
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
    const interfaces = await getInterfaces(managementAddress, apiKey, apiSecret);
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

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[opnsense-plugin] listening on port ${PORT}`);
});
