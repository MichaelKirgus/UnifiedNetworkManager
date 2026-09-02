import { Router } from 'express';
import axios from 'axios';
import { desc, eq } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { getRequiredSecretType } from '../secretsProvider';
import { resolvePluginEndpoint } from '../utils/pluginEndpoint';
import type { DeviceModelEntry } from '../types/deviceModels';
import { CredentialSlotDescriptor, normalizeCredentialSlots } from '../types/credentialSlots';
import {
  SettingsValidationError,
  getPluginOptions,
  resetPluginSettings,
  upsertPluginSettings,
} from '../pluginSettings';

const router = Router();

/** Parses a stored credentialSlots JSON column (never throws). */
function parseCredentialSlots(raw: unknown): CredentialSlotDescriptor[] | null {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  try {
    const parsed = normalizeCredentialSlots(JSON.parse(raw));
    return parsed ?? null;
  } catch {
    return null;
  }
}

function serializePlugin(row: any) {
  let deviceModels: DeviceModelEntry[] | null = null;
  if (typeof row.deviceModels === 'string' && row.deviceModels.length > 0) {
    try {
      const parsed = JSON.parse(row.deviceModels);
      deviceModels = Array.isArray(parsed) ? parsed : null;
    } catch {
      deviceModels = null;
    }
  }
  return {
    id: row.id,
    name: row.name,
    version: row.version,
    vendors: typeof row.vendors === 'string' ? JSON.parse(row.vendors) : row.vendors,
    capabilities: typeof row.capabilities === 'string' ? JSON.parse(row.capabilities) : row.capabilities,
    endpoint: row.endpoint,
    authType: row.authType,
    iconUrl: row.iconUrl ?? null,
    deviceModels,
    credentialSlots: parseCredentialSlots(row.credentialSlots),
    // Number of metric descriptors the plugin declared in /discover — the
    // "how many metrics can this plugin emit" figure for the Plugins page.
    declaredMetricCount: (() => {
      if (typeof row.metricDescriptors !== 'string' || row.metricDescriptors.length === 0) return null;
      try {
        const parsed = JSON.parse(row.metricDescriptors);
        return Array.isArray(parsed) ? parsed.length : null;
      } catch {
        return null;
      }
    })(),
    lastSeenAt: row.lastSeenAt ?? null,
  };
}

/** Validates an icon path coming from the webapp (query param) or /discover. */
function safeIconPath(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  const p = raw.trim();
  // Reject absolute URLs (scheme), protocol-relative, and path traversal.
  if (/^[a-z][a-z0-9+.-]*:/i.test(p) || p.startsWith('//') || p.includes('..')) return null;
  return p.startsWith('/') ? p : `/${p}`;
}

// GET /plugins/:id/icon - Proxies an icon served by the plugin itself.
// The plugin advertises its icon path in /discover (`iconUrl`); per-model icons
// are requested via the optional `path` query param (from the deviceModels
// catalog). Deliberately UNAUTHENTICATED so plain <img> tags work without a
// token; the path is validated to stay within the plugin's own origin.
router.get('/plugins/:id/icon', async (req, res) => {
  const { id } = req.params;
  const row = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, id),
  });
  if (!row) {
    res.status(404).json({ error: 'Plugin not found' });
    return;
  }

  const requested = typeof req.query.path === 'string' ? req.query.path : '';
  const path = safeIconPath(requested || row.iconUrl);
  if (!path) {
    res.status(404).json({ error: 'Plugin has no icon (and the requested path is invalid)' });
    return;
  }

  try {
    const endpoint = resolvePluginEndpoint(row.endpoint).replace(/\/+$/, '');
    const upstream = await axios.get(`${endpoint}${path}`, {
      timeout: 5_000,
      responseType: 'arraybuffer',
      maxContentLength: 1_024 * 1_024, // icons are small; cap at 1 MiB
    });
    const data = upstream.data as ArrayBuffer;
    if (!data || data.byteLength === 0) {
      res.status(404).json({ error: 'Plugin returned an empty icon' });
      return;
    }
    const contentType = (upstream.headers['content-type'] as string | undefined) ?? 'application/octet-stream';
    // Icons are static per plugin version — let the browser cache them.
    res.set('Content-Type', contentType);
    res.set('Cache-Control', 'public, max-age=300');
    // The webapp loads these via plain <img> tags from a different origin/port
    // (Vite dev :5173 → API :3000). Without CORP, Chrome blocks the cross-site
    // subresource load even though the route is unauthenticated.
    res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    res.status(200).send(Buffer.from(data));
  } catch (err) {
    const e = err as { status?: number; message?: string };
    // Upstream 404/403 → the icon simply doesn't exist there.
    if (e.status === 404 || e.status === 403) {
      res.status(404).json({ error: 'Icon not found on plugin' });
      return;
    }
    // eslint-disable-next-line no-console
    console.warn(`[plugins] icon proxy failed for ${id} (${path}):`, e.message);
    res.status(502).json({ error: 'Failed to fetch icon from plugin' });
  }
});

// All plugin read routes require plugins:read (the Plugins page + the
// reference data it feeds — device forms, plan creation, DeviceDetail).
router.get('/plugins', requireAuth, requirePermission('plugins:read'), async (_req, res) => {
  const result = await db.query.plugins.findMany({
    orderBy: [desc(schema.plugins.createdAt)],
  });
  res.status(200).json(result.map(serializePlugin));
});

// GET /plugins/:id/required-secret-type - The secret type a device plugin
// expects for its device credentials (read from the plugin's /discover), plus
// any additional named credential slots it declares (drives per-slot pickers).
router.get('/plugins/:id/required-secret-type', requireAuth, requirePermission('plugins:read'), async (req, res) => {
  const { id } = req.params;
  const [requiredSecretType, row] = await Promise.all([
    getRequiredSecretType(id),
    db.query.plugins.findFirst({ where: (plugins, { eq }) => eq(plugins.id, id) }),
  ]);
  res.status(200).json({ requiredSecretType, credentialSlots: parseCredentialSlots(row?.credentialSlots) });
});

// GET /plugins/:id/metrics - The metric descriptors a plugin declared in its
// /discover endpoint. The webapp renders device metrics generically from these
// (gauge/plot/text/table), so new plugins/metrics need no webapp changes.
router.get('/plugins/:id/metrics', requireAuth, requirePermission('plugins:read'), async (req, res) => {
  const { id } = req.params;
  const row = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, id),
  });
  if (!row) {
    res.status(404).json({ error: 'Plugin not found' });
    return;
  }
  let metrics: unknown[] = [];
  if (row.metricDescriptors) {
    try {
      const parsed = JSON.parse(row.metricDescriptors);
      metrics = Array.isArray(parsed) ? parsed : [];
    } catch {
      metrics = [];
    }
  }
  res.status(200).json({ pluginId: id, metrics });
});

// GET /plugins/:id/self-metrics - Runtime health samples of the plugin process
// itself (CPU%, memory, event-loop lag, poll duration/error rate, emitted
// metric count, log queue depth), collected by workers/pluginMetrics.ts from
// the plugin's auto-mounted GET /metrics endpoint. `latest` is the most recent
// sample; `history` carries up to `limit` samples newest-first for sparklines.
router.get('/plugins/:id/self-metrics', requireAuth, requirePermission('plugins:read'), async (req, res) => {
  const { id } = req.params;
  const row = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, id),
  });
  if (!row) {
    res.status(404).json({ error: 'Plugin not found' });
    return;
  }

  const rawLimit = Number(req.query.limit ?? 120); // default: last hour at the 30s poll cadence
  const limit = Math.min(Math.max(Number.isFinite(rawLimit) ? Math.floor(rawLimit) : 120, 1), 576);

  const samples = await db.query.pluginMetrics.findMany({
    where: (metrics, { eq }) => eq(metrics.pluginId, id),
    orderBy: [desc(schema.pluginMetrics.timestamp)],
    limit,
  });

  res.status(200).json({
    pluginId: id,
    latest: samples[0] ?? null,
    history: samples,
  });
});

// GET /plugins/:id/actions - The action catalog a plugin declared in its
// /discover endpoint (single-device actions + multi-device intents with input
// schemas). Drives plan creation: the webapp renders intent/step forms from it.
router.get('/plugins/:id/actions', requireAuth, requirePermission('plugins:read'), async (req, res) => {
  const { id } = req.params;
  const row = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, id),
  });
  if (!row) {
    res.status(404).json({ error: 'Plugin not found' });
    return;
  }
  let actions: unknown[] = [];
  if (row.actionDescriptors) {
    try {
      const parsed = JSON.parse(row.actionDescriptors);
      actions = Array.isArray(parsed) ? parsed : [];
    } catch {
      actions = [];
    }
  }
  res.status(200).json({ pluginId: id, actions });
});

// --- Plugin options & settings ---------------------------------------------
// Plugins declare typed option descriptors in /discover (cached on the
// plugins row). The API is the single authority for validation + persistence;
// the webapp renders a generic form from these descriptors.

// GET /plugins/:id/options - descriptors + current overrides + effective values.
router.get('/plugins/:id/options', requireAuth, requirePermission('plugins:read'), async (req, res) => {
  const { id } = req.params;
  try {
    const view = await getPluginOptions(id);
    res.status(200).json(view);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// PUT /plugins/:id/settings - validate + persist overrides (all-or-nothing).
router.put('/plugins/:id/settings', requireAuth, requirePermission('plugins:manage'), async (req, res) => {
  const { id } = req.params;
  const settings = (req.body ?? {}).settings as Record<string, unknown> | undefined;
  if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
    res.status(400).json({ error: "Body must be { \"settings\": { [key]: value } }" });
    return;
  }
  try {
    await upsertPluginSettings(id, settings);
    const view = await getPluginOptions(id);
    res.status(200).json(view);
  } catch (err) {
    if (err instanceof SettingsValidationError) {
      res.status(400).json({ error: err.message, fieldErrors: err.fieldErrors });
      return;
    }
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// DELETE /plugins/:id/settings - reset all overrides to descriptor defaults.
router.delete('/plugins/:id/settings', requireAuth, requirePermission('plugins:manage'), async (req, res) => {
  const { id } = req.params;
  try {
    await resetPluginSettings(id);
    const view = await getPluginOptions(id);
    res.status(200).json(view);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
