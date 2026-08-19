import { Router } from 'express';
import { desc, eq } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { getRequiredSecretType } from '../secretsProvider';
import {
  SettingsValidationError,
  getPluginOptions,
  resetPluginSettings,
  upsertPluginSettings,
} from '../pluginSettings';

const router = Router();

function serializePlugin(row: any) {
  return {
    id: row.id,
    name: row.name,
    version: row.version,
    vendors: typeof row.vendors === 'string' ? JSON.parse(row.vendors) : row.vendors,
    capabilities: typeof row.capabilities === 'string' ? JSON.parse(row.capabilities) : row.capabilities,
    endpoint: row.endpoint,
    authType: row.authType,
    lastSeenAt: row.lastSeenAt ?? null,
  };
}

router.get('/plugins', requireAuth, async (_req, res) => {
  const result = await db.query.plugins.findMany({
    orderBy: [desc(schema.plugins.createdAt)],
  });
  res.status(200).json(result.map(serializePlugin));
});

// GET /plugins/:id/required-secret-type - The secret type a device plugin
// expects for its device credentials (read from the plugin's /discover).
router.get('/plugins/:id/required-secret-type', requireAuth, async (req, res) => {
  const { id } = req.params;
  const requiredSecretType = await getRequiredSecretType(id);
  res.status(200).json({ requiredSecretType });
});

// GET /plugins/:id/metrics - The metric descriptors a plugin declared in its
// /discover endpoint. The webapp renders device metrics generically from these
// (gauge/plot/text/table), so new plugins/metrics need no webapp changes.
router.get('/plugins/:id/metrics', requireAuth, async (req, res) => {
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

// --- Plugin options & settings ---------------------------------------------
// Plugins declare typed option descriptors in /discover (cached on the
// plugins row). The API is the single authority for validation + persistence;
// the webapp renders a generic form from these descriptors.

// GET /plugins/:id/options - descriptors + current overrides + effective values.
router.get('/plugins/:id/options', requireAuth, async (req, res) => {
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
