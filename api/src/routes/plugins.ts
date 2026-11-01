import { Router } from 'express';
import { pluginAxios } from '../utils/pluginHttp';
import { desc, eq } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { getRequiredSecretTypes } from '../secretsProvider';
import { dispatchPluginAction } from '../utils/pluginDispatch';
import { resolvePluginEndpoint } from '../utils/pluginEndpoint';
import type { DeviceModelEntry } from '../types/deviceModels';
import type { DeviceSupport } from '../types/deviceSupport';
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

/** Parses a stored deviceSupport JSON column (never throws). */
function parseDeviceSupport(raw: unknown): DeviceSupport | null {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? (parsed as DeviceSupport) : null;
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
    // Short catalog description (see schema.plugins.description) — rendered by
    // the webapp's plugin picker under the display name; null when undeclared.
    description: typeof row.description === 'string' && row.description.length > 0 ? row.description : null,
    version: row.version,
    // Build tag baked into the image at CI build time (branch/release); null =
    // local/dev build or not advertised. Shown on the Plugins page next to version.
    buildTag: typeof row.buildTag === 'string' && row.buildTag.length > 0 ? row.buildTag : null,
    vendors: typeof row.vendors === 'string' ? JSON.parse(row.vendors) : row.vendors,
    capabilities: typeof row.capabilities === 'string' ? JSON.parse(row.capabilities) : row.capabilities,
    endpoint: row.endpoint,
    authType: row.authType,
    iconUrl: row.iconUrl ?? null,
    deviceModels,
    credentialSlots: parseCredentialSlots(row.credentialSlots),
    deviceSupport: parseDeviceSupport(row.deviceSupport),
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
    // mTLS state (Stage 1): true when discovery last confirmed this plugin is
    // serving TLS on its endpoint. Drives the Certificates page's "mtls" rows
    // and gates the re-enroll button on the Plugins page.
    tlsLive: !!row.tlsLive,
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
  const id = String(req.params.id ?? '');
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
    const upstream = await pluginAxios(row.endpoint).get(path, {
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
    console.warn(`[plugins] icon proxy failed for ${id} (${path}): ${e.message ?? 'unknown error'}`);
    res.status(502).json({ error: 'Failed to fetch icon from plugin' });
  }
});

// GET /plugins/:id/asset - Proxies a static TEXT asset served by the plugin
// itself (LICENSE.md, docs/*.md — see deviceSupport.license.file / docPath).
// Deliberately UNAUTHENTICATED like the icon proxy so <pre>/<img>-style loads
// work without a token; the path is validated to stay within the plugin's own
// origin and only text-ish content types are forwarded (no binary blobs).
router.get('/plugins/:id/asset', async (req, res) => {
  const id = String(req.params.id ?? '');
  const row = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, id),
  });
  if (!row) {
    res.status(404).json({ error: 'Plugin not found' });
    return;
  }

  const requested = typeof req.query.path === 'string' ? req.query.path : '';
  // Default to the plugin's documented docPath when no explicit path is given.
  let support: DeviceSupport | null = null;
  if (typeof row.deviceSupport === 'string' && row.deviceSupport.length > 0) {
    try {
      const parsed = JSON.parse(row.deviceSupport);
      support = parsed && typeof parsed === 'object' ? (parsed as DeviceSupport) : null;
    } catch {
      support = null;
    }
  }
  const path = safeIconPath(requested || support?.docPath || '');
  if (!path) {
    res.status(404).json({ error: 'No asset requested (and the plugin advertises no default doc)' });
    return;
  }

  try {
    const upstream = await pluginAxios(row.endpoint).get(`/assets${path}`, {
      timeout: 5_000,
      maxContentLength: 1_024 * 1_024, // docs are small; cap at 1 MiB
    });
    const contentType = (upstream.headers['content-type'] as string | undefined) ?? 'text/plain';
    if (!/^text\//.test(contentType)) {
      res.status(415).json({ error: `Asset is not text content (${contentType})` });
      return;
    }
    // Static per plugin version — let the browser cache it.
    res.set('Content-Type', contentType);
    res.set('Cache-Control', 'public, max-age=300');
    res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    res.status(200).send(upstream.data as string);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    if (e.status === 404 || e.status === 403) {
      res.status(404).json({ error: 'Asset not found on plugin' });
      return;
    }
    // eslint-disable-next-line no-console
    console.warn(`[plugins] asset proxy failed for ${id} (${path}): ${e.message ?? 'unknown error'}`);
    res.status(502).json({ error: 'Failed to fetch asset from plugin' });
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

// POST /plugins/:id/tls/renew - Force the plugin to enroll a FRESH mTLS leaf
// (same ACME account, new serial) and swap its live TLS listener. The old leaf
// stays valid until its expiry — this is rotation, not revocation. Gated on
// ca:manage (it's a CA operation). Only works for plugins whose SDK build
// serves POST /tls/renew (mTLS-enabled images); older images answer 404 and we
// surface that as a clear error.
router.post('/plugins/:id/tls/renew', requireAuth, requirePermission('ca:manage'), async (req, res) => {
  const id = String(req.params.id ?? '');
  try {
    const row = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, id) });
    if (!row) {
      res.status(404).json({ error: 'Plugin not found' });
      return;
    }
    // mTLS (Stage 1): pluginAxios picks the transport — a TLS-live plugin is
    // reached over https with our client cert, which /tls/renew requires anyway.
    const res2 = await pluginAxios(row.endpoint).post(
      '/tls/renew',
      {},
      { timeout: 30_000, headers: { 'x-plugin-api-key': process.env.PLUGIN_API_KEY ?? '' } }
    );
    // The SDK answers 200 { ok: true } on success; the registry row is refreshed
    // by the next /metrics poll (tlsCert carries the new serial).
    res.status(200).json({ renewed: true, ...(res2.data ?? {}) });
  } catch (err) {
    const e = err as { response?: { status?: number; data?: { error?: string } }; message?: string };
    if (e.response?.status === 404) {
      res.status(501).json({ error: 'This plugin image does not support re-enrollment (rebuild it with the current SDK)' });
      return;
    }
    if (e.response?.status === 403) {
      res.status(502).json({ error: 'Plugin rejected the request (plugin API key mismatch?)' });
      return;
    }
    console.warn(`[plugins] tls/renew failed for ${id}: ${e.message ?? String(err)}`);
    res.status(502).json({ error: `Re-enrollment failed: ${e.response?.data?.error ?? e.message ?? 'unknown error'}` });
  }
});

// GET /plugins/:id/required-secret-type - The secret type(s) a device plugin
// expects for its PRIMARY credentials (read from the plugin's /discover), plus
// any additional named credential slots it declares (drives per-slot pickers).
// `requiredSecretTypes` carries the full list when a plugin accepts several
// types (e.g. usernamePassword OR sshKeyPair); `requiredSecretType` stays for
// older consumers.
router.get('/plugins/:id/required-secret-type', requireAuth, requirePermission('plugins:read'), async (req, res) => {
  const id = String(req.params.id ?? '');
  const [secretTypes, row] = await Promise.all([
    getRequiredSecretTypes(id),
    db.query.plugins.findFirst({ where: eq(schema.plugins.id, id) }),
  ]);
  res.status(200).json({
    requiredSecretType: secretTypes.requiredSecretType,
    requiredSecretTypes: secretTypes.requiredSecretTypes,
    credentialSlots: parseCredentialSlots(row?.credentialSlots),
  });
});

// GET /plugins/:id/metrics - The metric descriptors a plugin declared in its
// /discover endpoint. The webapp renders device metrics generically from these
// (gauge/plot/text/table), so new plugins/metrics need no webapp changes.
router.get('/plugins/:id/metrics', requireAuth, requirePermission('plugins:read'), async (req, res) => {
  const id = String(req.params.id ?? '');
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
  const id = String(req.params.id ?? '');
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
    orderBy: [desc(schema.pluginMetrics.sampledAt)],
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
  const id = String(req.params.id ?? '');
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

// POST /plugins/:id/actions/execute - run ONE single-device READ action against a
// device's assignment and return its result. This is the "peek" path for pages
// that need live appliance data without creating a plan (e.g. the Containers
// page reading a custom app's current compose YAML before editing it). ONLY
// catalog entries with riskLevel 'read' may be executed here — write/dangerous
// actions MUST flow through the plan workflow (2FA + audit trail), so this route
// can never mutate a device. Gated by containers:read (the page that uses it);
// the read-only restriction is enforced against the persisted catalog, not the
// caller's claim.
router.post('/plugins/:id/actions/execute', requireAuth, requirePermission('containers:read'), async (req, res) => {
  const id = String(req.params.id ?? '');
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : '';
  const actionId = typeof body.actionId === 'string' ? body.actionId : '';
  const input = (body.input && typeof body.input === 'object' && !Array.isArray(body.input)) ? (body.input as Record<string, unknown>) : {};

  if (!deviceId || !actionId) {
    res.status(400).json({ error: 'deviceId and actionId are required' });
    return;
  }

  const row = await db.query.plugins.findFirst({ where: (plugins, { eq }) => eq(plugins.id, id) });
  if (!row) {
    res.status(404).json({ error: 'Plugin not found' });
    return;
  }
  let actions: Array<{ id?: string; riskLevel?: string; deviceCount?: number | 'N' }> = [];
  try {
    const parsed = row.actionDescriptors ? JSON.parse(row.actionDescriptors) : [];
    actions = Array.isArray(parsed) ? (parsed as typeof actions) : [];
  } catch {
    actions = [];
  }
  const entry = actions.find((a) => a.id === actionId);
  if (!entry || entry.deviceCount !== 1) {
    res.status(400).json({ error: `Unknown single-device action: ${actionId}` });
    return;
  }
  // Hard read-only gate — the persisted catalog is authoritative.
  if (entry.riskLevel !== 'read') {
    res.status(403).json({ error: `Action "${actionId}" is not a read action and must run through the plan workflow` });
    return;
  }

  const out = await dispatchPluginAction(deviceId, id, actionId, input);
  if (!out.ok) {
    res.status(502).json({ error: out.error ?? 'Action failed' });
    return;
  }
  // The plugin's ActionResult — `details` carries the payload (e.g. the YAML).
  const result = out.result ?? {};
  const details = (result.details ?? {}) as Record<string, unknown>;
  if (result.success === false) {
    res.status(409).json({ error: typeof details.error === 'string' ? details.error : 'Action reported failure', details });
    return;
  }
  res.status(200).json({ details });
});

// --- Plugin options & settings ---------------------------------------------
// Plugins declare typed option descriptors in /discover (cached on the
// plugins row). The API is the single authority for validation + persistence;
// the webapp renders a generic form from these descriptors.

// GET /plugins/:id/options - descriptors + current overrides + effective values.
router.get('/plugins/:id/options', requireAuth, requirePermission('plugins:read'), async (req, res) => {
  const id = String(req.params.id ?? '');
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
  const id = String(req.params.id ?? '');
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
  const id = String(req.params.id ?? '');
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
