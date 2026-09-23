import { Router, Request, Response } from 'express';
import { and, asc, eq, inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';

const router = Router();

/** One device + site display view (mirrors networks.ts). */
interface DeviceView {
  id: string;
  name: string;
  managementAddress: string;
  siteName: string | null;
}

async function loadDeviceViews(deviceIds: string[]): Promise<Map<string, DeviceView>> {
  const map = new Map<string, DeviceView>();
  if (deviceIds.length === 0) return map;
  const devices = await db.query.devices.findMany({ where: inArray(schema.devices.id, deviceIds) });
  const siteIds = Array.from(new Set(devices.map((d) => d.siteId).filter((s): s is string => !!s)));
  const sites = siteIds.length > 0 ? await db.query.sites.findMany({ where: inArray(schema.sites.id, siteIds) }) : [];
  const siteNameById = new Map(sites.map((s) => [s.id, s.name] as const));
  for (const d of devices) {
    map.set(d.id, {
      id: d.id,
      name: d.name,
      managementAddress: d.managementAddress,
      siteName: d.siteId ? (siteNameById.get(d.siteId) ?? null) : null,
    });
  }
  return map;
}

async function loadPluginNames(pluginIds: string[]): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  if (pluginIds.length === 0) return map;
  const plugins = await db.query.plugins.findMany({ where: inArray(schema.plugins.id, pluginIds) });
  for (const p of plugins) map.set(p.id, p.name);
  return map;
}

/** Result of the shared device-scoping logic: either "no visible devices" (the
 * caller responds with an empty array) or a WHERE clause to apply. */
type MailWhereResult = { kind: 'none' } | { kind: 'ok'; where?: unknown };

/**
 * Resolves the WHERE clause shared by all three mail endpoints. Returns
 * `{kind:'none'}` when a scoped caller has no visible devices (caller responds
 * with []). The optional extra clauses are AND-ed in after the device scoping.
 */
async function buildMailWhere(
  req: Request,
  identityCol: { deviceId: unknown },
  extraClauses: (unknown | undefined)[] = []
): Promise<MailWhereResult> {
  const { deviceId, siteId } = req.query as Record<string, string | undefined>;

  const allowed = await allowedDeviceIds(req);
  if (allowed !== null && allowed.size === 0) return { kind: 'none' };
  if (deviceId && allowed !== null && !allowed.has(deviceId)) return { kind: 'none' };

  const clauses = [...extraClauses].filter(Boolean);
  if (deviceId && siteId) {
    const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
    if (!device || device.siteId !== siteId) return { kind: 'none' };
    clauses.push(eq(identityCol.deviceId as never, deviceId));
  } else if (deviceId) {
    clauses.push(eq(identityCol.deviceId as never, deviceId));
  } else if (siteId) {
    let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
    if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
    if (deviceIds.length === 0) return { kind: 'none' };
    clauses.push(inArray(identityCol.deviceId as never, deviceIds));
  } else {
    if (allowed !== null) clauses.push(inArray(identityCol.deviceId as never, [...allowed]));
  }

  return { kind: 'ok', where: clauses.length > 0 ? and(...(clauses as [never, ...never[]])) : undefined };
}

// GET /mail/domains — all mail domains across devices (Mail page).
router.get('/mail/domains', requireAuth, requirePermission('mail:read'), async (req, res: Response) => {
  try {
    const result = await buildMailWhere(req, schema.mailDomains);
    if (result.kind === 'none') {
      res.status(200).json([]);
      return;
    }

    const rows = await db.query.mailDomains.findMany({
      ...(result.where ? { where: result.where as never } : {}),
      orderBy: [asc(schema.mailDomains.deviceId), asc(schema.mailDomains.domain)],
    });

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId)))),
      loadPluginNames(Array.from(new Set(rows.map((r) => r.pluginId)))),
    ]);

    res.status(200).json(
      rows.map((r) => {
        const device = deviceViews.get(r.deviceId);
        return {
          ...r,
          deviceName: device?.name ?? null,
          managementAddress: device?.managementAddress ?? null,
          siteName: device?.siteName ?? null,
          pluginName: pluginNames.get(r.pluginId) ?? null,
        };
      })
    );
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /mail/mailboxes — all mailboxes across devices. Optional `domain` filter.
router.get('/mail/mailboxes', requireAuth, requirePermission('mail:read'), async (req, res: Response) => {
  try {
    const { domain } = req.query as Record<string, string | undefined>;
    const result = await buildMailWhere(
      req,
      schema.mailMailboxes,
      [domain ? eq(schema.mailMailboxes.domain, domain) : undefined]
    );
    if (result.kind === 'none') {
      res.status(200).json([]);
      return;
    }

    const rows = await db.query.mailMailboxes.findMany({
      ...(result.where ? { where: result.where as never } : {}),
      orderBy: [asc(schema.mailMailboxes.deviceId), asc(schema.mailMailboxes.domain), asc(schema.mailMailboxes.localPart)],
    });

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId)))),
      loadPluginNames(Array.from(new Set(rows.map((r) => r.pluginId)))),
    ]);

    res.status(200).json(
      rows.map((r) => {
        const device = deviceViews.get(r.deviceId);
        return {
          ...r,
          deviceName: device?.name ?? null,
          managementAddress: device?.managementAddress ?? null,
          siteName: device?.siteName ?? null,
          pluginName: pluginNames.get(r.pluginId) ?? null,
        };
      })
    );
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /mail/aliases — all aliases across devices. Optional `domain` filter.
router.get('/mail/aliases', requireAuth, requirePermission('mail:read'), async (req, res: Response) => {
  try {
    const { domain } = req.query as Record<string, string | undefined>;
    const result = await buildMailWhere(
      req,
      schema.mailAliases,
      [domain ? eq(schema.mailAliases.domain, domain) : undefined]
    );
    if (result.kind === 'none') {
      res.status(200).json([]);
      return;
    }

    const rows = await db.query.mailAliases.findMany({
      ...(result.where ? { where: result.where as never } : {}),
      orderBy: [asc(schema.mailAliases.deviceId), asc(schema.mailAliases.domain), asc(schema.mailAliases.address)],
    });

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId)))),
      loadPluginNames(Array.from(new Set(rows.map((r) => r.pluginId)))),
    ]);

    res.status(200).json(
      rows.map((r) => {
        const device = deviceViews.get(r.deviceId);
        return {
          ...r,
          deviceName: device?.name ?? null,
          managementAddress: device?.managementAddress ?? null,
          siteName: device?.siteName ?? null,
          pluginName: pluginNames.get(r.pluginId) ?? null,
        };
      })
    );
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
