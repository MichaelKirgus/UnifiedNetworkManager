/**
 * Shared device/plugin display loaders for the cross-device inventory views
 * (mail, networks+hosts, security-checks, updates). Previously each of those
 * routes re-implemented this pair verbatim — one owner now.
 */

import { inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';

/** One device + site display view. */
export interface DeviceView {
  id: string;
  name: string;
  managementAddress: string;
  siteName: string | null;
}

/**
 * Batch-loads device + site display data for the given ids. Returns a map of
 * deviceId -> view (missing devices are simply absent — stale rows are swept
 * by the worker, but a delete race must not break the response).
 */
export async function loadDeviceViews(deviceIds: string[]): Promise<Map<string, DeviceView>> {
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

/** Batch-loads plugin display names for the given ids. */
export async function loadPluginNames(pluginIds: string[]): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  if (pluginIds.length === 0) return map;
  const plugins = await db.query.plugins.findMany({ where: inArray(schema.plugins.id, pluginIds) });
  for (const p of plugins) map.set(p.id, p.name);
  return map;
}
