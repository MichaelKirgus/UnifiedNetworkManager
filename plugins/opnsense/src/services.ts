/**
 * Services inventory for the cross-device Services page (OPNsense).
 *
 * Source of truth is the appliance's own service registry: GET /api/core/service/search
 * returns every rc-managed service with its running state (`status`: "running" |
 * "stopped") and a human description. That endpoint is what OPNsense's System →
 * Services UI uses, so the page mirrors exactly what an admin sees on the box.
 *
 * Best-effort enrichment over SSH (only when an `ssh` slot is bound): FreeBSD's
 * `rcctl get status <name>` gives a more precise state ("started" / "not running")
 * and can catch services whose API status lags after a restart. A missing slot or
 * any failure simply keeps the API-level rows unchanged — never an error.
 */

import type { AxiosInstance } from 'axios';
import type { ServiceRow } from '@unm/plugin-sdk';
import { searchServices } from './client/system';

/** Normalizes one core/service/search row into a unified ServiceRow.
 * Row shape (OPNsense Core Api/ServiceController::searchAction): { id, locked,
 * running: 1|0, description, name } — `id` is the service name plus an optional
 * "/instance" suffix ("dnsmasq/lan"), so it is the stable per-instance identity. */
function normalizeServiceRow(r: Record<string, unknown>): ServiceRow | null {
  const baseName = typeof r['name'] === 'string' ? (r['name'] as string).trim() : '';
  // Prefer `id` — it disambiguates multi-instance services (dnsmasq lan/wan);
  // fall back to the bare name when absent.
  const id = typeof r['id'] === 'string' && (r['id'] as string).trim() !== '' ? (r['id'] as string).trim() : baseName;
  if (!id) return null;

  let status: ServiceRow['status'];
  // Current shape: `running` is a 1/0 flag. Older releases may carry a `status`
  // text instead — tolerate both defensively.
  const runningFlag = r['running'];
  if (typeof runningFlag === 'number' || typeof runningFlag === 'boolean') {
    status = runningFlag ? 'running' : 'stopped';
  } else {
    const s = typeof r['status'] === 'string' ? (r['status'] as string).trim().toLowerCase() : '';
    if (s === 'running') status = 'running';
    else if (s === 'stopped' || s === 'not running') status = 'stopped';
    else status = 'unknown';
  }

  return {
    name: id,
    type: 'freebsd-rc',
    status,
    enabled: null, // the API doesn't expose boot-enablement per service
    pid: null,
    description: typeof r['description'] === 'string' && (r['description'] as string).trim() !== '' ? (r['description'] as string).trim() : null,
  };
}

/**
 * Collects every rc-managed service with its running state. THROWS when the
 * endpoint fails (the caller then stores null → /monitoring omits the key, so a
 * transient outage never wipes previously stored rows). Returns [] only for a
 * successful call that genuinely reports zero services — an empty array IS
 * authoritative on the API side (delete-on-absent at ingest).
 */
export async function collectServices(client: AxiosInstance): Promise<ServiceRow[]> {
  const res = await searchServices(client);
  if (!res.ok || !res.data) throw new Error(`core/service/search failed (HTTP ${res.status})`);
  // core/service/search wraps the list in a recordset ({ rows: [...] }); older
  // releases may return a bare array or an object keyed by service name.
  let rawRows: unknown[];
  const d = res.data as Record<string, unknown>;
  if (Array.isArray(d['rows'])) {
    rawRows = d['rows'] as unknown[];
  } else if (Array.isArray(res.data)) {
    rawRows = res.data as unknown[];
  } else if (d && typeof d === 'object') {
    rawRows = Object.values(d);
  } else {
    return [];
  }
  const rows: ServiceRow[] = [];
  for (const r of rawRows) {
    if (!r || typeof r !== 'object') continue;
    const row = normalizeServiceRow(r as Record<string, unknown>);
    if (row) rows.push(row);
  }
  return rows;
}
