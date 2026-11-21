import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * DNS module — DUAL BACKEND. Older OPNsense appliances run dnsmasq for DNS;
 * newer ones use Unbound (the user's fleet note: "in newer installations
 * unbound is used for DNS"). This client exposes one logical surface and
 * dispatches to the active backend, auto-detected per appliance with an
 * optional override.
 */

export type DnsBackend = 'dnsmasq' | 'unbound';

/**
 * Detects which DNS backend the appliance uses: Unbound when its service is
 * enabled (`GET /api/unbound/overview/is_enabled`), otherwise dnsmasq (the
 * historical default). Best-effort — a failing probe falls back to dnsmasq.
 */
export async function detectDnsBackend(client: AxiosInstance): Promise<DnsBackend> {
  try {
    const res = await get<{ enabled?: boolean | string }>(client, '/api/unbound/overview/is_enabled');
    if (res.ok && res.data?.enabled === true) return 'unbound';
    // Verified live on OPNsense 26.4: the flag is serialized as a STRING ("1"),
    // not a boolean — a strict `=== true` check silently fell back to dnsmasq
    // and every unbound-only fleet showed zero entries.
    if (res.ok && String(res.data?.enabled ?? '') === '1') return 'unbound';
  } catch {
    /* fall through to dnsmasq */
  }
  return 'dnsmasq';
}

// --- Host records (logical surface: add/remove/read a DNS host entry) ---------------

/** Adds a static DNS host record on the active backend. Staged; call reconfigureDns to activate. */
export async function addHostRecord(
  client: AxiosInstance,
  backend: DnsBackend,
  record: { name: string; ip: string; domain?: string; description?: string }
): Promise<OpnsenseApiResult> {
  if (backend === 'unbound') {
    // Unbound host-override item shape (verified live on OPNsense 26.4 via the
    // read-only get_host_override/<uuid>): hostname + optional domain, rr
    // A/AAAA, and `server` as the address field. An empty domain yields a
    // bare-name local-data entry — FQDNs go into `hostname` verbatim. The row
    // also carries a native free-text `description`.
    const item: Record<string, unknown> = {
      hostname: record.name,
      domain: (record.domain ?? '').toLowerCase(),
      rr: record.ip.includes(':') ? 'AAAA' : 'A',
      server: record.ip,
    };
    if (record.description) item['description'] = record.description;
    return post(client, '/api/unbound/settings/add_host_override', { item });
  }
  // dnsmasq host entry: { name, ip }. No native description field.
  return post(client, '/api/dnsmasq/settings/add_host', { name: record.name, ip: record.ip });
}

/** Removes a static DNS host record by uuid on the active backend. Staged. */
export async function deleteHostRecord(
  client: AxiosInstance,
  backend: DnsBackend,
  uuid: string
): Promise<OpnsenseApiResult> {
  if (backend === 'unbound') {
    return post(client, `/api/unbound/settings/del_host_override/${encodeURIComponent(uuid)}`, {});
  }
  return post(client, `/api/dnsmasq/settings/del_host/${encodeURIComponent(uuid)}`, {});
}

/** Lists static DNS host records on the active backend (rows[]). */
export async function searchHostRecords(
  client: AxiosInstance,
  backend: DnsBackend,
  query?: Record<string, unknown>
): Promise<OpnsenseApiResult> {
  if (backend === 'unbound') {
    return get(client, '/api/unbound/settings/search_host_override', query);
  }
  return get(client, '/api/dnsmasq/settings/search_host', query);
}

/**
 * Normalizes host-record rows from EITHER backend into `{name, ip}` pairs.
 * dnsmasq rows carry `name`/`ip`; unbound override rows (verified live on
 * OPNsense 26.4) carry `hostname` + optional `domain`, with the address in
 * `server`. The BARE hostname is used as the name — not the FQDN — so entries
 * group consistently with other plugins that store bare names, and dns.set /
 * dns.delete match uniformly across devices. Unbound rows also carry a native
 * free-text `description` (dnsmasq has none) — emitted when non-empty. Rows
 * without both fields are skipped (defensive — the field names have shifted
 * between OPNsense versions).
 */
export function parseHostRecordRows(data: unknown): Array<{ name: string; ip: string; domain?: string; description?: string }> {
  const d = data as { rows?: unknown } | null;
  if (!d || !Array.isArray(d.rows)) return [];
  const out: Array<{ name: string; ip: string; domain?: string; description?: string }> = [];
  for (const r of d.rows) {
    if (!r || typeof r !== 'object') continue;
    const row = r as Record<string, unknown>;
    const name = typeof row['name'] === 'string' ? row['name'].trim() : typeof row['hostname'] === 'string' ? (row['hostname'] as string).trim() : '';
    const ip =
      typeof row['ip'] === 'string' && row['ip'].trim() !== ''
        ? row['ip'].trim()
        : typeof row['server'] === 'string' && row['server'].trim() !== ''
          ? row['server'].trim()
          : typeof row['address'] === 'string'
            ? (row['address'] as string).trim()
            : '';
    if (!name || !ip) continue;
    // Unbound rows split the record into bare hostname + separate `domain`
    // (verified live on OPNsense 26.4); dnsmasq has no domain field → undefined.
    const domain = typeof row['domain'] === 'string' && row['domain'].trim() !== '' ? row['domain'].trim().toLowerCase().replace(/\.$/, '') : undefined;
    const description = typeof row['description'] === 'string' && row['description'].trim() !== '' ? row['description'].trim() : undefined;
    out.push({ name: name.toLowerCase(), ip, ...(domain !== undefined ? { domain } : {}), ...(description !== undefined ? { description } : {}) });
  }
  return out;
}

/** Activates staged DNS changes on the active backend. */
export async function reconfigureDns(client: AxiosInstance, backend: DnsBackend): Promise<OpnsenseApiResult> {
  if (backend === 'unbound') {
    return post(client, '/api/unbound/service/reconfigure', {});
  }
  return post(client, '/api/dnsmasq/service/reconfigure', {});
}

// --- dnsmasq-specific (exposed for completeness) --------------------------------------

/** GET /api/dnsmasq/settings/get — full dnsmasq settings. */
export function getDnsmasqSettings(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/dnsmasq/settings/get');
}

/** POST /api/dnsmasq/service/restart — restart dnsmasq. */
export function restartDnsmasq(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/dnsmasq/service/restart', {});
}

// --- Unbound-specific (exposed for completeness) -----------------------------------------

/** GET /api/unbound/settings/get — full unbound settings. */
export function getUnboundSettings(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/unbound/settings/get');
}

/** POST /api/unbound/service/restart — restart unbound. */
export function restartUnbound(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/unbound/service/restart', {});
}

// --- Unbound query log (qstats) — per-query rows for security insights ---------------------
// Since ~24.x OPNsense logs EVERY resolver query into a DuckDB database
// (/var/unbound/data/unbound.duckdb, 7-day on-box retention) and exposes it via
// /api/unbound/overview/search_queries. The response is a JSON array of the NEWEST
// rows (limit hardcoded to 1000 in the controller when no client/time filter is
// given), newest first. NOTE: `client` carries the reverse-resolved HOSTNAME instead
// of the IP whenever the appliance could resolve it — consumers must handle both.

/** One per-query row from the appliance's unbound qstats database. */
export interface UnboundQueryRow {
  /** The appliance's per-query uuid — stable dedupe key at UNM ingest. */
  uuid: string;
  /** Unix epoch SECONDS (UTC). */
  time: number;
  /** Client IP, or a hostname when the appliance reverse-resolved it. */
  client: string;
  family?: string | null;
  type?: string | null;
  domain: string;
  /** 'Pass' | 'Block' | 'Drop'. */
  action: string;
  /** 'Recursion' | 'Local' | 'Local-data' | 'Cache'. */
  source?: string | null;
  /** The appliance's own DNSBL list that blocked this query (null when none). */
  blocklist?: string | null;
  rcode?: string | null;
  resolveTimeMs?: number | null;
  dnssecStatus?: string | null;
  ttl?: number | null;
}

/**
 * Normalizes the search_queries response body into usable rows. Tolerates both
 * a bare array (the controller's shape) and a {rows: [...]} wrapper, and skips
 * anything missing its uuid/time/client/domain — feed noise never throws.
 */
export function parseUnboundQueryRows(data: unknown): UnboundQueryRow[] {
  const arr: unknown[] = Array.isArray(data) ? data : (data && typeof data === 'object' && Array.isArray((data as { rows?: unknown }).rows) ? ((data as { rows: unknown[] }).rows) : []);
  const out: UnboundQueryRow[] = [];
  for (const r of arr) {
    if (!r || typeof r !== 'object') continue;
    const row = r as Record<string, unknown>;
    const uuid = typeof row['uuid'] === 'string' ? row['uuid'].trim() : '';
    const time = Number(row['time']);
    const clientIp = typeof row['client'] === 'string' ? row['client'].trim() : '';
    const domain = typeof row['domain'] === 'string' ? row['domain'].trim() : '';
    if (!uuid || !Number.isFinite(time) || time <= 0 || !clientIp || !domain) continue; // unusable row — skip
    out.push({
      uuid,
      time: Math.trunc(time),
      client: clientIp,
      domain,
      action: typeof row['action'] === 'string' ? row['action'] : 'Pass',
      family: typeof row['family'] === 'string' ? row['family'] : null,
      type: typeof row['type'] === 'string' ? row['type'] : null,
      source: typeof row['source'] === 'string' ? row['source'] : null,
      blocklist: typeof row['blocklist'] === 'string' && row['blocklist'].trim() !== '' ? row['blocklist'] : null,
      rcode: typeof row['rcode'] === 'string' ? row['rcode'] : null,
      resolveTimeMs: Number.isFinite(Number(row['resolve_time_ms'])) ? Math.trunc(Number(row['resolve_time_ms'])) : null,
      dnssecStatus: typeof row['dnssec_status'] === 'string' ? row['dnssec_status'] : null,
      ttl: Number.isFinite(Number(row['ttl'])) ? Math.trunc(Number(row['ttl'])) : null,
    });
  }
  return out;
}

/**
 * Fetches the newest per-query rows (GET /api/unbound/overview/search_queries,
 * no params = latest 1000). Returns [] when the endpoint is absent (older
 * firmware without the query logger) or on any failure — callers treat that as
 * "feature not available here", never an error.
 */
export async function fetchUnboundQueries(client: AxiosInstance): Promise<UnboundQueryRow[]> {
  const res = await get<{ rows?: unknown } | unknown[]>(client, '/api/unbound/overview/search_queries');
  if (!res.ok) return []; // 404 on firmware without qstats — feature stays silent
  return parseUnboundQueryRows(res.data);
}
