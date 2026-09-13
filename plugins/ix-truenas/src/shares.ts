/**
 * File-share inventory + live client sessions for the TrueNAS plugin.
 *
 * Collects the four share/export protocols TrueNAS exposes and feeds them to the
 * UNM Shares page (cross-device) via two generic metric keys:
 *   - `shares[]`        — one row per SMB/CIFS, NFS, iSCSI or NVMe-oF export
 *                          (CONFIG objects; upserted + delete-on-absent by the API).
 *   - `shareSessions[]` — live CIFS/SMB + NFS client connections (LIVE state; the
 *                          API replaces them wholesale per poll).
 *
 * Reads use documented JSON-RPC methods:
 *   smb.share.query / nfs.shares.query / iscsi.target.query (+ iscsi.extent.query)
 *   nvmet.subsystem.query (+ nvmet.namespace.query)  [nvmet = TrueNAS 24.10+]
 * SMB share backing paths are resolved from a single pool.dataset.query (the
 * share name maps to the dataset it exports). Live client sessions come from the
 * SAME JSON-RPC methods that back the appliance's own Web UI session pages
 * (Sharing → SMB Status → Sessions / Sharing → NFS → Sessions):
 *   smb.status (no info-level filter — includes per-share share_connections)
 *   nfs.get_nfs3_clients  ({ip, export: "<client>:/mnt/path"})
 *   nfs.get_nfs4_clients  ([{info:{address, clientid, status}}])
 * No SSH is required — every device we can authenticate to exposes these
 * methods, so even devices without a bound ssh slot get session data. All three
 * are best-effort: a missing method (older release) or transient failure simply
 * yields no rows for that protocol and never counts toward device health.
 */

import { pickNumber, pickString } from '@unm/plugin-sdk';
import type { TruenasClient, TruenasCredentials } from './client/truenasClient';

/** One normalized share row (the `shares[]` metric shape the API ingests). */
export interface ShareRow {
  name: string;
  /** smb | nfs | iscsi | nvmeof. */
  type: 'smb' | 'nfs' | 'iscsi' | 'nvmeof';
  path?: string | null;
  status?: string;
  sessionCount?: number | null;
  extra?: Record<string, unknown>;
}

/** One live client-session row (the `shareSessions[]` metric shape). */
export interface ShareSessionRow {
  /** smb | nfs. */
  type: 'smb' | 'nfs';
  shareName: string;
  clientAddress?: string;
  user?: string | null;
  uptimeSeconds?: number | null;
}

/** True when a JSON-RPC error means "method does not exist" (older release). */
export function isMethodMissing(e: unknown): boolean {
  return e instanceof Error && /does not exist|no such method|-32601/i.test(e.message);
}

/** A query RPC that tolerates missing methods — returns [] when the appliance's
 * release predates the namespace (e.g. nvmet.* before 24.10). */
async function safeQuery<T>(client: TruenasClient, method: string, params: unknown[], creds: TruenasCredentials): Promise<T[]> {
  try {
    const r = await client.call<unknown>(method, params, creds);
    return Array.isArray(r) ? (r as T[]) : [];
  } catch (e) {
    if (isMethodMissing(e)) return [];
    throw e;
  }
}

/** Builds a dataset-name → mountpoint map from pool.dataset.query rows. Used to
 * resolve the backing path of SMB shares (whose RPC row carries no path field).
 * /monitoring already fetches pool.dataset.query for the Storage page, so it passes
 * those rows in — no extra RPC here. */
export function buildDatasetPathMap(rows: Record<string, unknown>[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const r of rows ?? []) {
    if (!r || typeof r !== 'object') continue;
    const name = pickString(r, ['name']);
    const mp = pickString(r, ['mountpoint']);
    if (name && mp) out.set(name, mp);
  }
  return out;
}

/** Resolves the backing path for an SMB share name: exact dataset match first,
 * then the nearest ancestor dataset (a share may export a sub-path of a dataset). */
function resolveSmbPath(shareName: string, dsMap: Map<string, string>): string | null {
  if (dsMap.has(shareName)) return dsMap.get(shareName) ?? null;
  // Walk up the share's path components looking for a known dataset prefix.
  const parts = shareName.split('/');
  for (let i = parts.length - 1; i >= 0; i--) {
    const candidate = parts.slice(0, i + 1).join('/');
    if (dsMap.has(candidate)) return dsMap.get(candidate) ?? null;
  }
  return null;
}

/** Queries a share-list RPC, trying the modern `sharing.*` namespace first and
 * falling back to the legacy name (older releases). Returns [] when neither exists. */
async function queryShares(
  client: TruenasClient,
  creds: TruenasCredentials,
  modern: string,
  legacy: string,
): Promise<Record<string, unknown>[]> {
  try {
    const r = await client.call<unknown>(modern, [], creds);
    return Array.isArray(r) ? (r as Record<string, unknown>[]) : [];
  } catch (e) {
    if (!isMethodMissing(e)) throw e; // real failure — surface it
    // Modern namespace absent on this release → legacy method name.
    return safeQuery<Record<string, unknown>>(client, legacy, [], creds);
  }
}

/** Collects SMB/CIFS shares. Modern releases expose `sharing.smb.query` whose rows
 * carry their own `path` + `enabled`; older ones use `smb.share.query` (no path —
 * resolved from the dataset map). */
async function collectSmbShares(
  client: TruenasClient,
  creds: TruenasCredentials,
  dsMap: Map<string, string>,
): Promise<ShareRow[]> {
  const rows = await queryShares(client, creds, 'sharing.smb.query', 'smb.share.query');
  if (rows.length === 0) return [];
  const out: ShareRow[] = [];
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const name = pickString(r, ['name']);
    if (!name) continue;
    const comment = pickString(r, ['comment']);
    // Modern rows carry the backing path directly; legacy ones need dataset resolution.
    const path = pickString(r, ['path']) ?? resolveSmbPath(name, dsMap);
    out.push({
      name,
      type: 'smb',
      path,
      status: r['enabled'] === false ? 'disabled' : 'enabled',
      extra: { ...(comment ? { comment } : {}) },
    });
  }
  return out;
}

/** Collects NFS shares. Modern releases expose `sharing.nfs.query` (rows carry
 * `path` + `enabled`); older ones use `nfs.shares.query`. */
async function collectNfsShares(client: TruenasClient, creds: TruenasCredentials): Promise<ShareRow[]> {
  const rows = await queryShares(client, creds, 'sharing.nfs.query', 'nfs.shares.query');
  const out: ShareRow[] = [];
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const path = pickString(r, ['path']);
    if (!path) continue; // NFS shares are identified by their exported path
    const hostsRaw = Array.isArray(r['hosts']) ? (r['hosts'] as unknown[]) : [];
    out.push({
      name: path,
      type: 'nfs',
      path,
      status: r['enabled'] === false ? 'disabled' : 'enabled',
      extra: {
        readOnly: r['ro'] === true || r['readonly'] === true,
        ...(hostsRaw.length > 0 ? { hosts: hostsRaw.filter((h): h is string => typeof h === 'string') } : {}),
      },
    });
  }
  return out;
}

/** Collects iSCSI targets (iscsi.target.query) with their LUN datasets attached. */
async function collectIscsiShares(client: TruenasClient, creds: TruenasCredentials): Promise<ShareRow[]> {
  const rows = await safeQuery<Record<string, unknown>>(client, 'iscsi.target.query', [], creds);
  if (rows.length === 0) return [];
  // Extents carry the backing dataset; the target↔extent association lives in its
  // own table (iscsi.targetextent: {target:<id>, extent:<id>}) — join through it.
  let extents: Record<string, unknown>[] = [];
  try {
    extents = await client.call<Record<string, unknown>[]>('iscsi.extent.query', [], creds);
  } catch (e) {
    if (!isMethodMissing(e)) throw e;
  }
  const pathByExtentId = new Map<number, string>();
  for (const ex of extents ?? []) {
    if (!ex || typeof ex !== 'object') continue;
    const eid = pickNumber(ex, ['id']);
    const ds = pickString(ex, ['path']) ?? pickString(ex, ['disk']);
    if (typeof eid === 'number' && ds) pathByExtentId.set(eid, ds);
  }
  let targetExtents: Record<string, unknown>[] = [];
  try {
    targetExtents = await client.call<Record<string, unknown>[]>('iscsi.targetextent.query', [], creds);
  } catch (e) {
    if (!isMethodMissing(e)) throw e; // real failure — surface it
  }
  const datasetsByTarget = new Map<number, string[]>();
  for (const te of targetExtents ?? []) {
    if (!te || typeof te !== 'object') continue;
    const tid = pickNumber(te, ['target']);
    const eid = pickNumber(te, ['extent']);
    if (typeof tid !== 'number' || typeof eid !== 'number') continue;
    const ds = pathByExtentId.get(eid);
    if (!ds) continue;
    const list = datasetsByTarget.get(tid) ?? [];
    list.push(ds);
    datasetsByTarget.set(tid, list);
  }
  const out: ShareRow[] = [];
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const id = pickNumber(r, ['id']);
    const name = pickString(r, ['name']) ?? (typeof id === 'number' ? `target-${id}` : undefined);
    if (!name) continue;
    out.push({
      name,
      type: 'iscsi',
      path: null,
      status: r['enabled'] === false ? 'disabled' : 'enabled',
      extra: {
        ...(typeof id === 'number' ? { id } : {}),
        alias: pickString(r, ['alias']),
        mode: pickString(r, ['mode']),
        ...(datasetsByTarget.has(id ?? -1) ? { datasets: datasetsByTarget.get(id ?? -1) } : {}),
      },
    });
  }
  return out;
}

/** Collects NVMe-oF subsystems (nvmet.subsystem.query, TrueNAS 24.10+) with their
 * namespace datasets attached. Returns [] on releases without the nvmet namespace. */
async function collectNvmeofShares(client: TruenasClient, creds: TruenasCredentials): Promise<ShareRow[]> {
  // The subsystem collection is `nvmet.subsys.*` (NOT "subsystem") — verified in
  // the live method catalog on both 25.10 and 26 BETA appliances.
  const rows = await safeQuery<Record<string, unknown>>(client, 'nvmet.subsys.query', [], creds);
  if (rows.length === 0) return [];
  let namespaces: Record<string, unknown>[] = [];
  try {
    namespaces = await client.call<Record<string, unknown>[]>('nvmet.namespace.query', [], creds);
  } catch (e) {
    if (!isMethodMissing(e)) throw e;
  }
  // Each namespace row nests its owning subsystem under `subsys` ({id,name,…});
  // the backing store is a ZFS dataset (`dataset`) or a block device path.
  const nsBySubsystem = new Map<number, string[]>();
  for (const n of namespaces ?? []) {
    if (!n || typeof n !== 'object') continue;
    const subsysObj = (n['subsys'] ?? {}) as Record<string, unknown>;
    const sid = pickNumber(subsysObj, ['id']) ?? pickNumber(n, ['subsystem']);
    const ds = pickString(n, ['dataset']) ?? pickString(n, ['device_path']);
    if (typeof sid !== 'number' || !ds) continue;
    const list = nsBySubsystem.get(sid) ?? [];
    list.push(ds);
    nsBySubsystem.set(sid, list);
  }
  const out: ShareRow[] = [];
  for (const r of rows) {
    if (!r || typeof r !== 'object') continue;
    const id = pickNumber(r, ['id']);
    const name = pickString(r, ['name']) ?? (typeof id === 'number' ? `subsystem-${id}` : undefined);
    if (!name) continue;
    out.push({
      name,
      type: 'nvmeof',
      path: null,
      status: r['enabled'] === false ? 'disabled' : 'enabled',
      extra: {
        ...(typeof id === 'number' ? { id } : {}),
        serialNumber: pickString(r, ['serial']),
        subnqn: pickString(r, ['subnqn']),
        ...(nsBySubsystem.has(id ?? -1) ? { namespaces: nsBySubsystem.get(id ?? -1) } : {}),
      },
    });
  }
  return out;
}

/** Collects ALL share types in parallel (each best-effort — one protocol's RPC
 * failing does not drop the others). Returns [] when nothing is configured.
 * `datasetRows` = the pool.dataset.query result /monitoring already fetched, used
 * to resolve SMB backing paths without an extra RPC. */
export async function collectShares(
  client: TruenasClient,
  creds: TruenasCredentials,
  datasetRows: Record<string, unknown>[],
): Promise<ShareRow[]> {
  const dsMap = buildDatasetPathMap(datasetRows);
  const [smbRes, nfsRes, iscsiRes, nvmeofRes] = await Promise.allSettled([
    collectSmbShares(client, creds, dsMap),
    collectNfsShares(client, creds),
    collectIscsiShares(client, creds),
    collectNvmeofShares(client, creds),
  ]);
  const out: ShareRow[] = [];
  for (const r of [smbRes, nfsRes, iscsiRes, nvmeofRes]) {
    if (r.status === 'fulfilled') out.push(...r.value);
    // Rejected → that protocol contributed nothing this poll.
  }
  return out;
}

// ---------------------------------------------------------------------------
// Live client sessions via the TrueNAS JSON-RPC API — the same three methods that
// back the appliance's own Web UI session pages. No SSH required: every device we
// can authenticate to exposes them, so even devices without a bound ssh slot get
// session data. Best-effort throughout — a missing method (older release) or a
// transient failure yields no rows for that protocol and never counts toward
// device health.
// ---------------------------------------------------------------------------

/** Parses `smb.status` output into SMB session rows — one row per open SHARE
 * connection, carrying the owning session's user + uptime. Sessions without any
 * share connections (e.g. IPC$-only management sessions) contribute nothing. */
function parseSmbSessions(raw: unknown): ShareSessionRow[] {
  const out: ShareSessionRow[] = [];
  if (!Array.isArray(raw)) return out;
  for (const s of raw) {
    if (!s || typeof s !== 'object') continue;
    const session = s as Record<string, unknown>;
    const user = pickString(session, ['username']);
    // Session uptime from creation_time (ISO with offset); null when unparseable.
    let uptime: number | null = null;
    const created = pickString(session, ['creation_time']);
    if (created) {
      const t = Date.parse(created);
      if (Number.isFinite(t)) uptime = Math.max(0, Math.floor((Date.now() - t) / 1000));
    }
    const conns = Array.isArray(session['share_connections']) ? session['share_connections'] : [];
    for (const c of conns as Record<string, unknown>[]) {
      if (!c || typeof c !== 'object') continue;
      const service = pickString(c, ['service']);
      // IPC$/ADMIN$ are the SMB admin pipes — every Windows box opens one for
      // name resolution; they are not file-share connections.
      if (!service || service === 'IPC$' || service === 'ADMIN$') continue;
      out.push({
        type: 'smb',
        shareName: service,
        clientAddress: pickString(session, ['remote_machine']) ?? '',
        user: user ?? null,
        uptimeSeconds: uptime,
      });
    }
  }
  return out;
}

/** Parses `nfs.get_nfs3_clients` rows ({ip, export:"<client>:/mnt/path"}) into NFS
 * session rows. The exported path IS the share's identity (NFS shares are keyed by
 * path), so strip the leading "<client>:" prefix to recover the share name. */
function parseNfs3Clients(raw: unknown): ShareSessionRow[] {
  const out: ShareSessionRow[] = [];
  if (!Array.isArray(raw)) return out;
  for (const r of raw) {
    if (!r || typeof r !== 'object') continue;
    const row = r as Record<string, unknown>;
    const ip = pickString(row, ['ip']);
    const exportStr = pickString(row, ['export']) ?? '';
    if (!ip && !exportStr) continue;
    // "10.110.1.22:/mnt/DATA01/BACKUP" → "/mnt/DATA01/BACKUP"; v6 clients arrive
    // as "[::1]:/path" — the first ':' after an optional bracketed address is the split.
    let shareName = exportStr;
    const colon = shareName.indexOf(':');
    if (colon !== -1) shareName = shareName.slice(colon + 1);
    out.push({ type: 'nfs', shareName, clientAddress: ip ?? '', user: null, uptimeSeconds: null });
  }
  return out;
}

/** Parses `nfs.get_nfs4_clients` rows (wrappers of {info:{address, clientid,
 * status}}) into NFS session rows. NFSv4 sessions carry no per-export identity —
 * the share name stays empty and the row is keyed by client address. */
function parseNfs4Clients(raw: unknown): ShareSessionRow[] {
  const out: ShareSessionRow[] = [];
  if (!Array.isArray(raw)) return out;
  for (const w of raw) {
    if (!w || typeof w !== 'object') continue;
    const info = (w as Record<string, unknown>)['info'];
    if (!info || typeof info !== 'object') continue;
    const row = info as Record<string, unknown>;
    out.push({
      type: 'nfs',
      shareName: '',
      clientAddress: pickString(row, ['address']) ?? '',
      user: null,
      uptimeSeconds: null,
    });
  }
  return out;
}

/** Builds live SMB + NFS client-session rows from the three raw RPC results that
 * back the appliance's own Web UI session pages (fetched by /monitoring in its
 * parallel batch — this is a pure parser, no I/O):
 *   smb.status (NO info-level filter — ['SESSIONS'] omits per-share connections)
 *   nfs.get_nfs3_clients  ({ip, export: "<client>:/mnt/path"})
 *   nfs.get_nfs4_clients  ([{info:{address, clientid, status}}])
 * A `null`/`undefined` raw value = that call failed or was skipped → no rows for
 * it. Returns [] when nothing is connected. */
export function collectShareSessions(
  smbStatusRaw: unknown,
  nfs3ClientsRaw: unknown,
  nfs4ClientsRaw: unknown,
): ShareSessionRow[] {
  const out: ShareSessionRow[] = [];
  if (smbStatusRaw !== null && smbStatusRaw !== undefined) out.push(...parseSmbSessions(smbStatusRaw));
  if (nfs3ClientsRaw !== null && nfs3ClientsRaw !== undefined) out.push(...parseNfs3Clients(nfs3ClientsRaw));
  if (nfs4ClientsRaw !== null && nfs4ClientsRaw !== undefined) out.push(...parseNfs4Clients(nfs4ClientsRaw));
  return out;
}

/** Stamps `sessionCount` onto SMB/NFS share rows from the live session snapshot:
 * SMB shares match by name, NFS shares by exported path (their row `name`).
 * iSCSI/NVMe-oF rows are left untouched (no per-share client identity in these RPCs). */
export function withSessionCounts(shares: ShareRow[], sessions: ShareSessionRow[]): ShareRow[] {
  const smbByShare = new Map<string, number>();
  const nfsByPath = new Map<string, number>();
  for (const s of sessions) {
    if (!s.shareName) continue;
    if (s.type === 'smb') smbByShare.set(s.shareName, (smbByShare.get(s.shareName) ?? 0) + 1);
    else nfsByPath.set(s.shareName, (nfsByPath.get(s.shareName) ?? 0) + 1);
  }
  return shares.map((sh) => {
    if (sh.type === 'smb') return { ...sh, sessionCount: smbByShare.get(sh.name) ?? 0 };
    if (sh.type === 'nfs') return { ...sh, sessionCount: nfsByPath.get(sh.name) ?? 0 };
    return sh;
  });
}
