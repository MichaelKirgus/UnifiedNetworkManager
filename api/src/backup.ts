import { createHash } from 'crypto';
import fs from 'fs';
import path from 'path';
import zlib from 'zlib';
import { Readable } from 'stream';
import { and, eq, getTableColumns, getTableName, inArray, or, sql } from 'drizzle-orm';
import { getTableConfig } from 'drizzle-orm/pg-core';
import { db } from './db';
import * as schema from './db/schema';
import {
  SETTING_DESCRIPTORS,
  getEffectiveSettingValue,
  invalidateSystemSettingsCache,
  updateSetting,
} from './systemSettings';
import {
  deleteBlobViaProvider,
  openBlobFromProvider,
  resolveFileRepoProvider,
  storeBlobViaProvider,
} from './fileRepoBroker';

/**
 * Backup / restore service for UNM's own database.
 *
 * Archive format: a gzip-compressed JSON document
 *   { manifest: { format:'unm-backup', schemaVersion, exportedAt, instanceName,
 *                 buildTag, scope, sections:{<key>:{rowCount, tables}} },
 *     data: { <sectionKey>: { <tableName>: [rows…] } } }
 * File extension `.unmbak.gz`. Bytes live either on the local backup volume
 * (`BACKUP_DIR`, docker volume `unm-backups`) or content-addressed in a bound
 * file-repo plugin instance (see fileRepoBroker).
 *
 * TABLE DISCOVERY IS EXCLUSION-BASED — new tables need no registration here:
 * every pgTable in db/schema.ts is discovered at runtime and included in
 * backups by default. What keeps data OUT of archives are the lists below:
 *   - EXCLUDED_TABLES  : never backed up (regenerable / high-volume / instance-local)
 *   - EXCLUDED_COLUMNS : per-table columns dropped from exported rows
 *   - ROW_FILTERS      : per-table row predicates; returning true drops the row
 * Section membership is pattern-based with a SAFE FALLBACK: tables that match
 * no explicit rule land in `liveInventory` (the regenerable tier, only shipped
 * by scope "all") — so an unknown new table is still covered by full backups
 * and visible in the manifest, without ever polluting config/planned scopes.
 *
 * Restore/replication uses a SAFE MERGE: upsert on each table's primary key
 * (discovered via drizzle's getTableConfig), rows absent from the archive are
 * never deleted. `system_settings` is merged through updateSetting() so type
 * validation and onChange hooks still fire; unknown keys are skipped, not fatal.
 */

// ---------------------------------------------------------------------------
// Format constants
// ---------------------------------------------------------------------------

export const BACKUP_FORMAT = 'unm-backup';
/** Bump when the archive layout changes incompatibly — older readers refuse newer archives. */
export const BACKUP_SCHEMA_VERSION = 1;
export const BACKUP_FILE_EXT = '.unmbak.gz';
/** Where local backup bytes live (docker volume `unm-backups` in compose). */
export const BACKUP_DIR: string = process.env.BACKUP_PATH ?? '/data/backups';
const PENDING_DIR = path.join(BACKUP_DIR, '.pending');

// ---------------------------------------------------------------------------
// Sections & presets
// ---------------------------------------------------------------------------

export const SECTION_KEYS = ['identity', 'settings', 'devices', 'documented', 'plans', 'liveInventory'] as const;
export type SectionKey = (typeof SECTION_KEYS)[number];

/** Presets are just bundles of sections. */
export const PRESETS: Record<string, readonly string[]> = {
  config: ['identity', 'settings', 'devices'],
  planned: ['documented', 'plans'],
  all: [...SECTION_KEYS],
};

/** Sections that may cross instance boundaries via replication (no live inventory). */
export const PORTABLE_SECTIONS: readonly SectionKey[] = ['identity', 'settings', 'devices', 'documented', 'plans'];

// ---------------------------------------------------------------------------
// Exclusion lists — the ONLY place data is kept out of backups.
// ---------------------------------------------------------------------------

/** Tables that NEVER go into any backup or replication export. */
export const EXCLUDED_TABLES: ReadonlySet<string> = new Set([
  // Instance-local credentials / auth state (re-mint / re-register on target)
  'api_tokens',
  'webauthn_credentials',
  // Regenerable plugin discovery cache
  'plugins',
  // High-volume regenerable telemetry & logs
  'telemetry',
  'plugin_logs',
  'firewall_events',
  'host_states',
  'plugin_metrics',
  'ntp_reference_readings',
  // Ephemeral runtime state
  'share_sessions',
  'config_jobs',
  'notifications',
  // Audit ledgers / separate subsystems
  'certificate_history',
  'repo_files',
  'repo_file_uses',
  // This feature's own bookkeeping (instance-local; bytes live elsewhere)
  'backups',
  'replication_targets',
]);

/** Per-table columns dropped from exported rows. Extend as instance-local cache columns appear. */
export const EXCLUDED_COLUMNS: Record<string, string[]> = {};

/** Per-table row filters — return true to drop a row from exports. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const ROW_FILTERS: Record<string, (row: any) => boolean> = {};

// ---------------------------------------------------------------------------
// Table discovery (runtime introspection of db/schema.ts)
// ---------------------------------------------------------------------------

/** Small stable sets for the config-tier sections; everything else falls back to liveInventory. */
const IDENTITY_TABLES: ReadonlySet<string> = new Set([
  'users',
  'roles',
  'credential_policies',
  'notification_prefs',
  'user_preferences',
]);
const DEVICE_TABLES: ReadonlySet<string> = new Set([
  'sites',
  'network_layers',
  'devices',
  'device_ips',
  'secrets',
  'device_plugins',
  'device_session_credentials',
  'plugin_settings',
  'device_port_roles',
  'plugin_state',
]);

function sectionForTable(name: string): SectionKey {
  if (IDENTITY_TABLES.has(name)) return 'identity';
  if (name === 'system_settings') return 'settings';
  if (name.startsWith('documented_')) return 'documented';
  if (name === 'plans' || name === 'plan_steps') return 'plans';
  if (DEVICE_TABLES.has(name)) return 'devices';
  // Safe fallback: unknown/new tables are treated as regenerable inventory —
  // still covered by scope "all", never polluting config/planned backups.
  return 'liveInventory';
}

/** Restore priority — parents before children; unknown tables sort after all config. */
const RESTORE_ORDER: Record<string, number> = {
  sites: 0,
  network_layers: 1,
  roles: 2,
  users: 3,
  credential_policies: 4,
  secrets: 5,
  devices: 6,
  device_ips: 7,
  device_plugins: 8,
  plugin_settings: 9,
  device_session_credentials: 10,
  device_port_roles: 11,
  plugin_state: 12,
  system_settings: 13,
  notification_prefs: 14,
  user_preferences: 15,
  documented_networks: 16,
  documented_hosts: 17,
  documented_host_ips: 18,
  plans: 19,
  plan_steps: 20,
};
const RESTORE_ORDER_DEFAULT = 30;

export interface TableMeta {
  /** DB table name (=== schema export key convention). */
  name: string;
  section: SectionKey;
  /** Primary-key column names — house convention: JS key === DB column name. */
  pkColumns: string[];
  /** All exported column JS keys (exclusions already removed), in select order. */
  columns: string[];
  /** JS key → DB column name (they differ for e.g. isBuiltin/is_builtin). */
  columnDbNames: Record<string, string>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tableRef: any;
}

let discoveredTables: Map<string, TableMeta> | null = null;

/** Discovers every pgTable in the schema (exclusion-based — see file header). */
export function discoverTables(): Map<string, TableMeta> {
  if (discoveredTables) return discoveredTables;
  const out = new Map<string, TableMeta>();
  for (const value of Object.values(schema)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const t = value as any;
    if (!t || t.constructor?.name !== 'PgTable') continue;
    let name: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let columns: Record<string, any>;
    try {
      name = getTableName(t);
      columns = getTableColumns(t) as Record<string, any>;
    } catch {
      continue; // not a usable table object — skip silently
    }
    if (EXCLUDED_TABLES.has(name)) continue;
    // Primary key: composite PKs declared via the extra-config callback surface in
    // getTableConfig().primaryKeys; single-column inline `.primaryKey()` marks set
    // column.primary instead. Prefer the explicit declaration when present.
    let pkColumns: string[] = [];
    try {
      const cfg = getTableConfig(t);
      const pk = cfg.primaryKeys[0];
      if (pk && Array.isArray(pk.columns) && pk.columns.length > 0) {
        pkColumns = pk.columns.map((c) => String(c.name));
      }
    } catch {
      // Tables without an extra-config callback throw here — fall through to the inline flags.
    }
    if (pkColumns.length === 0) {
      pkColumns = Object.values(columns)
        .filter((c) => c?.primary === true)
        .map((c) => String(c.name));
    }
    if (pkColumns.length === 0) {
      console.warn(`[backup] table "${name}" has no primary key — excluded from backups`);
      continue; // can't merge safely without a conflict target
    }
    const dropped = new Set(EXCLUDED_COLUMNS[name] ?? []);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const columnNames = Object.keys(columns).filter((k) => !dropped.has(k)) as any[];
    const columnDbNames: Record<string, string> = {};
    for (const [jsKey, col] of Object.entries(columns)) columnDbNames[jsKey] = String(col.name);
    out.set(name, { name, section: sectionForTable(name), pkColumns, columns: columnNames, columnDbNames, tableRef: t });
  }
  discoveredTables = out;
  return out;
}

/** All tables belonging to a section, in deterministic restore order. */
export function tablesInSection(section: SectionKey): TableMeta[] {
  const metas = [...discoverTables().values()].filter((m) => m.section === section);
  metas.sort(
    (a, b) => (RESTORE_ORDER[a.name] ?? RESTORE_ORDER_DEFAULT) - (RESTORE_ORDER[b.name] ?? RESTORE_ORDER_DEFAULT) || a.name.localeCompare(b.name),
  );
  return metas;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class BackupError extends Error {
  status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}

function assertKnownSections(sections: string[]): void {
  for (const s of sections) {
    if (!SECTION_KEYS.includes(s as SectionKey)) throw new BackupError(`Unknown backup section "${s}"`);
  }
}

/** 'config' | 'planned' | 'all' when the set matches a preset exactly, else 'custom'. */
export function scopeForSections(sections: string[]): string {
  for (const [preset, keys] of Object.entries(PRESETS)) {
    if (keys.length === sections.length && keys.every((k) => sections.includes(k))) return preset;
  }
  return 'custom';
}

// ---------------------------------------------------------------------------
// Archive build / parse
// ---------------------------------------------------------------------------

export interface BackupManifest {
  format: typeof BACKUP_FORMAT;
  schemaVersion: number;
  exportedAt: string;
  instanceName: string;
  buildTag: string;
  scope: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  sections: Record<string, { rowCount: number; tables: Record<string, number> }>;
}

export interface BackupArchive {
  manifest: BackupManifest;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: Record<string, Record<string, any[]>>;
}

/** Loads the rows of every requested section (exclusions applied). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function buildBackup(sections: string[]): Promise<Record<string, Record<string, any[]>>> {
  assertKnownSections(sections);
  const data: BackupArchive['data'] = {};
  for (const section of sections) {
    const byTable: Record<string, unknown[]> = {};
    let rowCount = 0;
    for (const meta of tablesInSection(section as SectionKey)) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const rows = (await db.select().from(meta.tableRef as any)) as any[];
      const filter = ROW_FILTERS[meta.name];
      const projected = rows
        .filter((r) => !(filter && filter(r)))
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .map((r) => {
          const out: Record<string, unknown> = {};
          for (const c of meta.columns) out[c] = r[c];
          return out;
        });
      byTable[meta.name] = projected;
      rowCount += projected.length;
    }
    data[section] = byTable;
  }
  return data;
}

/** Builds a full archive (manifest + data) for the given sections. */
export async function buildArchive(sections: string[]): Promise<BackupArchive> {
  const [instanceName, data] = await Promise.all([getEffectiveSettingValue('instanceName'), buildBackup(sections)]);
  const manifestSections: BackupManifest['sections'] = {};
  for (const [section, byTable] of Object.entries(data)) {
    const tables: Record<string, number> = {};
    let rowCount = 0;
    for (const [table, rows] of Object.entries(byTable)) {
      tables[table] = rows.length;
      rowCount += rows.length;
    }
    manifestSections[section] = { rowCount, tables };
  }
  return {
    manifest: {
      format: BACKUP_FORMAT,
      schemaVersion: BACKUP_SCHEMA_VERSION,
      exportedAt: new Date().toISOString(),
      instanceName: typeof instanceName === 'string' ? instanceName : '',
      buildTag: process.env.UNM_BUILD_TAG ?? '',
      scope: scopeForSections(sections),
      sections: manifestSections,
    },
    data,
  };
}

/** Gzips an archive and returns the bytes + content identity. */
export function gzipArchive(archive: BackupArchive): { buffer: Buffer; sha256: string; sizeBytes: number } {
  const json = JSON.stringify(archive);
  const buffer = zlib.gzipSync(Buffer.from(json, 'utf8'), { level: 6 });
  const sha256 = createHash('sha256').update(buffer).digest('hex');
  return { buffer, sha256, sizeBytes: buffer.length };
}

/** Gunzips + validates an archive. Throws BackupError on corrupt/foreign/newer archives. */
export function parseArchive(buf: Buffer): BackupArchive {
  let json: string;
  try {
    json = zlib.gunzipSync(buf).toString('utf8');
  } catch {
    throw new BackupError('Not a valid UNM backup (corrupt or not gzip-compressed)');
  }
  let doc: unknown;
  try {
    doc = JSON.parse(json);
  } catch {
    throw new BackupError('Not a valid UNM backup (malformed JSON)');
  }
  const d = doc as Partial<BackupArchive>;
  if (!d || typeof d !== 'object' || !d.manifest || typeof d.manifest !== 'object') {
    throw new BackupError('Not a valid UNM backup (missing manifest)');
  }
  if (d.manifest.format !== BACKUP_FORMAT) throw new BackupError(`Foreign archive format "${String(d.manifest.format)}"`);
  const version = Number((d.manifest as { schemaVersion?: unknown }).schemaVersion ?? 0);
  if (!Number.isFinite(version) || version > BACKUP_SCHEMA_VERSION) {
    throw new BackupError(`Backup was created by a newer UNM version (schema v${version}) — upgrade before restoring`);
  }
  if (!d.data || typeof d.data !== 'object') throw new BackupError('Not a valid UNM backup (missing data)');
  return d as BackupArchive;
}

// ---------------------------------------------------------------------------
// Local volume storage
// ---------------------------------------------------------------------------

export function localBackupPath(id: string): string {
  if (!/^[a-zA-Z0-9-]+$/.test(id)) throw new BackupError('Invalid backup id', 500);
  const resolved = path.resolve(BACKUP_DIR, `${id}${BACKUP_FILE_EXT}`);
  // Containment guard: the joined path must stay inside BACKUP_DIR. The allowlist
  // regex above already forbids separators/`..`, this makes it explicit for auditors.
  if (!resolved.startsWith(path.resolve(BACKUP_DIR) + path.sep)) throw new BackupError('Invalid backup id', 500);
  return resolved;
}

export async function storeLocalBackup(id: string, buffer: Buffer): Promise<void> {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  await fs.promises.writeFile(localBackupPath(id), buffer);
}

/** Returns null when the file is missing (deleted out-of-band). */
export async function openLocalBackup(id: string): Promise<Buffer | null> {
  try {
    return await fs.promises.readFile(localBackupPath(id));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

export async function deleteLocalBackup(id: string): Promise<void> {
  try {
    await fs.promises.unlink(localBackupPath(id));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
}

// ---------------------------------------------------------------------------
// Pending restore uploads (staged until apply or discard)
// ---------------------------------------------------------------------------

function pendingPath(pendingId: string): string {
  if (!/^[a-zA-Z0-9-]+$/.test(pendingId)) throw new BackupError('Invalid pending id', 500);
  const resolved = path.resolve(PENDING_DIR, `${pendingId}${BACKUP_FILE_EXT}`);
  // Containment guard: the joined path must stay inside PENDING_DIR (see localBackupPath).
  if (!resolved.startsWith(path.resolve(PENDING_DIR) + path.sep)) throw new BackupError('Invalid pending id', 500);
  return resolved;
}

export async function storePendingUpload(pendingId: string, buffer: Buffer): Promise<void> {
  fs.mkdirSync(PENDING_DIR, { recursive: true });
  await fs.promises.writeFile(pendingPath(pendingId), buffer);
}

/** Returns null when the staged file is missing. */
export async function openPendingUpload(pendingId: string): Promise<Buffer | null> {
  try {
    return await fs.promises.readFile(pendingPath(pendingId));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

export async function deletePendingUpload(pendingId: string): Promise<void> {
  try {
    await fs.promises.unlink(pendingPath(pendingId));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
}

// ---------------------------------------------------------------------------
// File-repo destination (strict instance binding — see fileRepoBroker)
// ---------------------------------------------------------------------------

/** Structural twin of fileRepoBroker's ProviderRecord (not exported from there). */
export interface FileRepoProvider {
  id: string;
  name: string;
  endpoint: string;
  capabilities: string[];
  lastSeenAt: string | null;
}

/** Resolves the BOUND provider for a repo-backed backup. No fallback to siblings. */
export async function resolveBoundProvider(providerId: string): Promise<FileRepoProvider> {
  const provider = await resolveFileRepoProvider(providerId);
  if (!provider) {
    throw new BackupError(`File-repo instance "${providerId}" is not registered or online — its backup bytes cannot be reached`, 409);
  }
  return provider;
}

export async function storeRepoBackup(provider: FileRepoProvider, buffer: Buffer): Promise<{ sha256: string; sizeBytes: number }> {
  return storeBlobViaProvider(provider, Readable.from(buffer));
}

/** Returns null when the bound instance answers 404 (bytes gone from its volume). */
export async function openRepoBackup(provider: FileRepoProvider, sha256: string): Promise<Buffer | null> {
  const stream = await openBlobFromProvider(provider, sha256);
  if (!stream) return null;
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks);
}

export async function deleteRepoBackup(provider: FileRepoProvider, sha256: string): Promise<void> {
  await deleteBlobViaProvider(provider, sha256);
}

// ---------------------------------------------------------------------------
// Safe merge engine (shared by restore + replication)
// ---------------------------------------------------------------------------

export interface TableMergeResult {
  table: string;
  created: number;
  updated: number;
  /** Rows skipped (e.g. unknown setting keys). */
  skipped?: number;
}

export interface SectionMergeReport {
  section: string;
  tables: TableMergeResult[];
  warnings: string[];
}

function pkKey(meta: TableMeta, row: Record<string, unknown>): string {
  return meta.pkColumns.map((c) => String(row[c] ?? '')).join('\u0001');
}

/** Existing PK tuples for the given rows (single query for single-col PKs, chunked OR-of-ANDs otherwise). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function existingPkSet(tx: any, meta: TableMeta, rows: Record<string, unknown>[]): Promise<Set<string>> {
  const found = new Set<string>();
  if (rows.length === 0) return found;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const t = meta.tableRef as any;
  if (meta.pkColumns.length === 1) {
    const col = meta.pkColumns[0];
    const values = [...new Set(rows.map((r) => r[col]))];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    for (let i = 0; i < values.length; i += 500) {
      const chunk = values.slice(i, i + 500);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const existing = await tx.select({ [col]: t[col] }).from(t).where(inArray(t[col], chunk as any[]));
      for (const r of existing) found.add(String(r[col]));
    }
    return found; // single-col PK: the key IS the value
  }
  const selectObj = Object.fromEntries(meta.pkColumns.map((c) => [c, t[c]]));
  for (let i = 0; i < rows.length; i += 200) {
    const chunk = rows.slice(i, i + 200);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const conds: any[] = chunk.map((r) => and(...meta.pkColumns.map((c) => eq(t[c], r[c]))));
    const whereClause = conds.length === 1 ? conds[0] : or(...conds);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const existing: any[] = await tx.select(selectObj).from(t).where(whereClause);
    for (const r of existing) found.add(pkKey(meta, r));
  }
  return found;
}

/** Upserts rows on the table's PK. Returns created/updated counts. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function mergeTable(tx: any, meta: TableMeta, rows: Record<string, unknown>[]): Promise<TableMergeResult> {
  if (rows.length === 0) return { table: meta.name, created: 0, updated: 0 };
  const existing = await existingPkSet(tx, meta, rows);
  let created = 0;
  for (const r of rows) if (!existing.has(pkKey(meta, r))) created += 1;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const t = meta.tableRef as any;
  // Column names come from our own schema introspection — safe to splice as identifiers.
  const pkSet = new Set(meta.pkColumns);
  const setObj: Record<string, unknown> = {};
  for (const c of meta.columns) if (!pkSet.has(c)) setObj[c] = sql.raw(`excluded."${meta.columnDbNames[c]}"`);
  const target = meta.pkColumns.map((c) => t[c]);

  for (let i = 0; i < rows.length; i += 500) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await tx.insert(t).values(rows.slice(i, i + 500)).onConflictDoUpdate({ target, set: setObj });
  }
  return { table: meta.name, created, updated: rows.length - created };
}

/** Merges system_settings through updateSetting() so validation + onChange hooks fire. */
async function mergeSettings(
  rows: Record<string, unknown>[],
  excludeKeys?: ReadonlySet<string>,
): Promise<{ result: TableMergeResult; warnings: string[] }> {
  const known = new Set(SETTING_DESCRIPTORS.map((d) => d.key));
  let created = 0;
  let updated = 0;
  let skipped = 0;
  const warnings: string[] = [];
  for (const row of rows) {
    const key = String(row['key'] ?? '');
    if (!known.has(key)) {
      skipped += 1;
      warnings.push(`Setting "${key}" no longer exists — skipped`);
      continue;
    }
    if (excludeKeys?.has(key)) {
      skipped += 1; // excluded by the replication target's policy
      continue;
    }
    try {
      await updateSetting(key, row.value ?? '');
      updated += 1;
    } catch (err) {
      skipped += 1;
      warnings.push(`Setting "${key}" rejected: ${(err as Error).message}`);
    }
  }
  invalidateSystemSettingsCache();
  return { result: { table: 'system_settings', created, updated, skipped }, warnings };
}

export interface ApplyOptions {
  /** Sections to apply (default: every section present in the archive). */
  sections?: string[];
  /** Setting keys to skip (replication exclusion policy). */
  excludeSettingKeys?: ReadonlySet<string>;
}

/**
 * Applies an archive with SAFE MERGE semantics — upsert by PK, absent rows
 * untouched. Each section runs in its own transaction (settings merged row-by-row
 * through updateSetting outside a tx). Throws BackupError on unknown sections;
 * per-table failures roll back only their section and re-throw after reporting.
 */
export async function applyArchive(archive: BackupArchive, opts: ApplyOptions = {}): Promise<SectionMergeReport[]> {
  const presentSections = Object.keys(archive.data);
  const wanted = (opts.sections ?? presentSections).filter((s) => presentSections.includes(s));
  assertKnownSections(wanted);

  // Warn (but proceed) on build-tag mismatch — different UNM builds may still be compatible.
  const warnings: string[] = [];
  if (archive.manifest.buildTag && process.env.UNM_BUILD_TAG && archive.manifest.buildTag !== process.env.UNM_BUILD_TAG) {
    warnings.push(`Archive was exported by build "${archive.manifest.buildTag}" (this instance runs "${process.env.UNM_BUILD_TAG}")`);
  }

  const reports: SectionMergeReport[] = [];
  for (const section of wanted) {
    const byTable = archive.data[section] ?? {};
    if (section === 'settings') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const rows = (byTable['system_settings'] ?? []) as any[];
      const { result, warnings: w } = await mergeSettings(rows, opts.excludeSettingKeys);
      reports.push({ section, tables: [result], warnings: [...warnings, ...w] });
      continue;
    }
    const report: SectionMergeReport = { section, tables: [], warnings: [] };
    try {
      await db.transaction(async (tx) => {
        for (const meta of tablesInSection(section as SectionKey)) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const rows = byTable[meta.name] ?? [];
          if (!Array.isArray(rows)) continue;
          report.tables.push(await mergeTable(tx, meta, rows));
        }
      });
    } catch (err) {
      throw new BackupError(`Section "${section}" failed to apply: ${(err as Error).message}`, 409);
    }
    reports.push(report);
  }
  return reports;
}

/** Rejects non-portable sections (used by the replication inbound endpoint). */
export function assertPortableSections(sections: string[]): void {
  for (const s of sections) {
    if (!PORTABLE_SECTIONS.includes(s as SectionKey)) {
      throw new BackupError(`Section "${s}" is not portable across instances (live inventory must be regenerated locally)`);
    }
  }
}
