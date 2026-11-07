import { Router, Request, Response } from 'express';
import { randomUUID } from 'crypto';
import fs from 'fs';
import { desc, eq } from 'drizzle-orm';
import { requireAuth, requirePermission } from '../auth/middleware';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { PROBE_USERNAME } from '../radius/probe';
import { getEffectiveSettingValue } from '../systemSettings';
import { listFileRepoProviders } from '../fileRepoBroker';
import {
  BACKUP_FILE_EXT,
  BackupArchive,
  BackupError,
  PRESETS,
  SECTION_KEYS,
  applyArchive,
  assertPortableSections,
  buildArchive,
  deleteLocalBackup,
  deletePendingUpload,
  deleteRepoBackup,
  discoverTables,
  EXCLUDED_TABLES,
  gzipArchive,
  localBackupPath,
  openLocalBackup,
  openPendingUpload,
  openRepoBackup,
  parseArchive,
  resolveBoundProvider,
  scopeForSections,
  storeLocalBackup,
  storePendingUpload,
  storeRepoBackup,
} from '../backup';
import {
  buildPortableExport,
  deleteTarget,
  findDueTargets,
  listTargets,
  runTargetSync,
  upsertTarget,
} from '../replication';
import { rerenderRadiusConfig } from '../radius/mutations';

/**
 * Backup / restore routes (Backups page).
 *
 * All endpoints require the `instance:backup` permission. Uploads are RAW
 * octet-stream bodies with an `x-backup-name` header — no multipart parser
 * needed (same house pattern as files.ts); archives are gzip-compressed JSON
 * documents, typically a few MB even for full-scope backups.
 *
 * Stored backup bytes live either on the local volume (`BACKUP_DIR`, docker
 * volume `unm-backups`) or content-addressed in a BOUND file-repo plugin
 * instance — see backup.ts for the strict-instance-binding rules.
 */

export const backupsRouter = Router();

function readBackupNameHeader(req: Request): string {
  const raw = req.headers['x-backup-name'];
  const name = Array.isArray(raw) ? (raw[0] ?? '') : (raw ?? '');
  return String(name).trim().slice(0, 256);
}

function isJsonBody(req: Request): boolean {
  const ct = String(req.headers['content-type'] ?? '');
  return ct.includes('application/json');
}

/** HTTP status carried on an error (BackupError, FileRepoError or broker provider errors), else null. */
function httpStatus(err: unknown): number | null {
  if (err && typeof err === 'object' && typeof (err as { status?: unknown }).status === 'number') {
    return (err as { status: number }).status;
  }
  return null;
}

/** Sends the error's carried HTTP status + message, or rethrows for the global handler. */
function sendError(res: Response, err: unknown): void | never {
  const status = httpStatus(err);
  if (status) {
    res.status(status).json({ error: err instanceof Error ? err.message : String(err) });
    return;
  }
  throw err;
}

/** Collects a raw request body into a Buffer (archives are small enough to buffer). */
function readRawBody(req: Request): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Enriches a backups row with live destination state for the list view. */
async function enrichBackupRow(
  row: typeof schema.backups.$inferSelect,
): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = { ...row };
  let providerName: string | null = null;
  if (row.source === 'repo' && row.providerId) {
    const providers = await listFileRepoProviders();
    const p = providers.find((x) => x.id === row.providerId);
    providerName = p ? `${p.name} (${p.online ? 'online' : 'offline'})` : `unknown provider ${row.providerId}`;
  } else if (row.source === 'local') {
    try {
      await fs.promises.access(localBackupPath(row.id));
    } catch {
      out.fileMissing = true; // bytes deleted out-of-band — metadata row remains
    }
  }
  out.providerName = providerName;
  return out;
}

// GET /backups/meta — section keys, presets and exclusion info for the UI.
backupsRouter.get('/backups/meta', requireAuth, requirePermission('instance:backup'), async (_req: Request, res: Response) => {
  const tables = [...discoverTables().values()];
  res.status(200).json({
    sections: SECTION_KEYS.map((key) => ({
      key,
      tables: tables.filter((t) => t.section === key).map((t) => t.name),
    })),
    presets: PRESETS,
    excludedTables: [...EXCLUDED_TABLES],
  });
});

// POST /backups — create a backup. Body: { name?, preset? | sections[], destination: 'local'|'repo', providerId?, passphrase? }.
// `passphrase` is required when the explicit section list contains "secrets" —
// it encrypts the decrypted credentials into a portable envelope (never stored).
backupsRouter.post('/backups', requireAuth, requirePermission('instance:backup'), async (req, res) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  let sections: string[];
  if (Array.isArray(body.sections)) {
    sections = (body.sections as unknown[]).filter((s): s is string => typeof s === 'string');
  } else if (typeof body.preset === 'string' && PRESETS[body.preset]) {
    sections = [...PRESETS[body.preset]];
  } else {
    res.status(400).json({ error: 'Provide either "sections" (array) or a known "preset"' });
    return;
  }
  if (sections.length === 0) {
    res.status(400).json({ error: 'No sections selected' });
    return;
  }
  const passphrase = typeof body.passphrase === 'string' && body.passphrase !== '' ? body.passphrase : undefined;
  const destination = body.destination === 'repo' ? 'repo' : 'local';
  const providerId = typeof body.providerId === 'string' && body.providerId.trim() !== '' ? body.providerId.trim().slice(0, 128) : null;

  try {
    if (destination === 'repo' && !providerId) throw new BackupError('Repo destination requires a "providerId"');
    const archive = await buildArchive(sections, { passphrase });
    const { buffer, sha256, sizeBytes } = gzipArchive(archive);
    const id = randomUUID();

    let source: 'local' | 'repo' = 'local';
    let storedProviderId: string | null = null;
    if (destination === 'repo') {
      const provider = await resolveBoundProvider(providerId!); // 409 when the instance is gone/offline
      const identity = await storeRepoBackup(provider, buffer);
      source = 'repo';
      storedProviderId = provider.id;
      // The provider computed the content identity — trust it over our local hash.
      res.status(201).json({ backup: await insertBackupRow(id, String(body.name ?? '').trim() || defaultName(sections), sections, identity.sizeBytes, identity.sha256, source, storedProviderId) });
      return;
    }

    await storeLocalBackup(id, buffer);
    res.status(201).json({ backup: await insertBackupRow(id, String(body.name ?? '').trim() || defaultName(sections), sections, sizeBytes, sha256, source, storedProviderId) });
  } catch (err) {
    return sendError(res, err);
  }
});

function defaultName(sections: string[]): string {
  const scope = scopeForSections(sections);
  return `backup-${scope}-${new Date().toISOString().slice(0, 10)}`;
}

async function insertBackupRow(
  id: string,
  name: string,
  sections: string[],
  sizeBytes: number,
  sha256: string,
  source: 'local' | 'repo',
  providerId: string | null,
): Promise<Record<string, unknown>> {
  const row = await db.insert(schema.backups).values({
    id,
    name,
    scope: scopeForSections(sections),
    sections: JSON.stringify(sections),
    sizeBytes,
    sha256,
    source,
    providerId,
    createdAt: new Date().toISOString(),
  }).returning();
  return enrichBackupRow(row[0]);
}

// GET /backups — list stored backups, newest first.
backupsRouter.get('/backups', requireAuth, requirePermission('instance:backup'), async (_req: Request, res: Response) => {
  try {
    const rows = await db.select().from(schema.backups).orderBy(desc(schema.backups.createdAt));
    const enriched = [];
    for (const row of rows) enriched.push(await enrichBackupRow(row));
    res.status(200).json({ backups: enriched });
  } catch (err) {
    return sendError(res, err);
  }
});

// DELETE /backups/:id — remove metadata + bytes (local unlink or bound-instance blob delete).
backupsRouter.delete('/backups/:id', requireAuth, requirePermission('instance:backup'), async (req: Request, res: Response) => {
  const id = String(req.params.id ?? '');
  try {
    const rows = await db.select().from(schema.backups).where(eq(schema.backups.id, id));
    if (rows.length === 0) {
      res.status(404).json({ error: 'Backup not found' });
      return;
    }
    const row = rows[0];
    if (row.source === 'repo') {
      if (!row.providerId) throw new BackupError('Repo backup has no bound provider', 500);
      await deleteRepoBackup(await resolveBoundProvider(row.providerId), row.sha256); // 409 when instance gone
    } else {
      await deleteLocalBackup(id);
    }
    await db.delete(schema.backups).where(eq(schema.backups.id, id));
    res.status(200).json({ deleted: true });
  } catch (err) {
    return sendError(res, err);
  }
});

// GET /backups/:id/download — stream the archive bytes (attachment download).
backupsRouter.get('/backups/:id/download', requireAuth, requirePermission('instance:backup'), async (req: Request, res: Response) => {
  const id = String(req.params.id ?? '');
  try {
    const rows = await db.select().from(schema.backups).where(eq(schema.backups.id, id));
    if (rows.length === 0) {
      res.status(404).json({ error: 'Backup not found' });
      return;
    }
    const row = rows[0];
    let buffer: Buffer | null;
    if (row.source === 'repo') {
      if (!row.providerId) throw new BackupError('Repo backup has no bound provider', 500);
      buffer = await openRepoBackup(await resolveBoundProvider(row.providerId), row.sha256); // 409 when instance gone
    } else {
      buffer = await openLocalBackup(id);
    }
    if (!buffer) {
      res.status(410).json({ error: 'Backup metadata exists but its bytes are missing (deleted out-of-band)' });
      return;
    }
    const safeName = row.name.replace(/"/g, '').slice(0, 200);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${safeName}${BACKUP_FILE_EXT}"`);
    res.status(200).send(buffer);
  } catch (err) {
    return sendError(res, err);
  }
});

// POST /backups/restore/upload — stage an uploaded archive for restore. RAW octet-stream
// body + optional x-backup-name header. Returns the parsed manifest as a preview;
// nothing is applied until /backups/restore/apply.
backupsRouter.post('/backups/restore/upload', requireAuth, requirePermission('instance:backup'), async (req: Request, res: Response) => {
  if (isJsonBody(req)) {
    res.status(400).json({ error: 'Uploads must be sent as application/octet-stream' });
    return;
  }
  try {
    const buffer = await readRawBody(req);
    if (buffer.length === 0) throw new BackupError('Empty upload');
    const archive = parseArchive(buffer); // throws BackupError(400) on corrupt/foreign/newer archives
    const pendingId = randomUUID();
    await storePendingUpload(pendingId, buffer);
    res.status(201).json({ pendingId, manifest: archive.manifest });
  } catch (err) {
    return sendError(res, err);
  }
});

// POST /backups/restore/apply — merge-apply a staged upload or a stored backup.
// Body: { pendingId? | backupId?, sections?, passphrase? }. Safe merge: upsert by PK,
// absent rows untouched. `passphrase` unlocks the secrets envelope when present.
backupsRouter.post('/backups/restore/apply', requireAuth, requirePermission('instance:backup'), async (req, res) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const pendingId = typeof body.pendingId === 'string' ? body.pendingId : null;
  const backupId = typeof body.backupId === 'string' ? body.backupId : null;
  if (!pendingId && !backupId) {
    res.status(400).json({ error: 'Provide "pendingId" (staged upload) or "backupId" (stored backup)' });
    return;
  }
  const sections = Array.isArray(body.sections) ? (body.sections as unknown[]).filter((s): s is string => typeof s === 'string') : undefined;
  const passphrase = typeof body.passphrase === 'string' && body.passphrase !== '' ? body.passphrase : undefined;

  try {
    let buffer: Buffer | null;
    if (pendingId) {
      buffer = await openPendingUpload(pendingId);
      if (!buffer) throw new BackupError('Staged upload no longer exists — re-upload it', 410);
    } else {
      const rows = await db.select().from(schema.backups).where(eq(schema.backups.id, backupId!));
      if (rows.length === 0) throw new BackupError('Backup not found', 404);
      const row = rows[0];
      buffer = row.source === 'repo'
        ? await openRepoBackup(await resolveBoundProvider(row.providerId!), row.sha256)
        : await openLocalBackup(row.id);
      if (!buffer) throw new BackupError('Backup bytes are missing (deleted out-of-band)', 410);
    }

    const archive: BackupArchive = parseArchive(buffer);
    // Continue past a failed section so one bad table (e.g. a duplicate username in
    // identity) doesn't silently block the rest — each section is its own transaction,
    // and failures are reported per-section in `report[].error`.
    const reports = await applyArchive(archive, { sections, continueOnSectionError: true, passphrase });
    if (pendingId) await deletePendingUpload(pendingId); // applied — drop the staged copy
    res.status(200).json({ report: reports });
  } catch (err) {
    return sendError(res, err);
  }
});

// DELETE /backups/restore/pending/:pendingId — discard a staged upload without applying.
backupsRouter.delete('/backups/restore/pending/:pendingId', requireAuth, requirePermission('instance:backup'), async (req: Request, res: Response) => {
  try {
    await deletePendingUpload(String(req.params.pendingId ?? ''));
    res.status(200).json({ deleted: true });
  } catch (err) {
    return sendError(res, err);
  }
});

// ---------------------------------------------------------------------------
// Replication — peer-facing endpoints + target management
// ---------------------------------------------------------------------------

// POST /replication/inbound — receive a push from a peer instance.
// Body: { manifest, data, caRootPem?, secretsPassphrase? }. Applies the SAME safe
// merge as restore; only portable sections are accepted (400 otherwise) — except
// `secrets`, which is allowed when the sender provides the envelope passphrase
// (RADIUS failover slaves need the NAS shared secrets to authenticate identically).
backupsRouter.post('/replication/inbound', requireAuth, requirePermission('instance:backup'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as { manifest?: unknown; data?: Record<string, Record<string, unknown[]>>; caRootPem?: unknown; secretsPassphrase?: unknown };
  if (!body.manifest || typeof body.manifest !== 'object' || !body.data || typeof body.data !== 'object') {
    res.status(400).json({ error: 'Body must be a backup archive { manifest, data } (see GET /replication/export)' });
    return;
  }
  try {
    const sections = Object.keys(body.data);
    assertPortableSections(sections.filter((s) => s !== 'secrets')); // liveInventory & co. are rejected with 400
    const passphrase = typeof body.secretsPassphrase === 'string' ? body.secretsPassphrase : '';
    if (sections.includes('secrets') && !passphrase) {
      res.status(400).json({ error: 'The "secrets" section requires secretsPassphrase in the request body' });
      return;
    }
    const reports = await applyArchive(
      { manifest: body.manifest as BackupArchive['manifest'], data: body.data, ...(typeof body.caRootPem === 'string' ? { caRootPem: body.caRootPem } : {}) },
      { passphrase: passphrase || undefined },
    );
    // RADIUS failover: merged NAS clients / profiles / revocations (and an adopted
    // CA root) only take effect once the raddb files are re-rendered — do it now,
    // not on the next local mutation. The sidecar watches mtimes and SIGHUPs radiusd.
    if (sections.includes('radius') || sections.includes('secrets')) {
      void rerenderRadiusConfig();
    }
    res.status(200).json({ report: reports, receivedAt: new Date().toISOString() });
  } catch (err) {
    return sendError(res, err);
  }
});

// GET /replication/export?sections=a,b — portable export for pull-mode peers.
backupsRouter.get('/replication/export', requireAuth, requirePermission('instance:backup'), async (req: Request, res: Response) => {
  try {
    const raw = typeof req.query.sections === 'string' ? req.query.sections : '';
    const sections = raw.split(',').map((s) => s.trim()).filter(Boolean);
    const archive = await buildPortableExport(sections.length > 0 ? sections : undefined);
    res.status(200).json({ manifest: archive.manifest, data: archive.data });
  } catch (err) {
    return sendError(res, err);
  }
});

// GET /replication/targets — list replication targets (tokens are never returned).
backupsRouter.get('/replication/targets', requireAuth, requirePermission('instance:backup'), async (_req: Request, res: Response) => {
  try {
    const targets = await listTargets();
    res.status(200).json({ targets });
  } catch (err) {
    return sendError(res, err);
  }
});

// POST /replication/targets — create a target. Body: { name, baseUrl, token, direction?, enabled?, intervalMinutes?, excludeKeys?, sections?, includeSecrets?, secretsPassphrase? }.
backupsRouter.post('/replication/targets', requireAuth, requirePermission('instance:backup'), async (req, res) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const target = await upsertTarget({
      name: String(body.name ?? ''),
      baseUrl: String(body.baseUrl ?? ''),
      token: String(body.token ?? ''),
      direction: body.direction === 'pull' ? 'pull' : 'push',
      enabled: typeof body.enabled === 'boolean' ? body.enabled : undefined,
      intervalMinutes: body.intervalMinutes == null ? null : Number(body.intervalMinutes),
      excludeKeys: Array.isArray(body.excludeKeys) ? (body.excludeKeys as unknown[]).filter((k): k is string => typeof k === 'string') : undefined,
      sections: Array.isArray(body.sections) ? (body.sections as unknown[]).filter((s): s is string => typeof s === 'string') : null,
      includeSecrets: typeof body.includeSecrets === 'boolean' ? body.includeSecrets : undefined,
      secretsPassphrase: typeof body.secretsPassphrase === 'string' || body.secretsPassphrase === null ? (body.secretsPassphrase as string | null) : undefined,
    });
    res.status(201).json({ target });
  } catch (err) {
    return sendError(res, err);
  }
});

// PATCH /replication/targets/:id — update a target. Same body shape as create.
backupsRouter.patch('/replication/targets/:id', requireAuth, requirePermission('instance:backup'), async (req: Request, res: Response) => {
  try {
    const id = String(req.params.id ?? '');
    const body = (req.body ?? {}) as Record<string, unknown>;
    if (!body.name || !body.baseUrl || !body.token) {
      res.status(400).json({ error: 'name, baseUrl and token are required' });
      return;
    }
    const target = await upsertTarget(
      {
        name: String(body.name),
        baseUrl: String(body.baseUrl),
        token: String(body.token),
        direction: body.direction === 'pull' ? 'pull' : 'push',
        enabled: typeof body.enabled === 'boolean' ? body.enabled : undefined,
        intervalMinutes: body.intervalMinutes == null ? null : Number(body.intervalMinutes),
        excludeKeys: Array.isArray(body.excludeKeys) ? (body.excludeKeys as unknown[]).filter((k): k is string => typeof k === 'string') : undefined,
        sections: Array.isArray(body.sections) ? (body.sections as unknown[]).filter((s): s is string => typeof s === 'string') : null,
        includeSecrets: typeof body.includeSecrets === 'boolean' ? body.includeSecrets : undefined,
        secretsPassphrase: typeof body.secretsPassphrase === 'string' || body.secretsPassphrase === null ? (body.secretsPassphrase as string | null) : undefined,
      },
      id,
    );
    res.status(200).json({ target });
  } catch (err) {
    return sendError(res, err);
  }
});

// DELETE /replication/targets/:id — remove a target.
backupsRouter.delete('/replication/targets/:id', requireAuth, requirePermission('instance:backup'), async (req: Request, res: Response) => {
  try {
    const deleted = await deleteTarget(String(req.params.id ?? ''));
    if (!deleted) {
      res.status(404).json({ error: 'Target not found' });
      return;
    }
    res.status(200).json({ deleted: true });
  } catch (err) {
    return sendError(res, err);
  }
});

// POST /replication/sync { targetId } — manual "Sync now"; runs the same job as the scheduler.
backupsRouter.post('/replication/sync', requireAuth, requirePermission('instance:backup'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const targetId = typeof body.targetId === 'string' ? body.targetId : '';
  if (!targetId) {
    res.status(400).json({ error: '"targetId" is required' });
    return;
  }
  try {
    const report = await runTargetSync(targetId);
    // The job persists the outcome; surface it even on sync errors (200 + status field).
    res.status(200).json({ report });
  } catch (err) {
    return sendError(res, err);
  }
});

// GET /replication/due — targets currently due for a scheduled sync (debug/ops helper).
backupsRouter.get('/replication/due', requireAuth, requirePermission('instance:backup'), async (_req: Request, res: Response) => {
  try {
    const due = await findDueTargets();
    res.status(200).json({ targets: due.map((t) => ({ id: t.id, name: t.name })) });
  } catch (err) {
    return sendError(res, err);
  }
});

/** One mirrored radpostauth row as served to the primary's monitor worker. */
interface SlaveAuthEventView {
  /** The SLAVE's local radpostauth id (stable within that instance). */
  id: number;
  username: string;
  result: 'accept' | 'reject' | null;
  calledStationId: string | null;
  callingStationId: string | null;
  authdate: string; // ISO
}

function toSlaveEvent(row: Record<string, unknown>): SlaveAuthEventView {
  const reply = typeof row.reply === 'string' ? row.reply : '';
  return {
    id: Number(row.id),
    username: String(row.username ?? ''),
    result: reply.startsWith('Access-Reject') ? 'reject' : reply.startsWith('Access-Accept') ? 'accept' : null,
    calledStationId: (row.calledStationId as string | null) ?? null,
    callingStationId: (row.callingStationId as string | null) ?? null,
    authdate: row.authdate instanceof Date ? row.authdate.toISOString() : String(row.authdate),
  };
}

/**
 * GET /replication/slave-status — RADIUS failover monitoring endpoint.
 *
 * The PRIMARY's radiusMonitor worker polls this on every replication target
 * that carries the `radius` section (same credential as inbound sync: a peer
 * token with `instance:backup`). It returns the slave's own self-monitoring
 * state (probe outcome + 24h counters — identical shape to GET /radius/status)
 * plus NEW auth attempts since the caller's cursor, so failed logins on a
 * failover slave are visible and alertable on the primary without shared storage.
 *
 *   ?cursorId=<n> — only rows with id > n (the SLAVE's local radpostauth id).
 *                   The id is a monotonically increasing bigserial, so this is
 *                   exact: no duplicates, no misses, and immune to timestamp
 *                   precision loss (Postgres keeps microseconds; JS Dates do not —
 *                   an authdate-based cursor would re-serve its own last row forever).
 *   no cursorId   — bootstrap: the NEWEST `limit` rows (oldest first). A fresh
 *                   primary therefore mirrors recent history but not the full past.
 *
 * The response also carries `latestEvent` (the newest non-probe row) so the
 * caller can detect a RESET of this table (ids restarted below its cursor while
 * authdates moved far forward) and re-bootstrap instead of missing new events.
 */
backupsRouter.get(
  '/replication/slave-status',
  requireAuth,
  requirePermission('instance:backup'),
  async (req: Request, res: Response) => {
    try {
      // NOTE: the OpenAPI validator (express-openapi-validator v5 forces coerceTypes)
      // converts declared integer query params to NUMBERS before this handler runs —
      // accept both string and number, never rely on `typeof === 'string'` here.
      const rawCursor = req.query.cursorId;
      const cursorIdRaw = typeof rawCursor === 'string' || typeof rawCursor === 'number' ? Number(rawCursor) : NaN;
      const cursorId = Number.isFinite(cursorIdRaw) ? Math.max(0, Math.floor(cursorIdRaw)) : null;
      const limit = Math.min(500, Math.max(1, Number(req.query.limit ?? 200) || 200));

      // Latest self-monitoring state (same shape as GET /radius/status).
      const stateRes = await pool.query(`SELECT * FROM radius_monitor_state WHERE id = $1`, ['unm']);
      const s = stateRes.rows[0];

      // 24h counters — the probe's heartbeat rows are excluded (not real logins).
      const counts = await pool.query(
        `SELECT count(*) FILTER (WHERE reply LIKE 'Access-Reject%') AS rejects,
                count(*) FILTER (WHERE reply LIKE 'Access-Accept%') AS accepts,
                max(authdate) AS "lastAttemptAt"
         FROM radpostauth
         WHERE authdate > now() - interval '24 hours' AND username <> $1`,
        [PROBE_USERNAME]
      );
      const c = counts.rows[0];

      // New events past the cursor (strict id comparison — exact, no precision loss).
      let eventRows: Array<Record<string, unknown>>;
      if (cursorId != null) {
        const evRes = await pool.query(
          `SELECT id, username, reply, calledstationid AS "calledStationId", callingstationid AS "callingStationId", authdate
           FROM radpostauth
           WHERE username <> $1 AND id > $2
           ORDER BY id ASC
           LIMIT $3`,
          [PROBE_USERNAME, cursorId, limit]
        );
        eventRows = evRes.rows;
      } else {
        // Bootstrap (no cursor yet): newest N rows, returned oldest-first.
        const evRes = await pool.query(
          `SELECT id, username, reply, calledstationid AS "calledStationId", callingstationid AS "callingStationId", authdate
           FROM radpostauth
           WHERE username <> $1
           ORDER BY id DESC
           LIMIT $2`,
          [PROBE_USERNAME, limit]
        );
        eventRows = evRes.rows.reverse();
      }

      // Newest non-probe row — lets the caller detect a table reset (see above).
      const latestRes = await pool.query(
        `SELECT id, authdate FROM radpostauth WHERE username <> $1 ORDER BY id DESC LIMIT 1`,
        [PROBE_USERNAME]
      );
      const le = latestRes.rows[0];

      const enabled = String(await getEffectiveSettingValue('radiusEnabled')) !== 'false';
      res.status(200).json({
        enabled,
        probe: s
          ? {
              lastProbeAt: (s['lastProbeAt'] as string | null) ?? null,
              outcome: (s['probeOutcome'] as string | null) ?? null, // ok | bad-auth | timeout
              packetType: (s['packetType'] as string | null) ?? null,
              latencyMs: s['latencyMs'] != null ? Number(s['latencyMs']) : null,
              detail: (s['detail'] as string | null) ?? null,
            }
          : null,
        last24h: {
          rejects: Number(c?.rejects ?? 0),
          accepts: Number(c?.accepts ?? 0),
          lastAttemptAt: c?.lastAttemptAt ? new Date(c.lastAttemptAt).toISOString() : null,
        },
        events: eventRows.map(toSlaveEvent),
        latestEvent: le ? { id: Number(le.id), authdate: le.authdate instanceof Date ? le.authdate.toISOString() : String(le.authdate) } : null,
      });
    } catch (err) {
      return sendError(res, err);
    }
  }
);
