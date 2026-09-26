import { createHash } from 'crypto';
import { randomUUID } from 'crypto';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import { Readable } from 'stream';
import { desc, eq, inArray } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';
import { deleteBlobViaProvider, openBlobFromProvider, resolveFileRepoProvider, storeBlobViaProvider } from './fileRepoBroker';

/**
 * Central file repository — storage layer.
 *
 * The repo is a DEVICE-INDEPENDENT store owned by the UNM API: metadata (name,
 * category, size, sha256, who uploaded it, when) lives in Postgres
 * (`repo_files` + `repo_file_uses`). The BYTES live either on the api-local
 * volume (`FILE_REPO_PATH`, default /data/file-repo — legacy rows with
 * `providerId = NULL`) or in a file-repo PLUGIN (capability `fileRepo`) that
 * stores them content-addressed by sha256. No device plugin ever sees any of
 * this — plugins do repo CRUD through the API's internal `/plugin/files/*`
 * routes (SDK createFileRepoClient) and push files onto devices via their own
 * native transport. The broker (fileRepoBroker.ts) resolves which provider owns
 * a file's bytes; this module keeps the metadata + local-fallback logic.
 *
 * Content identity is the SHA-256 of the bytes — re-uploading identical content
 * dedupes (the existing row/file is returned), and a same-name/different-content
 * upload gets a `-1`, `-2`, … suffix so nothing is ever silently overwritten.
 */

/** Error carrying an HTTP status so routes can map it directly. */
export class FileRepoError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** One repo file (the row shape the webapp + plugin client consume). */
export interface RepoFileEntry {
  id: string;
  name: string;
  category: string;
  sizeBytes: number;
  sha256: string;
  uploadedBy: string | null;
  createdAt: string;
  /** The file-repo plugin storing the bytes (null = api-local volume, legacy). */
  providerId: string | null;
  /** Display name for `uploadedBy` — user id resolved to username ('plugin' passes through). */
  uploadedByName?: string | null;
}

/** One usage record (audit trail — which file was used, for what device, when). */
export interface RepoFileUse {
  id: string;
  fileId: string;
  deviceId: string | null;
  note: string | null;
  usedBy: string | null;
  createdAt: string;
  /** Display name for `usedBy` — user id resolved to username ('plugin' passes through). */
  usedByName?: string | null;
}

/** The repo root on disk. Only the api container mounts this path. */
export function repoRoot(): string {
  const root = (process.env.FILE_REPO_PATH ?? '/data/file-repo').replace(/\/+$/, '');
  if (!root.startsWith('/')) throw new FileRepoError(500, `FILE_REPO_PATH must be an absolute path: ${root}`);
  return root;
}

/** Sanitizes a user-supplied file name for on-disk use (keeps it human-readable). */
export function sanitizeFileName(name: string): string {
  const base = path.basename((name ?? '').trim()).replace(/[/\\]+/g, '');
  // Keep letters/digits/dots/dashes/underscores/spaces; everything else → '_'.
  let out = base.replace(/[^\w.\- ]+/g, '_').replace(/\s+/g, ' ').slice(0, 180).trim();
  if (!out || out === '.' || out === '..') out = 'file';
  return out;
}

/** Maps a row to the public entry shape. */
function toEntry(row: typeof schema.repoFiles.$inferSelect): RepoFileEntry {
  return {
    id: row.id,
    name: row.name,
    category: row.category,
    sizeBytes: Number(row.sizeBytes ?? 0),
    sha256: row.sha256,
    uploadedBy: row.uploadedBy,
    createdAt: row.createdAt,
    // Which file-repo plugin stores the bytes (null = api-local volume). The
    // webapp uses this to show a per-file repo badge; device plugins ignore it.
    providerId: row.providerId ?? null,
  };
}

/**
 * Batch-resolves user ids to usernames. One query per list call; unknown ids
 * (deleted users) are simply absent from the map — callers fall back to the raw
 * id so columns never render empty. 'plugin' is filtered out (not a user).
 */
async function usernamesByIds(ids: Iterable<string | null | undefined>): Promise<Map<string, string>> {
  const set = new Set<string>();
  for (const id of ids) if (id && id !== 'plugin') set.add(id);
  const map = new Map<string, string>();
  if (set.size > 0) {
    const users = await db.query.users.findMany({ where: (u, { inArray }) => inArray(u.id, [...set]) });
    for (const u of users) map.set(u.id, u.username);
  }
  return map;
}

/** Resolves the `uploadedBy` ids of a batch of repo file entries. */
async function resolveUploaders(entries: RepoFileEntry[]): Promise<Map<string, string>> {
  return usernamesByIds(entries.map((e) => e.uploadedBy));
}

/** Lists repo files (newest first), optionally filtered by category. */
export async function listRepoFiles(category?: string): Promise<RepoFileEntry[]> {
  const rows = await db.query.repoFiles.findMany({
    where: category ? (t) => eq(t.category, category) : undefined,
    orderBy: [desc(schema.repoFiles.createdAt)],
  });
  const entries = rows.map(toEntry);
  const usernames = await resolveUploaders(entries);
  for (const e of entries) {
    if (!e.uploadedBy || e.uploadedBy === 'plugin') continue;
    e.uploadedByName = usernames.get(e.uploadedBy) ?? e.uploadedBy;
  }
  return entries;
}

/** Fetches one repo file by id (null when absent). */
export async function getRepoFile(id: string): Promise<RepoFileEntry | null> {
  const row = await db.query.repoFiles.findFirst({ where: (t) => eq(t.id, id) });
  return row ? toEntry(row) : null;
}

/** Finds an existing file by content hash (dedupe on re-upload). */
export async function findRepoFileBySha256(sha256: string): Promise<RepoFileEntry | null> {
  const row = await db.query.repoFiles.findFirst({ where: (t) => eq(t.sha256, sha256) });
  return row ? toEntry(row) : null;
}

/** Absolute on-disk path for a stored file (relative storagePath under the repo root). */
export function storagePathFor(storagePath: string): string {
  // Confine to the repo root — never let a stored path escape it.
  const abs = path.resolve(repoRoot(), storagePath);
  if (!abs.startsWith(path.resolve(repoRoot()) + path.sep)) throw new FileRepoError(500, `Storage path escapes the repo root: ${storagePath}`);
  return abs;
}

/**
 * Adds a file to the repo. The BYTES go either to a file-repo provider (when one
 * is online — content-addressed by sha256) or to the api-local volume (legacy /
 * no-provider fallback). Identical content (same sha256) is deduped — the
 * existing entry is returned with `deduplicated: true`. Same name + different
 * content gets a numeric suffix so nothing is ever silently overwritten.
 */
export async function addRepoFile(args: {
  data: Readable | Buffer;
  name: string;
  category?: string;
  uploadedBy?: string | null;
  /** Explicit file-repo provider id (e.g. from an x-file-provider header). Omitted = default provider or local fallback. */
  providerId?: string | null;
}): Promise<{ entry: RepoFileEntry; deduplicated: boolean }> {
  const category = sanitizeCategory(args.category);
  const base = sanitizeFileName(args.name);

  // Resolve where the bytes live. An explicit provider is honored even if it's a
  // different instance (multi-segment repos); otherwise the default, else local.
  const provider = await resolveFileRepoProvider(args.providerId ?? null);

  let sha256: string;
  let sizeBytes = 0;
  let storagePath: string;
  let rowProviderId: string | null = null;

  if (provider) {
    // Provider path — the plugin hashes + stores content-addressed and reports
    // back the identity. The API never buffers or re-hashes the bytes.
    const stored = await storeBlobViaProvider(provider, args.data as Readable);
    sha256 = stored.sha256;
    sizeBytes = stored.sizeBytes;
    rowProviderId = provider.id;
    // Informational only — providers key by sha256, not this path. Kept for a
    // human-readable "where it would have lived" hint in the metadata.
    storagePath = path.posix.join(category, new Date().toISOString().slice(0, 10), base);
  } else {
    // Local fallback — api-local volume (legacy layout + hashing).
    const root = repoRoot();
    const dateDir = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const dir = path.join(root, category, dateDir);
    await fsp.mkdir(dir, { recursive: true });

    const tmpPath = path.join(dir, `.upload-${randomUUID()}`);
    const hash = createHash('sha256');
    try {
      if (Buffer.isBuffer(args.data)) {
        await fsp.writeFile(tmpPath, args.data);
        hash.update(args.data);
        sizeBytes = args.data.length;
      } else {
        const out = fs.createWriteStream(tmpPath);
        for await (const chunk of args.data) {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          hash.update(buf);
          sizeBytes += buf.length;
          if (!out.write(buf)) await new Promise<void>((r) => out.once('drain', r));
        }
        await new Promise<void>((resolve, reject) => {
          out.end(() => resolve());
          out.on('error', reject);
        });
      }
    } catch (e) {
      await fsp.unlink(tmpPath).catch(() => undefined);
      throw new FileRepoError(500, `Failed writing upload: ${(e as Error).message}`);
    }

    sha256 = hash.digest('hex');

    // Choose a non-colliding disk name in this day directory.
    let diskName = base;
    for (let i = 1; ; i++) {
      const candidate = path.join(dir, diskName);
      try {
        await fsp.access(candidate);
        const dot = base.lastIndexOf('.');
        diskName = dot > 0 ? `${base.slice(0, dot)}-${i}${base.slice(dot)}` : `${base}-${i}`;
      } catch {
        break; // free
      }
    }
    await fsp.rename(tmpPath, path.join(dir, diskName));
    storagePath = path.posix.join(category, dateDir, diskName);
  }

  // Dedupe — identical content already stored (in ANY repo). The bytes are
  // idempotent either way; we just return the existing row.
  const existing = await findRepoFileBySha256(sha256);
  if (existing) {
    return { entry: existing, deduplicated: true };
  }

  const id = randomUUID();
  const createdAt = new Date().toISOString();
  await db.insert(schema.repoFiles).values({
    id,
    name: (args.name ?? '').trim() || base,
    category,
    sizeBytes,
    sha256,
    storagePath,
    uploadedBy: args.uploadedBy ?? null,
    createdAt,
    providerId: rowProviderId,
  });

  const stored = await db.query.repoFiles.findFirst({ where: (t) => eq(t.id, id) });
  if (!stored) throw new FileRepoError(500, 'File row vanished after insert');
  return { entry: toEntry(stored), deduplicated: false };
}

/** Opens a stored file for streaming (null when the row or its bytes are gone). */
export async function openRepoFile(id: string): Promise<{ entry: RepoFileEntry; stream: Readable } | null> {
  const row = await db.query.repoFiles.findFirst({ where: (t) => eq(t.id, id) });
  if (!row) return null;

  // Provider-backed bytes — route to the plugin that owns them by sha256.
  if (row.providerId) {
    const provider = await resolveFileRepoProvider(row.providerId);
    if (!provider) return null; // owning repo gone — treat as missing content
    const stream = await openBlobFromProvider(provider, row.sha256);
    if (!stream) return null; // 404 from the provider — bytes missing from that volume
    return { entry: toEntry(row), stream };
  }

  // Legacy local-volume read.
  let abs: string;
  try {
    abs = storagePathFor(row.storagePath);
  } catch {
    return null;
  }
  try {
    await fsp.access(abs);
  } catch {
    return null; // metadata without bytes — treat as missing (route returns 404/502)
  }
  return { entry: toEntry(row), stream: fs.createReadStream(abs) };
}

/** Deletes a repo file (metadata + content). Missing content is tolerated. */
export async function deleteRepoFile(id: string): Promise<void> {
  const row = await db.query.repoFiles.findFirst({ where: (t) => eq(t.id, id) });
  if (!row) throw new FileRepoError(404, 'File not found');

  // Remove the bytes from wherever they live. Tolerate failures — metadata is
  // dropped regardless and orphaned blobs are harmless + idempotent.
  try {
    if (row.providerId) {
      const provider = await resolveFileRepoProvider(row.providerId);
      if (provider) await deleteBlobViaProvider(provider, row.sha256);
    } else {
      let abs: string;
      try {
        abs = storagePathFor(row.storagePath);
      } catch {
        abs = ''; // malformed path — just drop the metadata
      }
      if (abs) await fsp.unlink(abs).catch(() => undefined);
    }
  } catch { /* best-effort content removal */ }

  // Usage records are audit data — keep them (they reference the file by id).
  await db.delete(schema.repoFiles).where(eq(schema.repoFiles.id, id));
}

/** Records a usage of a repo file (audit trail for "which file was used when"). */
export async function recordRepoFileUse(
  fileId: string,
  use: { deviceId?: string | null; note?: string | null; usedBy?: string | null }
): Promise<RepoFileUse> {
  const row = await db.query.repoFiles.findFirst({ where: (t) => eq(t.id, fileId) });
  if (!row) throw new FileRepoError(404, 'File not found');
  const id = randomUUID();
  const createdAt = new Date().toISOString();
  await db.insert(schema.repoFileUses).values({
    id,
    fileId,
    deviceId: use.deviceId ?? null,
    note: use.note ?? null,
    usedBy: use.usedBy ?? null,
    createdAt,
  });
  return { id, fileId, deviceId: use.deviceId ?? null, note: use.note ?? null, usedBy: use.usedBy ?? null, createdAt };
}

/** Lists the usage history of one repo file (newest first). */
export async function listRepoFileUses(fileId: string): Promise<RepoFileUse[]> {
  const rows = await db.query.repoFileUses.findMany({
    where: (t) => eq(t.fileId, fileId),
    orderBy: [desc(schema.repoFileUses.createdAt)],
  });
  const uses: RepoFileUse[] = rows.map((r) => ({ id: r.id, fileId: r.fileId, deviceId: r.deviceId, note: r.note, usedBy: r.usedBy, createdAt: r.createdAt }));
  const names = await usernamesByIds(uses.map((u) => u.usedBy));
  for (const u of uses) {
    if (!u.usedBy || u.usedBy === 'plugin') continue;
    u.usedByName = names.get(u.usedBy) ?? u.usedBy;
  }
  return uses;
}

/** Normalizes a category string for on-disk use (lowercase slug). */
function sanitizeCategory(category?: string): string {
  const c = (category ?? '').trim().toLowerCase().replace(/[^a-z0-9\-_]+/g, '-').replace(/^-+|-+$/g, '');
  return c.length > 0 && c.length <= 40 ? c : 'other';
}
