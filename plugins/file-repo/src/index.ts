/**
 * UNM file-repo storage backend (capability `fileRepo`).
 *
 * This is the STATELESS BYTES HALF of the central file repository. The UNM API
 * owns ALL metadata in Postgres (`repo_files` + `repo_file_uses`) and brokers
 * every read/write here; this plugin only stores and serves raw bytes on a local
 * volume (a docker named volume or host path — see FILE_REPO_PATH). It has NO
 * database connection of its own.
 *
 * Why content-addressed: the API computes nothing about the bytes itself — it
 * streams an upload straight through to `PUT /store`, and this plugin hashes +
 * stores them, returning `{ sha256, sizeBytes }`. The API then records those in
 * the metadata row. Storing by SHA-256 makes every operation idempotent:
 *   - re-uploading identical content is a no-op (the bytes already exist);
 *   - the same file can be referenced from many rows / devices safely;
 *   - there are never two on-disk copies of one blob.
 * On-disk layout shards by the first two hash chars: `<root>/<aa>/<sha256>`.
 *
 * Multi-instance: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several file
 * repos in different network segments — each advertises a distinct identity and
 * its own volume, so the API can route files per-repo (see the API's
 * resolveFileRepoProvider). The contract is identical across instances.
 *
 * Future backends: this plugin is the LOCAL-FILESYSTEM implementation of the
 * `fileRepo` capability. An S3 / cloud-storage backend would be a NEW plugin
 * advertising the same capability with the same three routes — the API broker,
 * device plugins and webapp never change (they only ever see the API).
 */

import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import { createHash, randomUUID } from 'crypto';
import type { Readable } from 'stream';
import type { PluginOptionDescriptor } from '@unm/plugin-sdk';
import { FILE_REPO_DEVICE_SUPPORT } from './deviceSupport';
import {
  createPluginLogger,
  createPluginServer,
  readSettings,
  requirePluginKey,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000011';
export const PLUGIN_NAME = 'File Repository (Local Storage)';

const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  version: '0.1.0',
  vendors: ['unm'],
  capabilities: ['fileRepo'],
  authType: 'token',
});

/** Configurable options (the settings header flows through like any plugin). */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (store failures) to the UNM API for the Logs view. Disable to keep logging container-local only.',
  },
];

const server = createPluginServer({
  identity,
  logTag: 'file-repo',
  // Static doc/license assets served at /assets/* (proxied by the API's
  // GET /plugins/:id/asset) — referenced from discovery.deviceSupport.
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    // The `fileRepo` capability is what the API broker looks for (mirrors how
    // secretsProvider advertises its secret types). No per-device metrics.
    fileRepo: { backend: 'local-filesystem' },
    options: PLUGIN_OPTIONS,
    // License/help/docs metadata for UNM's Plugins page (see ./deviceSupport.ts).
    deviceSupport: FILE_REPO_DEVICE_SUPPORT,
  },
});
const app = server.app;

const logger = createPluginLogger(identity);

/** The on-disk store root. Only THIS container mounts it (see docker-compose). */
function storeRoot(): string {
  const root = (process.env.FILE_REPO_PATH ?? '/data/file-repo').replace(/\/+$/, '');
  if (!root.startsWith('/')) throw new Error(`FILE_REPO_PATH must be an absolute path: ${root}`);
  return root;
}

/** Validates a content key is a SHA-256 hex string (defensive — never trust the caller). */
function assertKey(key: string): void {
  if (!/^[a-f0-9]{64}$/i.test(key)) throw Object.assign(new Error(`Invalid store key: ${key}`), { status: 400 });
}

/** Maps a sha256 to its sharded on-disk path. */
function blobPath(sha256: string): string {
  return path.join(storeRoot(), sha256.slice(0, 2).toLowerCase(), sha256.toLowerCase());
}

async function exists(p: string): Promise<boolean> {
  try {
    await fsp.access(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Streams a readable into the content-addressed store. Hashes while writing to a
 * temp file, then renames it into place (atomic on the same volume). Identical
 * content is idempotent — an existing blob is kept and the temp copy dropped.
 */
async function storeStream(source: Readable): Promise<{ sha256: string; sizeBytes: number }> {
  const root = storeRoot();
  const hash = createHash('sha256');
  let sizeBytes = 0;

  // Final path is unknown until the full hash is computed → write to a temp file.
  const tmpPath = path.join(root, `.upload-${randomUUID()}`);
  await fsp.mkdir(root, { recursive: true });
  try {
    const out = fs.createWriteStream(tmpPath);
    for await (const chunk of source) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      hash.update(buf);
      sizeBytes += buf.length;
      if (!out.write(buf)) await new Promise<void>((r) => out.once('drain', r)); // backpressure
    }
    await new Promise<void>((resolve, reject) => {
      out.end(() => resolve());
      out.on('error', reject);
    });
  } catch (e) {
    await fsp.unlink(tmpPath).catch(() => undefined);
    throw e;
  }

  const sha256 = hash.digest('hex');
  const finalPath = blobPath(sha256);
  if (await exists(finalPath)) {
    // Identical content already stored — idempotent no-op. Drop our temp copy.
    await fsp.unlink(tmpPath).catch(() => undefined);
  } else {
    await fsp.mkdir(path.dirname(finalPath), { recursive: true });
    await fsp.rename(tmpPath, finalPath); // atomic on the same volume
  }
  return { sha256, sizeBytes };
}

/**
 * PUT /store — store a raw octet-stream body. Returns `{ sha256, sizeBytes }`
 * (the content identity + length) so the API can record metadata without hashing
 * itself. Idempotent for identical content; atomic on success.
 */
app.put('/store', requirePluginKey, async (req, res) => {
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);
  try {
    const result = await storeStream(req as unknown as Readable);
    res.status(201).json(result);
  } catch (err) {
    logger.error(`Failed to store upload: ${(err as Error).message}`);
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * GET /store/:key — stream a stored blob back by its SHA-256 key. Raw bytes, no
 * envelope (multi-GB ISOs must not be buffered). 404 when the key is unknown or
 * the bytes are missing from the volume.
 */
app.get('/store/:key', requirePluginKey, async (req, res) => {
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);
  const key = String(req.params.key ?? '');
  try {
    assertKey(key);
  } catch (e) {
    res.status(400).json({ error: (e as Error).message });
    return;
  }
  const abs = blobPath(key);
  if (!(await exists(abs))) {
    res.status(404).json({ error: 'Blob not found in the file-repo volume' });
    return;
  }
  const stream = fs.createReadStream(abs);
  res.setHeader('Content-Type', 'application/octet-stream');
  stream.pipe(res);
  stream.on('error', () => {
    if (!res.headersSent) res.status(502).json({ error: 'Failed to stream the blob' });
    else res.destroy();
  });
});

/**
 * DELETE /store/:key — remove a stored blob. Tolerates missing content (the API
 * deletes metadata regardless; orphaned blobs are harmless and idempotent).
 */
app.delete('/store/:key', requirePluginKey, async (req, res) => {
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);
  const key = String(req.params.key ?? '');
  try {
    assertKey(key);
  } catch (e) {
    res.status(400).json({ error: (e as Error).message });
    return;
  }
  await fsp.unlink(blobPath(key)).catch(() => undefined); // ENOENT is fine
  res.status(204).end();
});

// listen() binds the conventional plugin port (4080 by default) and starts mDNS
// advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[file-repo] fatal startup error:', err);
  process.exit(1);
});
