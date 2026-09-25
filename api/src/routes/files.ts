import { Router, Request, Response } from 'express';
import { Readable } from 'stream';
import { requireAuth, requirePermission } from '../auth/middleware';
import {
  FileRepoError,
  addRepoFile,
  deleteRepoFile,
  getRepoFile,
  listRepoFiles,
  listRepoFileUses,
  openRepoFile,
  recordRepoFileUse,
} from '../fileRepo';

/**
 * Central file repository routes.
 *
 * TWO routers:
 *   - filesRouter (PUBLIC, mounted after the OpenAPI validator): JWT + page
 *     permissions. The webapp's Files page lists/uploads/downloads/deletes repo
 *     files here. Uploads are RAW octet-stream bodies with `x-file-name` /
 *     `x-file-category` headers — no multipart parser needed and multi-GB ISOs
 *     stream straight through (express.json only touches application/json).
 *   - internalFileRepoRouter (INTERNAL, mounted BEFORE the OpenAPI validator):
 *     gated by the shared x-plugin-api-key. Plugins do repo CRUD here (SDK
 *     createFileRepoClient) — they NEVER touch the volume or the database.
 *
 * The API is the ONLY component that reads/writes the repo volume + metadata;
 * plugins push files onto devices via their own native transport after fetching
 * them through /plugin/files/:id/content.
 */

const MAX_NAME_LEN = 256;

function readNameHeader(req: Request): string {
  const raw = req.headers['x-file-name'];
  const name = Array.isArray(raw) ? (raw[0] ?? '') : (raw ?? '');
  return String(name).trim();
}

function readCategoryHeader(req: Request): string | undefined {
  const raw = req.headers['x-file-category'];
  const cat = Array.isArray(raw) ? (raw[0] ?? '') : (raw ?? '');
  const c = String(cat).trim();
  return c.length > 0 ? c.slice(0, 40) : undefined;
}

function isJsonBody(req: Request): boolean {
  const ct = String(req.headers['content-type'] ?? '');
  return ct.includes('application/json');
}

// ---------------------------------------------------------------------------
// PUBLIC — /files (webapp Files page)
// ---------------------------------------------------------------------------

export const filesRouter = Router();

// GET /files — list repo files, newest first. Optional ?category= filter.
filesRouter.get('/files', requireAuth, requirePermission('files:read'), async (req: Request, res: Response) => {
  try {
    const category = typeof req.query.category === 'string' && req.query.category !== '' ? req.query.category : undefined;
    const files = await listRepoFiles(category);
    res.status(200).json({ files });
  } catch (err) {
    if (err instanceof FileRepoError) return void res.status(err.status).json({ error: err.message });
    throw err;
  }
});

// POST /files — upload a file. RAW octet-stream body + x-file-name header
// (+ optional x-file-category). Identical content is deduped (existing row
// returned, `deduplicated: true`); same name + different content gets a suffix.
filesRouter.post('/files', requireAuth, requirePermission('files:write'), async (req: Request, res: Response) => {
  if (isJsonBody(req)) {
    res.status(400).json({ error: 'Uploads must be sent as application/octet-stream with an x-file-name header' });
    return;
  }
  const name = readNameHeader(req);
  if (!name) {
    res.status(400).json({ error: 'Missing x-file-name header (the original file name)' });
    return;
  }
  if (name.length > MAX_NAME_LEN) {
    res.status(400).json({ error: `File name must be at most ${MAX_NAME_LEN} characters` });
    return;
  }
  try {
    const uploadedBy = typeof req.user?.sub === 'string' ? req.user.sub : null;
    // Stream the request body straight into storage (no in-memory buffering).
    const { entry, deduplicated } = await addRepoFile({
      data: req as unknown as Readable,
      name,
      category: readCategoryHeader(req),
      uploadedBy,
    });
    res.status(201).json({ file: entry, deduplicated });
  } catch (err) {
    if (err instanceof FileRepoError) return void res.status(err.status).json({ error: err.message });
    throw err;
  }
});

// GET /files/:id — download a repo file (raw bytes, Content-Disposition
// attachment). Records a usage row for the audit trail.
filesRouter.get('/files/:id', requireAuth, requirePermission('files:read'), async (req: Request, res: Response) => {
  try {
    const opened = await openRepoFile(req.params.id);
    if (!opened) {
      res.status(404).json({ error: 'File not found or its content is missing from the repo volume' });
      return;
    }
    void recordRepoFileUse(opened.entry.id, { usedBy: req.user?.sub ?? null }).catch(() => undefined); // audit only
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${opened.entry.name.replace(/"/g, '')}"`
    );
    if (opened.entry.sizeBytes > 0) res.setHeader('Content-Length', String(opened.entry.sizeBytes));
    opened.stream.pipe(res);
    opened.stream.on('error', () => {
      if (!res.headersSent) res.status(502).json({ error: 'Failed to stream the file' });
      else res.destroy();
    });
  } catch (err) {
    if (err instanceof FileRepoError) return void res.status(err.status).json({ error: err.message });
    throw err;
  }
});

// GET /files/:id/uses — the usage audit trail for one file (newest first).
filesRouter.get('/files/:id/uses', requireAuth, requirePermission('files:read'), async (req: Request, res: Response) => {
  try {
    const entry = await getRepoFile(req.params.id);
    if (!entry) {
      res.status(404).json({ error: 'File not found' });
      return;
    }
    const uses = await listRepoFileUses(entry.id);
    res.status(200).json({ fileId: entry.id, uses });
  } catch (err) {
    if (err instanceof FileRepoError) return void res.status(err.status).json({ error: err.message });
    throw err;
  }
});

// DELETE /files/:id — remove a file (content + metadata). Usage rows are kept.
filesRouter.delete('/files/:id', requireAuth, requirePermission('files:write'), async (req: Request, res: Response) => {
  try {
    await deleteRepoFile(req.params.id);
    res.status(204).end();
  } catch (err) {
    if (err instanceof FileRepoError) return void res.status(err.status).json({ error: err.message });
    throw err;
  }
});

// ---------------------------------------------------------------------------
// INTERNAL — /plugin/files/* (plugins, x-plugin-api-key)
// ---------------------------------------------------------------------------

export const internalFileRepoRouter = Router();

const pluginAuth = (req: Request, res: Response, next: () => void): void => {
  if (req.headers['x-plugin-api-key'] !== process.env.PLUGIN_API_KEY) {
    res.status(403).json({ error: 'Forbidden: Invalid plugin API key' });
    return;
  }
  next();
};

// GET /plugin/files — list repo files for a plugin (optional ?category=).
internalFileRepoRouter.get('/plugin/files', pluginAuth, async (req: Request, res: Response) => {
  try {
    const category = typeof req.query.category === 'string' && req.query.category !== '' ? req.query.category : undefined;
    const files = await listRepoFiles(category);
    res.status(200).json({ files });
  } catch (err) {
    if (err instanceof FileRepoError) return void res.status(err.status).json({ error: err.message });
    throw err;
  }
});

// POST /plugin/files — a plugin adds a file to the repo (raw octet-stream +
// x-file-name header, same contract as the public upload). E.g. a firmware
// image the plugin downloaded from a vendor feed on behalf of a device.
internalFileRepoRouter.post('/plugin/files', pluginAuth, async (req: Request, res: Response) => {
  if (isJsonBody(req)) {
    res.status(400).json({ error: 'Uploads must be sent as application/octet-stream with an x-file-name header' });
    return;
  }
  const name = readNameHeader(req);
  if (!name) {
    res.status(400).json({ error: 'Missing x-file-name header (the original file name)' });
    return;
  }
  try {
    const { entry, deduplicated } = await addRepoFile({
      data: req as unknown as Readable,
      name,
      category: readCategoryHeader(req),
      uploadedBy: null, // plugin upload — no user context on this hop
    });
    res.status(201).json(entry);
  } catch (err) {
    if (err instanceof FileRepoError) return void res.status(err.status).json({ error: err.message });
    throw err;
  }
});

// GET /plugin/files/:id — metadata for one repo file (name/category/size/sha256).
internalFileRepoRouter.get('/plugin/files/:id', pluginAuth, async (req: Request, res: Response) => {
  try {
    const entry = await getRepoFile(req.params.id);
    if (!entry) {
      res.status(404).json({ error: 'File not found' });
      return;
    }
    res.status(200).json(entry);
  } catch (err) {
    if (err instanceof FileRepoError) return void res.status(err.status).json({ error: err.message });
    throw err;
  }
});

// GET /plugin/files/:id/content — fetch a repo file's raw bytes. This is the
// "use" path: the plugin streams the content into its OWN native device
// transport (TrueNAS filesystem.put over /_upload, an OPNsense config upload…).
internalFileRepoRouter.get('/plugin/files/:id/content', pluginAuth, async (req: Request, res: Response) => {
  try {
    const opened = await openRepoFile(req.params.id);
    if (!opened) {
      res.status(404).json({ error: 'File not found or its content is missing from the repo volume' });
      return;
    }
    void recordRepoFileUse(opened.entry.id, { usedBy: 'plugin', note: 'fetched by plugin for device use' }).catch(() => undefined);
    res.setHeader('Content-Type', 'application/octet-stream');
    if (opened.entry.sizeBytes > 0) res.setHeader('Content-Length', String(opened.entry.sizeBytes));
    opened.stream.pipe(res);
    opened.stream.on('error', () => {
      if (!res.headersSent) res.status(502).json({ error: 'Failed to stream the file' });
      else res.destroy();
    });
  } catch (err) {
    if (err instanceof FileRepoError) return void res.status(err.status).json({ error: err.message });
    throw err;
  }
});

// DELETE /plugin/files/:id — a plugin removes a repo file.
internalFileRepoRouter.delete('/plugin/files/:id', pluginAuth, async (req: Request, res: Response) => {
  try {
    await deleteRepoFile(req.params.id);
    res.status(204).end();
  } catch (err) {
    if (err instanceof FileRepoError) return void res.status(err.status).json({ error: err.message });
    throw err;
  }
});

// POST /plugin/files/:id/use — record that a plugin USED a repo file on a
// device (audit trail: which file, for what device, when). Body: { deviceId?, note? }.
internalFileRepoRouter.post('/plugin/files/:id/use', pluginAuth, async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  try {
    const use = await recordRepoFileUse(req.params.id, {
      deviceId: typeof body.deviceId === 'string' && body.deviceId !== '' ? body.deviceId : null,
      note: typeof body.note === 'string' && body.note !== '' ? body.note.slice(0, 500) : null,
      usedBy: 'plugin',
    });
    res.status(200).json({ ok: true, use });
  } catch (err) {
    if (err instanceof FileRepoError) return void res.status(err.status).json({ error: err.message });
    throw err;
  }
});
