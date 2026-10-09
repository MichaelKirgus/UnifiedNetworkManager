import { Router, Request, Response } from 'express';
import { eq, asc } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';

const router = Router();

/**
 * Network layers — the registry behind the topology view's horizontal bands.
 * Seeded with four built-ins (core / distribution / access / endpoint) in
 * initDb(); users may add custom layers and re-color/reorder any of them.
 * Built-in ids are stable strings referenced by the classification heuristic
 * (utils/topology.ts classifyLayer), so they cannot be deleted; custom layers
 * can, unless a device's manual override still references one (409).
 */

export interface NetworkLayerRow {
  id: string;
  name: string;
  sort: number;
  color: string;
  isBuiltin: boolean;
}

function serialize(row: typeof schema.networkLayers.$inferSelect): NetworkLayerRow {
  return { id: row.id, name: row.name, sort: row.sort, color: row.color, isBuiltin: row.isBuiltin };
}

/** Slugs a layer name into an id: lowercase alphanumerics + dashes. */
function slugify(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
}

/** Hex color like "#e11d48" (3 or 6 digits). */
function isValidColor(value: unknown): value is string {
  return typeof value === 'string' && /^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/.test(value.trim());
}

interface LayerInput {
  name?: unknown;
  color?: unknown;
  sort?: unknown;
}

// GET /layers — list all layers in band order (open to any authenticated user;
// the topology page needs them for band headers + device chips).
router.get('/layers', requireAuth, async (_req: Request, res: Response) => {
  const rows = await db.query.networkLayers.findMany({ orderBy: [asc(schema.networkLayers.sort), asc(schema.networkLayers.name)] });
  res.status(200).json(rows.map(serialize));
});

// POST /layers — create a custom layer (requires layers:write). The id is a
// slug of the name; on collision it gets a numeric suffix. New layers append
// after all existing ones (max sort + 1).
router.post('/layers', requireAuth, requirePermission('layers:write'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as LayerInput;

  if (typeof body.name !== 'string' || body.name.trim().length === 0) {
    res.status(400).json({ error: '"name" must be a non-empty string' });
    return;
  }
  const name = body.name.trim();
  if (name.length > 64) {
    res.status(400).json({ error: '"name" must be at most 64 characters' });
    return;
  }
  const color = typeof body.color === 'string' ? body.color.trim() : '#8b5cf6';
  if (!isValidColor(color)) {
    res.status(400).json({ error: '"color" must be a hex color (e.g. "#e11d48")' });
    return;
  }

  // Name is unique — reject duplicates outright (the id slug may collide with
  // different names, e.g. "DMZ" vs "Dmz", so the name check comes first).
  const dupName = await db.query.networkLayers.findFirst({ where: eq(schema.networkLayers.name, name) });
  if (dupName) {
    res.status(409).json({ error: `A layer named "${name}" already exists` });
    return;
  }

  // Unique id: slug, then numeric suffix on collision.
  let id = slugify(name);
  if (!id) id = 'layer';
  const taken = new Set<string>();
  for (const row of await db.query.networkLayers.findMany()) taken.add(row.id);
  let candidate = id;
  let n = 2;
  while (taken.has(candidate)) {
    candidate = `${id}-${n++}`;
  }

  const maxSort = await pool.query('SELECT COALESCE(MAX(sort), 0) AS m FROM network_layers');
  const sort = Number(maxSort.rows[0]?.m ?? 0) + 1;

  await db.insert(schema.networkLayers).values({ id: candidate, name, sort, color, isBuiltin: false });
  const created = await db.query.networkLayers.findFirst({ where: eq(schema.networkLayers.id, candidate) });
  if (!created) {
    res.status(500).json({ error: 'Failed to retrieve created layer' });
    return;
  }
  res.status(201).json(serialize(created));
});

// PATCH /layers/:id — partial update of name/color/sort (requires layers:write).
router.patch('/layers/:id', requireAuth, requirePermission('layers:write'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as LayerInput;

  const existing = await db.query.networkLayers.findFirst({ where: eq(schema.networkLayers.id, String(req.params.id ?? '')) });
  if (!existing) {
    res.status(404).json({ error: 'Layer not found' });
    return;
  }

  const updates: Partial<typeof schema.networkLayers.$inferInsert> = {};

  if (body.name !== undefined) {
    if (typeof body.name !== 'string' || body.name.trim().length === 0) {
      res.status(400).json({ error: '"name" must be a non-empty string' });
      return;
    }
    const name = body.name.trim();
    if (name.length > 64) {
      res.status(400).json({ error: '"name" must be at most 64 characters' });
      return;
    }
    const dupName = await db.query.networkLayers.findFirst({ where: eq(schema.networkLayers.name, name) });
    if (dupName && dupName.id !== existing.id) {
      res.status(409).json({ error: `A layer named "${name}" already exists` });
      return;
    }
    updates.name = name;
  }

  if (body.color !== undefined) {
    if (!isValidColor(body.color)) {
      res.status(400).json({ error: '"color" must be a hex color (e.g. "#e11d48")' });
      return;
    }
    updates.color = body.color.trim();
  }

  if (body.sort !== undefined) {
    const n = typeof body.sort === 'number' ? body.sort : Number(body.sort);
    if (!Number.isInteger(n) || n < 1) {
      res.status(400).json({ error: '"sort" must be a positive integer' });
      return;
    }
    updates.sort = n;
  }

  if (Object.keys(updates).length === 0) {
    res.status(400).json({ error: 'Provide at least one of: name, color, sort' });
    return;
  }

  await db.update(schema.networkLayers).set(updates).where(eq(schema.networkLayers.id, existing.id));
  const updated = await db.query.networkLayers.findFirst({ where: eq(schema.networkLayers.id, existing.id) });
  if (!updated) {
    res.status(500).json({ error: 'Failed to retrieve updated layer' });
    return;
  }
  res.status(200).json(serialize(updated));
});

// DELETE /layers/:id — remove a custom layer (requires layers:write). Built-ins
// are never deletable (the heuristic references their ids); custom layers are
// refused with 409 while any device's manual override still points at them.
router.delete('/layers/:id', requireAuth, requirePermission('layers:write'), async (req: Request, res: Response) => {
  const existing = await db.query.networkLayers.findFirst({ where: eq(schema.networkLayers.id, String(req.params.id ?? '')) });
  if (!existing) {
    res.status(404).json({ error: 'Layer not found' });
    return;
  }

  if (existing.isBuiltin) {
    res.status(409).json({ error: `Built-in layer "${existing.name}" cannot be deleted` });
    return;
  }

  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM devices WHERE "layerOverride" = $1', [existing.id]);
  const referencingCount = Number(rows[0]?.n ?? 0);
  if (referencingCount > 0) {
    res.status(409).json({
      error: `Cannot delete layer "${existing.name}": ${referencingCount} device(s) still use it as their manual override. Clear those overrides first.`,
    });
    return;
  }

  // Documented hosts may also be placed on this layer — refuse while any do,
  // so no documented host is left pointing at a deleted layer.
  const { rows: docRows } = await pool.query('SELECT COUNT(*)::int AS n FROM documented_hosts WHERE "layerId" = $1', [existing.id]);
  const docCount = Number(docRows[0]?.n ?? 0);
  if (docCount > 0) {
    res.status(409).json({
      error: `Cannot delete layer "${existing.name}": ${docCount} documented host(s) are placed on it. Unassign the layer from those hosts first.`,
    });
    return;
  }

  await db.delete(schema.networkLayers).where(eq(schema.networkLayers.id, existing.id));
  res.status(204).send();
});

export default router;
