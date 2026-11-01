import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { eq } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';

const router = Router();

/** IANA timezone identifiers (e.g. "Europe/Berlin") — validated via Intl. */
function isValidTimezone(value: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: value });
    return true;
  } catch {
    return false;
  }
}

/** ISO-3166-1 alpha-2 country codes (e.g. "DE"). */
function isValidCountryCode(value: string): boolean {
  return /^[A-Z]{2}$/.test(value);
}

interface SiteInput {
  name?: unknown;
  description?: unknown;
  address?: unknown;
  country?: unknown;
  timezone?: unknown;
  latitude?: unknown;
  longitude?: unknown;
}

export interface SiteValues {
  name?: string;
  /** `null` on a partial update clears the field (stores NULL). */
  description?: string | null;
  address?: string | null;
  country?: string | null;
  timezone?: string | null;
  latitude?: number | null;
  longitude?: number | null;
}

/** Validates a GPS coordinate value: finite number within WGS84 ranges, or null. */
function parseCoordinate(
  value: unknown,
  field: 'latitude' | 'longitude'
): { ok: true; value: number | null } | { ok: false; error: string } {
  if (value === null) return { ok: true, value: null };
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n)) {
    return { ok: false, error: `"${field}" must be a finite number or null` };
  }
  const limit = field === 'latitude' ? 90 : 180;
  if (n < -limit || n > limit) {
    return { ok: false, error: `"${field}" must be between ${-limit} and ${limit}` };
  }
  return { ok: true, value: n };
}

/**
 * Validates a site payload. `name` is required (non-empty); the rest are
 * optional strings — or `null` on partial updates, which clears them — with
 * `timezone` additionally checked as an IANA id. Returns `{ values }` or `{ error }`.
 */
function validateSite(input: SiteInput, { partial = false }: { partial?: boolean } = {}) {
  const values: SiteValues = {};

  if (input.name !== undefined || !partial) {
    if (typeof input.name !== 'string' || input.name.trim().length === 0) {
      return { error: '"name" must be a non-empty string' };
    }
    values.name = input.name.trim();
  }

  for (const field of ['description', 'address'] as const) {
    if (input[field] === undefined) continue;
    if (input[field] === null) {
      values[field] = null;
      continue;
    }
    if (typeof input[field] !== 'string') {
      return { error: `"${field}" must be a string or null` };
    }
    values[field] = input[field].trim();
  }

  // Country is an ISO-3166-1 alpha-2 code (e.g. "DE"), not free text.
  if (input.country !== undefined) {
    if (input.country === null) {
      values.country = null;
    } else if (typeof input.country !== 'string' || !isValidCountryCode(input.country.trim().toUpperCase())) {
      return { error: '"country" must be an ISO-3166-1 alpha-2 code (e.g. "DE") or null' };
    } else {
      values.country = input.country.trim().toUpperCase();
    }
  }

  if (input.timezone !== undefined) {
    if (input.timezone === null) {
      values.timezone = null;
    } else if (typeof input.timezone !== 'string' || !isValidTimezone(input.timezone)) {
      return { error: '"timezone" must be a valid IANA timezone identifier (e.g. "Europe/Berlin") or null' };
    } else {
      values.timezone = input.timezone;
    }
  }

  // GPS location: all-or-nothing — both coordinates must be provided together
  // (or both omitted / both null to clear). Prevents accidentally clearing a
  // single coordinate. Values must be finite numbers within WGS84 ranges.
  if (input.latitude !== undefined || input.longitude !== undefined) {
    if (input.latitude === undefined || input.longitude === undefined) {
      return { error: 'Provide both latitude and longitude, or neither' };
    }
    const lat = parseCoordinate(input.latitude, 'latitude');
    if (!lat.ok) {
      return { error: lat.error };
    }
    const lng = parseCoordinate(input.longitude, 'longitude');
    if (!lng.ok) {
      return { error: lng.error };
    }
    values.latitude = lat.value;
    values.longitude = lng.value;
  }

  if (partial && Object.keys(values).length === 0) {
    return { error: 'Provide at least one of: name, description, address, country, timezone, latitude, longitude' };
  }
  return { values };
}

function serializeSite(row: typeof schema.sites.$inferSelect) {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? undefined,
    address: row.address ?? undefined,
    country: row.country ?? undefined,
    timezone: row.timezone ?? undefined,
    latitude: row.latitude ?? undefined,
    longitude: row.longitude ?? undefined,
    createdAt: row.createdAt,
  };
}

// GET /sites — list all sites (requires sites:read; the Sites page and the
// site pickers on other pages gate their queries on this permission).
router.get('/sites', requireAuth, requirePermission('sites:read'), async (_req: Request, res: Response) => {
  const rows = await db.query.sites.findMany({ orderBy: [schema.sites.name] });
  res.status(200).json(rows.map(serializeSite));
});

// POST /sites — create a site (requires sites:write).
router.post('/sites', requireAuth, requirePermission('sites:write'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as SiteInput;
  const check = validateSite(body);
  if ('error' in check) {
    res.status(400).json({ error: check.error });
    return;
  }

  const id = uuidv4();
  // Non-partial validation guarantees `name` is present.
  await db.insert(schema.sites).values({
    id,
    name: check.values.name as string,
    description: check.values.description ?? null,
    address: check.values.address ?? null,
    country: check.values.country ?? null,
    timezone: check.values.timezone ?? null,
    latitude: check.values.latitude ?? null,
    longitude: check.values.longitude ?? null,
    createdAt: new Date().toISOString(),
  });

  const created = await db.query.sites.findFirst({ where: eq(schema.sites.id, id) });
  if (!created) {
    res.status(500).json({ error: 'Failed to retrieve created site' });
    return;
  }
  res.status(201).json(serializeSite(created));
});

// PATCH /sites/:id — partial update (requires sites:write).
router.patch('/sites/:id', requireAuth, requirePermission('sites:write'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as SiteInput;
  const check = validateSite(body, { partial: true });
  if ('error' in check) {
    res.status(400).json({ error: check.error });
    return;
  }

  const existing = await db.query.sites.findFirst({ where: eq(schema.sites.id, String(req.params.id ?? '')) });
  if (!existing) {
    res.status(404).json({ error: 'Site not found' });
    return;
  }

  await db.update(schema.sites).set(check.values).where(eq(schema.sites.id, String(req.params.id ?? '')));

  const updated = await db.query.sites.findFirst({ where: eq(schema.sites.id, String(req.params.id ?? '')) });
  if (!updated) {
    res.status(500).json({ error: 'Failed to retrieve updated site' });
    return;
  }
  res.status(200).json(serializeSite(updated));
});

// DELETE /sites/:id — remove a site (requires sites:write). Refused with 409
// while any device still references it, so no assignment is ever orphaned.
router.delete('/sites/:id', requireAuth, requirePermission('sites:write'), async (req: Request, res: Response) => {
  const existing = await db.query.sites.findFirst({ where: eq(schema.sites.id, String(req.params.id ?? '')) });
  if (!existing) {
    res.status(404).json({ error: 'Site not found' });
    return;
  }

  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM devices WHERE "siteId" = $1', [existing.id]);
  const referencingCount = Number(rows[0]?.n ?? 0);
  if (referencingCount > 0) {
    res.status(409).json({
      error: `Cannot delete site "${existing.name}": ${referencingCount} device(s) still reference it. Unassign the site from those devices first.`,
    });
    return;
  }

  // Documented hosts may also be placed at this site — refuse while any do,
  // so no documented host is ever left pointing at a deleted site.
  const { rows: docRows } = await pool.query('SELECT COUNT(*)::int AS n FROM documented_hosts WHERE "siteId" = $1', [existing.id]);
  const docCount = Number(docRows[0]?.n ?? 0);
  if (docCount > 0) {
    res.status(409).json({
      error: `Cannot delete site "${existing.name}": ${docCount} documented host(s) are placed at it. Unassign the site from those hosts first.`,
    });
    return;
  }

  await db.delete(schema.sites).where(eq(schema.sites.id, existing.id));
  res.status(204).send();
});

export default router;
