import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { and, asc, desc, eq, ilike, inArray, like, ne } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { PROBE_USERNAME } from '../radius/probe';
import { getEffectiveSettingValue } from '../systemSettings';
import { requireAuth, requirePermission } from '../auth/middleware';

/**
 * RADIUS NAS clients (the unm-radius sidecar — FreeRADIUS EAP-TLS).
 *
 *   GET    /radius/nas-clients      -> list NAS clients (+ resolved secret metadata)
 *   POST   /radius/nas-clients      -> add one { name?, ip, secretId? }
 *   PATCH  /radius/nas-clients/:id  -> update name / ip / secretId (null clears the secret)
 *   DELETE /radius/nas-clients/:id  -> remove one
 *
 * The shared secret is NEVER stored here — each row references a secrets.id
 * (same pattern as device_plugins.secretId). At render time api/src/radius/
 * resolves + decrypts it via the owning provider. Reading requires `radius:read`;
 * writes require `radius:write`. Every mutation re-renders the raddb files on the
 * shared volume so the change hot-applies (SIGHUP) without a container restart —
 * best-effort, since the DB write is authoritative and one bad credential must
 * not wedge CRUD.
 */

const router = Router();

/** A NAS client row enriched with its secret's display metadata (no values). */
export interface RadiusNasClientView {
  id: string;
  name: string | null;
  ip: string;
  secretId: string | null;
  /** Display label of the referenced secret (metadata only — never the value). */
  secretLabel: string | null;
  /** The secret's type (e.g. 'apiKeyNoSecret', 'tunnelPsk') for the picker UI. */
  secretType: string | null;
  createdAt: string;
}

type Row = typeof schema.radiusNasClients.$inferSelect;

/** Resolves each row's secret label + type from the secrets table (one query). */
async function toViews(rows: Row[]): Promise<RadiusNasClientView[]> {
  const ids = rows.map((r) => r.secretId).filter((s): s is string => Boolean(s));
  const meta = new Map<string, { label: string | null; type: string }>();
  if (ids.length > 0) {
    const secrets = await db.query.secrets.findMany({ where: inArray(schema.secrets.id, ids) });
    for (const s of secrets) meta.set(s.id, { label: s.label, type: s.type });
  }
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    ip: r.ip,
    secretId: r.secretId,
    secretLabel: r.secretId && meta.has(r.secretId) ? (meta.get(r.secretId)?.label ?? null) : null,
    secretType: r.secretId && meta.has(r.secretId) ? (meta.get(r.secretId)?.type ?? null) : null,
    createdAt: r.createdAt,
  }));
}

/** Re-renders the raddb files after a mutation. Best-effort — see module doc. */
async function rerender(): Promise<void> {
  try {
    await require('../radius/radiusConfig').writeRadiusConfig();
  } catch (err) {
    console.warn('[radius] config re-render after NAS client change failed:', (err as Error).message);
  }
}

/** Accepts an IPv4 or IPv6 literal. Rejects empty / whitespace / hostnames. */
function isValidIp(value: string): boolean {
  const t = value.trim();
  if (!t || /\s/.test(t)) return false;
  // IPv4 dotted quad (each octet 0-255).
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) {
    return t.split('.').every((o) => Number(o) <= 255);
  }
  // IPv6 — at least one colon and only hex/colon chars (covers full + compressed).
  if (t.includes(':')) return /^[0-9a-fA-F:]+$/.test(t);
  return false;
}

/** Validates a secretId reference against the secrets table. Returns an error string or null. */
async function validateSecretRef(secretId: unknown): Promise<string | null> {
  if (secretId === null || secretId === undefined) return null; // clearing / not set
  if (typeof secretId !== 'string' || !secretId.trim()) return '"secretId" must be a string or null';
  const row = await db.query.secrets.findFirst({ where: (s, { eq }) => eq(s.id, secretId.trim()) });
  if (!row) return `Referenced credentials not found (${secretId})`;
  return null;
}

// GET /radius/nas-clients — list all NAS clients with resolved secret metadata.
router.get(
  '/radius/nas-clients',
  requireAuth,
  requirePermission('radius:read'),
  async (_req: Request, res: Response) => {
    const rows = await db.query.radiusNasClients.findMany({ orderBy: [asc(schema.radiusNasClients.ip)] });
    res.status(200).json(await toViews(rows));
  }
);

// POST /radius/nas-clients — add a NAS client.
router.post(
  '/radius/nas-clients',
  requireAuth,
  requirePermission('radius:write'),
  async (req: Request, res: Response) => {
    const body = (req.body ?? {}) as Record<string, unknown>;

    if (typeof body.ip !== 'string' || !isValidIp(body.ip)) {
      res.status(400).json({ error: '"ip" must be a valid IPv4 or IPv6 address' });
      return;
    }
    const ip = body.ip.trim();
    const name = typeof body.name === 'string' && body.name.trim() ? body.name.trim().slice(0, 128) : null;

    const secretErr = await validateSecretRef(body.secretId);
    if (secretErr) {
      res.status(secretErr.startsWith('Referenced') ? 404 : 400).json({ error: secretErr });
      return;
    }

    // IP is unique — a NAS has one address.
    const existing = await db.query.radiusNasClients.findFirst({ where: (r, { eq }) => eq(r.ip, ip) });
    if (existing) {
      res.status(409).json({ error: `A NAS client with IP ${ip} already exists` });
      return;
    }

    const id = uuidv4();
    const createdAt = new Date().toISOString();
    await db.insert(schema.radiusNasClients).values({
      id,
      name,
      ip,
      secretId: typeof body.secretId === 'string' ? body.secretId.trim() : null,
      createdAt,
    });

    await rerender();
    const [row] = await db.query.radiusNasClients.findMany({ where: (r, { eq }) => eq(r.id, id) });
    res.status(201).json((await toViews([row]))[0]);
  }
);

// PATCH /radius/nas-clients/:id — update name / ip and/or the secret reference.
router.patch(
  '/radius/nas-clients/:id',
  requireAuth,
  requirePermission('radius:write'),
  async (req: Request, res: Response) => {
    const id = String(req.params.id ?? '');
    const current = await db.query.radiusNasClients.findFirst({ where: (r, { eq }) => eq(r.id, id) });
    if (!current) {
      res.status(404).json({ error: 'NAS client not found' });
      return;
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const patch: Partial<Row> = {};

    // name — present in body means "set it" (empty string clears to null).
    if ('name' in body) {
      if (body.name === null || (typeof body.name === 'string' && !body.name.trim())) patch.name = null;
      else if (typeof body.name !== 'string') {
        res.status(400).json({ error: '"name" must be a string or null' });
        return;
      } else patch.name = body.name.trim().slice(0, 128);
    }

    // ip — optional change; must stay unique.
    if ('ip' in body) {
      if (typeof body.ip !== 'string' || !isValidIp(body.ip)) {
        res.status(400).json({ error: '"ip" must be a valid IPv4 or IPv6 address' });
        return;
      }
      const ip = body.ip.trim();
      if (ip !== current.ip) {
        const clash = await db.query.radiusNasClients.findFirst({ where: (r, { eq }) => eq(r.ip, ip) });
        if (clash && clash.id !== id) {
          res.status(409).json({ error: `A NAS client with IP ${ip} already exists` });
          return;
        }
      }
      patch.ip = ip;
    }

    // secretId — present in body means "set it" (null clears the credential).
    if ('secretId' in body) {
      const secretErr = await validateSecretRef(body.secretId);
      if (secretErr) {
        res.status(secretErr.startsWith('Referenced') ? 404 : 400).json({ error: secretErr });
        return;
      }
      patch.secretId = typeof body.secretId === 'string' ? body.secretId.trim() : null;
    }

    if (Object.keys(patch).length === 0) {
      res.status(400).json({ error: 'No updatable fields provided' });
      return;
    }

    await db.update(schema.radiusNasClients).set(patch).where(eq(schema.radiusNasClients.id, id));
    await rerender();
    const [row] = await db.query.radiusNasClients.findMany({ where: (r, { eq }) => eq(r.id, id) });
    res.status(200).json((await toViews([row]))[0]);
  }
);

// DELETE /radius/nas-clients/:id — remove a NAS client.
router.delete(
  '/radius/nas-clients/:id',
  requireAuth,
  requirePermission('radius:write'),
  async (req: Request, res: Response) => {
    const id = String(req.params.id ?? '');
    const current = await db.query.radiusNasClients.findFirst({ where: (r, { eq }) => eq(r.id, id) });
    if (!current) {
      res.status(404).json({ error: 'NAS client not found' });
      return;
    }
    await db.delete(schema.radiusNasClients).where(eq(schema.radiusNasClients.id, id));
    await rerender();
    res.status(204).send();
  }
);
/**
 * Per-user RADIUS reply profiles (VLAN / static IP / session limits) keyed by
 * client cert serial. The exec script reads this table at auth time and prints
 * the set fields as reply attributes — see radiusConfig.renderUserProfileScript.
 *
 *   GET    /radius/user-profiles      -> list all (+ resolved cert name)
 *   POST   /radius/user-profiles      -> add one { serial, ...fields }
 *   PATCH  /radius/user-profiles/:id  -> update fields (null clears a field)
 *   DELETE /radius/user-profiles/:id  -> remove one
 */
export interface RadiusUserProfileView {
  id: string;
  serial: string;
  name: string | null;
  /** Display label of the matching wifi_client_certs row (metadata only). */
  certName: string | null;
  vlanId: number | null;
  framedIp: string | null;
  framedIpv6: string | null;
  sessionTimeoutSec: number | null;
  idleTimeoutSec: number | null;
  replyMessage: string | null;
  createdAt: string;
}

type ProfileRow = typeof schema.radiusUserProfiles.$inferSelect;

/** Resolves each row's cert name from wifi_client_certs (one query). */
async function toProfileViews(rows: ProfileRow[]): Promise<RadiusUserProfileView[]> {
  const serials = rows.map((r) => r.serial);
  const names = new Map<string, string>();
  if (serials.length > 0) {
    const certs = await db.query.wifiClientCerts.findMany({ where: inArray(schema.wifiClientCerts.serial, serials) });
    for (const c of certs) names.set(c.serial.toLowerCase(), c.name);
  }
  return rows.map((r) => ({
    id: r.id,
    serial: r.serial,
    name: r.name,
    certName: names.get(r.serial.toLowerCase()) ?? null,
    vlanId: r.vlanId,
    framedIp: r.framedIp,
    framedIpv6: r.framedIpv6,
    sessionTimeoutSec: r.sessionTimeoutSec,
    idleTimeoutSec: r.idleTimeoutSec,
    replyMessage: r.replyMessage,
    createdAt: r.createdAt,
  }));
}

/** Accepts an IPv4 or IPv6 literal (same rules as NAS clients). */
function isValidProfileIp(value: string): boolean {
  const t = value.trim();
  if (!t || /\s/.test(t)) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return t.split('.').every((o) => Number(o) <= 255);
  if (t.includes(':')) return /^[0-9a-fA-F:]+$/.test(t);
  return false;
}

/** Parses + validates one profile field set from a request body. */
function parseProfileFields(body: Record<string, unknown>): { patch: Partial<ProfileRow>; error: string | null } {
  const patch: Partial<ProfileRow> = {};
  if ('vlanId' in body) {
    if (body.vlanId === null || body.vlanId === undefined) patch.vlanId = null;
    else if (!Number.isInteger(body.vlanId as number) || (body.vlanId as number) < 1 || (body.vlanId as number) > 4094)
      return { patch, error: '"vlanId" must be an integer between 1 and 4094 or null' };
    else patch.vlanId = body.vlanId as number;
  }
  if ('framedIp' in body) {
    if (body.framedIp === null || body.framedIp === undefined) patch.framedIp = null;
    else if (typeof body.framedIp !== 'string' || !isValidProfileIp(body.framedIp))
      return { patch, error: '"framedIp" must be a valid IPv4 or IPv6 address or null' };
    else patch.framedIp = body.framedIp.trim();
  }
  if ('framedIpv6' in body) {
    if (body.framedIpv6 === null || body.framedIpv6 === undefined) patch.framedIpv6 = null;
    else if (typeof body.framedIpv6 !== 'string' || !isValidProfileIp(body.framedIpv6))
      return { patch, error: '"framedIpv6" must be a valid IPv4 or IPv6 address or null' };
    else patch.framedIpv6 = body.framedIpv6.trim();
  }
  for (const key of ['sessionTimeoutSec', 'idleTimeoutSec'] as const) {
    if (key in body) {
      if (body[key] === null || body[key] === undefined) patch[key] = null;
      else if (!Number.isInteger(body[key] as number) || (body[key] as number) < 60)
        return { patch, error: `"${key}" must be an integer ≥ 60 or null` };
      else patch[key] = body[key] as number;
    }
  }
  if ('replyMessage' in body) {
    if (body.replyMessage === null || body.replyMessage === undefined) patch.replyMessage = null;
    else if (typeof body.replyMessage !== 'string') return { patch, error: '"replyMessage" must be a string or null' };
    // SECURITY: this value is printed verbatim by the per-auth exec script and
    // parsed back line-by-line into RADIUS attributes. Strip CR/LF/tabs so a
    // crafted message can't inject extra "Attr = value" lines, then trim + cap
    // length (RADIUS Reply-Message is 253 octets; keep headroom).
    else patch.replyMessage = body.replyMessage.replace(/[\r\n\t]/g, ' ').trim().slice(0, 256);
  }
  return { patch, error: null };
}

// GET /radius/user-profiles — list all profiles with resolved cert names.
router.get(
  '/radius/user-profiles',
  requireAuth,
  requirePermission('radius:read'),
  async (_req: Request, res: Response) => {
    const rows = await db.query.radiusUserProfiles.findMany({ orderBy: [asc(schema.radiusUserProfiles.serial)] });
    res.status(200).json(await toProfileViews(rows));
  }
);

// POST /radius/user-profiles — add a profile for one client cert serial.
router.post(
  '/radius/user-profiles',
  requireAuth,
  requirePermission('radius:write'),
  async (req: Request, res: Response) => {
    const body = (req.body ?? {}) as Record<string, unknown>;

    if (typeof body.serial !== 'string' || !/^[0-9a-fA-F]{2,64}$/.test(body.serial.trim())) {
      res.status(400).json({ error: '"serial" must be a hex certificate serial (no 0x prefix)' });
      return;
    }
    const serial = body.serial.trim().toLowerCase();

    const { patch, error } = parseProfileFields(body);
    if (error) {
      res.status(400).json({ error });
      return;
    }

    // Serial is unique — one profile per client cert.
    const existing = await db.query.radiusUserProfiles.findFirst({ where: (r, { eq }) => eq(r.serial, serial) });
    if (existing) {
      res.status(409).json({ error: `A RADIUS profile for this certificate already exists` });
      return;
    }

    const id = uuidv4();
    await db.insert(schema.radiusUserProfiles).values({
      id,
      serial,
      name: typeof body.name === 'string' && body.name.trim() ? body.name.trim().slice(0, 128) : null,
      ...patch,
      createdAt: new Date().toISOString(),
    });

    await rerender();
    const [row] = await db.query.radiusUserProfiles.findMany({ where: (r, { eq }) => eq(r.id, id) });
    res.status(201).json((await toProfileViews([row]))[0]);
  }
);

// PATCH /radius/user-profiles/:id — update fields (null clears a field).
router.patch(
  '/radius/user-profiles/:id',
  requireAuth,
  requirePermission('radius:write'),
  async (req: Request, res: Response) => {
    const id = String(req.params.id ?? '');
    const current = await db.query.radiusUserProfiles.findFirst({ where: (r, { eq }) => eq(r.id, id) });
    if (!current) {
      res.status(404).json({ error: 'RADIUS profile not found' });
      return;
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const patch: Partial<ProfileRow> = {};

    if ('name' in body) {
      if (body.name === null || (typeof body.name === 'string' && !body.name.trim())) patch.name = null;
      else if (typeof body.name !== 'string') {
        res.status(400).json({ error: '"name" must be a string or null' });
        return;
      } else patch.name = body.name.trim().slice(0, 128);
    }

    const { patch: fields, error } = parseProfileFields(body);
    if (error) {
      res.status(400).json({ error });
      return;
    }
    Object.assign(patch, fields);

    if (Object.keys(patch).length === 0) {
      res.status(400).json({ error: 'No updatable fields provided' });
      return;
    }

    await db.update(schema.radiusUserProfiles).set(patch).where(eq(schema.radiusUserProfiles.id, id));
    await rerender();
    const [row] = await db.query.radiusUserProfiles.findMany({ where: (r, { eq }) => eq(r.id, id) });
    res.status(200).json((await toProfileViews([row]))[0]);
  }
);

// DELETE /radius/user-profiles/:id — remove a profile.
router.delete(
  '/radius/user-profiles/:id',
  requireAuth,
  requirePermission('radius:write'),
  async (req: Request, res: Response) => {
    const id = String(req.params.id ?? '');
    const current = await db.query.radiusUserProfiles.findFirst({ where: (r, { eq }) => eq(r.id, id) });
    if (!current) {
      res.status(404).json({ error: 'RADIUS profile not found' });
      return;
    }
    await db.delete(schema.radiusUserProfiles).where(eq(schema.radiusUserProfiles.id, id));
    await rerender();
    res.status(204).send();
  }
);

/**
 * RADIUS self-monitoring + auth log (unsuccessful-login audit trail).
 *
 *   GET /radius/status     -> latest probe outcome of the radiusMonitor worker
 *                             (+ whether RADIUS is enabled) — no secret material.
 *   GET /radius/auth-log   -> recent radpostauth rows (one per completed auth
 *                             attempt, accept AND reject), newest first, with
 *                             optional result/username filters + limit.
 *
 * Both are read-only and require `radius:read`. The probe client's shared
 * secret is NEVER exposed here — only the outcome of probing with it.
 */

// GET /radius/status — latest self-monitoring state (probe outcome + counters).
router.get(
  '/radius/status',
  requireAuth,
  requirePermission('radius:read'),
  async (_req: Request, res: Response) => {
    const [stateRes] = await Promise.all([pool.query(`SELECT * FROM radius_monitor_state WHERE id = $1`, ['unm'])]);
    const s = stateRes.rows[0];

    // Recent auth-attempt counters for the last 24h (cheap — indexed by id/authdate).
    // The probe's own test requests are excluded: they are UNM's heartbeat, not
    // real login attempts (they would otherwise count as a reject every minute).
    const counts = await pool.query(
      `SELECT count(*) FILTER (WHERE reply LIKE 'Access-Reject%') AS rejects,
              count(*) FILTER (WHERE reply LIKE 'Access-Accept%') AS accepts,
              max(authdate) AS lastAttemptAt
       FROM radpostauth
       WHERE authdate > now() - interval '24 hours' AND username <> $1`,
      [PROBE_USERNAME]
    );
    const c = counts.rows[0];

    const enabled = String(await getEffectiveSettingValue('radiusEnabled')) !== 'false';
    res.status(200).json({
      enabled,
      probe: s
        ? {
            lastProbeAt: s['lastProbeAt'] as string | null,
            outcome: (s['probeOutcome'] as string | null) ?? null, // ok | bad-auth | timeout
            packetType: (s['packetType'] as string | null) ?? null,
            latencyMs: s['latencyMs'] != null ? Number(s['latencyMs']) : null,
            detail: (s['detail'] as string | null) ?? null,
          }
        : null, // worker has not run yet (or RADIUS was just enabled)
      last24h: {
        rejects: Number(c?.rejects ?? 0),
        accepts: Number(c?.accepts ?? 0),
        lastAttemptAt: c?.lastAttemptAt ? new Date(c.lastAttemptAt).toISOString() : null,
      },
    });
  }
);

// GET /radius/auth-log — recent auth attempts (the failed-login audit trail).
router.get(
  '/radius/auth-log',
  requireAuth,
  requirePermission('radius:read'),
  async (req: Request, res: Response) => {
    const limit = Math.min(500, Math.max(1, Number(req.query.limit ?? 100) || 100));
    const result = String(req.query.result ?? ''); // '' | 'reject' | 'accept'
    const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';

    const clauses: Array<ReturnType<typeof like>> = [ne(schema.radpostauth.username, PROBE_USERNAME)]; // heartbeat rows are not logins
    if (result === 'reject') clauses.push(like(schema.radpostauth.reply, 'Access-Reject%'));
    else if (result === 'accept') clauses.push(like(schema.radpostauth.reply, 'Access-Accept%'));
    if (search) clauses.push(ilike(schema.radpostauth.username, `%${search}%`));

    const rows = await db.query.radpostauth.findMany({
      where: clauses.length > 0 ? and(...clauses) : undefined,
      orderBy: [desc(schema.radpostauth.id)],
      limit,
    });
    res.status(200).json(
      rows.map((r) => ({
        id: Number(r.id),
        username: r.username,
        result: (r.reply ?? '').startsWith('Access-Reject') ? 'reject' : (r.reply ?? '').startsWith('Access-Accept') ? 'accept' : (r.reply ?? null),
        calledStationId: r.calledStationId,
        callingStationId: r.callingStationId,
        authdate: r.authdate instanceof Date ? r.authdate.toISOString() : String(r.authdate),
      }))
    );
  }
);

export default router;
