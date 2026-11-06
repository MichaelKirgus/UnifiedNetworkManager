/**
 * radius mutations — the single implementation of every RADIUS write.
 *
 * These functions are the ONLY place NAS-client and user-profile rows are
 * created, updated or deleted. They are called by the plan executor's local-
 * mutation branch (api/src/plans/systemActions.ts) so that RADIUS changes flow
 * through the plan workflow (2FA-gated execution, full audit trail, retryable,
 * automatable). Every successful mutation re-renders the raddb files on the
 * shared volume so FreeRADIUS hot-applies it (SIGHUP) without a restart —
 * best-effort: the DB write is authoritative and one bad credential must not
 * wedge a plan step.
 */

import { v4 as uuidv4 } from 'uuid';
import { eq, inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';

/** Re-renders the raddb files after a mutation. Best-effort — see module doc. */
export async function rerenderRadiusConfig(): Promise<void> {
  try {
    await require('./radiusConfig').writeRadiusConfig();
  } catch (err) {
    console.warn('[radius] config re-render failed:', (err as Error).message);
  }
}

/** Accepts an IPv4 or IPv6 literal. Rejects empty / whitespace / hostnames. */
export function isValidIp(value: string): boolean {
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
export async function validateSecretRef(secretId: unknown): Promise<string | null> {
  if (secretId === null || secretId === undefined) return null; // clearing / not set
  if (typeof secretId !== 'string' || !secretId.trim()) return '"secretId" must be a string or null';
  const row = await db.query.secrets.findFirst({ where: (s, { eq }) => eq(s.id, secretId.trim()) });
  if (!row) return `Referenced credentials not found (${secretId})`;
  return null;
}

// --- NAS clients -------------------------------------------------------------

/** Creates one NAS client. Throws on validation failure / duplicate IP. */
export async function createNasClient(input: Record<string, unknown>): Promise<{ id: string }> {
  if (typeof input.ip !== 'string' || !isValidIp(input.ip)) {
    throw new Error('"ip" must be a valid IPv4 or IPv6 address');
  }
  const ip = input.ip.trim();
  const name = typeof input.name === 'string' && input.name.trim() ? input.name.trim().slice(0, 128) : null;

  const secretErr = await validateSecretRef(input.secretId);
  if (secretErr) throw new Error(secretErr);

  // IP is unique — a NAS has one address.
  const existing = await db.query.radiusNasClients.findFirst({ where: (r, { eq }) => eq(r.ip, ip) });
  if (existing) throw new Error(`A NAS client with IP ${ip} already exists`);

  const id = uuidv4();
  await db.insert(schema.radiusNasClients).values({
    id,
    name,
    ip,
    secretId: typeof input.secretId === 'string' ? input.secretId.trim() : null,
    createdAt: new Date().toISOString(),
  });
  await rerenderRadiusConfig();
  return { id };
}

/** Updates a NAS client's name / ip and/or secret reference. Throws when missing or invalid. */
export async function updateNasClient(id: string, patchInput: Record<string, unknown>): Promise<{ id: string }> {
  const current = await db.query.radiusNasClients.findFirst({ where: (r, { eq }) => eq(r.id, id) });
  if (!current) throw new Error('NAS client not found');

  const patch: Partial<typeof schema.radiusNasClients.$inferInsert> = {};

  // name — present in body means "set it" (empty string clears to null).
  if ('name' in patchInput) {
    if (patchInput.name === null || (typeof patchInput.name === 'string' && !patchInput.name.trim())) patch.name = null;
    else if (typeof patchInput.name !== 'string') throw new Error('"name" must be a string or null');
    else patch.name = patchInput.name.trim().slice(0, 128);
  }

  // ip — optional change; must stay unique.
  if ('ip' in patchInput) {
    if (typeof patchInput.ip !== 'string' || !isValidIp(patchInput.ip)) throw new Error('"ip" must be a valid IPv4 or IPv6 address');
    const ip = patchInput.ip.trim();
    if (ip !== current.ip) {
      const clash = await db.query.radiusNasClients.findFirst({ where: (r, { eq }) => eq(r.ip, ip) });
      if (clash && clash.id !== id) throw new Error(`A NAS client with IP ${ip} already exists`);
    }
    patch.ip = ip;
  }

  // secretId — present in body means "set it" (null clears the credential).
  if ('secretId' in patchInput) {
    const secretErr = await validateSecretRef(patchInput.secretId);
    if (secretErr) throw new Error(secretErr);
    patch.secretId = typeof patchInput.secretId === 'string' ? patchInput.secretId.trim() : null;
  }

  if (Object.keys(patch).length === 0) throw new Error('No updatable fields provided');

  await db.update(schema.radiusNasClients).set(patch).where(eq(schema.radiusNasClients.id, id));
  await rerenderRadiusConfig();
  return { id };
}

/** Deletes one NAS client. Throws when missing. */
export async function deleteNasClient(id: string): Promise<{ deleted: number }> {
  const current = await db.query.radiusNasClients.findFirst({ where: (r, { eq }) => eq(r.id, id) });
  if (!current) throw new Error('NAS client not found');
  await db.delete(schema.radiusNasClients).where(eq(schema.radiusNasClients.id, id));
  await rerenderRadiusConfig();
  return { deleted: 1 };
}

// --- User profiles -----------------------------------------------------------

/** Accepts an IPv4 or IPv6 literal (same rules as NAS clients). */
function isValidProfileIp(value: string): boolean {
  const t = value.trim();
  if (!t || /\s/.test(t)) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return t.split('.').every((o) => Number(o) <= 255);
  if (t.includes(':')) return /^[0-9a-fA-F:]+$/.test(t);
  return false;
}

/** Parses + validates one profile field set. Throws on the first invalid field. */
function parseProfileFields(body: Record<string, unknown>): Partial<typeof schema.radiusUserProfiles.$inferInsert> {
  const patch: Partial<typeof schema.radiusUserProfiles.$inferInsert> = {};
  if ('vlanId' in body) {
    if (body.vlanId === null || body.vlanId === undefined) patch.vlanId = null;
    else if (!Number.isInteger(body.vlanId as number) || (body.vlanId as number) < 1 || (body.vlanId as number) > 4094)
      throw new Error('"vlanId" must be an integer between 1 and 4094 or null');
    else patch.vlanId = body.vlanId as number;
  }
  if ('framedIp' in body) {
    if (body.framedIp === null || body.framedIp === undefined) patch.framedIp = null;
    else if (typeof body.framedIp !== 'string' || !isValidProfileIp(body.framedIp))
      throw new Error('"framedIp" must be a valid IPv4 or IPv6 address or null');
    else patch.framedIp = body.framedIp.trim();
  }
  if ('framedIpv6' in body) {
    if (body.framedIpv6 === null || body.framedIpv6 === undefined) patch.framedIpv6 = null;
    else if (typeof body.framedIpv6 !== 'string' || !isValidProfileIp(body.framedIpv6))
      throw new Error('"framedIpv6" must be a valid IPv4 or IPv6 address or null');
    else patch.framedIpv6 = body.framedIpv6.trim();
  }
  for (const key of ['sessionTimeoutSec', 'idleTimeoutSec'] as const) {
    if (key in body) {
      if (body[key] === null || body[key] === undefined) patch[key] = null;
      else if (!Number.isInteger(body[key] as number) || (body[key] as number) < 60)
        throw new Error(`"${key}" must be an integer ≥ 60 or null`);
      else patch[key] = body[key] as number;
    }
  }
  if ('replyMessage' in body) {
    if (body.replyMessage === null || body.replyMessage === undefined) patch.replyMessage = null;
    else if (typeof body.replyMessage !== 'string') throw new Error('"replyMessage" must be a string or null');
    // SECURITY: this value is printed verbatim by the per-auth exec script and
    // parsed back line-by-line into RADIUS attributes. Strip CR/LF/tabs so a
    // crafted message can't inject extra "Attr = value" lines, then trim + cap
    // length (RADIUS Reply-Message is 253 octets; keep headroom).
    else patch.replyMessage = body.replyMessage.replace(/[\r\n\t]/g, ' ').trim().slice(0, 256);
  }
  return patch;
}

/** Creates one user profile (keyed by client cert serial). Throws on validation failure / duplicate. */
export async function createProfile(input: Record<string, unknown>): Promise<{ id: string }> {
  if (typeof input.serial !== 'string' || !/^[0-9a-fA-F]{2,64}$/.test(input.serial.trim())) {
    throw new Error('"serial" must be a hex certificate serial (no 0x prefix)');
  }
  const serial = input.serial.trim().toLowerCase();

  const patch = parseProfileFields(input);

  // Serial is unique — one profile per client cert.
  const existing = await db.query.radiusUserProfiles.findFirst({ where: (r, { eq }) => eq(r.serial, serial) });
  if (existing) throw new Error('A RADIUS profile for this certificate already exists');

  const id = uuidv4();
  await db.insert(schema.radiusUserProfiles).values({
    id,
    serial,
    name: typeof input.name === 'string' && input.name.trim() ? input.name.trim().slice(0, 128) : null,
    ...patch,
    createdAt: new Date().toISOString(),
  });
  await rerenderRadiusConfig();
  return { id };
}

/** Updates a user profile's fields (null clears a field). Throws when missing or invalid. */
export async function updateProfile(id: string, patchInput: Record<string, unknown>): Promise<{ id: string }> {
  const current = await db.query.radiusUserProfiles.findFirst({ where: (r, { eq }) => eq(r.id, id) });
  if (!current) throw new Error('RADIUS profile not found');

  const patch: Partial<typeof schema.radiusUserProfiles.$inferInsert> = {};

  if ('name' in patchInput) {
    if (patchInput.name === null || (typeof patchInput.name === 'string' && !patchInput.name.trim())) patch.name = null;
    else if (typeof patchInput.name !== 'string') throw new Error('"name" must be a string or null');
    else patch.name = patchInput.name.trim().slice(0, 128);
  }

  Object.assign(patch, parseProfileFields(patchInput));

  if (Object.keys(patch).length === 0) throw new Error('No updatable fields provided');

  await db.update(schema.radiusUserProfiles).set(patch).where(eq(schema.radiusUserProfiles.id, id));
  await rerenderRadiusConfig();
  return { id };
}

/** Deletes one user profile. Throws when missing. */
export async function deleteProfile(id: string): Promise<{ deleted: number }> {
  const current = await db.query.radiusUserProfiles.findFirst({ where: (r, { eq }) => eq(r.id, id) });
  if (!current) throw new Error('RADIUS profile not found');
  await db.delete(schema.radiusUserProfiles).where(eq(schema.radiusUserProfiles.id, id));
  await rerenderRadiusConfig();
  return { deleted: 1 };
}

/** Deletes many user profiles by id (unknown ids are ignored). Returns the count. */
export async function deleteProfiles(ids: string[]): Promise<{ deleted: number }> {
  const unique = Array.from(new Set(ids.map((s) => s.trim()).filter(Boolean)));
  if (unique.length === 0) return { deleted: 0 };
  const result = await db.delete(schema.radiusUserProfiles).where(inArray(schema.radiusUserProfiles.id, unique)).returning({ id: schema.radiusUserProfiles.id });
  if (result.length > 0) await rerenderRadiusConfig();
  return { deleted: result.length };
}

/** Deletes many NAS clients by id (unknown ids are ignored). Returns the count. */
export async function deleteNasClients(ids: string[]): Promise<{ deleted: number }> {
  const unique = Array.from(new Set(ids.map((s) => s.trim()).filter(Boolean)));
  if (unique.length === 0) return { deleted: 0 };
  const result = await db.delete(schema.radiusNasClients).where(inArray(schema.radiusNasClients.id, unique)).returning({ id: schema.radiusNasClients.id });
  if (result.length > 0) await rerenderRadiusConfig();
  return { deleted: result.length };
}
