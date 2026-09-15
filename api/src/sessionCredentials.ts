import { and, eq } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';

/**
 * Session credentials — which secret an INTERACTIVE session (SSH console or SFTP
 * file browsing) may use on a device.
 *
 * Background: every plugin's SSH/SFTP data path already reads its credential from
 * `credentials.slots.ssh` (the SDK's resolveSshCredentials). Before this module,
 * that slot held exactly ONE secret — the one bound to the assignment in the UI.
 * This feature lets a user keep several personal credentials and pick which one a
 * live session uses, without touching the assignment:
 *
 *   - Each secret carries two opt-in flags (`interactiveLoginAllowed`,
 *     `fileAccessAllowed`) deciding whether it may be used for an interactive SSH
 *     console / SFTP file session at all. Only `usernamePassword` and
 *     `sshKeyPair` types are ever eligible (other types cannot log in over SSH).
 *   - A user sees their OWN flagged secrets plus any flagged secret created by a
 *     global writer (`secrets:write`) — the shared pool (e.g. admin-provisioned
 *     credentials). Other users' personal secrets stay private.
 *   - Per device + purpose ('console' | 'filesystem') a user stores an ORDERED
 *     list of preferred secret ids (device_session_credentials table). The first
 *     still-eligible entry is auto-used; the rest remain available for re-picking.
 *
 * Resolution outcome for one session open:
 *   - 0 eligible secrets            → error "no credential available" (409)
 *   - exactly 1, or a stored default → that secret id (auto-use, no prompt)
 *   - several + no valid default     → `credential_selection_required` (409) with
 *                                      the candidate list — the webapp shows a picker.
 *
 * The chosen id rides the console ticket / filesystem request and is injected by
 * deviceConsole.ts / deviceFilesystem.ts into `credentials.slots.ssh`, so plugins
 * need no changes at all.
 */

/** Which kind of interactive session this applies to. */
export type SessionPurpose = 'console' | 'filesystem';

/** Secret types that can actually authenticate an SSH/SFTP session. */
const SESSION_SECRET_TYPES: ReadonlySet<string> = new Set(['usernamePassword', 'sshKeyPair']);

/** One secret the caller may use for a session (metadata only — no material). */
export interface EligibleSessionSecret {
  id: string;
  label: string | null;
  type: string;
  /** True when this is the caller's own secret (vs. from the shared pool). */
  own: boolean;
}

/** The full answer to "what can I use for a session on this device?". */
export interface SessionCredentialOptions {
  purpose: SessionPurpose;
  /** All eligible secrets, ordered: stored default first, then the rest (label order). */
  candidates: EligibleSessionSecret[];
  /** The secret that would be auto-used now (head of a valid stored list / sole candidate), or null = prompt. */
  defaultSecretId: string | null;
}

/** Error carrying an HTTP status + optional machine-readable code/candidates. */
export class SessionCredentialError extends Error {
  status: number;
  code?: string;
  candidates?: EligibleSessionSecret[];
  constructor(status: number, message: string, extra?: { code?: string; candidates?: EligibleSessionSecret[] }) {
    super(message);
    this.status = status;
    if (extra?.code) this.code = extra.code;
    if (extra?.candidates) this.candidates = extra.candidates;
  }
}

/** The flag column for a purpose. */
function flagColumn(purpose: SessionPurpose): 'interactiveLoginAllowed' | 'fileAccessAllowed' {
  return purpose === 'console' ? 'interactiveLoginAllowed' : 'fileAccessAllowed';
}

/** Human-readable name of the session kind (for error messages). */
function purposeLabel(purpose: SessionPurpose): string {
  return purpose === 'console' ? 'an interactive SSH console' : 'SFTP file access';
}

/**
 * Resolves which user ids currently hold `secrets:write` — their secrets form the
 * shared pool visible to personal-area users. Batched for a set of creator ids.
 */
async function globalWriterUserIds(userIds: string[]): Promise<Set<string>> {
  const out = new Set<string>();
  if (userIds.length === 0) return out;
  const rows = await db.query.users.findMany({ where: (users, { inArray }) => inArray(users.id, userIds) });
  for (const u of rows) {
    let perms: string[] = [];
    try {
      perms = JSON.parse(u.permissions);
    } catch {
      /* treat as empty */
    }
    if (Array.isArray(perms) && perms.includes('secrets:write')) out.add(u.id);
  }
  return out;
}

/**
 * Lists every secret the caller may use for `purpose` sessions: flagged + of an
 * SSH-capable type, AND either owned by the caller or created by a global writer.
 */
export async function listEligibleSessionSecrets(userId: string, purpose: SessionPurpose): Promise<EligibleSessionSecret[]> {
  const flag = flagColumn(purpose);
  const rows = await db.query.secrets.findMany({ where: (secrets) => eq(secrets[flag], true) });
  const eligible = rows.filter((r) => SESSION_SECRET_TYPES.has(r.type));

  // Visibility: own + shared pool (created by current global writers).
  const creators = [...new Set(eligible.map((r) => r.userId))];
  const writers = await globalWriterUserIds(creators);

  return eligible
    .filter((r) => r.userId === userId || writers.has(r.userId))
    .map((r) => ({ id: r.id, label: r.label, type: r.type, own: r.userId === userId }))
    .sort((a, b) => (a.label ?? '').localeCompare(b.label ?? ''));
}

/** Reads the caller's stored ordered preference for one device+purpose. */
async function storedPreference(userId: string, deviceId: string, purpose: SessionPurpose): Promise<string[]> {
  const row = await db.query.deviceSessionCredentials.findFirst({
    where: and(
      eq(schema.deviceSessionCredentials.userId, userId),
      eq(schema.deviceSessionCredentials.deviceId, deviceId),
      eq(schema.deviceSessionCredentials.purpose, purpose)
    ),
  });
  if (!row) return [];
  try {
    const parsed = JSON.parse(row.secretIds);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

/**
 * Full options for the webapp's credential picker: eligible candidates ordered by
 * the stored preference (valid entries first, in order), then the rest. `defaultSecretId`
 * is what would be auto-used — null means "prompt the user".
 */
export async function getSessionCredentialOptions(
  userId: string,
  deviceId: string,
  purpose: SessionPurpose
): Promise<SessionCredentialOptions> {
  const candidates = await listEligibleSessionSecrets(userId, purpose);
  if (candidates.length === 0) {
    return { purpose, candidates: [], defaultSecretId: null };
  }

  const byId = new Map(candidates.map((c) => [c.id, c]));
  const stored = await storedPreference(userId, deviceId, purpose);
  const ordered: EligibleSessionSecret[] = [];
  const used = new Set<string>();
  for (const id of stored) {
    const c = byId.get(id);
    if (!c || used.has(c.id)) continue; // stale/unknown ids are dropped silently
    ordered.push(c);
    used.add(c.id);
  }
  for (const c of candidates) {
    if (!used.has(c.id)) ordered.push(c);
  }

  const defaultSecretId = ordered.length === 1 ? ordered[0].id : stored.some((id) => byId.has(id)) ? ordered[0].id : null;

  return { purpose, candidates: ordered, defaultSecretId };
}

/**
 * Resolves the secret id to use for ONE session open. Throws SessionCredentialError:
 *   - 409 `no_credential` when nothing eligible exists (the "show an error" case);
 *   - 403 when a requested id is not among the caller's eligible secrets;
 *   - 409 `credential_selection_required` with candidates when several exist and no
 *     valid stored default — the webapp then shows the picker.
 */
export async function resolveSessionCredential(
  userId: string,
  deviceId: string,
  purpose: SessionPurpose,
  requestedId?: string
): Promise<string> {
  const options = await getSessionCredentialOptions(userId, deviceId, purpose);

  if (options.candidates.length === 0) {
    throw new SessionCredentialError(
      409,
      `No credential available for ${purposeLabel(purpose)} on this device. Create a username/password or SSH key-pair secret with the matching usage flag enabled (Secrets page), or ask an administrator to provide one.`,
      { code: 'no_credential' }
    );
  }

  if (requestedId) {
    const chosen = options.candidates.find((c) => c.id === requestedId);
    if (!chosen) {
      throw new SessionCredentialError(403, 'The selected credential is not available for this session');
    }
    return chosen.id;
  }

  if (options.defaultSecretId) return options.defaultSecretId;

  // Several candidates, no valid stored default → ask the user to pick.
  throw new SessionCredentialError(
    409,
    `Multiple credentials are available for ${purposeLabel(purpose)} — choose which one to use.`,
    { code: 'credential_selection_required', candidates: options.candidates }
  );
}

/**
 * Stores the caller's ordered preference for a device+purpose (replaces any prior
 * list). Only ids that are currently eligible for this user+purpose are kept —
 * everything else is dropped silently so stale rows never break resolution.
 */
export async function setSessionCredentialPreference(
  userId: string,
  deviceId: string,
  purpose: SessionPurpose,
  secretIds: string[]
): Promise<EligibleSessionSecret[]> {
  if (purpose !== 'console' && purpose !== 'filesystem') {
    throw new SessionCredentialError(400, '"purpose" must be "console" or "filesystem"');
  }
  const candidates = await listEligibleSessionSecrets(userId, purpose);
  const eligible = new Set(candidates.map((c) => c.id));
  const cleaned: string[] = [];
  for (const id of secretIds) {
    if (typeof id === 'string' && eligible.has(id) && !cleaned.includes(id)) cleaned.push(id);
  }

  await db.insert(schema.deviceSessionCredentials)
    .values({
      id: `${userId}|${deviceId}|${purpose}`,
      userId,
      deviceId,
      purpose,
      secretIds: JSON.stringify(cleaned),
      updatedAt: new Date().toISOString(),
    })
    .onConflictDoUpdate({
      target: [schema.deviceSessionCredentials.userId, schema.deviceSessionCredentials.deviceId, schema.deviceSessionCredentials.purpose],
      set: { secretIds: JSON.stringify(cleaned), updatedAt: new Date().toISOString() },
    });

  return candidates;
}
