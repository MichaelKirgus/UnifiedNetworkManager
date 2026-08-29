/**
 * @unm/snmp-client — shared SNMP transport for UnifiedNetworkManager plugins.
 *
 * Native UDP implementation on top of the `net-snmp` npm package (pure JS —
 * no CLI subprocess, so credentials never appear in a command line):
 *  - v1/v2c community and v3 USM credential handling (one place, one contract)
 *  - numeric OIDs everywhere — no MIB name resolution, no MIB files needed
 *  - timeout/retry budgeting that fits the API's poll window
 *  - single-subtree walks AND multi-subtree combined GetBulk walks
 *    (snmpWalkMulti — one PDU stream for N subtrees, shared session)
 *  - result maps keyed by LEADING-DOT dotted OIDs with TYPED values
 *    (SnmpValue = number | bigint | boolean | Buffer | string)
 *
 * Plugin-specific concerns (which OIDs to walk, table layouts, caching, rate
 * math) stay in each plugin — this package is transport only.
 */

import * as snmp from 'net-snmp';

/** Hard cap so a single walk can never exceed the API's 10s poll budget. */
const WALK_BUDGET_MS = 9_500;

/**
 * SNMP credentials as stored in the `snmp` secret type.
 *
 * v1/v2c use a community string; v3 uses USM (username + security level,
 * with optional auth/priv protocol+password pairs). The fields for the other
 * version family are simply absent — callers validate per-version before
 * constructing credentials (see resolveCredentials in each plugin's index.ts).
 */
export interface SnmpCredentials {
  version: 'v1' | 'v2c' | 'v3';
  /** v1/v2c only. */
  community?: string;
  // v3 (USM) only — present when version === 'v3'.
  username?: string;
  securityLevel?: 'noAuthNoPriv' | 'authNoPriv' | 'authPriv';
  authProtocol?: 'MD5' | 'SHA';
  authPassword?: string;
  privProtocol?: 'DES' | 'AES';
  privPassword?: string;
}

/** Transport knobs shared by snmpWalk/snmpGet/snmpWalkMulti. Plugins may extend this. */
export interface TransportOptions {
  timeoutMs: number;
  retries: number;
  /** Agent UDP port (default 161). */
  port?: number;
  /**
   * GetBulk max-repetitions per PDU for walks (v2c/v3; v1 ignores it —
   * getNext has no bulk semantics). Default 50. Higher values cut the PDU
   * count on large tables but grow each response; keep ≤ ~200 so a single
   * PDU stays well under the UDP/agent limits.
   */
  maxRepetitions?: number;
}

/** Walk default — matches the historical hardcoded value. */
const DEFAULT_MAX_REPETITIONS = 50;

/**
 * A typed SNMP varbind value, as returned by snmpWalk/snmpGet and echoed by
 * snmpSet. Mapping from the wire types:
 *   Integer32 / Counter32 / Gauge32 / TimeTicks → number (signed, as-is)
 *   Counter64 (typed tag 70 AND RFC-2578 8-byte OCTET STRING) → bigint
 *   Boolean → boolean
 *   binary OCTET STRING (MacAddress = 6 raw bytes, opaque data…) → Buffer
 *   printable-ASCII OCTET STRING / DisplayString → string (utf8)
 *   OID / IpAddress → dotted string
 */
export type SnmpValue = number | bigint | boolean | Buffer | string;

/** Accepts both leading-dot plugin constants ('.1.3.6…') and bare dotted OIDs. */
function stripDot(oid: string): string {
  return oid.replace(/^\./, '');
}

/** Maps our credential contract onto a net-snmp session (fresh per operation). */
function createSession(host: string, creds: SnmpCredentials, opts: TransportOptions): snmp.Session {
  const sessionOpts = {
    timeout: Math.max(50, opts.timeoutMs),
    retries: Math.max(0, opts.retries),
    port: opts.port ?? 161,
  };

  if (creds.version === 'v3') {
    // DES privacy uses crypto.createCipheriv('des-cbc'), which Node ≥17 rejects
    // without --openssl-legacy-provider → fail fast with an actionable message.
    if ((creds.securityLevel ?? 'noAuthNoPriv') === 'authPriv' && creds.privProtocol === 'DES') {
      throw new Error(`SNMPv3 DES privacy is not supported by the native transport (Node ≥17 OpenSSL) — use AES instead`);
    }
    const level =
      creds.securityLevel === 'authNoPriv'
        ? snmp.SecurityLevel.authNoPriv
        : creds.securityLevel === 'authPriv'
          ? snmp.SecurityLevel.authPriv
          : snmp.SecurityLevel.noAuthNoPriv;
    const user: snmp.V3User = { name: creds.username ?? '', level };
    if (level !== snmp.SecurityLevel.noAuthNoPriv && creds.authProtocol) {
      // authKey/privKey hold PASSPHRASES — the library derives the localized
      // keys itself (RFC 3414 A.2.1), exactly like `snmpwalk -A/-X`.
      user.authProtocol = creds.authProtocol === 'MD5' ? snmp.AuthProtocols.md5 : snmp.AuthProtocols.sha;
      user.authKey = creds.authPassword ?? '';
    }
    if (level === snmp.SecurityLevel.authPriv && creds.privProtocol) {
      // Only AES reaches here — DES throws above.
      user.privProtocol = snmp.PrivProtocols.aes;
      user.privKey = creds.privPassword ?? '';
    }
    return snmp.createV3Session(host, user, sessionOpts);
  }

  // createSession defaults to v1 when version is omitted — pass it explicitly.
  const version = creds.version === 'v1' ? snmp.Version1 : snmp.Version2c;
  return snmp.createSession(host, creds.community ?? '', { ...sessionOpts, version });
}

/** Decodes an RFC-2578 Counter64 (8 big-endian bytes) to a bigint. */
function decodeCounter64(buf: Buffer): SnmpValue {
  return buf.length === 8 ? buf.readBigUInt64BE() : buf.toString('hex');
}

/** True when every byte is printable ASCII (0x20–0x7E). */
function isPrintableAscii(buf: Buffer): boolean {
  for (let i = 0; i < buf.length; i++) if (buf[i] < 0x20 || buf[i] > 0x7e) return false;
  return true;
}

/** Coerces a numeric wire value to a finite JS number (0 for malformed). */
function asNumber(v: unknown): number {
  const n = typeof v === 'number' ? v : Number(v ?? 0);
  return Number.isFinite(n) ? n : 0;
}

/** Maps a raw net-snmp varbind value to its typed SnmpValue form. */
function normalizeValue(vb: snmp.VarBind): SnmpValue {
  const t = vb.type;
  if (t === snmp.ObjectType.Integer) return asNumber(vb.value); // Integer32 — signed, keep sign
  if (t === snmp.ObjectType.Counter || t === snmp.ObjectType.Gauge || t === snmp.ObjectType.TimeTicks) {
    return asNumber(vb.value); // Counter32 / Gauge32 / Unsigned32 / TimeTicks
  }
  if (t === snmp.ObjectType.Counter64) {
    // The npm agent's own mock encodes Counter64 with a non-standard tag-70;
    // the library's readUint64 yields an 8-byte big-endian Buffer for it.
    const v = vb.value;
    if (Buffer.isBuffer(v)) return decodeCounter64(v);
    if (typeof v === 'number') return BigInt(Math.trunc(v));
    const s = typeof v === 'string' ? v.trim() : '';
    return /^\d+$/.test(s) ? BigInt(s) : s; // decimal string → bigint, else pass through
  }
  if (t === snmp.ObjectType.OID || t === snmp.ObjectType.IpAddress) {
    return String(vb.value ?? ''); // dotted OID / "a.b.c.d" — keep as-is
  }
  if (t === snmp.ObjectType.Boolean) return !!vb.value;
  // OctetString / Opaque arrive as Buffer (or string).
  const v = vb.value;
  if (v === null || v === undefined) return '';
  if (Buffer.isBuffer(v)) {
    // Real devices encode RFC-2578 Counter64 as tag 0x04 + exactly 8 bytes,
    // which the library types as OctetString. Decode to bigint — but only
    // when the bytes are not a plain printable string: real counters carry
    // leading zero bytes, while an 8-char ifAlias must survive intact.
    if (v.length === 8 && !isPrintableAscii(v)) return decodeCounter64(v);
    // Any other binary OCTET STRING (MacAddress = 6 raw bytes, opaque data…)
    // is handed over as the raw Buffer — plugins consume it directly
    // (normalizeMac() accepts Buffers).
    if (!isPrintableAscii(v)) return v;
    return v.toString('utf8');
  }
  return String(v);
}

/** Wraps transport errors in the shape plugins already log (`<op> failed for <host>: …`). */
function wrapError(op: string, host: string, err: unknown): Error {
  const msg = err instanceof Error ? err.message : String(err);
  return new Error(`${op} failed for ${host}: ${msg}`);
}

/** Promise wrapper around a callback-based session request. */
function promiseRequest<T>(fn: (cb: (err: Error | null, result?: T) => void) => void): Promise<T> {
  return new Promise((resolve, reject) => fn((err, result) => (err ? reject(err) : resolve(result as T))));
}

/**
 * Walks the subtree under the FIRST given OID and returns a map of full
 * leading-dot OID → typed value (snmpwalk-CLI semantics — extra OIDs are
 * ignored). Throws on timeout / agent error; an empty subtree resolves to an
 * empty map.
 */
export async function snmpWalk(
  host: string,
  creds: SnmpCredentials,
  oids: string[],
  opts: TransportOptions
): Promise<Map<string, SnmpValue>> {
  const base = stripDot(oids[0] ?? '');
  if (!base) return new Map();

  const session = createSession(host, creds, opts);
  try {
    return await walkSubtree(session, host, base, opts);
  } catch (err) {
    throw wrapError('snmpwalk', host, err);
  } finally {
    session.close();
  }
}

/**
 * GetBulk-driven subtree walk with an overall deadline replicating the old
 * CLI budget: min(timeoutMs × (retries+1) + 2s, 9.5s). The library's own
 * per-request timeout/retries cover single PDUs; this bounds the whole walk.
 */
function walkSubtree(session: snmp.Session, host: string, baseOid: string, opts: TransportOptions): Promise<Map<string, SnmpValue>> {
  const budgetMs = Math.min(opts.timeoutMs * (opts.retries + 1) + 2_000, WALK_BUDGET_MS);
  return new Promise((resolve, reject) => {
    let settled = false;
    const out = new Map<string, SnmpValue>();
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        reject(new Error(`timed out after ${budgetMs}ms`));
      }
    }, budgetMs);

    session.subtree(
      baseOid,
      opts.maxRepetitions ?? DEFAULT_MAX_REPETITIONS, // per-GetBulk-PDU (v2c/v3); v1 falls back to getNext internally
      varbinds => {
        for (const vb of varbinds) if (!snmp.isVarbindError(vb)) out.set(`.${vb.oid}`, normalizeValue(vb));
        return false; // keep going — subtree() stops at the boundary itself
      },
      err => {
        clearTimeout(timer);
        if (settled) return;
        settled = true;
        if (err) reject(err);
        else resolve(out);
      }
    );
  });
}

/**
 * Walks MULTIPLE subtrees in ONE combined GetBulk stream over a single shared
 * session and returns their merged map of full leading-dot OID → typed value.
 *
 * Why: N separate snmpWalk calls mean N sessions (socket churn +, for v3,
 * N RFC-3414 discovery exchanges) and N independent PDU streams. The combined
 * loop sends one varbind per cursor in the repeat section of each GetBulk PDU
 * (nonRepeaters=0), so every subtree advances up to `maxRepetitions` OIDs per
 * PDU — live-profiled on LANCOM hardware: 15 LCOS inventory subtrees drop from
 * ~52 PDUs / ~4.7s (batched single walks) to ~17 PDUs / ~1.2s with identical
 * varbind counts.
 *
 * Semantics preserved per subtree:
 *   - missing/empty subtrees simply contribute nothing (no throw);
 *   - error varbinds are filtered; a cursor whose response OID leaves its own
 *     subtree (EndOfMibView or past-boundary) is finished and dropped from
 *     later PDUs — values can never leak between subtrees;
 *   - the whole walk is bounded by the same ≤9.5s deadline as snmpWalk.
 *
 * v1 has no GetBulk: falls back to sequential subtree walks on the shared
 * session (still one socket, still one deadline).
 */
export async function snmpWalkMulti(
  host: string,
  creds: SnmpCredentials,
  bases: string[],
  opts: TransportOptions
): Promise<Map<string, SnmpValue>> {
  const out = new Map<string, SnmpValue>();
  // Dedupe + drop empties; keep first-seen order (cursor order is stable).
  const seen = new Set<string>();
  const cleanBases: string[] = [];
  for (const b of bases) {
    const s = stripDot(b);
    if (!s || seen.has(s)) continue;
    seen.add(s);
    cleanBases.push(s);
  }
  if (!cleanBases.length) return out;

  const session = createSession(host, creds, opts);
  try {
    await walkMultiSubtrees(session, host, cleanBases, opts, out);
    return out;
  } catch (err) {
    throw wrapError('snmpwalk', host, err);
  } finally {
    session.close();
  }
}

/** True when `oid` is inside the subtree rooted at `base` (both dot-less). */
function oidInSubtree(base: string, oid: string): boolean {
  if (!oid.startsWith(base)) return false;
  const rest = oid.slice(base.length);
  return rest === '' || rest.startsWith('.');
}

/** One GetBulk PDU over the given cursor OIDs (nonRepeaters=0). */
function getBulkPdu(
  session: snmp.Session,
  oids: string[],
  maxRepetitions: number
): Promise<snmp.VarBind[][]> {
  return new Promise((resolve, reject) => {
    session.getBulk(oids, 0, maxRepetitions, (err, result) => {
      if (err) return reject(err);
      // net-snmp layout with nonRepeaters=0: an array of N arrays —
      // resp[c] holds up to `maxRepetitions` varbinds for cursor c.
      const arr = Array.isArray(result) ? result : [];
      resolve(arr.map((vbs) => (Array.isArray(vbs) ? vbs : vbs ? [vbs as snmp.VarBind] : [])));
    });
  });
}

/** The combined-walk loop (v2c/v3 GetBulk, v1 sequential fallback). */
async function walkMultiSubtrees(
  session: snmp.Session,
  host: string,
  bases: string[],
  opts: TransportOptions,
  out: Map<string, SnmpValue>
): Promise<void> {
  const budgetMs = WALK_BUDGET_MS; // multi-walks are the long pole — use the full cap
  const deadline = Date.now() + budgetMs;
  const maxRepetitions = Math.max(1, opts.maxRepetitions ?? DEFAULT_MAX_REPETITIONS);

  if (credsVersionIsV1(session)) {
    // v1: no GetBulk — sequential subtree walks on the shared session.
    for (const base of bases) {
      if (Date.now() > deadline) throw new Error(`timed out after ${budgetMs}ms`);
      const sub = await walkSubtree(session, host, base, opts);
      for (const [k, v] of sub) out.set(k, v);
    }
    return;
  }

  let cursors: { base: string; next: string }[] = bases.map((b) => ({ base: b, next: b }));
  while (cursors.length > 0) {
    if (Date.now() > deadline) throw new Error(`timed out after ${budgetMs}ms`);
    const perCursor = await getBulkPdu(session, cursors.map((c) => c.next), maxRepetitions);

    const nextCursors: { base: string; next: string }[] = [];
    for (let i = 0; i < cursors.length; i++) {
      const cursor = cursors[i];
      const vbs = perCursor[i] ?? [];
      let finished = false;
      let lastOid: string | null = null;
      for (const vb of vbs) {
        if (snmp.isVarbindError(vb)) { finished = true; break; } // EOM / noSuch* → subtree done
        const oid = String(vb.oid);
        if (!oidInSubtree(cursor.base, oid)) { finished = true; break; } // left the subtree — stop this cursor only
        out.set(`.${oid}`, normalizeValue(vb));
        lastOid = oid;
      }
      if (!finished && lastOid !== null) nextCursors.push({ base: cursor.base, next: lastOid });
    }
    cursors = nextCursors;
  }
}

/** v1 sessions have no GetBulk — detect via the session's version field. */
function credsVersionIsV1(session: snmp.Session): boolean {
  return (session as unknown as { version?: number }).version === snmp.Version1;
}

/**
 * GETs the given OIDs and returns a map of full leading-dot OID → typed
 * value. For scalars and small fixed tables where a whole-subtree walk is
 * wasteful. OIDs that don't exist on the agent are simply absent from the
 * result (error varbinds are filtered). Throws like snmpWalk.
 */
export async function snmpGet(
  host: string,
  creds: SnmpCredentials,
  oids: string[],
  opts: TransportOptions
): Promise<Map<string, SnmpValue>> {
  if (!oids.length) return new Map();

  const session = createSession(host, creds, opts);
  try {
    const varbinds = await promiseRequest<snmp.VarBind[]>(cb => session.get(oids.map(stripDot), cb));
    const out = new Map<string, SnmpValue>();
    for (const vb of varbinds) if (!snmp.isVarbindError(vb)) out.set(`.${vb.oid}`, normalizeValue(vb));
    return out;
  } catch (err) {
    throw wrapError('snmpget', host, err);
  } finally {
    session.close();
  }
}

/**
 * SETs a single OID and returns the typed value the agent echoed back in its
 * response PDU ('' when the echo carries no varbind). Throws on rejection /
 * timeout like snmpWalk — callers treat that as "SET rejected".
 *
 * `syntax` is the SNMP type tag for the value:
 *   s = DisplayString/STRING, i = INTEGER, t = TimeTicks, x = OCTET STRING (hex),
 *   a = IpAddress. Counter/Gauge objects are never SET in practice.
 * Values may be passed natively: numbers for 'i'/'t', Buffer or hex string
 * for 'x', strings everywhere else.
 */
export async function snmpSet(
  host: string,
  creds: SnmpCredentials,
  oid: string,
  syntax: 's' | 'i' | 't' | 'x' | 'a',
  value: string | number | Buffer,
  opts: TransportOptions
): Promise<SnmpValue> {
  let type: number;
  let payload: unknown;
  switch (syntax) {
    case 's':
      type = snmp.ObjectType.OctetString;
      payload = typeof value === 'string' ? value : Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
      break;
    case 'i':
      type = snmp.ObjectType.Integer;
      payload = toIntValue(value, oid, host, 'integer');
      break;
    case 't':
      type = snmp.ObjectType.TimeTicks;
      payload = toIntValue(value, oid, host, 'TimeTicks', true);
      break;
    case 'x':
      type = snmp.ObjectType.OctetString;
      payload = Buffer.isBuffer(value) ? value : Buffer.from(String(value).replace(/[^0-9a-f]/gi, ''), 'hex');
      break;
    case 'a':
      // The library validates the dotted quad (4 octets 0–255) and throws a
      // RequestInvalidError otherwise.
      type = snmp.ObjectType.IpAddress;
      payload = String(value);
      break;
  }

  const session = createSession(host, creds, opts);
  try {
    const varbinds = await promiseRequest<snmp.VarBind[]>(cb =>
      session.set([{ oid: stripDot(oid), type, value: payload }], cb)
    );
    for (const vb of varbinds) if (!snmp.isVarbindError(vb)) return normalizeValue(vb);
    return '';
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`snmpset failed for ${host} (${oid}): ${msg}`);
  } finally {
    session.close();
  }
}

/** Coerces a SET value to an integer (strings via parseInt, as before). */
function toIntValue(value: string | number | Buffer, oid: string, host: string, what: string, nonNegative = false): number {
  const n = typeof value === 'number' ? value : parseInt(String(value), 10);
  if (!Number.isFinite(n) || !Number.isInteger(n) || (nonNegative && n < 0)) {
    throw new Error(`snmpset failed for ${host} (${oid}): invalid ${what} "${String(value)}"`);
  }
  return n;
}

/** Suffix of `oid` after `base.`, or '' when it doesn't extend base. */
export function suffixOf(oid: string, base: string): string {
  return oid.startsWith(base + '.') ? oid.slice(base.length + 1) : '';
}

/**
 * Normalizes MAC representations to aa:bb:cc:dd:ee:ff. Accepts dotted/hyphen/
 * Cisco-grouped text forms AND raw binary Buffers (SNMP MacAddress columns —
 * 6 raw bytes, hex-encoded internally). Any other SnmpValue is stringified
 * first (defensive for mis-typed columns). Returns '' unless exactly 12 hex digits.
 */
export function normalizeMac(raw: SnmpValue | undefined): string {
  const text = Buffer.isBuffer(raw) ? raw.toString('hex') : String(raw ?? '');
  const hex = text.replace(/[^0-9a-f]/gi, '').toLowerCase();
  if (hex.length !== 12) return ''; // non-Ethernet MAC length — don't guess
  return hex.replace(/(.{2})(?=.)/g, '$1:');
}

/* ------------------------------------------------------------------ *
 * Credential resolution from the flat `snmp` secret field map.
 * Shared by every SNMP-based plugin so per-version validation rules live in
 * exactly one place (v1/v2c need a community; v3 needs USM username + level,
 * with auth/priv pairs added per security level).
 * ------------------------------------------------------------------ */

/** Reads a trimmed string field from the decrypted secret fields. */
export function strField(fields: Record<string, unknown>, key: string): string {
  const v = fields[key];
  return typeof v === 'string' ? v.trim() : '';
}

const V3_SECURITY_LEVELS = ['noAuthNoPriv', 'authNoPriv', 'authPriv'] as const;
const V3_AUTH_PROTOCOLS = ['MD5', 'SHA'] as const;
const V3_PRIV_PROTOCOLS = ['DES', 'AES'] as const;

/**
 * Builds + validates SNMP credentials from a flat field map. Error messages are
 * source-neutral (no "secret"/"query param" wording) since the same builder
 * serves /monitoring bodies and query-param routes alike.
 */
export function buildSnmpCredentials(
  fields: Record<string, unknown>
): { creds?: SnmpCredentials; error?: string } {
  const versionRaw = strField(fields, 'version') || 'v2c';
  if (versionRaw !== 'v1' && versionRaw !== 'v2c' && versionRaw !== 'v3') {
    return { error: `SNMP version "${versionRaw}" is not supported — this plugin supports v1, v2c and v3.` };
  }

  // v1/v2c — community string based.
  if (versionRaw === 'v1' || versionRaw === 'v2c') {
    const community = strField(fields, 'community');
    if (!community) return { error: `No SNMP community configured for ${versionRaw} devices.` };
    return { creds: { version: versionRaw, community } };
  }

  // v3 (USM) — username + security level; auth/priv pairs per level.
  const username = strField(fields, 'username');
  if (!username) return { error: 'SNMPv3 requires a USM username.' };

  const securityLevel = strField(fields, 'securityLevel') || 'noAuthNoPriv';
  if (!(V3_SECURITY_LEVELS as readonly string[]).includes(securityLevel)) {
    return { error: `SNMPv3 security level "${securityLevel}" is invalid — use noAuthNoPriv, authNoPriv or authPriv.` };
  }

  const creds: SnmpCredentials = { version: 'v3', username, securityLevel: securityLevel as SnmpCredentials['securityLevel'] };

  if (securityLevel !== 'noAuthNoPriv') {
    const authProtocol = strField(fields, 'authProtocol');
    const authPassword = strField(fields, 'authPassword');
    if (!authProtocol || !authPassword) {
      return { error: `SNMPv3 security level "${securityLevel}" requires an auth protocol and auth password.` };
    }
    if (!(V3_AUTH_PROTOCOLS as readonly string[]).includes(authProtocol)) {
      return { error: `SNMPv3 auth protocol "${authProtocol}" is invalid — use MD5 or SHA.` };
    }
    creds.authProtocol = authProtocol as 'MD5' | 'SHA';
    creds.authPassword = authPassword;
  }

  if (securityLevel === 'authPriv') {
    const privProtocol = strField(fields, 'privProtocol');
    const privPassword = strField(fields, 'privPassword');
    if (!privProtocol || !privPassword) {
      return { error: 'SNMPv3 security level "authPriv" requires a privacy protocol and privacy password.' };
    }
    if (!(V3_PRIV_PROTOCOLS as readonly string[]).includes(privProtocol)) {
      return { error: `SNMPv3 privacy protocol "${privProtocol}" is invalid — use DES or AES.` };
    }
    creds.privProtocol = privProtocol as 'DES' | 'AES';
    creds.privPassword = privPassword;
  }

  return { creds };
}
