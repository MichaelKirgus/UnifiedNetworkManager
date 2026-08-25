/**
 * @unm/snmp-client — shared SNMP transport for UnifiedNetworkManager plugins.
 *
 * Wraps the net-snmp CLI (`snmpwalk` / `snmpget` / `snmpset`) with:
 *  - v1/v2c community and v3 USM credential handling (one place, one contract)
 *  - forced numeric OIDs in output (-O n) so parsing never depends on loaded MIBs
 *  - timeout/retry budgeting that fits the API's poll window
 *  - line parsing of `OID = TYPE: value` output incl. wrapped continuation lines
 *
 * Plugin-specific concerns (which OIDs to walk, table layouts, caching, rate
 * math) stay in each plugin — this package is transport only.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/** Default location of net-snmp's standard MIBs on alpine. */
export const DEFAULT_MIB_DIR = '/usr/share/snmp/mibs';

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

/** Transport knobs shared by snmpWalk/snmpget. Plugins may extend this. */
export interface TransportOptions {
  timeoutMs: number;
  retries: number;
  /** Container-internal directory holding extra (vendor) MIB files. */
  mibDir?: string;
}

/**
 * Builds the version/authentication CLI args for snmpwalk/snmpget/snmpset from credentials.
 * v1/v2c use a community string; v3 uses USM (security level + username, with
 * auth/priv protocol+password pairs added per security level).
 */
export function buildVersionArgs(creds: SnmpCredentials): string[] {
  if (creds.version === 'v3') {
    const level = creds.securityLevel ?? 'noAuthNoPriv';
    const args = ['-v', '3', '-l', level, '-u', creds.username ?? ''];
    if (level !== 'noAuthNoPriv' && creds.authProtocol) {
      args.push('-a', creds.authProtocol, '-A', creds.authPassword ?? '');
    }
    if (level === 'authPriv' && creds.privProtocol) {
      args.push('-x', creds.privProtocol, '-X', creds.privPassword ?? '');
    }
    return args;
  }
  // snmpwalk expects `-v 1` / `-v 2c` (no "v" prefix); the secret stores 'v1'/'v2c'.
  return ['-v', creds.version.replace(/^v/, ''), '-c', creds.community ?? ''];
}

/** Common CLI args after the version/credential ones. */
function buildCommonArgs(creds: SnmpCredentials, opts: TransportOptions): string[] {
  const args = buildVersionArgs(creds);
  // Force numeric OIDs in the output — without this, net-snmp resolves them to
  // MIB names (e.g. SNMPv2-MIB::sysDescr.0) which depends on loaded MIBs and
  // would break our numeric-OID parsing below.
  args.push('-O', 'n');
  args.push('-t', String(Math.max(1, Math.round(opts.timeoutMs / 1000))));
  args.push('-r', String(opts.retries));
  // `-M` REPLACES the MIB search path (it does not extend it) — so always
  // include the standard net-snmp dir alongside any vendor volume. Without
  // this, a configured mibDir silently breaks resolution of SNMPv2-MIB & co.
  if (opts.mibDir) args.push('-M', [opts.mibDir, DEFAULT_MIB_DIR].filter(Boolean).join(':'));
  return args;
}

function mibDirsEnv(mibDir?: string): NodeJS.ProcessEnv {
  const mibdirs = [mibDir, DEFAULT_MIB_DIR].filter(Boolean).join(':');
  return { ...process.env, MIBDIRS: mibdirs };
}

/**
 * Runs `snmpwalk` for the given OID(s) and returns a map of full OID → value.
 * Throws on non-zero exit / timeout — callers decide how to degrade.
 */
export async function snmpWalk(
  host: string,
  creds: SnmpCredentials,
  oids: string[],
  opts: TransportOptions
): Promise<Map<string, string>> {
  const args = buildCommonArgs(creds, opts);
  args.push(host, ...oids);

  const budgetMs = Math.min(opts.timeoutMs * (opts.retries + 1) + 2_000, WALK_BUDGET_MS);

  try {
    const { stdout } = await execFileAsync('snmpwalk', args, {
      timeout: budgetMs,
      maxBuffer: 16 * 1024 * 1024,
      env: mibDirsEnv(opts.mibDir),
    });
    return parseWalkOutput(stdout);
  } catch (err) {
    const e = err as Error & { stderr?: string };
    // Keep the first few lines — net-snmp's "Reason: (noSuchName)…" line is
    // what callers need to tell an agent-answered error apart from a timeout.
    const detail = ((e.stderr ?? '') || e.message).trim().split('\n').slice(0, 3).join(' | ');
    throw new Error(`snmpwalk failed for ${host}: ${detail}`);
  }
}

/**
 * Runs `snmpget` for the given OID(s) and returns a map of full OID → value.
 * For scalars and small fixed tables where a whole-subtree walk is wasteful.
 * OIDs that don't exist on the agent are simply absent from the result (the
 * "No Such Object" line doesn't match the output format). Throws like snmpWalk.
 */
export async function snmpGet(
  host: string,
  creds: SnmpCredentials,
  oids: string[],
  opts: TransportOptions
): Promise<Map<string, string>> {
  const args = buildCommonArgs(creds, opts);
  args.push(host, ...oids);

  // snmpget answers one PDU per OID — a flat budget is fine.
  const budgetMs = Math.min(opts.timeoutMs * (opts.retries + 1) + 2_000, WALK_BUDGET_MS);

  try {
    const { stdout } = await execFileAsync('snmpget', args, {
      timeout: budgetMs,
      maxBuffer: 4 * 1024 * 1024,
      env: mibDirsEnv(opts.mibDir),
    });
    return parseWalkOutput(stdout);
  } catch (err) {
    const e = err as Error & { stderr?: string };
    // Keep the first few lines — net-snmp's "Reason: (noSuchName)…" line is
    // what callers need to tell an agent-answered error apart from a timeout.
    const detail = ((e.stderr ?? '') || e.message).trim().split('\n').slice(0, 3).join(' | ');
    throw new Error(`snmpget failed for ${host}: ${detail}`);
  }
}

/**
 * Runs `snmpset` for a single OID and returns the value the agent echoed back
 * in its response PDU (the new value, as printed by net-snmp). Throws on
 * non-zero exit / timeout like snmpWalk — callers treat that as "SET rejected".
 *
 * `syntax` is the SNMP type tag net-snmp expects for the value:
 *   s = DisplayString/STRING, i = INTEGER, t = TimeTicks, x = OCTET STRING (hex),
 *   a = IpAddress. Counter/Gauge objects are never SET in practice.
 */
export async function snmpSet(
  host: string,
  creds: SnmpCredentials,
  oid: string,
  syntax: 's' | 'i' | 't' | 'x' | 'a',
  value: string,
  opts: TransportOptions
): Promise<string> {
  const args = buildCommonArgs(creds, opts);
  // snmpset takes exactly one OID + its type/value pair.
  args.push(host, oid, `${syntax}:${value}`);

  const budgetMs = Math.min(opts.timeoutMs * (opts.retries + 1) + 2_000, WALK_BUDGET_MS);

  try {
    const { stdout } = await execFileAsync('snmpset', args, {
      timeout: budgetMs,
      maxBuffer: 4 * 1024 * 1024,
      env: mibDirsEnv(opts.mibDir),
    });
    // snmpset prints the response PDU in walk format ("OID = TYPE: value") —
    // reuse the shared parser and return whatever the agent confirmed.
    const parsed = parseWalkOutput(stdout);
    for (const v of parsed.values()) return v;
    return '';
  } catch (err) {
    const e = err as Error & { stderr?: string };
    // Keep the first few lines — net-snmp's "Reason:" line distinguishes a
    // rejected SET from a transport failure.
    const detail = ((e.stderr ?? '') || e.message).trim().split('\n').slice(0, 3).join(' | ');
    throw new Error(`snmpset failed for ${host} (${oid}): ${detail}`);
  }
}

/**
 * Parses `snmpwalk`/`snmpget` output lines of the form:
 *   .1.3.6.1.2.1.1.1.0 = STRING: Linux host 6.1 ...
 * Long values wrap onto continuation lines (no "OID =" prefix) at net-snmp's
 * display width — those are appended to the previous entry WITHOUT a space
 * while the value's opening quote is still open, so wrapped strings reassemble
 * exactly (a naive space-join corrupts every value longer than ~35 chars).
 */
export function parseWalkOutput(stdout: string): Map<string, string> {
  const raw = new Map<string, { type: string; text: string }>();
  let lastOid: string | null = null;

  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue;
    // Type names may contain hyphens ("Hex-STRING") — \w alone would drop those
    // lines and smear their values onto the previous entry.
    const m = line.match(/^(\S+)\s*=\s*([\w-]+):\s?(.*)$/);
    if (m) {
      lastOid = m[1];
      raw.set(lastOid, { type: m[2], text: m[3] });
    } else {
      // net-snmp prints EMPTY string values WITHOUT a type prefix (`OID = ""`).
      // Without this branch they'd be treated as continuation lines and smeared
      // onto the previous entry's value (corrupting long hostnames).
      const empty = line.match(/^(\S+)\s*=\s*""\s*$/);
      if (empty) {
        lastOid = empty[1];
        raw.set(lastOid, { type: 'STRING', text: '""' });
      } else if (lastOid && raw.has(lastOid)) {
        const e = raw.get(lastOid)!;
        // Continuation of a wrapped quoted value? Append verbatim — no space.
        const quoteOpen = e.text.startsWith('"') && !e.text.endsWith('"');
        e.text += quoteOpen ? line.trim() : ` ${line.trim()}`;
      }
    }
  }

  const entries = new Map<string, string>();
  for (const [oid, { type, text }] of raw) entries.set(oid, extractValue(type, text));
  return entries;
}

/** Normalizes a typed value to its machine-readable form. */
export function extractValue(type: string, raw: string): string {
  const text = (raw ?? '').trim();
  switch (type) {
    case 'INTEGER':
    case 'Gauge32':
    case 'Counter32':
    case 'Counter64':
    case 'Unsigned32':
    case 'Timeticks': {
      const m = text.match(/(\d+)/); // "up(1)", "12345 (2 min, 3 sec)" → number
      return m ? m[1] : '';
    }
    case 'OBJECT IDENTIFIER':
      return text; // dotted OID or resolved name — keep as-is
    default: {
      // net-snmp wraps DisplayStrings in double quotes when they need escaping
      // (some builds quote all strings) — strip the outer pair.
      if (text.length >= 2 && text.startsWith('"') && text.endsWith('"')) return text.slice(1, -1);
      return text; // STRING, OCTET STRING, MAC ADDRESS, IpAddress, ...
    }
  }
}

/** Suffix of `oid` after `base.`, or '' when it doesn't extend base. */
export function suffixOf(oid: string, base: string): string {
  return oid.startsWith(base + '.') ? oid.slice(base.length + 1) : '';
}

/** Normalizes MAC representations ("00-1A-2B..", "001a.2b3c.4d5e") to aa:bb:cc:dd:ee:ff. */
export function normalizeMac(raw: string): string {
  const hex = (raw ?? '').replace(/[^0-9a-f]/gi, '').toLowerCase();
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
