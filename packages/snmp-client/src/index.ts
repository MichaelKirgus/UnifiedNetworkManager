/**
 * @unm/snmp-client — shared SNMP transport for UnifiedNetworkManager plugins.
 *
 * Wraps the net-snmp CLI (`snmpwalk` / `snmpget`) with:
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
 * Builds the version/authentication CLI args for snmpwalk/snmpget from credentials.
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
  if (opts.mibDir) args.push('-M', opts.mibDir); // extra MIB search dir (volume mount)
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
    const detail = ((e.stderr ?? '') || e.message).trim().split('\n')[0];
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
    const detail = ((e.stderr ?? '') || e.message).trim().split('\n')[0];
    throw new Error(`snmpget failed for ${host}: ${detail}`);
  }
}

/**
 * Parses `snmpwalk`/`snmpget` output lines of the form:
 *   .1.3.6.1.2.1.1.1.0 = STRING: Linux host 6.1 ...
 * Long values wrap onto continuation lines (no "OID =" prefix) — those are
 * appended to the previous entry.
 */
export function parseWalkOutput(stdout: string): Map<string, string> {
  const entries = new Map<string, string>();
  let lastOid: string | null = null;

  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue;
    // Type names may contain hyphens ("Hex-STRING") — \w alone would drop those
    // lines and smear their values onto the previous entry.
    const m = line.match(/^(\S+)\s*=\s*([\w-]+):\s?(.*)$/);
    if (m) {
      lastOid = m[1];
      entries.set(lastOid, extractValue(m[2], m[3]));
    } else if (lastOid) {
      entries.set(lastOid, `${entries.get(lastOid)} ${line.trim()}`);
    }
  }
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
