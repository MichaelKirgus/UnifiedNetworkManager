import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/** Default location of net-snmp's standard MIBs on alpine. */
const DEFAULT_MIB_DIR = '/usr/share/snmp/mibs';

/** Hard cap so a single walk can never exceed the API's 10s poll budget. */
const WALK_BUDGET_MS = 9_500;

/**
 * SNMP credentials as stored in the `snmp` secret type.
 *
 * v1/v2c use a community string; v3 uses USM (username + security level,
 * with optional auth/priv protocol+password pairs). The fields for the other
 * version family are simply absent — callers validate per-version before
 * constructing credentials (see resolveCredentials in index.ts).
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

export interface WalkOptions {
  timeoutMs: number;
  retries: number;
  /** Container-internal directory holding extra (vendor) MIB files. */
  mibDir?: string;
  /** How long the slow-path inventory snapshot stays fresh. */
  inventoryTtlMs: number;
}

export interface SystemInfo {
  description: string;
  objectId: string;
  name: string;
  location: string;
  contact: string;
  uptimeSeconds: number | null;
}

export interface InterfaceInfo {
  ifIndex: string;
  name: string; // '' when the device exposes no name for this index
  type: string; // human-readable (e.g. 'ethernetCsmacd') or numeric fallback
  speedBps: number | null;
  mac: string; // '' when unavailable
  status: string; // 'up' | 'down' | 'testing' | 'unknown'
}

/** Octet counters per ifIndex (64-bit preferred, 32-bit fallback). */
export interface Counters {
  [ifIndex: string]: { inOctets: number; outOctets: number };
}

export interface InventorySnapshot {
  collectedAt: number;
  system: SystemInfo | null;
  interfaces: InterfaceInfo[];
  counters: Counters;
  /** True when the device exposes ifHC* (64-bit) counters. */
  useHc: boolean;
}

export interface InventoryResult {
  snapshot: InventorySnapshot | null;
  /** True when the data came from the TTL cache (not re-walked this call). */
  fromCache: boolean;
  /** Set when the refresh attempt failed but a cached fallback was returned. */
  error?: string;
}

/* ------------------------------------------------------------------ *
 * OID map — numeric OIDs so we never depend on MIB name resolution.
 * Standard MIBs (SNMPv2-MIB, IF-MIB) ship with net-snmp itself; the
 * mounted volume is for vendor-specific MIBs that users may add later.
 * ------------------------------------------------------------------ */

// SNMPv2-MIB system group — scalar instances are addressed with a trailing ".0".
const SYS_BASE = '.1.3.6.1.2.1.1';
const SYSTEM_OIDS = {
  description: `${SYS_BASE}.1`, // sysDescr
  objectId: `${SYS_BASE}.2`, // sysObjectID
  uptime: `${SYS_BASE}.3`, // sysUpTime (Timeticks, 1/100 s)
  contact: `${SYS_BASE}.4`, // sysContact
  name: `${SYS_BASE}.5`, // sysName
  location: `${SYS_BASE}.6`, // sysLocation
} as const;

const IF_TABLE = '.1.3.6.1.2.1.2.2.1'; // ifTable (IF-MIB)
const IF_XTABLE = '.1.3.6.1.2.1.31.1.1.1'; // ifXTable (IF-MIB)

const COUNTERS_32 = { in: `${IF_TABLE}.10`, out: `${IF_TABLE}.16` };
const COUNTERS_HC = { in: '.1.3.6.1.2.1.31.1.1.1.6', out: '.1.3.6.1.2.1.31.1.1.1.10' };

const IF_TYPE_NAMES: Record<number, string> = {
  1: 'other',
  6: 'ethernetCsmacd',
  7: 'ieee8023MacBridge',
  14: 'propWireless',
  24: 'softwareLoopback',
  53: 'propVirtual',
  136: 'atm',
};

const OPER_STATUS_NAMES: Record<number, string> = { 1: 'up', 2: 'down', 3: 'testing' };

/* ------------------------------------------------------------------ *
 * snmpwalk wrapper + output parsing
 * ------------------------------------------------------------------ */

/**
 * Builds the version/authentication CLI args for snmpwalk from credentials.
 * v1/v2c use a community string; v3 uses USM (security level + username, with
 * auth/priv protocol+password pairs added per security level).
 */
function buildVersionArgs(creds: SnmpCredentials): string[] {
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

/**
 * Runs `snmpwalk` for the given OID(s) and returns a map of full OID → value.
 * Throws on non-zero exit / timeout — callers decide how to degrade.
 */
async function snmpWalk(
  host: string,
  creds: SnmpCredentials,
  oids: string[],
  opts: WalkOptions
): Promise<Map<string, string>> {
  const args = buildVersionArgs(creds);
  // Force numeric OIDs in the output — without this, net-snmp resolves them to
  // MIB names (e.g. SNMPv2-MIB::sysDescr.0) which depends on loaded MIBs and
  // would break our numeric-OID parsing below.
  args.push('-O', 'n');
  args.push('-t', String(Math.max(1, Math.round(opts.timeoutMs / 1000))));
  args.push('-r', String(opts.retries));
  if (opts.mibDir) args.push('-M', opts.mibDir); // extra MIB search dir (volume mount)
  args.push(host, ...oids);

  const mibdirs = [opts.mibDir, DEFAULT_MIB_DIR].filter(Boolean).join(':');
  const budgetMs = Math.min(opts.timeoutMs * (opts.retries + 1) + 2_000, WALK_BUDGET_MS);

  try {
    const { stdout } = await execFileAsync('snmpwalk', args, {
      timeout: budgetMs,
      maxBuffer: 16 * 1024 * 1024,
      env: { ...process.env, MIBDIRS: mibdirs },
    });
    return parseWalkOutput(stdout);
  } catch (err) {
    const e = err as Error & { stderr?: string };
    const detail = ((e.stderr ?? '') || e.message).trim().split('\n')[0];
    throw new Error(`snmpwalk failed for ${host}: ${detail}`);
  }
}

/**
 * Parses `snmpwalk` output lines of the form:
 *   .1.3.6.1.2.1.1.1.0 = STRING: Linux host 6.1 ...
 * Long values wrap onto continuation lines (no "OID =" prefix) — those are
 * appended to the previous entry.
 */
function parseWalkOutput(stdout: string): Map<string, string> {
  const entries = new Map<string, string>();
  let lastOid: string | null = null;

  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue;
    const m = line.match(/^(\S+)\s*=\s*(\w+):\s?(.*)$/);
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
function extractValue(type: string, raw: string): string {
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
    default:
      return text; // STRING, OCTET STRING, MAC ADDRESS, IpAddress, ...
  }
}

/** Suffix of `oid` after `base.`, or '' when it doesn't extend base. */
function suffixOf(oid: string, base: string): string {
  return oid.startsWith(base + '.') ? oid.slice(base.length + 1) : '';
}

/* ------------------------------------------------------------------ *
 * System group (SNMPv2-MIB) — slow path
 * ------------------------------------------------------------------ */

async function walkSystem(host: string, creds: SnmpCredentials, opts: WalkOptions): Promise<SystemInfo | null> {
  try {
    // One walk of the whole system subtree — snmpwalk only processes the FIRST
    // OID when given several, so a single broad subtree is both correct and faster.
    const out = await snmpWalk(host, creds, [SYS_BASE], opts);
    // Scalar instances are addressed with a trailing ".0".
    const get = (oid: string): string => out.get(`${oid}.0`) ?? '';

    const uptimeTicks = Number(get(SYSTEM_OIDS.uptime));
    return {
      description: get(SYSTEM_OIDS.description),
      objectId: get(SYSTEM_OIDS.objectId),
      name: get(SYSTEM_OIDS.name),
      location: get(SYSTEM_OIDS.location),
      contact: get(SYSTEM_OIDS.contact),
      uptimeSeconds: Number.isFinite(uptimeTicks) && uptimeTicks > 0 ? Math.round(uptimeTicks / 100) : null,
    };
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * Interface table (IF-MIB ifTable + ifXTable) — slow path
 * ------------------------------------------------------------------ */

interface TableResult {
  interfaces: InterfaceInfo[];
  counters: Counters;
  useHc: boolean;
}

async function walkTables(host: string, creds: SnmpCredentials, opts: WalkOptions): Promise<TableResult | null> {
  try {
    const [ifOut, xOut] = await Promise.all([
      snmpWalk(host, creds, [IF_TABLE], opts),
      snmpWalk(host, creds, [IF_XTABLE], opts).catch(() => new Map<string, string>()),
    ]);

    // Accumulate per-ifIndex attributes from both tables.
    const byIndex = new Map<
      string,
      { name: string; type: number | null; speedBps: number | null; mac: string; operStatus: number | null }
    >();
    const counters: Counters = {};
    let useHc = false;

    const row = (idx: string) => {
      let r = byIndex.get(idx);
      if (!r) {
        r = { name: '', type: null, speedBps: null, mac: '', operStatus: null };
        byIndex.set(idx, r);
      }
      return r;
    };

    for (const [oid, value] of ifOut) {
      const suffix = suffixOf(oid, IF_TABLE); // e.g. "2.3" → field 2, index 3
      const dot = suffix.indexOf('.');
      if (dot < 0) continue;
      const field = Number(suffix.slice(0, dot));
      const idx = suffix.slice(dot + 1);

      switch (field) {
        case 2: // ifDescr — fallback name
          row(idx).name ||= value;
          break;
        case 3: {
          const n = Number(value);
          if (Number.isFinite(n)) row(idx).type = n;
          break;
        }
        case 5: {
          const n = Number(value); // ifSpeed (bits/s, saturates at 2^32)
          if (Number.isFinite(n)) row(idx).speedBps = n;
          break;
        }
        case 6:
          row(idx).mac = normalizeMac(value);
          break;
        case 8: {
          const n = Number(value); // ifOperStatus
          if (Number.isFinite(n)) row(idx).operStatus = n;
          break;
        }
        case 10: {
          const n = Number(value); // ifInOctets (32-bit)
          if (Number.isFinite(n)) {
            counters[idx] ??= { inOctets: 0, outOctets: 0 };
            counters[idx].inOctets = n;
          }
          break;
        }
        case 16: {
          const n = Number(value); // ifOutOctets (32-bit)
          if (Number.isFinite(n)) {
            counters[idx] ??= { inOctets: 0, outOctets: 0 };
            counters[idx].outOctets = n;
          }
          break;
        }
      }
    }

    for (const [oid, value] of xOut) {
      const suffix = suffixOf(oid, IF_XTABLE);
      const dot = suffix.indexOf('.');
      if (dot < 0) continue;
      const field = Number(suffix.slice(0, dot));
      const idx = suffix.slice(dot + 1);

      switch (field) {
        case 6: // ifHCInOctets (64-bit — preferred)
          useHc = true;
          counters[idx] ??= { inOctets: 0, outOctets: 0 };
          counters[idx].inOctets = Number(value);
          break;
        case 8: {
          const n = Number(value); // ifHighSpeed (bits/s — preferred over ifSpeed)
          if (Number.isFinite(n)) row(idx).speedBps = n;
          break;
        }
        case 10: // ifHCOutOctets (64-bit — preferred)
          useHc = true;
          counters[idx] ??= { inOctets: 0, outOctets: 0 };
          counters[idx].outOctets = Number(value);
          break;
        case 18: // ifName — preferred display name
          row(idx).name ||= value;
          break;
      }
    }

    const interfaces: InterfaceInfo[] = Array.from(byIndex.entries())
      .sort((a, b) => Number(a[0]) - Number(b[0]))
      .map(([ifIndex, r]) => ({
        ifIndex,
        name: r.name,
        type: r.type !== null ? IF_TYPE_NAMES[r.type] ?? String(r.type) : 'unknown',
        speedBps: r.speedBps,
        mac: r.mac,
        status: r.operStatus !== null ? OPER_STATUS_NAMES[r.operStatus] ?? 'unknown' : 'unknown',
      }));

    return { interfaces, counters, useHc };
  } catch {
    return null;
  }
}

/** Normalizes MAC representations ("00-1A-2B..", "001a.2b3c.4d5e") to aa:bb:cc:dd:ee:ff. */
function normalizeMac(raw: string): string {
  const hex = (raw ?? '').replace(/[^0-9a-f]/gi, '').toLowerCase();
  if (hex.length !== 12) return ''; // non-Ethernet MAC length — don't guess
  return hex.replace(/(.{2})(?=.)/g, '$1:');
}

/* ------------------------------------------------------------------ *
 * Inventory cache (slow path, TTL-based — opnsense LIVE/INVENTORY split)
 * ------------------------------------------------------------------ */

const inventoryCache = new Map<string, InventorySnapshot>();

/**
 * Returns the cached inventory snapshot for a host, performing the slow
 * walks only when the cache is empty or older than `inventoryTtlMs`.
 * Never throws — degrades to stale/empty data with an explanatory error.
 */
export async function getInventory(
  host: string,
  creds: SnmpCredentials,
  opts: WalkOptions
): Promise<InventoryResult> {
  const cached = inventoryCache.get(host);
  if (cached && Date.now() - cached.collectedAt < opts.inventoryTtlMs) {
    return { snapshot: cached, fromCache: true };
  }

  // System group and interface tables are independent — walk in parallel.
  const [system, tables] = await Promise.all([
    walkSystem(host, creds, opts).catch(() => null),
    walkTables(host, creds, opts).catch(() => null),
  ]);

  if (!system && !tables) {
    return {
      snapshot: cached ?? null,
      fromCache: cached !== undefined,
      error: 'SNMP walks failed — no system or interface data could be collected.',
    };
  }

  const snapshot: InventorySnapshot = {
    collectedAt: Date.now(),
    system: system ?? cached?.system ?? null,
    interfaces: tables && tables.interfaces.length > 0 ? tables.interfaces : (cached?.interfaces ?? []),
    counters: tables?.counters ?? {},
    useHc: tables?.useHc ?? false,
  };
  inventoryCache.set(host, snapshot);

  // Partial failure is worth surfacing even though we have usable data.
  const error = !system && cached?.system ? undefined : !system ? 'System group walk failed.' : undefined;
  return { snapshot, fromCache: false, ...(error ? { error } : {}) };
}

/* ------------------------------------------------------------------ *
 * Fast path — counter-only walk for per-cycle rate computation
 * ------------------------------------------------------------------ */

/**
 * Walks just the traffic counters (64-bit when the device has them).
 * Two parallel single-OID walks — snmpwalk only processes the FIRST OID when
 * given several, so in/out must be separate calls.
 */
export async function walkCounters(
  host: string,
  creds: SnmpCredentials,
  opts: WalkOptions,
  useHc: boolean
): Promise<Counters | null> {
  const inBase = useHc ? COUNTERS_HC.in : COUNTERS_32.in;
  const outBase = useHc ? COUNTERS_HC.out : COUNTERS_32.out;

  try {
    const [inOut, outOut] = await Promise.all([
      snmpWalk(host, creds, [inBase], opts),
      snmpWalk(host, creds, [outBase], opts),
    ]);

    const counters: Counters = {};
    for (const [oid, value] of inOut) {
      const n = Number(value);
      if (!Number.isFinite(n)) continue;
      const idx = suffixOf(oid, inBase);
      if (!idx) continue;
      counters[idx] ??= { inOctets: 0, outOctets: 0 };
      counters[idx].inOctets = n;
    }
    for (const [oid, value] of outOut) {
      const n = Number(value);
      if (!Number.isFinite(n)) continue;
      const idx = suffixOf(oid, outBase);
      if (!idx) continue;
      counters[idx] ??= { inOctets: 0, outOctets: 0 };
      counters[idx].outOctets = n;
    }
    return counters;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ *
 * Rate computation (counter deltas → bits/s) with baseline cache
 * ------------------------------------------------------------------ */

interface Baseline {
  value: number;
  at: number;
}

const baselines = new Map<string, Baseline>(); // `${host}:${ifIndex}:in|out`

/**
 * Computes per-interface rx/tx rates in bits/s from the current counters and
 * updates the baseline cache. Returns null for a direction when there is no
 * previous sample yet or the counter reset/wrapped (new < old).
 */
export function computeRates(
  host: string,
  counters: Counters
): Record<string, { rx: number | null; tx: number | null }> {
  const now = Date.now();
  const rates: Record<string, { rx: number | null; tx: number | null }> = {};

  for (const [ifIndex, c] of Object.entries(counters)) {
    rates[ifIndex] = {
      rx: sampleRate(`${host}:${ifIndex}:in`, c.inOctets, now),
      tx: sampleRate(`${host}:${ifIndex}:out`, c.outOctets, now),
    };
  }
  return rates;
}

function sampleRate(key: string, current: number, now: number): number | null {
  const prev = baselines.get(key);
  // Always refresh the baseline so the NEXT cycle has a reference point.
  baselines.set(key, { value: current, at: now });

  if (!prev || now <= prev.at) return null; // first sample — no delta yet
  if (current < prev.value) return null; // counter reset/wrap — skip this sample

  const seconds = (now - prev.at) / 1000;
  return ((current - prev.value) * 8) / seconds; // octets/s → bits/s
}
