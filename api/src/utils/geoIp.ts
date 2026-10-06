/**
 * GeoIP lookups for flow endpoint IPs (Flows page "Location" column).
 *
 * Mirrors reverseDns.ts: strictly best-effort — never throws, caches positive
 * results (negatives are re-checked so a newly fetched file can answer them),
 * and loads the active database lazily on first use. The
 * ACTIVE file is whatever `geoipActiveFileId` points at in system settings (the
 * geoip worker updates it after each successful refresh). When no file has ever
 * been fetched, every lookup returns null and the Flows route simply omits the
 * location fields — a missing database must never break the page.
 *
 * Two database kinds are supported:
 *   - MMDB (MaxMind GeoLite2-City / ipinfo mmdb-lite) via maxmind-db-reader —
 *     the whole file is read into memory once at open; lookups are synchronous
 *     and fast, and IPv6 works.
 *   - CSV (dp-ip single-IP rows, IP2Location LITE FromIP/ToIP ranges) parsed
 *     into a compact sorted range index with binary search. IPv4 only — v6
 *     returns null for CSV sources (documented limitation).
 */

import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import MaxmindDBReader from 'maxmind-db-reader';
import { pool } from '../db';
import { openRepoFile } from '../fileRepo';

export interface GeoResult {
  countryCode?: string; // ISO-3166 alpha-2 (e.g. "US")
  countryName?: string; // localized English name (e.g. "United States")
  city?: string; // most-specific populated place
}

const RESULT_TTL_MS = 10 * 60_000; // per-IP result cache — DBs change monthly, not per request
const MAX_RESULT_CACHE = 20_000;

/** Single fixed temp slot — only one database is active at a time. */
const TMP_PATH = path.join(os.tmpdir(), 'unm-geoip-active.bin');

// ── Loaded-database state (module-level, process-wide) ───────────────────────

interface CsvIndex {
  fromNums: number[]; // sorted ascending — one entry per row/range
  toNums: number[];
  countryCodes: string[];
  countryNames: string[];
  cityNames: string[];
}

type LoadedDb =
  | { fileId: string; sha256: string; kind: 'mmdb'; reader: ReturnType<typeof MaxmindDBReader.openSync> }
  | { fileId: string; sha256: string; kind: 'csv'; csv: CsvIndex };

let loaded: LoadedDb | null = null;
let loadingPromise: Promise<LoadedDb | null> | null = null;

/** Per-IP POSITIVE-result cache (cleared whenever the active file changes). */
const resultCache = new Map<string, { res: GeoResult; at: number }>();

function pruneResultCache(): void {
  if (resultCache.size <= MAX_RESULT_CACHE) return;
  const now = Date.now();
  for (const [ip, e] of resultCache) if (now - e.at > RESULT_TTL_MS) resultCache.delete(ip);
}

// ── IPv4 helpers ──────────────────────────────────────────────────────────────

/** Parses an IPv4 literal to an unsigned int in [0, 2^32). NaN when not v4. */
function ipv4ToInt(ip: string): number {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return NaN;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const octet = Number(m[i]);
    if (octet > 255) return NaN;
    n = n * 256 + octet; // stays < 2^32, well within Number's safe range
  }
  return n;
}

/**
 * Parses a CSV IP cell to an unsigned int. Accepts BOTH dotted-quad (dp-ip)
 * and plain decimal integers — IP2Location LITE writes FromIP/ToIP as raw
 * integers (e.g. `16777216` = 1.0.0.0), which ipv4ToInt alone would reject.
 */
function ipCellToNum(cell: string): number {
  const t = cell.trim();
  if (/^\d{1,10}$/.test(t)) {
    const n = Number(t);
    return n >= 0 && n < 2 ** 32 ? n : NaN;
  }
  return ipv4ToInt(t);
}

/** True for a plain IPv4 or IPv6 literal (zone ids stripped). */
function isIpLiteral(ip: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return true; // v4
  const bare = ip.split('%')[0];
  return /^[0-9a-fA-F:]+$/.test(bare) && bare.includes(':'); // v6 (lenient)
}

// ── CSV layout detection + index building ────────────────────────────────────

interface CsvLayout {
  fromCol: number;
  toCol: number; // === fromCol for single-IP rows
  codeCol: number | null;
  nameCol: number | null;
  cityCol: number | null;
}

/**
 * Detects the CSV column layout from a header row. IP2Location LITE is
 * recognized by its FromIP/ToIP pair (range rows); anything else is treated as
 * single-IP rows (dp-ip style) where the IP column is the first one and country
 * code/name are disambiguated by which "country" column holds 2-letter codes.
 */
function detectCsvLayout(header: string[], sampleRow: string[]): CsvLayout {
  const lower = header.map((h) => h.trim().toLowerCase());

  // IP2Location LITE — explicit FromIP/ToIP range columns.
  const fromIdx = lower.findIndex((h) => h === 'fromip');
  const toIdx = lower.findIndex((h) => h === 'toip');
  if (fromIdx >= 0 && toIdx >= 0) {
    return {
      fromCol: fromIdx,
      toCol: toIdx,
      codeCol: colByHeader(lower, ['country', 'iso_code', 'countrycode']),
      nameCol: null, // LITE's Country column is the ISO code; no separate name
      cityCol: colByHeader(lower, ['city']),
    };
  }

  // Single-IP rows (dp-ip style). IP = first column that parses as an IPv4 in
  // the sample row, else column 0.
  let ipCol = 0;
  for (let i = 0; i < header.length; i++) {
    if (/ip/i.test(header[i]) || !Number.isNaN(ipCellToNum(sampleRow[i] ?? ''))) { ipCol = i; break; }
  }

  // Country code vs name: prefer a column whose sample value is exactly 2 chars.
  const countryCols = lower.map((h, i) => ({ h, i })).filter(({ h }) => /country/i.test(h));
  let codeCol: number | null = null;
  let nameCol: number | null = null;
  for (const { i } of countryCols) {
    const v = (sampleRow[i] ?? '').trim();
    if (/^[a-z]{2}$/i.test(v)) { if (codeCol === null) codeCol = i; else if (nameCol === null) nameCol = i; }
  }
  // Fallbacks when the sample didn't disambiguate.
  if (codeCol === null && countryCols.length > 0) codeCol = countryCols[0].i;
  if (nameCol === null && countryCols.length > 1) nameCol = countryCols.find((c) => c.i !== codeCol)?.i ?? null;

  return { fromCol: ipCol, toCol: ipCol, codeCol, nameCol, cityCol: colByHeader(lower, ['city']) };
}

function colByHeader(lower: string[], names: string[]): number | null {
  for (const n of names) {
    const i = lower.findIndex((h) => h === n || h.replace(/[\s_-]/g, '') === n);
    if (i >= 0) return i;
  }
  // Loose match — any header containing the name.
  for (const n of names) {
    const i = lower.findIndex((h) => h.includes(n));
    if (i >= 0) return i;
  }
  return null;
}

/** Streams a CSV file into a sorted range index (binary-searchable). */
async function buildCsvIndex(filePath: string, layout: CsvLayout): Promise<CsvIndex> {
  const fromNums: number[] = [];
  const toNums: number[] = [];
  const countryCodes: string[] = [];
  const countryNames: string[] = [];
  const cityNames: string[] = [];

  const stream = fs.createReadStream(filePath, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  let headerSeen = false;
  for await (const line of rl) {
    if (!line || !line.trim()) continue;
    // Minimal CSV split — GeoIP exports are unquoted comma files. A quoted
    // field containing a comma would mis-split, but none of the supported
    // sources quote their columns.
    const cells = line.split(',');
    if (!headerSeen) { headerSeen = true; continue; } // skip header row

    const fromNum = ipCellToNum(cells[layout.fromCol] ?? '');
    if (Number.isNaN(fromNum)) continue; // malformed / non-IP row — skip
    const toNum = layout.toCol === layout.fromCol ? fromNum : ipCellToNum(cells[layout.toCol] ?? '');
    if (Number.isNaN(toNum) || toNum < fromNum) continue;

    fromNums.push(fromNum);
    toNums.push(toNum);
    countryCodes.push(layout.codeCol !== null ? (cells[layout.codeCol] ?? '').trim() : '');
    countryNames.push(layout.nameCol !== null ? (cells[layout.nameCol] ?? '').trim() : '');
    cityNames.push(layout.cityCol !== null ? (cells[layout.cityCol] ?? '').trim() : '');
  }

  // Rows are expected pre-sorted by FromIP; sort defensively so binary search is valid.
  const order = fromNums.map((_, i) => i).sort((a, b) => fromNums[a] - fromNums[b]);
  return {
    fromNums: order.map((i) => fromNums[i]),
    toNums: order.map((i) => toNums[i]),
    countryCodes: order.map((i) => countryCodes[i]),
    countryNames: order.map((i) => countryNames[i]),
    cityNames: order.map((i) => cityNames[i]),
  };
}

/** Binary search: largest row with fromNum <= ip, then check ip <= toNum. */
function csvLookup(csv: CsvIndex, ipNum: number): GeoResult | null {
  let lo = 0;
  let hi = csv.fromNums.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (csv.fromNums[mid] <= ipNum) { found = mid; lo = mid + 1; }
    else hi = mid - 1;
  }
  if (found < 0 || ipNum > csv.toNums[found]) return null;

  const code = csv.countryCodes[found];
  const name = csv.countryNames[found];
  const city = csv.cityNames[found];
  if (!code && !name && !city) return null;
  return { countryCode: code || undefined, countryName: name || undefined, city: city || undefined };
}

// ── MMDB lookup ───────────────────────────────────────────────────────────────

function mmdbLookup(reader: ReturnType<typeof MaxmindDBReader.openSync>, ip: string): GeoResult | null {
  let data: Record<string, any> | null = null;
  try {
    data = reader.getGeoDataSync(ip) ?? null;
  } catch {
    return null; // unknown IP / unsupported family — best-effort
  }
  if (!data || typeof data !== 'object') return null;

  const countryCode: string | undefined = data.country?.iso_code;
  const countryName: string | undefined = pickName(data.country?.names);
  const city: string | undefined = pickName(data.city?.names) ?? (typeof data.subdivisions?.[0]?.names?.en === 'string' ? data.subdivisions[0].names.en : undefined);
  if (!countryCode && !countryName && !city) return null;
  return { countryCode, countryName, city };
}

/** GeoLite2 names are keyed by locale — prefer English, fall back to any. */
function pickName(names: Record<string, string> | undefined): string | undefined {
  if (!names || typeof names !== 'object') return undefined;
  return names.en ?? Object.values(names).find((v) => typeof v === 'string' && v.length > 0);
}

// ── Database loading ──────────────────────────────────────────────────────────

/** Streams a readable into a file (bounded by the caller's maxBytes upstream). */
async function streamToFile(source: NodeJS.ReadableStream, destPath: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const out = fs.createWriteStream(destPath);
    // pipe() alone does the writing — a manual 'data' listener would double-write.
    source.on('error', reject);
    out.on('finish', resolve);
    out.on('error', reject);
    source.pipe(out, { end: true });
  });
}

/**
 * True when the stored BYTES are an MMDB database. Sniffs the magic header
 * (`\x00\x00\x01\x00`) — NOT the file extension, because the worker names files
 * `geoip-<basename>-<YYYY-MM-DD>` (date suffix AFTER the original extension),
 * so a real GeoLite2-City.mmdb is stored as e.g. `…City.mmdb-2026-10-06` and an
 * endsWith('.mmdb') check would misroute it down the CSV path.
 */
async function sniffMmdb(filePath: string): Promise<boolean> {
  try {
    const fh = await fsp.open(filePath, 'r');
    try {
      const head = Buffer.alloc(4);
      const { bytesRead } = await fh.read(head, 0, 4, 0);
      return (
        bytesRead === 4 &&
        head[0] === 0x00 && head[1] === 0x00 && head[2] === 0x01 && head[3] === 0x00
      );
    } finally { await fh.close(); }
  } catch { return false; }
}

/**
 * Loads (or reuses) the active GeoIP database. Returns null when enrichment is
 * disabled, no file has been fetched yet, or the file can't be read — callers
 * treat all of these as "no location data" and move on.
 */
/**
 * Reads the two pointer rows DIRECTLY from system_settings — deliberately NOT
 * via getEffectiveValues(). The worker writes `geoipActiveFileId` with a raw
 * SQL upsert and busts its OWN module instance's settings cache, but another
 * replica's 5 s TTL cache can still hold the previous pointer. A direct read is
 * cheap (2 rows) and always fresh; a short in-process snapshot bounds it to at
 * most one query per POINTER_TTL_MS even when a top-talkers request fans out
 * hundreds of concurrent lookups. The worker calls resetGeoIpCache() after each
 * successful store, so the same process picks up a new file immediately.
 */
const POINTER_TTL_MS = 2_000;
let pointerSnap: { at: number; enabled: boolean; fileId: string } | null = null;

async function readActivePointer(): Promise<{ enabled: boolean; fileId: string }> {
  if (pointerSnap && Date.now() - pointerSnap.at < POINTER_TTL_MS) return pointerSnap;
  try {
    const res = await pool.query(
      `SELECT "key", value FROM system_settings WHERE "key" IN ('geoipEnabled','geoipActiveFileId')`
    );
    let enabled = true; // default-on — matches the registry descriptor
    let fileId = '';
    for (const row of res.rows) {
      if (row.key === 'geoipEnabled') enabled = String(row.value).trim() !== 'false';
      else if (row.key === 'geoipActiveFileId') fileId = String(row.value ?? '').trim();
    }
    pointerSnap = { at: Date.now(), enabled, fileId };
    return pointerSnap;
  } catch {
    return { enabled: false, fileId: '' }; // DB hiccup — degrade to "no data" (not snapshotted)
  }
}

async function ensureLoaded(): Promise<LoadedDb | null> {
  const pointer = await readActivePointer();
  if (!pointer.enabled) return null;
  const fileId = pointer.fileId;
  if (!fileId) return null;

  if (loaded && loaded.fileId === fileId) return loaded;
  if (loadingPromise) return loadingPromise;

  loadingPromise = (async (): Promise<LoadedDb | null> => {
    const opened = await openRepoFile(fileId);
    if (!opened) throw new Error(`active geoip file ${fileId} is missing from the repository`);

    await streamToFile(opened.stream, TMP_PATH);

    let db: LoadedDb;
    if (await sniffMmdb(TMP_PATH)) {
      // openSync reads the whole file into memory — safe to drop the temp copy.
      const reader = MaxmindDBReader.openSync(TMP_PATH);
      await fsp.unlink(TMP_PATH).catch(() => undefined);
      db = { fileId, sha256: opened.entry.sha256, kind: 'mmdb', reader };
    } else {
      // CSV — detect layout from header + first data row, then stream-index it.
      const head = await fsp.open(TMP_PATH);
      let headerLine = '';
      try {
        const buf = Buffer.alloc(8192);
        const { bytesRead } = await head.read(buf, 0, buf.length, 0);
        const text = buf.subarray(0, bytesRead).toString('utf8');
        const nl = text.indexOf('\n');
        headerLine = (nl >= 0 ? text.slice(0, nl) : text).replace(/^\uFEFF/, ''); // strip BOM
      } finally { await head.close(); }

      const headerCells = headerLine.split(',').map((c) => c.trim());
      // Peek the first data row for code/name disambiguation.
      let sampleRow: string[] = [];
      try {
        const s2 = fs.createReadStream(TMP_PATH, { encoding: 'utf8' });
        const rl2 = readline.createInterface({ input: s2, crlfDelay: Infinity });
        for await (const line of rl2) { if (line && line.trim()) { sampleRow = line.split(','); break; } }
      } catch { /* best effort */ }

      const layout = detectCsvLayout(headerCells, sampleRow);
      const csv = await buildCsvIndex(TMP_PATH, layout);
      await fsp.unlink(TMP_PATH).catch(() => undefined);
      db = { fileId, sha256: opened.entry.sha256, kind: 'csv', csv };
    }

    // A new file is active — any cached per-IP results are stale.
    resultCache.clear();
    loaded = db;
    return db;
  })().finally(() => { loadingPromise = null; });

  return loadingPromise;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Resolve an IP literal to a GeoIP result. Returns `null` when the IP isn't a
 * plain literal, no database is active/loaded, or the DB has no entry for it.
 * Never throws. Positive results cache 10 min (cleared on file change);
 * negatives are re-evaluated so a newly fetched database can answer them.
 */
export async function lookupGeoIp(ip: string): Promise<GeoResult | null> {
  if (!isIpLiteral(ip)) return null;

  const hit = resultCache.get(ip);
  if (hit && Date.now() - hit.at < RESULT_TTL_MS) return hit.res;

  let db: LoadedDb | null = null;
  try {
    db = await ensureLoaded();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(`[geoip] failed to load active database:`, (err as Error).message);
    return null;
  }
  if (!db) return null;

  let res: GeoResult | null = null;
  try {
    if (db.kind === 'mmdb') res = mmdbLookup(db.reader, ip);
    else {
      const n = ipv4ToInt(ip); // CSV is IPv4-only — v6 yields NaN → null
      res = Number.isNaN(n) ? null : csvLookup(db.csv, n);
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(`[geoip] lookup failed for ${ip}:`, (err as Error).message);
    res = null;
  }

  // Cache POSITIVE results only. A negative ("IP not in this database") is
  // re-evaluated on every call: the active file can change at any time, and a
  // cached null would survive until TTL even though the NEW database might
  // know the IP (e.g. an MMDB without it replaced by a CSV that does). The
  // re-check is cheap — ensureLoaded returns the in-memory DB instantly when
  // the pointer is unchanged, and the lookup itself is a sync read / binary
  // search.
  if (res) {
    resultCache.set(ip, { res, at: Date.now() });
    pruneResultCache();
  }
  return res;
}

/**
 * Drop the loaded DB, result cache and pointer snapshot — forces a fresh read
 * of `geoipActiveFileId` + reload on the next lookup. The geoip worker calls
 * this after each successful store so THIS process switches to the new file
 * immediately (other replicas follow within POINTER_TTL_MS). Also exported as a
 * test hook.
 */
export function resetGeoIpCache(): void {
  loaded = null;
  loadingPromise = null;
  pointerSnap = null;
  resultCache.clear();
}
