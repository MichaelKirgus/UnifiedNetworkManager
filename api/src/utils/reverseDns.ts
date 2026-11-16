/**
 * Reverse-DNS (PTR) resolution engine for flow endpoint IPs.
 *
 * Shared by three consumers:
 *   - workers/flows.ts      — the 5-min rollup enriches NEW tuples as they land;
 *   - workers/reverseDns.ts — backfill worker drains pre-existing/unresolved rows
 *                             on a budgeted beat (scalability for large networks);
 *   - routes/flows.ts       — top-talkers falls back to one live lookup per IP
 *                             that has no stored hostname yet.
 *
 * Resolver modes (setting `rdnsMode`):
 *   - system  — the container's default resolver (Docker DNS → host resolv.conf)
 *               via node:dns; zero configuration, what UNM did before this engine;
 *   - custom  — explicit nameservers (`rdnsServers`, "host[:port], …") queried
 *               over plain DNS/UDP with `rdnsStrategy` = failover (sticky last-
 *               good server) or round-robin;
 *   - doh     — DNS-over-HTTPS against an RFC 8484 endpoint (`rdnsDohUrl`,
 *               default https://dns.google/resolve) — useful where plain UDP/53
 *               is blocked but HTTPS egress exists.
 *
 * Scalability: the unit of resolution is the ADDRESS, not the flow row. Results
 * (positive AND negative) persist in reverse_dns_cache with per-kind TTLs, so a
 * large network converges to "each distinct external IP resolved once per TTL"
 * regardless of traffic volume; every consumer reads the cache first and only
 * fresh/missing IPs hit the wire, bounded by an explicit per-call budget.
 *
 * Strictly best-effort everywhere: any failure degrades to hostname null and is
 * cached as a negative for the short negative TTL so transient resolver hiccups
 * self-heal within minutes instead of hammering the resolver on every beat.
 */

import { promises as dns } from 'node:dns';
import dgram from 'node:dgram';
import { pool } from '../db';
import { getEffectiveValues } from '../systemSettings';
// All IP parsing lives in the shared SDK module — never re-implement it here.
import { ipToWords } from '@unm/plugin-sdk';

export type RdnsMode = 'system' | 'custom' | 'doh';
export type RdnsStrategy = 'failover' | 'round-robin';

const DEFAULT_DOH_URL = 'https://dns.google/resolve';
/** Max concurrent in-flight lookups inside one batch (protects the resolver). */
const CONCURRENCY = 8;

// ── Effective configuration ──────────────────────────────────────────────────

export interface RdnsConfig {
  enabled: boolean;
  mode: RdnsMode;
  /** custom mode only — parsed "host[:port]" entries (default port 53). */
  servers: Array<{ host: string; port: number }>;
  strategy: RdnsStrategy;
  dohUrl: string;
  timeoutMs: number;
  positiveTtlMs: number;
  negativeTtlMs: number;
}

/** Parses the effective settings into a resolver config (pure — unit-testable). */
export function parseRdnsConfig(values: Record<string, string | number | boolean>): RdnsConfig {
  const modeRaw = String(values.rdnsMode ?? 'system');
  const mode: RdnsMode = modeRaw === 'custom' || modeRaw === 'doh' ? modeRaw : 'system';
  const servers: Array<{ host: string; port: number }> = [];
  for (const raw of String(values.rdnsServers ?? '').split(',')) {
    const entry = raw.trim();
    if (!entry) continue;
    // "host" or "host:port" — a bare IPv6 literal would need brackets, which the
    // setting validation rejects up front; keep this parser deliberately simple.
    const lastColon = entry.lastIndexOf(':');
    let host = entry;
    let port = 53;
    if (lastColon > 0) {
      const maybePort = Number(entry.slice(lastColon + 1));
      if (Number.isInteger(maybePort) && maybePort >= 1 && maybePort <= 65535) {
        host = entry.slice(0, lastColon);
        port = maybePort;
      }
    }
    if (host) servers.push({ host, port });
  }
  const strategyRaw = String(values.rdnsStrategy ?? 'failover');
  return {
    enabled: values.rdnsEnabled === true,
    mode,
    servers,
    strategy: strategyRaw === 'round-robin' ? 'round-robin' : 'failover',
    dohUrl: (String(values.rdnsDohUrl ?? '').trim() || DEFAULT_DOH_URL).replace(/\/+$/, ''),
    timeoutMs: Math.min(Math.max(Number(values.rdnsTimeoutMs) || 2_000, 500), 30_000),
    positiveTtlMs: (Math.min(Math.max(Number(values.rdnsPositiveTtlHours) || 24, 1), 720)) * 3_600_000,
    negativeTtlMs: (Math.min(Math.max(Number(values.rdnsNegativeTtlMinutes) || 15, 1), 1_440)) * 60_000,
  };
}

// ── in-addr.arpa / ip6.arpa naming ───────────────────────────────────────────
// The ARPA NAME is a DNS naming convention (not IP math) — but the address
// parsing that feeds it comes exclusively from the SDK.

/**
 * Builds the reverse-DNS query name for an IPv4/IPv6 literal:
 *   192.0.2.1      → "1.2.0.192.in-addr.arpa"
 *   2001:db8::1    → "…nibbles….ip6.arpa" (32 reversed hex nibbles)
 * Returns null for anything that is not a valid IP literal (SDK-validated).
 */
export function arpaName(ip: string): string | null {
  const p = ipToWords(String(ip));
  if (!p) return null;
  if (p.family === 'v4') {
    // v4 occupies the last two words, MSB first — reverse the four octets.
    const hi = p.words[6];
    const lo = p.words[7];
    return `${lo & 255}.${(lo >>> 8) & 255}.${hi & 255}.${(hi >>> 8) & 255}.in-addr.arpa`;
  }
  // v6: 32 hex nibbles, most-significant first — reversed one nibble per label.
  const nibbles = p.words.flatMap((w) => [
    (w >> 12) & 0xf, (w >> 8) & 0xf, (w >> 4) & 0xf, w & 0xf,
  ]);
  return [...nibbles].reverse().map((n) => n.toString(16)).join('.') + '.ip6.arpa';
}

// ── DNS-over-UDP client (custom mode) ────────────────────────────────────────
// Minimal RFC 1035 PTR query/answer handling — the API has no other way to
// target a specific nameserver (node:dns always uses the system resolver).

/** Encodes a dotted domain name into DNS wire labels. */
export function encodeQname(name: string): Buffer {
  const parts = name.split('.').filter(Boolean);
  const chunks: number[] = [];
  for (const label of parts) {
    if (label.length > 63) throw new Error(`DNS label exceeds 63 chars in "${name}"`);
    chunks.push(label.length, ...Array.from(label, (c) => c.charCodeAt(0)));
  }
  chunks.push(0); // root label terminator
  return Buffer.from(chunks);
}

/** Builds a complete PTR query packet for the given arpa name. */
export function buildPtrQuery(id: number, qname: string): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id & 0xffff, 0);
  header.writeUInt16BE(0x0100, 2); // RD (recursion desired), standard query
  header.writeUInt16BE(1, 4);      // qdcount = 1
  const question = Buffer.concat([encodeQname(qname), Buffer.from([0, 12, 0, 1])]); // QTYPE PTR, QCLASS IN
  return Buffer.concat([header, question]);
}

/**
 * Decodes a domain name from a DNS message at `offset`, following compression
 * pointers (RFC 1035 §4.1.4) with a hop guard against pointer cycles.
 * Returns the name WITHOUT trailing dot plus the offset just past the ENCODED
 * FIELD — when a pointer is used that is right after the 2-byte pointer itself
 * (the target data lives elsewhere in the message), not after the target data.
 */
export function decodeDnsName(buf: Buffer, offset: number): { name: string; next: number } {
  const labels: string[] = [];
  let pos = offset;
  let hops = 0;
  let fieldEnd = -1; // set when a pointer is followed — the field ends after it
  for (;;) {
    if (pos >= buf.length || ++hops > 32) throw new Error('malformed DNS name (truncation or pointer cycle)');
    const len = buf[pos];
    if (len === 0) {
      pos += 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      // Compression pointer — the second byte is the high byte of a 14-bit offset.
      if (pos + 1 >= buf.length) throw new Error('malformed DNS name (truncated pointer)');
      const target = ((len & 0x3f) << 8) | buf[pos + 1];
      if (fieldEnd === -1) fieldEnd = pos + 2; // the encoded field ends after this pointer
      pos = target; // continue decoding from the target (may chain further pointers)
      continue;
    }
    if (len & 0x20) throw new Error('unsupported DNS name encoding');
    pos += 1;
    if (pos + len > buf.length) throw new Error('malformed DNS name (truncated label)');
    labels.push(buf.subarray(pos, pos + len).toString('utf8'));
    pos += len;
  }
  return { name: labels.join('.'), next: fieldEnd !== -1 ? fieldEnd : pos };
}

/** Extracts the first PTR answer from a DNS response packet (null = no PTR). */
export function parsePtrAnswer(buf: Buffer): string | null {
  if (buf.length < 12) throw new Error('DNS response too short');
  const ancount = buf.readUInt16BE(6);
  // Skip the question section — its qname may itself use compression pointers.
  let pos: number;
  try {
    ({ next: pos } = decodeDnsName(buf, 12));
  } catch {
    return null; // unparseable question — treat as no answer rather than crash a beat
  }
  if (pos + 4 > buf.length) return null;
  pos += 4; // qtype + qclass
  for (let i = 0; i < ancount && pos < buf.length; i++) {
    let recEnd: number;
    try { ({ next: recEnd } = decodeDnsName(buf, pos)); } catch { return null; }
    const afterName = recEnd; // past the (possibly pointer-compressed) name
    if (afterName + 10 > buf.length) return null;
    const type = buf.readUInt16BE(afterName);
    const rdlength = buf.readUInt16BE(afterName + 8);
    const rdataStart = afterName + 10;
    if (rdataStart + rdlength > buf.length) return null;
    if (type === 12) { // PTR
      try {
        const target = decodeDnsName(buf, rdataStart);
        return target.name || null;
      } catch {
        return null;
      }
    }
    pos = rdataStart + rdlength;
  }
  return null;
}

interface PendingUdp {
  resolve: (name: string | null) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
}

let udpSocket: dgram.Socket | null = null;
const pendingUdp = new Map<number, PendingUdp>();
let nextQueryId = Math.floor(Math.random() * 0xffff);

function ensureUdpSocket(): dgram.Socket {
  if (udpSocket) return udpSocket;
  const socket = dgram.createSocket('udp4');
  socket.on('message', (msg: Buffer) => {
    if (msg.length < 12) return;
    const id = msg.readUInt16BE(0);
    const pending = pendingUdp.get(id);
    if (!pending) return; // stale/duplicate response — ignore
    pendingUdp.delete(id);
    clearTimeout(pending.timer);
    try {
      pending.resolve(parsePtrAnswer(msg));
    } catch (err) {
      pending.reject(err as Error);
    }
  });
  socket.on('error', () => { /* socket-level errors surface per-query via timeout */ });
  udpSocket = socket;
  return socket;
}

/** Sends one PTR query to a specific nameserver over UDP. Null = no PTR record. */
function queryUdpServer(server: { host: string; port: number }, qname: string, timeoutMs: number): Promise<string | null> {
  const socket = ensureUdpSocket();
  const id = (nextQueryId = (nextQueryId + 1) & 0xffff);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingUdp.delete(id);
      reject(new Error(`DNS query to ${server.host}:${server.port} timed out after ${timeoutMs} ms`));
    }, timeoutMs);
    timer.unref?.();
    pendingUdp.set(id, { resolve, reject, timer });
    socket.send(buildPtrQuery(id, qname), server.port, server.host, (err) => {
      if (!err) { recordRdnsWireQuery('custom'); return; } // packet actually left the box
      const pending = pendingUdp.get(id);
      if (!pending) return;
      pendingUdp.delete(id);
      clearTimeout(pending.timer);
      reject(new Error(`DNS send to ${server.host}:${server.port} failed: ${err.message}`));
    });
  });
}

// ── DOH client (doh mode, RFC 8484) ──────────────────────────────────────────

/** Queries one PTR record through an RFC 8484 /resolve endpoint. Null = no PTR. */
async function queryDoh(cfg: RdnsConfig, qname: string): Promise<string | null> {
  const url = `${cfg.dohUrl}/resolve?name=${encodeURIComponent(qname)}&type=PTR`;
  recordRdnsWireQuery('doh');
  const res = await fetch(url, { signal: AbortSignal.timeout(cfg.timeoutMs) });
  if (!res.ok) throw new Error(`DOH request failed (HTTP ${res.status})`);
  const json = (await res.json()) as { Status?: number; Answer?: Array<{ type?: number; data?: string }> };
  // RFC 8484: Status 0 = NOERROR, 3 = NXDOMAIN → both mean "no PTR"; other
  // codes (servfail, refused…) are real failures worth surfacing.
  if (typeof json.Status === 'number' && json.Status !== 0 && json.Status !== 3) {
    throw new Error(`DOH resolver error (status ${json.Status})`);
  }
  const answer = Array.isArray(json.Answer) ? json.Answer.find((a) => a.type === 12 && typeof a.data === 'string') : undefined;
  return answer?.data ?? null;
}

// ── Server selection (failover / round-robin) ────────────────────────────────

let rrIndex = 0;        // round-robin cursor across the configured servers
let stickyIndex = -1;   // failover: last server that answered successfully

/** Returns the ordered server list to try for one lookup. */
export function pickServerOrder(cfg: RdnsConfig): Array<{ host: string; port: number }> {
  const n = cfg.servers.length;
  if (n === 0) return [];
  if (cfg.strategy === 'round-robin') {
    const start = rrIndex % n;
    rrIndex += 1;
    return Array.from({ length: n }, (_, i) => cfg.servers[(start + i) % n]);
  }
  // failover — configured order, but starting at the last known-good server.
  const start = stickyIndex >= 0 && stickyIndex < n ? stickyIndex : 0;
  return Array.from({ length: n }, (_, i) => cfg.servers[(start + i) % n]);
}

/** Marks a server as the new failover starting point (called after success). */
export function noteServerSuccess(cfg: RdnsConfig, host: string): void {
  if (cfg.strategy !== 'failover') return;
  const idx = cfg.servers.findIndex((s) => s.host === host);
  if (idx >= 0) stickyIndex = idx;
}

// ── Wire-query rate (Workers & HA page) ──────────────────────────────────────
// Counts only requests that actually went out on the wire — cache hits are
// free and must not show up as load. A trailing-60s timestamp window gives a
// stable req/s figure for the status endpoint; volume is bounded by the batch
// limit + concurrency pool, so the array stays small.

export interface RdnsStats {
  /** Live DNS requests sent since process start (cache hits excluded). */
  totalQueries: number;
  /** Requests in the trailing 60 s. */
  queriesPerMinute: number;
  /** Trailing-60s rate normalized to per-second. */
  reqPerSec: number;
  /** ISO timestamp of the most recent wire query (null when none yet). */
  at: string | null;
  /** Resolver mode used for the most recent query. */
  mode: RdnsMode | null;
}

const rdnsStats: RdnsStats = { totalQueries: 0, queriesPerMinute: 0, reqPerSec: 0, at: null, mode: null };
const wireQueryTimes: number[] = [];

/** Records one live DNS request actually sent (called from the three resolver paths). */
export function recordRdnsWireQuery(mode: RdnsMode): void {
  rdnsStats.totalQueries += 1;
  const now = Date.now();
  wireQueryTimes.push(now);
  while (wireQueryTimes.length > 0 && wireQueryTimes[0] < now - 60_000) wireQueryTimes.shift();
  rdnsStats.queriesPerMinute = wireQueryTimes.length;
  rdnsStats.reqPerSec = wireQueryTimes.length / 60;
  rdnsStats.at = new Date(now).toISOString();
  rdnsStats.mode = mode;
}

/** Snapshot for GET /system/status (Workers & HA page card). */
export function getRdnsStats(): RdnsStats {
  return { ...rdnsStats };
}

// ── Single-IP resolution across modes + strategies ───────────────────────────

/** Normalizes a PTR answer: strips trailing dot, rejects empty. */
function normalizeHostname(raw: string | null): string | null {
  if (!raw) return null;
  const name = raw.endsWith('.') ? raw.slice(0, -1) : raw;
  return name || null;
}

/**
 * Resolves ONE IP to a hostname (or null). Tries the configured servers in
 * order (failover/round-robin); system mode uses node:dns directly. Throws when
 * every attempt fails — callers cache that as a negative result.
 */
export async function resolveIpOnce(ip: string, cfg: RdnsConfig): Promise<string | null> {
  const qname = arpaName(ip);
  if (!qname) return null; // not an IP literal — never queried

  if (cfg.mode === 'system') {
    // node:dns always uses the system resolver; v4 + v6 both supported.
    recordRdnsWireQuery('system');
    const answers = await dns.reverse(ip);
    return normalizeHostname(Array.isArray(answers) && answers.length > 0 ? String(answers[0]) : null);
  }

  if (cfg.mode === 'doh') {
    // Single endpoint — no server list to fail over; the timeout bounds it.
    return normalizeHostname(await queryDoh(cfg, qname));
  }

  // custom mode — walk the ordered servers until one answers.
  const order = pickServerOrder(cfg);
  if (order.length === 0) throw new Error('rdnsMode=custom but no nameservers configured (rdnsServers is empty)');
  let lastErr: unknown = null;
  for (const server of order) {
    try {
      const name = await queryUdpServer(server, qname, cfg.timeoutMs);
      noteServerSuccess(cfg, server.host);
      return normalizeHostname(name);
    } catch (err) {
      lastErr = err; // fail over to the next server
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}

// ── Persistent cache + batched resolution ────────────────────────────────────

interface CacheRow {
  ip: string;
  hostname: string | null;
  resolvedAtMs: number;
}

/** Loads cached results for the given IPs (freshness judged by the caller). */
async function loadCached(ips: string[]): Promise<Map<string, CacheRow>> {
  const out = new Map<string, CacheRow>();
  if (ips.length === 0) return out;
  const res = await pool.query<{ ip: string; hostname: string | null; resolvedAtMs: number }>(
    `SELECT ip::text AS ip, hostname, EXTRACT(EPOCH FROM "resolvedAt") * 1000 AS "resolvedAtMs"
     FROM reverse_dns_cache WHERE ip = ANY($1::inet[])`,
    [ips],
  );
  for (const r of res.rows) out.set(String(r.ip), { ip: String(r.ip), hostname: r.hostname, resolvedAtMs: Number(r.resolvedAtMs) });
  return out;
}

/** Persists resolution results (positive AND negative — both are cached). */
async function storeResults(results: Array<{ ip: string; hostname: string | null }>): Promise<void> {
  if (results.length === 0) return;
  const ips = results.map((r) => r.ip);
  const hostnames = results.map((r) => r.hostname);
  await pool.query(
    `INSERT INTO reverse_dns_cache (ip, hostname, "resolvedAt")
     SELECT u.ip::inet, u.hostname, now()
     FROM unnest($1::text[], $2::text[]) AS u(ip, hostname)
     ON CONFLICT (ip) DO UPDATE SET hostname = EXCLUDED.hostname, "resolvedAt" = now()`,
    [ips, hostnames],
  );
}

/**
 * Resolves a batch of IPs to hostnames with the full pipeline: settings gate →
 * persistent cache (fresh positives/negatives reused) → bounded live lookups →
 * store results. Returns ip → hostname|null for every VALID input IP; invalid
 * literals are simply absent from the map. When `rdnsEnabled` is off the map is
 * empty — no DNS traffic at all, which is the "no rDNS" control.
 *
 * @param ips   candidate IPs (duplicates fine)
 * @param budget max number of NEW live lookups this call may perform; uncapped
 *               remainder stays unresolved for a later beat (scalability knob).
 */
export async function resolveHostnames(ips: string[], budget?: number): Promise<Map<string, string | null>> {
  const cfg = await parseRdnsConfig(await getEffectiveValues());
  const result = new Map<string, string | null>();
  if (!cfg.enabled) return result;

  // Dedupe + validate (SDK) — one resolution per distinct address.
  const unique: string[] = [];
  const seen = new Set<string>();
  for (const raw of ips) {
    const ip = String(raw).trim();
    if (!ip || seen.has(ip)) continue;
    if (arpaName(ip) === null) continue; // not a valid literal — skip silently
    seen.add(ip);
    unique.push(ip);
  }
  if (unique.length === 0) return result;

  const now = Date.now();
  const cached = await loadCached(unique);
  const toResolve: string[] = [];
  for (const ip of unique) {
    const row = cached.get(ip);
    if (!row) { toResolve.push(ip); continue; }
    // Freshness depends on the KIND of result — negatives re-check much sooner.
    const ttlMs = row.hostname === null ? cfg.negativeTtlMs : cfg.positiveTtlMs;
    if (now - row.resolvedAtMs < ttlMs) {
      result.set(ip, row.hostname); // fresh cache hit — no wire traffic
    } else {
      toResolve.push(ip); // stale — re-resolve below
    }
  }

  const limit = Math.max(1, budget ?? Number.MAX_SAFE_INTEGER);
  if (toResolve.length > limit) {
    // Over budget — the remainder is left for a later beat/rollup. They are NOT
    // cached as negatives: an unresolved IP must not look "known empty".
    for (const ip of toResolve.slice(limit)) result.set(ip, null);
  }

  const capped = toResolve.slice(0, limit);
  if (capped.length > 0) {
    const fresh = new Map<string, string | null>();
    let cursor = 0;
    // Fixed-size worker pool — bounds concurrent DNS traffic per batch.
    await Promise.all(
      Array.from({ length: Math.min(CONCURRENCY, capped.length) }, async () => {
        for (;;) {
          const idx = cursor;
          cursor += 1;
          if (idx >= capped.length) return;
          const ip = capped[idx];
          try {
            fresh.set(ip, await resolveIpOnce(ip, cfg));
          } catch {
            fresh.set(ip, null); // every server failed → negative result
          }
        }
      }),
    );
    void storeResults([...fresh.entries()].map(([ip, hostname]) => ({ ip, hostname })));
    for (const [ip, hostname] of fresh) result.set(ip, hostname);
  }

  return result;
}

/** One-off live lookup (top-talkers fallback) — same cache + budget pipeline. */
export async function resolveOne(ip: string): Promise<string | null> {
  const map = await resolveHostnames([ip], 1);
  return map.get(String(ip).trim()) ?? null;
}

/** Prunes cache rows far beyond their TTL (called by the backfill worker). */
export async function pruneRdnsCache(cfg: RdnsConfig): Promise<number> {
  // Keep at most ~4× the positive TTL — enough for slow consumers, bounded growth.
  const keepMs = Math.max(cfg.positiveTtlMs, cfg.negativeTtlMs) * 4;
  const res = await pool.query(`DELETE FROM reverse_dns_cache WHERE "resolvedAt" < now() - ($1 || ' milliseconds')::interval`, [String(keepMs)]);
  return Number(res.rowCount ?? 0);
}

/** Test hook — drop the shared UDP socket + in-flight state. */
export function resetReverseDnsEngine(): void {
  for (const pending of pendingUdp.values()) clearTimeout(pending.timer);
  pendingUdp.clear();
  if (udpSocket) {
    try { udpSocket.close(); } catch { /* already closed */ }
    udpSocket = null;
  }
  rrIndex = 0;
  stickyIndex = -1;
  wireQueryTimes.length = 0;
  rdnsStats.totalQueries = 0;
  rdnsStats.queriesPerMinute = 0;
  rdnsStats.reqPerSec = 0;
  rdnsStats.at = null;
  rdnsStats.mode = null;
}
