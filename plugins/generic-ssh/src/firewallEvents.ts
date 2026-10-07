/**
 * Generic SSH plugin — kernel firewall event collection + push.
 *
 * Linux has no single "firewall log" API like OPNsense's; the universal source
 * is the KERNEL netfilter log: every packet that hits an `nft ... log` /
 * `iptables -j LOG` statement (or a logged policy drop) lands in journald as a
 * kernel message of the shape
 *
 *   [PREFIX] IN=eth0 OUT= MAC=aa:... SRC=1.2.3.4 DST=5.6.7.8 LEN=40 TOS=0x00
 *            PREC=0x00 TTL=64 ID=1234 DF PROTO=TCP SPT=443 DPT=22 WINDOW=...
 *
 * This module reads those lines INCREMENTALLY from journald (cursor-based, the
 * same pattern as OPNsense's digest cursor) and pushes them to the API's
 * internal POST /plugin/firewall-events endpoint — so they appear on the
 * cross-device Firewall Events page exactly like OPNsense rows.
 *
 * Design notes:
 *  - Timestamps: journald gives `__REALTIME_TIMESTAMP` (µs since epoch, UTC).
 *    The API expects appliance-LOCAL wall clock without TZ (it subtracts the
 *    device's known UTC offset itself), so we convert with the host's own
 *    `date +%z` offset read in the same exec. No year-rollover guessing.
 *  - vendorEventId: kernel lines carry no native id → stable sha256 over
 *    (host, realtime µs, message). The API dedupes on
 *    (deviceId, pluginId, vendorEventId), so re-sent batches are harmless.
 *  - First sight takes a bounded baseline of the newest journal entries;
 *    afterwards each beat reads only what accumulated since the stored cursor.
 *    A rotated-away/invalid cursor resets to a fresh baseline.
 *  - Action mapping: logged kernel packets are, in practice, drops/blocks —
 *    that is why people log them. Lines whose prefix says DROP/BLOCK → 'block';
 *    ACCEPT/ALLOW-ish prefixes → 'pass'; unmarked lines default to 'block'.
 *  - Runs fire-and-forget from /monitoring (never blocks or fails the poll);
 *    one extra cheap exec per beat on hosts without journalctl yields nothing.
 */

import { createHash } from 'node:crypto';
import type { CommandRunner } from './client/privilege';
import { stateStore, EFFECTIVE_UUID } from './stateStore';

const STATE_NAMESPACE = 'firewall-events'; // must be unique per feature
/** Max journal entries scanned per beat (backlog protection on busy boxes). */
const SCAN_LIMIT = 5000;
/** First-sight baseline: the newest N journal entries. */
const BASELINE_ENTRIES = 2000;

// ---------------------------------------------------------------------------
// Row shape — matches the API's POST /plugin/firewall-events contract exactly
// (see api/src/routes/internal.ts). Kept local like OPNsense's FirewallEventRow.
// ---------------------------------------------------------------------------

export interface KernelFirewallEvent {
  /** Stable per-line id: sha256(host|realtimeUs|message), hex32 — dedupe key. */
  vendorEventId: string;
  /** Host-local wall clock, verbatim "YYYY-MM-DDTHH:MM:SS" (NO timezone). */
  ts: string;
  /** block | pass (see module docs for the mapping heuristic). */
  action: string;
  reason: string | null;
  interfaceName: string;
  srcIp: string;
  dstIp: string;
  proto: string | null;
  srcPort: number | null;
  dstPort: number | null;
  ruleId: string | null;
  ruleName: string | null;
}

// ---------------------------------------------------------------------------
// Parsing helpers (pure — unit-testable without SSH)
// ---------------------------------------------------------------------------

/** "IN=eth0 OUT= MAC=..." — a netfilter log line always names an interface and SRC. */
const FW_LINE_RE = /(?:\bIN=|\bOUT=)[^\s]*.*\bSRC=/;

/** Maps numeric kernel protocol codes to names (nf_log usually emits names). */
const PROTO_BY_NUM: Record<string, string> = { '1': 'icmp', '6': 'tcp', '17': 'udp' };

function field(msg: string, name: string): string | null {
  const m = msg.match(new RegExp(`\\b${name}=(\\S+)`));
  return m ? m[1] : null;
}

/** Parses ONE kernel netfilter log message into a row (null when not one). */
export function parseKernelFirewallLine(
  host: string,
  realtimeUs: number | null,
  offsetMinutes: number,
  message: string,
): KernelFirewallEvent | null {
  // nft/iptables log prefixes are concatenated DIRECTLY onto the first field —
  // "UNM-DROPIN=eth0 OUT= SRC=..." (no separating space). Split them so the
  // \b-based IN=/OUT= extraction below works for both fields.
  const msg = message.replace(/^([^\s]*)(?=(?:IN|OUT)=)/, '$1 ');

  if (!FW_LINE_RE.test(msg)) return null;

  const srcIp = field(msg, 'SRC');
  if (!srcIp) return null; // SRC is the one mandatory field

  // Leading text before IN=/OUT= is the log prefix (nft `log prefix "..."` /
  // iptables --log-prefix). It names WHY the packet was logged.
  const bodyStart = msg.search(/\b(?:IN|OUT)=[^\s]*/);
  const prefix = bodyStart > 0 ? msg.slice(0, bodyStart).replace(/[\[\]]/g, '').trim() : '';

  let action = 'block'; // default — logged kernel packets are drops in practice
  if (prefix && /\b(accept|allow|pass)\b/i.test(prefix)) action = 'pass';

  const protoRaw = field(msg, 'PROTO');
  const proto = protoRaw ? (PROTO_BY_NUM[protoRaw] ?? protoRaw.toLowerCase()) : null;

  // Timestamp: host-local ISO without TZ from the UTC µs + host offset.
  let ts = '';
  if (realtimeUs !== null && Number.isFinite(realtimeUs)) {
    const localMs = Math.floor(realtimeUs / 1000) + offsetMinutes * 60_000;
    const d = new Date(localMs); // UTC getters on the shifted value = local wall clock
    const p = (n: number): string => String(n).padStart(2, '0');
    ts = `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}T` +
      `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  }

  const portOf = (v: string | null): number | null => {
    if (!v) return null;
    const n = Number(v);
    return Number.isFinite(n) && n >= 0 && n <= 65_535 ? Math.trunc(n) : null;
  };

  return {
    vendorEventId: createHash('sha256').update(`${host}|${realtimeUs ?? ''}|${message}`).digest('hex').slice(0, 32),
    ts,
    action,
    reason: prefix !== '' ? prefix.slice(0, 128) : null,
    // Input drops carry IN=<iface>; output drops have an empty IN= and the
    // egress interface in OUT= — fall back to it.
    interfaceName: field(msg, 'IN') || field(msg, 'OUT') || '',
    srcIp,
    dstIp: field(msg, 'DST') ?? '',
    proto,
    srcPort: portOf(field(msg, 'SPT')),
    dstPort: portOf(field(msg, 'DPT')),
    ruleId: null, // kernel lines carry no rule id — the prefix is the closest thing
    ruleName: null,
  };
}

/** "+0200" / "-0530" → minutes east of UTC (0 when unparseable). */
export function parseUtcOffset(s: string): number {
  const m = s.trim().match(/^([+-])(\d{2}):?(\d{2})$/);
  if (!m) return 0;
  const sign = m[1] === '-' ? -1 : 1;
  return sign * (Number(m[2]) * 60 + Number(m[3]));
}

// ---------------------------------------------------------------------------
// Host-side read: ONE exec, sectioned output.
//   __OFFSET__ <date +%z>    host's UTC offset (for local wall clock)
//   __JRCODE__ <n>           journalctl's own exit code (0 = cursor resolved;
//                            non-zero with a stored cursor = rotated/vacuumed)
//   __ENDCUR__ <cursor>      cursor of the NEWEST entry in this read window —
//                            where to resume when everything was consumed
//   then one JSON object per line: kernel netfilter log entries, pre-filtered
//   on the host (kernel identifier + IN=/OUT=…SRC= shape) and capped at
//   SCAN_LIMIT lines to bound transfer.
// The full journal window goes through a temp file so journalctl's exit code
// is observable (a pipe would mask it with head/grep's status).
// ---------------------------------------------------------------------------

function buildReadScript(cursor: string | null): string {
  const limit = String(SCAN_LIMIT);
  const baseline = String(BASELINE_ENTRIES);
  return [
    'printf \'__OFFSET__ %s\\n\' "$(date +%z 2>/dev/null || echo +0000)"',
    'if command -v journalctl >/dev/null 2>&1; then',
    '  TMPF=$(mktemp) || exit 1',
    cursor
      ? `  journalctl --no-pager --cursor=${shq(cursor)} -o json >"$TMPF" 2>/dev/null`
      : `  journalctl --no-pager -n ${baseline} -o json >"$TMPF" 2>/dev/null`,
    '  JRC=$?',
    '  printf \'__JRCODE__ %s\\n\' "$JRC"',
    '  if [ "$JRC" = "0" ]; then',
    `    printf '__ENDCUR__ %s\\n' "$(tail -n 1 "$TMPF" | sed -n 's/.*"__CURSOR":"\\([^"]*\\)".*/\\1/p')"`,
    `    grep -aE '"(SYSLOG_IDENTIFIER|_TRANSPORT)":"kernel"' "$TMPF" | grep -aE '(IN=|OUT=).*SRC=' | head -n ${limit}`,
    '  fi',
    '  rm -f "$TMPF"',
    'fi',
  ].join('\n');
}

/** Shell-quotes a value for safe embedding (single quotes). */
function shq(v: string): string {
  return `'${v.replace(/'/g, "'\\''")}'`;
}

interface ParsedRead {
  offsetMinutes: number;
  /** journalctl's exit code (null when journalctl is absent / no output). */
  jrcode: number | null;
  events: KernelFirewallEvent[];
  /** Cursor of the newest entry in the read window (null = nothing read). */
  endCursor: string | null;
  /** Cursor of the last event actually parsed (null when no events). */
  lastPushedCursor: string | null;
}

function parseReadOutput(host: string, stdout: string): ParsedRead {
  const lines = stdout.split('\n');
  let offsetMinutes = 0;
  let jrcode: number | null = null;
  let endCursor: string | null = null;
  const events: KernelFirewallEvent[] = [];
  let lastPushedCursor: string | null = null;

  for (const line of lines) {
    if (line.startsWith('__OFFSET__ ')) {
      offsetMinutes = parseUtcOffset(line.slice(11));
      continue;
    }
    if (line.startsWith('__JRCODE__ ')) {
      const n = Number(line.slice(11).trim());
      jrcode = Number.isFinite(n) ? n : null;
      continue;
    }
    if (line.startsWith('__ENDCUR__ ')) {
      endCursor = line.slice(11).trim() !== '' ? line.slice(11).trim() : null;
      continue;
    }
    const t = line.trim();
    if (!t.startsWith('{')) continue; // not a journal entry — skip
    let entry: Record<string, unknown>;
    try {
      entry = JSON.parse(t) as Record<string, unknown>;
    } catch {
      continue; // truncated/malformed line — skip
    }
    const msg = typeof entry['MESSAGE'] === 'string' ? (entry['MESSAGE'] as string) : '';
    if (!msg) continue;
    const rtRaw = entry['__REALTIME_TIMESTAMP'];
    const realtimeUs = typeof rtRaw === 'string' && /^\d+$/.test(rtRaw) ? Number(rtRaw) : null;

    const row = parseKernelFirewallLine(host, realtimeUs, offsetMinutes, msg);
    if (row && row.ts !== '') { // no usable timestamp → unusable for the API
      events.push(row);
      if (typeof entry['__CURSOR'] === 'string' && (entry['__CURSOR'] as string).length > 0) {
        lastPushedCursor = entry['__CURSOR'] as string;
      }
    }
  }

  return { offsetMinutes, jrcode, events, endCursor, lastPushedCursor };
}

// ---------------------------------------------------------------------------
// Push client — global fetch (Node ≥18; runtime is node:20-alpine), one retry.
// ---------------------------------------------------------------------------

const apiBase = (): string => (process.env.UNM_API_URL ?? 'http://localhost:3000/v1').replace(/\/+$/, '');

async function pushEventBatch(deviceId: string, events: KernelFirewallEvent[]): Promise<boolean> {
  const key = process.env.PLUGIN_API_KEY;
  if (!key) return false; // no API key → store is a no-op anyway (dev mode)
  const body = JSON.stringify({ pluginId: EFFECTIVE_UUID, deviceId, events });
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(`${apiBase()}/plugin/firewall-events`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-plugin-api-key': key },
        body,
        signal: AbortSignal.timeout(5_000),
      });
      if (res.ok) return true;
    } catch { /* retry / give up below */ }
    if (attempt === 0) await new Promise((r) => setTimeout(r, 500));
  }
  return false; // cursor NOT advanced — the same rows are re-read next beat
}

// ---------------------------------------------------------------------------
// Entry point — fire-and-forget from /monitoring
// ---------------------------------------------------------------------------

/**
 * Reads new kernel firewall log lines for one host and pushes them to the API.
 * Never throws: a dead journal, missing journalctl or an unreachable API must
 * never break the poll. The cursor lives in the shared state store keyed by
 * management address (survives container restarts; instance-scoped).
 */
export async function collectAndPushFirewallEvents(
  host: string,
  deviceId: string | null,
  backend: CommandRunner,
): Promise<void> {
  if (!deviceId) return; // no device scope → nothing to attribute rows to

  let cursor: string | null = null;
  try {
    const stored = await stateStore.get(STATE_NAMESPACE, host);
    if (stored && typeof stored === 'object' && typeof (stored as Record<string, unknown>)['cursor'] === 'string') {
      cursor = ((stored as Record<string, unknown>)['cursor'] as string) || null;
    }
  } catch { /* best-effort — no cursor means a fresh baseline */ }

  const r = await backend.exec(buildReadScript(cursor), 30_000).catch(() => null);
  if (!r || (r.stdout ?? '').trim() === '') return; // exec failed — keep the old cursor

  const parsed = parseReadOutput(host, r.stdout ?? '');

  // A stored cursor that journald can no longer resolve (journal rotated or
  // vacuumed) → drop it so the next beat takes a fresh baseline.
  if (cursor !== null && parsed.jrcode !== null && parsed.jrcode !== 0) {
    try { await stateStore.delete(STATE_NAMESPACE, [host]); } catch { /* best-effort */ }
    return;
  }

  const storeCursor = async (value: string): Promise<void> => {
    if (value === cursor) return; // nothing moved
    try {
      await stateStore.put([{ namespace: STATE_NAMESPACE, key: host, value: { cursor: value }, deviceId }]);
    } catch { /* best-effort — worst case the next beat re-sends and dedupe absorbs it */ }
  };

  if (parsed.events.length === 0) {
    // Nothing new. If a window was read, advance past it so its entries are not
    // re-scanned next beat; an empty SUCCESSFUL read means we sit at the tail —
    // keep the cursor as-is (no ping-pong back to baseline on quiet hosts).
    if (parsed.endCursor) await storeCursor(parsed.endCursor);
    return;
  }

  const ok = await pushEventBatch(String(deviceId), parsed.events);
  if (!ok) return; // cursor NOT advanced — re-read next beat, API dedupes

  // Advance the cursor only after a successful push. The API dedupes by
  // (deviceId, pluginId, vendorEventId), so even a lost-ack race can't create
  // duplicate rows. When the read hit the scan cap the window was NOT fully
  // consumed — resume from the last pushed event instead of skipping over the
  // remainder (it is picked up on the next beat).
  const target = parsed.events.length >= SCAN_LIMIT
    ? (parsed.lastPushedCursor ?? parsed.endCursor)
    : parsed.endCursor;
  await storeCursor(target ?? '');
}
