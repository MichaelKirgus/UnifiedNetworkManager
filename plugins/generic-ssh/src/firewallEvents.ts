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
 *  - THROTTLING: `journalctl --cursor=…` re-scans the journal from the stored
 *    cursor on EVERY call — on a busy box that is real CPU work, and at the
 *    default 30 s metrics cadence it kept spawning journalctl processes
 *    continuously (observed: host pinned at 100 % CPU). The read therefore
 *    runs at most once per `intervalMs` per host (plugin option
 *    `firewallEventsIntervalMs`, default = every poll for backward compat); a
 *    quiet host's cursor already sits at the journal tail, so skipping beats
 *    only delays new events by up to one interval.
 */

import { createHash } from 'node:crypto';
import type { CommandRunner } from './client/privilege';
import { stateStore, EFFECTIVE_UUID } from './stateStore';

const STATE_NAMESPACE = 'firewall-events'; // must be unique per feature
/** Default max journal entries scanned per beat (backlog protection on busy boxes). */
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

function buildReadScript(cursor: string | null, scanLimit: number): string {
  const limit = String(scanLimit);
  const baseline = String(BASELINE_ENTRIES);
  // Native journald field filter — only KERNEL entries are serialized to JSON.
  // Without it a cursor read dumps EVERY entry in the window (every service's
  // log) as JSON: on a busy box that is hundreds of MB and takes MINUTES, which
  // orphaned journalctl processes pinned the host at 100 % CPU (observed: ~15
  // concurrent re-scans from one stale cursor). With the filter journald walks
  // the range but never serializes non-kernel entries — tiny + fast output even
  // for a huge backlog window. Netfilter log lines arrive via kmsg and carry
  // SYSLOG_IDENTIFIER=kernel, so nothing we care about is filtered out.
  const jctlArgs = cursor
    ? `--cursor=${shq(cursor)} -o json SYSLOG_IDENTIFIER=kernel`
    : `-n ${baseline} -o json SYSLOG_IDENTIFIER=kernel`;
  return [
    'printf \'__OFFSET__ %s\\n\' "$(date +%z 2>/dev/null || echo +0000)"',
    'if command -v journalctl >/dev/null 2>&1; then',
    '  TMPF=$(mktemp) || exit 1',
    // Host-side hard bound (coreutils/busybox `timeout` when present): even a
    // slow filtered scan dies after ~20 s (exit code 124) instead of running for
    // minutes and orphaning on the host when the SSH exec budget ends.
    '  if command -v timeout >/dev/null 2>&1; then',
    `    timeout -k 5 20 journalctl --no-pager ${jctlArgs} >"$TMPF" 2>/dev/null`,
    '  else',
    `    journalctl --no-pager ${jctlArgs} >"$TMPF" 2>/dev/null`,
    '  fi',
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

/** Per-host throttle + scan-cap options (from plugin settings). */
export interface FirewallEventOptions {
  /** Minimum ms between journal reads per host. ≤0/undefined = every poll
   *  (legacy behavior). Default in the option descriptor: 300_000. */
  intervalMs?: number;
  /** Max journal entries scanned per beat (backlog protection). */
  scanLimit?: number;
}

/** Shape of the persisted state row: `{ cursor, lastReadAt }`. */
interface FwState {
  cursor?: string | null;
  lastReadAt?: number;
}

function readFwState(stored: unknown): FwState {
  if (!stored || typeof stored !== 'object') return {};
  const o = stored as Record<string, unknown>;
  const out: FwState = {};
  if (typeof o['cursor'] === 'string' && o['cursor'] !== '') out.cursor = o['cursor'];
  else if (o['cursor'] === null) out.cursor = null;
  if (typeof o['lastReadAt'] === 'number' && Number.isFinite(o['lastReadAt'])) out.lastReadAt = o['lastReadAt'];
  return out;
}

/**
 * Reads new kernel firewall log lines for one host and pushes them to the API.
 * Never throws: a dead journal, missing journalctl or an unreachable API must
 * never break the poll. The cursor + last-read timestamp live in the shared
 * state store keyed by management address (survive container restarts;
 * instance-scoped).
 *
 * THROTTLING: when `intervalMs` > 0 and a read happened less than that long
 * ago, this call returns WITHOUT touching the host — no journalctl process is
 * spawned. That is what keeps quiet hosts at zero journal load between reads;
 * on busy boxes it bounds the re-scan rate to one per interval instead of one
 * per metrics poll (the 100 %-CPU regression).
 */
export async function collectAndPushFirewallEvents(
  host: string,
  deviceId: string | null,
  backend: CommandRunner,
  opts?: FirewallEventOptions,
): Promise<void> {
  if (!deviceId) return; // no device scope → nothing to attribute rows to

  const intervalMs = Math.max(0, Number(opts?.intervalMs) || 0);
  const scanLimit = Math.max(100, Math.trunc(Number(opts?.scanLimit) || SCAN_LIMIT));

  let cursor: string | null = null;
  let lastReadAt: number | undefined;
  try {
    const stored = await stateStore.get(STATE_NAMESPACE, host);
    const st = readFwState(stored);
    cursor = st.cursor ?? null;
    lastReadAt = st.lastReadAt;
  } catch { /* best-effort — no cursor means a fresh baseline */ }

  // Throttle: a recent successful read already consumed this window. Skipping
  // here is safe — the stored cursor still points at the journal tail (or just
  // behind it), so nothing is lost, only delayed by ≤ intervalMs.
  if (intervalMs > 0 && typeof lastReadAt === 'number' && Date.now() - lastReadAt < intervalMs) {
    return;
  }

  const r = await backend.exec(buildReadScript(cursor, scanLimit), 30_000).catch(() => null);

  // Stamp the throttle window EVEN WHEN THE READ FAILED. Without this a
  // persistently slow journal (huge backlog → every read exceeds the exec
  // budget) defeats the interval entirely: each beat retries immediately and —
  // because the SDK timeout only drops the SSH socket, never kills the remote
  // process — leaves an orphaned `journalctl --cursor=…` re-scanning on the
  // host for minutes (observed: ~15 concurrent orphans, load 16 on 4 cores).
  // With the stamp, a slow journal costs at most ONE bounded attempt per
  // interval; the cursor is untouched so nothing is lost.
  const persist = async (value: string | null): Promise<void> => {
    // Always stamp lastReadAt — it is the throttle window itself. A failed
    // push keeps the OLD cursor so the next beat re-reads the same rows (the
    // API dedupes by vendorEventId, so a lost-ack race can't duplicate).
    try {
      await stateStore.put([{ namespace: STATE_NAMESPACE, key: host, value: { cursor: value ?? null, lastReadAt: Date.now() }, deviceId }]);
    } catch { /* best-effort — worst case the next beat re-sends and dedupe absorbs it */ }
  };

  if (!r || (r.stdout ?? '').trim() === '') {
    await persist(cursor); // exec failed — keep the old cursor, throttle until next interval
    return;
  }

  const parsed = parseReadOutput(host, r.stdout ?? '');

  // A stored cursor that journald can no longer resolve (journal rotated or
  // vacuumed) → drop it so the next beat takes a fresh baseline. Exit code 124
  // is `timeout` killing a slow scan — NOT a bad cursor: keep it and retry on
  // the next interval (the host-side bound makes that attempt cheap).
  if (cursor !== null && parsed.jrcode !== null && parsed.jrcode !== 0 && parsed.jrcode !== 124) {
    try { await stateStore.delete(STATE_NAMESPACE, [host]); } catch { /* best-effort */ }
    return;
  }

  if (parsed.events.length === 0) {
    // Nothing new. If a window was read, advance past it so its entries are not
    // re-scanned next beat; an empty SUCCESSFUL read means we sit at the tail —
    // keep the cursor as-is (no ping-pong back to baseline on quiet hosts).
    await persist(parsed.endCursor ?? cursor);
    return;
  }

  const ok = await pushEventBatch(String(deviceId), parsed.events);
  if (!ok) {
    await persist(cursor); // NOT advanced — re-read next beat, API dedupes
    return;
  }

  // Advance the cursor only after a successful push. When the read hit the scan
  // cap the window was NOT fully consumed — resume from the last pushed event
  // instead of skipping over the remainder (it is picked up on the next beat).
  const target = parsed.events.length >= scanLimit
    ? (parsed.lastPushedCursor ?? parsed.endCursor)
    : parsed.endCursor;
  await persist(target);
}
