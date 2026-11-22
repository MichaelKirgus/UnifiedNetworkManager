/**
 * @unm/plugin-sdk — rotation-aware plain log file tailing (shared core).
 *
 * Many appliances write per-app/per-host log files that never reach stdout or
 * the system journal (reverse-proxy per-site logs, appliance middleware logs,
 * app-specific files under /var/log/…). This module gives ANY plugin with a
 * shell-exec primitive (the SDK's own SshClient, generic-ssh's privilege
 * backends, …) one consistent way to collect those files INCREMENTALLY:
 *
 *   - Per-file cursor = { inode, byteOffset } persisted in the plugin's state
 *     store (namespace 'file-tail', key = management address). The cursor
 *     advances ONLY after a successful push — a lost ack re-sends the same
 *     rows and the API dedupes them by vendorEventId.
 *   - Rotation-aware: unseen path → bounded baseline of the newest N lines;
 *     same inode grew → read [offset, size); same inode shrank → truncate
 *     reset (read from 0); different inode → rotation (fresh baseline);
 *     path gone → cursor entry dropped. Hosts whose `stat` cannot report an
 *     inode (rare busybox builds) fall back to size-only identity — a shrink
 *     is then ambiguous and conservatively re-baselines.
 *   - ONE exec per beat: the host script stats every configured pattern,
 *     reads only the new byte ranges (capped), and emits sectioned output
 *     with base64 data blocks so arbitrary log bytes survive the SSH channel
 *     untouched (no line mangling, no locale issues).
 *   - Broad patterns stay safe: compressed archives (.gz/.xz/…) are skipped on
 *     the host — they are not seekable, so incremental tailing is impossible and
 *     reading them would ingest binary garbage — as are non-text files (NUL byte
 *     in the first 4 KB, e.g. wtmp/btmp under /var/log/*). Large plain files are
 *     fine: only their newest lines (baseline) or capped ranges are ever read.
 *   - Each ingested line becomes a row on POST /plugin/security-events
 *     (message = line, appname = source label, hostname = management address,
 *     top-level deviceId = the device this plugin instance was polled for),
 *     so plain log files flow into the same security pipeline as syslog.
 *
 * Timestamps: lines are parsed with a small heuristic set (ISO 8601, BSD
 * syslog "Nov 22 17:10:04", nginx "[22/Nov/2026:17:10:04 +0100]"). Formats
 * without an explicit zone are host-LOCAL wall clocks — converted to UTC with
 * the host's own `date +%z` offset read in the same exec (same convention as
 * firewall events). Unparseable lines fall back to the read time.
 *
 * This module is transport-agnostic: collectAndPushFileTailLines() takes a
 * minimal `exec` function and the SDK's PluginStateStore, so each plugin
 * passes its own instance-scoped store + command runner.
 */

import { createHash } from 'node:crypto';
import { shQuote } from './ssh';
import type { PluginStateStore } from './stateStore';

// ---------------------------------------------------------------------------
// Constants / caps
// ---------------------------------------------------------------------------

/** State-store namespace for file-tail cursors (one row per host). */
export const FILE_TAIL_STATE_NAMESPACE = 'file-tail';

/** Max files read per beat (backlog protection on glob-heavy configs). */
export const FILE_TAIL_MAX_FILES_PER_BEAT = 50;
/** Max bytes read from ONE file per beat (1 MiB — bigger backlogs drain over beats). */
export const FILE_TAIL_MAX_BYTES_PER_FILE = 1_048_576;
/** First-sight baseline: the newest N lines of an unseen/rotated file. */
export const FILE_TAIL_DEFAULT_BASELINE_LINES = 200;
/** Default minimum ms between reads per host (throttle window). */
export const FILE_TAIL_DEFAULT_INTERVAL_MS = 300_000;

/** Levels a source line may pin (mirrors the API's security-events levels). */
export type LogLineLevel = 'debug' | 'info' | 'warn' | 'error';
const LOG_LINE_LEVELS: readonly string[] = ['debug', 'info', 'warn', 'error'];

// ---------------------------------------------------------------------------
// Source configuration — line grammar: `<pattern> [label] [level]`
// ---------------------------------------------------------------------------

/** One configured log source (a path or glob, optional label + level pin). */
export interface LogSourceSpec {
  /** Absolute path or glob (`*`, `**`) on the remote host. */
  pattern: string;
  /** Display name for rows' appname (default: derived from the pattern). */
  label?: string;
  /** Level pinned for every line of this source (overrides detection). */
  level?: LogLineLevel;
}

/**
 * Parses the `logSources` option text. One source per line:
 *   /var/log/nginx/*.log            → pattern only
 *   /opt/app/logs/archive/*.out app-x  → pattern + label (globs incl. recursive ** work)
 *   /var/log/auth.log auth error    → pattern + label + level pin
 * Blank lines and `#` comments are ignored; malformed lines (no absolute
 * pattern, unknown level) are skipped. Duplicate patterns keep the first.
 */
export function parseLogSources(text: string | undefined | null): LogSourceSpec[] {
  const out: LogSourceSpec[] = [];
  if (!text || typeof text !== 'string') return out;
  const seen = new Set<string>();

  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    const pattern = parts[0];
    // Absolute paths only — the host script embeds these in `find`/`stat`
    // calls, and a relative pattern would resolve against the remote cwd.
    if (!pattern.startsWith('/')) continue;

    let label: string | undefined;
    let level: LogLineLevel | undefined;
    if (parts.length > 1) {
      const l = parts[1].trim();
      if (l !== '') label = l.slice(0, 128); // appname column cap on the API side
    }
    if (parts.length > 2) {
      const lv = parts[2].toLowerCase();
      if (!LOG_LINE_LEVELS.includes(lv)) continue; // unknown level → skip line
      level = lv as LogLineLevel;
    }

    if (seen.has(pattern)) continue;
    seen.add(pattern);
    out.push({ pattern, label, level });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Rotation decision table (pure — unit-testable without SSH)
// ---------------------------------------------------------------------------

/** Stored per-file cursor: where the last successful push left off. */
export interface FileTailCursor {
  /** Inode string when `stat` could report one (null = size-only identity). */
  inode: string | null;
  /** Byte offset already consumed — the next read starts here. */
  offset: number;
}

/** Fresh stat of one candidate file on the host. */
export interface FileTailStat {
  path: string;
  size: number;
  inode: string | null;
}

/** What to do with ONE file this beat. */
export type FileTailPlan =
  /** Read exactly [from, to) — same inode grew (or truncate reset). */
  | { kind: 'read'; path: string; from: number; to: number }
  /** First sight / rotation: take the newest `lines` lines only. */
  | { kind: 'baseline'; path: string; lines: number }
  /** Nothing new — no output section for this file. */
  | { kind: 'skip'; path: string };

/** Result of planning a beat: per-file actions + cursors to drop. */
export interface FileTailDecision {
  plans: FileTailPlan[];
  /** Paths with a stored cursor that no longer exist — drop their entries. */
  droppedPaths: string[];
}

/**
 * The rotation decision table. For every stat:
 *   - no stored cursor            → baseline (newest N lines)
 *   - same inode, size > offset   → read [offset, size)
 *   - same inode, size == offset  → skip (quiet file)
 *   - same inode, size < offset   → truncate reset: read [0, size)
 *   - different inode             → rotation: fresh baseline
 *   - no inode on either side     → size-only identity: grow reads from the
 *                                    stored offset; a shrink is ambiguous
 *                                    (truncate vs rotate) → re-baseline.
 */
export function decideFileTailActions(
  cursors: ReadonlyMap<string, FileTailCursor>,
  stats: readonly FileTailStat[],
  baselineLines: number,
): FileTailDecision {
  const lines = Math.max(1, Math.trunc(baselineLines));
  const plans: FileTailPlan[] = [];
  const present = new Set<string>();

  for (const st of stats) {
    if (!st || typeof st.path !== 'string' || st.path === '') continue;
    if (typeof st.size !== 'number' || !Number.isFinite(st.size) || st.size < 0) continue;
    present.add(st.path);

    const cur = cursors.get(st.path);
    if (!cur) {
      plans.push({ kind: 'baseline', path: st.path, lines });
      continue;
    }

    const bothInodes = cur.inode !== null && st.inode !== null;
    if (bothInodes && cur.inode === st.inode) {
      if (st.size > cur.offset) plans.push({ kind: 'read', path: st.path, from: cur.offset, to: st.size });
      else if (st.size < cur.offset) plans.push(st.size > 0 ? { kind: 'read', path: st.path, from: 0, to: st.size } : { kind: 'skip', path: st.path });
      else plans.push({ kind: 'skip', path: st.path });
    } else if (bothInodes) {
      // Different inode → the file was rotated away and replaced.
      plans.push({ kind: 'baseline', path: st.path, lines });
    } else if (st.size > cur.offset) {
      plans.push({ kind: 'read', path: st.path, from: cur.offset, to: st.size });
    } else if (st.size < cur.offset) {
      plans.push({ kind: 'baseline', path: st.path, lines });
    } else {
      plans.push({ kind: 'skip', path: st.path });
    }
  }

  const droppedPaths: string[] = [];
  for (const p of cursors.keys()) if (!present.has(p)) droppedPaths.push(p);

  return { plans, droppedPaths };
}

// ---------------------------------------------------------------------------
// Sectioned output codec — markers + base64 data blocks
// ---------------------------------------------------------------------------
// The host script emits, per file with new content:
//   __FILE__ <path> <size> <inode-or-dash>
//   __DATA_BEGIN__
//   <base64 of the byte range, wrapped at 100 columns by `base64 -w 100`>
//   __DATA_END__
// plus one header line:
//   __OFFSET__ <+|-hhmm>     (the host's UTC offset from `date +%z`)
// Base64 keeps arbitrary log bytes intact across the SSH channel; the wrap is
// cosmetic and stripped on decode.

export const FILE_TAIL_MARKER_OFFSET = '__OFFSET__';
export const FILE_TAIL_MARKER_FILE = '__FILE__';
export const FILE_TAIL_MARKER_DATA_BEGIN = '__DATA_BEGIN__';
export const FILE_TAIL_MARKER_DATA_END = '__DATA_END__';

/** Decodes a wrapped base64 block (one or more lines) to bytes. */
export function decodeBase64Block(wrapped: string): Buffer {
  return Buffer.from(wrapped.replace(/\s+/g, ''), 'base64');
}

// ---------------------------------------------------------------------------// Host-side read script — ONE exec per beat, POSIX sh (runs via the remote
// login shell; no bashisms). The rotation DECISION stays in TypeScript
// (decideFileTailActions above); the shell only implements the simple "what to
// fetch" rule that is safe without knowing the full table:
//   - cursor exists, same inode, file grew  → byte range [offset, size) capped
//   - anything else (new / rotated / shrank) → baseline budget read of the
//     newest BASELINE_BYTES bytes (a superset — TS keeps only the last N lines
//     and computes exact cursors from the reported offsets).
// Every section is a BYTE RANGE with an absolute start offset, so line byte
// offsets (the dedupe identity) are exact even on live-growing files.
// ---------------------------------------------------------------------------

/** Byte budget for baseline reads (≈ hundreds of typical log lines; TS keeps only the last N). */
export const FILE_TAIL_BASELINE_BYTES = 65_536;
/** Marker: one per matched file — `__STAT__ <path> <size> <inode-or-dash>`. */
export const FILE_TAIL_MARKER_STAT = '__STAT__';

/** Options for the host read script (all capped to bound transfer + work). */
export interface FileTailReadOptions {
  /** Max bytes read from ONE file per beat on range reads. */
  maxBytesPerFile?: number;
  /** Byte budget for baseline (first-sight/rotation) reads. */
  baselineBytes?: number;
  /** Max files processed per beat across all patterns. */
  maxFilesPerBeat?: number;
}

/**
 * Builds the one-shot POSIX sh read script for a beat. `cursors` are embedded
 * as a quoted heredoc (path<TAB>inode-or-dash<TAB>offset per line) so the shell
 * can apply the fetch rule without any other plugin state on the host.
 */
export function buildFileTailReadScript(
  sources: readonly LogSourceSpec[],
  cursors: ReadonlyMap<string, FileTailCursor>,
  opts?: FileTailReadOptions,
): string {
  const cap = Math.max(1024, Math.trunc(opts?.maxBytesPerFile ?? FILE_TAIL_MAX_BYTES_PER_FILE));
  const baseBytes = Math.max(4096, Math.trunc(opts?.baselineBytes ?? FILE_TAIL_BASELINE_BYTES));
  const maxFiles = Math.max(1, Math.trunc(opts?.maxFilesPerBeat ?? FILE_TAIL_MAX_FILES_PER_BEAT));

  // Patterns as a shell array-of-words via quoted literals (one per line).
  const patternLines = sources.map((s) => shQuote(s.pattern)).join(' ');

  // Cursor heredoc body — raw lines inside a QUOTED delimiter (no expansion),
  // so arbitrary path characters are safe (except newlines in paths, which no
  // sane log layout has).
  const cursorLines: string[] = [];
  for (const [path, cur] of cursors) {
    if (!cur || !Number.isFinite(cur.offset) || cur.offset < 0) continue;
    cursorLines.push(`${path}\t${cur.inode ?? '-'}\t${Math.trunc(cur.offset)}`);
  }

  return [
    'printf \'__OFFSET__ %s\\n\' "$(date +%z 2>/dev/null || echo +0000)"',
    'TMPD=$(mktemp -d 2>/dev/null) || TMPD=/tmp',
    'CH="$TMPD/chunk"; CH2="$TMPD/chunk2"',
    'CURF="$TMPD/cursors"; FILES="$TMPD/files"; FSL="$TMPD/files.sorted"',
    `cat >"$CURF" <<'UNM_CURSORS_EOF'`,
    ...cursorLines,
    'UNM_CURSORS_EOF',
    'TAB=$(printf \'\\t\')',
    ': >"$FILES"',
    // --- expand every pattern into a file list -----------------------------
    `for P in ${patternLines}; do`,
    '  case "$P" in',
    "    *'*'*|*'?'*|*'['*)",
    '      case "$P" in',
    '        *"**"*)',
    // recursive glob: walk from the prefix before the first *, match last segment
    '          D=${P%%\\**}; N=${P##*/}',
    `          find "$D" -type f -name "$N" 2>/dev/null >>"$FILES"`,
    '          ;;',
    '        *)',
    // single-level glob in the final segment → bounded find; else recursive fallback
    '          PA=${P%/*}; GS=${P##*/}',
    '          case "$GS" in',
    "            *'*'*|*'?'*|*'['*)",
    `              find "$PA" -maxdepth 1 -type f -name "$GS" 2>/dev/null >>"$FILES"`,
    '              ;;',
    '            *)',
    '              D=${P%%\\**}; N=${P##*/}',
    `              find "$D" -type f -name "$N" 2>/dev/null >>"$FILES"`,
    '              ;;',
    '          esac',
    '          ;;',
    '      esac',
    '      ;;',
    '    *) [ -f "$P" ] && printf \'%s\\n\' "$P" >>"$FILES" ;;',
    '  esac',
    'done',
    `sort -u "$FILES" 2>/dev/null | head -n ${maxFiles} >"$FSL" || :`,
    // --- per file: stat, fetch rule, sectioned output ----------------------
    'while IFS= read -r F; do',
    '  [ -f "$F" ] || continue',
    // Compressed archives are not seekable — incremental byte-range tailing is
    // impossible and reading them would ingest binary garbage. Skip silently so
    // broad patterns (e.g. /var/log/*) stay safe next to rotated .gz copies.
    '  case "$F" in *.gz|*.gzip|*.xz|*.bz2|*.zst|*.zip|*.lz4) continue ;; esac',
    '  S=$(stat -c %s -- "$F" 2>/dev/null) || S=\'\'',
    "  case \"$S\" in ''|*[!0-9]*) S=$(wc -c <\"$F\" 2>/dev/null | tr -d ' \\t') ;; esac",
    "  case \"$S\" in ''|*[!0-9]*) continue ;; esac",
    // Binary files (wtmp/btmp/lastlog under /var/log/*): a NUL byte in the first
    // 4 KB marks non-text. Skipped BEFORE __STAT__ so the TS side never sees them
    // (a cursor for that path, if any, is dropped as "gone" on this beat).
    '  HB="$TMPD/head.bin"',
    '  head -c 4096 "$F" >"$HB" 2>/dev/null || continue',
    "  H=$(wc -c <\"$HB\" | tr -d ' \\t')",
    "  T=$(LC_ALL=C tr -d '\\000' <\"$HB\" | wc -c | tr -d ' \\t')",
    '  [ "$T" != "$H" ] && continue',
    "  I=$(stat -c %i -- \"$F\" 2>/dev/null) || I='-'",
    "  case \"$I\" in ''|*[!0-9]*) I='-' ;; esac",
    '  printf \'__STAT__ %s %s %s\\n\' "$F" "$S" "$I"',
    '  [ "$S" -eq 0 ] && continue',
    // cursor lookup (small file — linear scan is fine)
    "  CUR_I=''; CUR_OFF=''",
    '  while IFS="$TAB" read -r CP CI CO; do',
    '    if [ "$CP" = "$F" ]; then CUR_I=$CI; CUR_OFF=$CO; break; fi',
    '  done <"$CURF"',
    // fetch rule (see module docs — the decision table itself lives in TS)
    '  START=0; LEN=0',
    '  if [ -n "$CUR_OFF" ] && [ "$I" != "-" ] && [ "$I" = "$CUR_I" ] && [ "$S" -gt "$CUR_OFF" ]; then',
    '    START=$((CUR_OFF + 1))',
    '    LEN=$((S - CUR_OFF))',
    `    [ "$LEN" -gt ${cap} ] && LEN=${cap}`,
    '  else',
    `    B=${baseBytes}`,
    '    [ "$S" -lt "$B" ] && B="$S"',
    '    START=$((S - B + 1))',
    '    LEN=$B',
    '  fi',
    // byte-range read (tail -c is 1-based: +N starts AT byte N)
    '  if tail -c "+$START" -- "$F" >"$CH" 2>/dev/null; then',
    '    if [ "$LEN" -gt 0 ] && ! { head -c "$LEN" "$CH" >"$CH2" && mv "$CH2" "$CH"; }; then continue; fi',
    "    L=$(wc -c <\"$CH\" | tr -d ' \\t')",
    "    case \"$L\" in ''|*[!0-9]*) L=0 ;; esac",
    '    if [ "$L" -gt 0 ]; then',
    '      printf \'__FILE__ %s %s\\n\' "$F" $((START - 1))',
    "      printf '%s\\n' '__DATA_BEGIN__'",
    // base64 keeps arbitrary bytes intact; -w wrap is cosmetic (decoder strips it),
    // plain base64 fallback for busybox builds without -w.
    '      base64 -w 100 <"$CH" 2>/dev/null || base64 <"$CH"',
    "      printf '%s\\n' '__DATA_END__'",
    '    fi',
    '  fi',
    'done <"$FSL"',
    'rm -rf "$TMPD" 2>/dev/null || true',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Output parser (pure — unit-testable without SSH)
// ---------------------------------------------------------------------------

/** One decoded data section: a byte range of one file. */
export interface FileTailSection {
  path: string;
  /** Absolute byte offset of the section's first byte in the file. */
  startOffset: number;
  data: Buffer;
}

/** Everything the host reported for one beat. */
export interface ParsedFileTailRead {
  /** Host UTC offset in minutes (from `date +%z`; 0 when unparseable). */
  offsetMinutes: number;
  /** Every matched file: path → fresh stat (quiet files included). */
  stats: Map<string, FileTailStat>;
  /** Files with new content: path → decoded byte range (at most one each). */
  sections: Map<string, FileTailSection>;
}

/** Parses the sectioned stdout of buildFileTailReadScript. */
export function parseFileTailOutput(stdout: string): ParsedFileTailRead {
  const lines = stdout.split('\n');
  let offsetMinutes = 0;
  const stats = new Map<string, FileTailStat>();
  const sections = new Map<string, FileTailSection>();

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    if (line.startsWith(FILE_TAIL_MARKER_OFFSET + ' ')) {
      offsetMinutes = parseHostZuluOffset(line.slice(FILE_TAIL_MARKER_OFFSET.length + 1));
      i += 1;
      continue;
    }

    // `__STAT__ <path> <size> <inode-or-dash>` — path may contain spaces, so
    // anchor on the two numeric fields at the END of the line.
    if (line.startsWith(FILE_TAIL_MARKER_STAT + ' ')) {
      const m = line.slice(FILE_TAIL_MARKER_STAT.length + 1).match(/^(.*) (\d+) ([0-9]+|-)$/);
      if (m) stats.set(m[1], { path: m[1], size: Number(m[2]), inode: m[3] === '-' ? null : m[3] });
      i += 1;
      continue;
    }

    // `__FILE__ <path> <startOffset>` followed by a base64 block. Base64's
    // alphabet has no underscores, so data lines can never collide with markers.
    if (line.startsWith(FILE_TAIL_MARKER_FILE + ' ')) {
      const m = line.slice(FILE_TAIL_MARKER_FILE.length + 1).match(/^(.*) (\d+)$/);
      i += 1;
      if (!m) continue;
      let inData = false;
      const b64: string[] = [];
      while (i < lines.length) {
        const l2 = lines[i];
        if (l2 === FILE_TAIL_MARKER_DATA_BEGIN) { inData = true; i += 1; continue; }
        if (l2 === FILE_TAIL_MARKER_DATA_END) break;
        if (inData) b64.push(l2);
        i += 1;
      }
      sections.set(m[1], { path: m[1], startOffset: Number(m[2]), data: decodeBase64Block(b64.join('')) });
      continue;
    }

    i += 1; // anything else (shell noise) — ignore
  }

  return { offsetMinutes, stats, sections };
}

/** "+0130" / "-0530" → minutes east of UTC (0 when unparseable). */
export function parseHostZuluOffset(s: string): number {
  const m = s.trim().match(/^([+-])(\d{2}):?(\d{2})$/);
  if (!m) return 0;
  const sign = m[1] === '-' ? -1 : 1;
  return sign * (Number(m[2]) * 60 + Number(m[3]));
}

// ---------------------------------------------------------------------------// Line heuristics — timestamps + levels
// ---------------------------------------------------------------------------

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

/** nginx access/error log: [22/Nov/2026:17:10:04 +0100] (zone optional). */
const NGINX_TS_RE = /\[(\d{1,2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}:\d{2}:\d{2})(?: ([+-]\d{4}))?\]/;
/** ISO 8601 at line start: 2026-11-22T17:10:04(.123)(Z|+01:00)? or space-separated. */
const ISO_TS_RE = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,](\d{1,6}))?(Z|[+-]\d{2}:?\d{2})?/;
/** BSD syslog at line start: Nov 22 17:10:04 (no year). */
const BSD_TS_RE = /^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2})/;

/**
 * Extracts a line's timestamp as epoch ms. Formats without an explicit zone
 * are host-LOCAL wall clocks — shifted to UTC by `offsetMinutes` (the host's
 * own `date +%z`, read in the same exec). Nothing recognizable → fallbackMs
 * (the read time), so every line always yields a usable tsMs.
 */
export function parseLogLineTimestampMs(line: string, offsetMinutes: number, fallbackMs: number): number {
  const fb = Number.isFinite(fallbackMs) ? Math.trunc(fallbackMs) : Date.now();

  // nginx — usually carries an explicit zone; without one it is host-local.
  const ng = line.match(NGINX_TS_RE);
  if (ng) {
    const [, day, mon, year, hms, zone] = ng;
    const month = MONTHS[mon];
    if (month !== undefined) {
      const [hh, mm, ss] = hms.split(':').map(Number);
      let ms: number;
      if (zone) {
        // Build an ISO string Date.parse understands: 2026-11-22T17:10:04+01:00
        const z = `${zone.slice(0, 3)}:${zone.slice(3)}`;
        ms = Date.parse(`${year}-${String(month + 1).padStart(2, '0')}-${String(Number(day)).padStart(2, '0')}T${hms}${z}`);
      } else {
        ms = Date.UTC(Number(year), month, Number(day), hh, mm, ss) - offsetMinutes * 60_000;
      }
      if (Number.isFinite(ms)) return Math.trunc(ms);
    }
  }

  // ISO 8601 — explicit zone wins; otherwise host-local.
  const iso = line.match(ISO_TS_RE);
  if (iso) {
    const [, y, mo, d, hms, frac, zone] = iso;
    const [hh, mi, ss] = hms.split(':').map(Number);
    const fracMs = frac ? Math.round(Number(`0.${frac}`) * 1000) : 0;
    let ms: number;
    if (zone && zone.toUpperCase() !== 'Z') {
      const z = zone.length === 5 ? `${zone.slice(0, 3)}:${zone.slice(3)}` : zone; // +0100 → +01:00
      ms = Date.parse(`${y}-${mo}-${d}T${hms}${z}`);
    } else {
      const base = Date.UTC(Number(y), Number(mo) - 1, Number(d), hh, mi, ss);
      ms = zone && zone.toUpperCase() === 'Z' ? base : base - offsetMinutes * 60_000;
    }
    if (Number.isFinite(ms)) return Math.trunc(ms + fracMs);
  }

  // BSD syslog — no year: assume the read-time year, and if that lands more
  // than two days in the future it is from the previous year (Dec→Jan rollover).
  const bsd = line.match(BSD_TS_RE);
  if (bsd) {
    const [, mon, day, hms] = bsd;
    const month = MONTHS[mon];
    if (month !== undefined) {
      const [hh, mi, ss] = hms.split(':').map(Number);
      let year = new Date(fb).getUTCFullYear();
      let ms = Date.UTC(year, month, Number(day), hh, mi, ss) - offsetMinutes * 60_000;
      if (ms > fb + 2 * 86_400_000) {
        year -= 1;
        ms = Date.UTC(year, month, Number(day), hh, mi, ss) - offsetMinutes * 60_000;
      }
      if (Number.isFinite(ms)) return Math.trunc(ms);
    }
  }

  return fb;
}

/**
 * Detects a line's level. Precedence: the source's pinned level (when set) >
 * error-ish words > warn-ish > debug/trace > info. Word-boundary matching on
 * the common tokens covers nginx ("[error]"), syslog (CRIT/FATAL), journald
 * and most app loggers without per-format parsers.
 */
export function detectLogLevel(line: string, override?: LogLineLevel): LogLineLevel {
  if (override) return override;
  if (/\b(error|err|crit(?:ical)?|fatal|panic)\b/i.test(line)) return 'error';
  if (/\bwarn(?:ing)?\b/i.test(line)) return 'warn';
  if (/\b(debug|trace)\b/i.test(line)) return 'debug';
  return 'info';
}

// ---------------------------------------------------------------------------
// Dedupe identity
// ---------------------------------------------------------------------------

/**
 * Stable per-line id: sha1(host | path | inode-identity | byteOffset | line), hex40.
 * The API dedupes security events on (pluginId, vendorEventId), so a re-sent
 * batch after a lost ack is harmless — the same bytes at the same offsets hash
 * to the same ids. `identity` is the file's inode string (or 'noid' on hosts
 * whose stat cannot report one). The LINE CONTENT is part of the id because an
 * in-place truncate reuses byte offsets under the SAME inode: without it, new
 * content at offset 0 would collide with the pre-truncate line that occupied
 * offset 0 and be silently dropped (observed live: only non-colliding lines
 * survived a truncate reset). The one accepted consequence: if a file is
 * truncated and the new content is byte-identical at an already-pushed offset,
 * it dedupes to the old row — duplicates are the safer failure mode for a
 * security feed.
 */
export function fileTailVendorEventId(host: string, path: string, identity: string, byteOffset: number, line: string): string {
  return createHash('sha1').update(`${host}|${path}|${identity}|${byteOffset}|${line}`).digest('hex');
}

// ---------------------------------------------------------------------------
// Section → rows (pure — unit-testable without SSH)
// ---------------------------------------------------------------------------

/** One ingested line, shaped for POST /plugin/security-events. */
export interface FileTailEventRow {
  /** Stable per-line id: sha1(host|path|inode-identity|byteOffset|lineText), hex40. */
  vendorEventId: string;
  /** The log line verbatim (the API truncates at 4 KB). */
  message: string;
  tsMs: number;
  level: LogLineLevel;
  /** Device management address — the row's hostname on the API side. */
  hostname: string;
  /** Source label (or derived basename) for the appname column. */
  appname: string | null;
}

export interface BuildFileTailRowsArgs {
  host: string;
  path: string;
  /** Inode identity for the dedupe id (inode string, or 'noid'). */
  identity: string;
  /** Absolute byte offset of `data[0]` in the file. */
  startOffset: number;
  data: Buffer;
  appname: string | null;
  levelOverride?: LogLineLevel;
  offsetMinutes: number;
  readTimeMs: number;
  /** Baseline reads keep only the last N lines (0/undefined = all). */
  maxLines?: number;
}

export interface BuildFileTailRowsResult {
  rows: FileTailEventRow[];
  /** Bytes of `data` fully consumed — the cursor advances to startOffset + this. */
  consumedBytes: number;
}

/** An incomplete trailing line is held back (re-read next beat) up to this size. */
const PARTIAL_HOLD_MAX = 65_536;

/**
 * Splits a decoded section into rows with EXACT absolute byte offsets.
 * Incomplete-tail rule: when the section does not end in \n, the trailing
 * partial line is NOT ingested and NOT consumed — the writer may still be
 * finishing it, so the cursor stops before it and the next beat re-reads from
 * there (classic tail -F semantics). Exception: a "line" longer than
 * PARTIAL_HOLD_MAX is treated as complete (buffered writers / single-line JSON
 * logs), otherwise a chatty buffered file would pin the cursor forever.
 */
export function buildFileTailRows(args: BuildFileTailRowsArgs): BuildFileTailRowsResult {
  const { host, path, identity, startOffset, data, appname, levelOverride, offsetMinutes, readTimeMs } = args;
  if (!data || data.length === 0) return { rows: [], consumedBytes: 0 };

  let consumed = data.length;
  if (data[data.length - 1] !== 0x0a) {
    const nl = data.lastIndexOf(0x0a); // -1 → the whole buffer is one partial line
    const partialSize = data.length - (nl + 1);
    if (partialSize <= PARTIAL_HOLD_MAX) consumed = nl + 1;
  }

  interface LineRef { text: string; offset: number; }
  const lineRefs: LineRef[] = [];
  let pos = 0;
  while (pos < consumed) {
    const nl = data.indexOf(0x0a, pos);
    if (nl === -1 || nl >= consumed) break; // no more complete lines
    const len = nl - pos;
    if (len > 0) lineRefs.push({ text: data.subarray(pos, nl).toString('utf8'), offset: startOffset + pos });
    pos = nl + 1;
  }
  if (pos < consumed) {
    // Unterminated trailing region — only reachable when the PARTIAL_HOLD_MAX
    // exception above treated it as complete (buffered writer / single-line
    // JSON log): ingest it as one final line instead of dropping it.
    const len = consumed - pos;
    if (len > 0) lineRefs.push({ text: data.subarray(pos, consumed).toString('utf8'), offset: startOffset + pos });
  }

  const maxLines = args.maxLines && args.maxLines > 0 ? Math.trunc(args.maxLines) : 0;
  const kept = maxLines > 0 ? lineRefs.slice(-maxLines) : lineRefs;

  const rows: FileTailEventRow[] = [];
  for (const lr of kept) {
    rows.push({
      vendorEventId: fileTailVendorEventId(host, path, identity, lr.offset, lr.text),
      message: lr.text,
      tsMs: parseLogLineTimestampMs(lr.text, offsetMinutes, readTimeMs),
      level: detectLogLevel(lr.text, levelOverride),
      hostname: host,
      appname,
    });
  }
  return { rows, consumedBytes: consumed };
}

// ---------------------------------------------------------------------------
// Pattern → file attribution (client-side glob match)
// ---------------------------------------------------------------------------

/** Compiles a log-source pattern to an anchored RegExp (** = any depth). */
export function logSourcePatternToRegex(pattern: string): RegExp {
  let re = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        // '**' — recursive: when followed by '/', consume whole dir segments
        if (pattern[i + 2] === '/') { re += '(?:[^/]+/)*'; i += 2; }
        else { re += '.*'; i += 1; }
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${re}$`);
}

/** First source whose pattern matches the path (null when none). */
export function matchLogSource(path: string, sources: readonly LogSourceSpec[]): LogSourceSpec | null {
  for (const s of sources) if (logSourcePatternToRegex(s.pattern).test(path)) return s;
  return null;
}

// ---------------------------------------------------------------------------
// Push client — global fetch (Node ≥18), one retry per chunk, top-level
// deviceId scope (the API's /plugin/security-events fallback field).
// ---------------------------------------------------------------------------

/** The API caps security-event batches at 5000 rows per request. */
const MAX_PUSH_CHUNK = 5_000;

const apiBase = (): string => (process.env.UNM_API_URL ?? 'http://localhost:3000/v1').replace(/\/+$/, '');

async function pushFileTailBatch(pluginId: string, deviceId: string, rows: FileTailEventRow[]): Promise<boolean> {
  const key = process.env.PLUGIN_API_KEY;
  if (!key) return false; // no API key → the state store is a no-op anyway (dev mode)

  for (let i = 0; i < rows.length; i += MAX_PUSH_CHUNK) {
    const body = JSON.stringify({ pluginId, deviceId, events: rows.slice(i, i + MAX_PUSH_CHUNK) });
    let ok = false;
    for (let attempt = 0; attempt < 2 && !ok; attempt++) {
      try {
        const res = await fetch(`${apiBase()}/plugin/security-events`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-plugin-api-key': key },
          body,
          signal: AbortSignal.timeout(5_000),
        });
        ok = res.ok;
      } catch { /* retry / give up below */ }
      if (!ok && attempt === 0) await new Promise((r) => setTimeout(r, 500));
    }
    // A failed chunk stops the batch: earlier chunks are acked (dedupe-safe),
    // and because the cursors do NOT advance, the next beat re-reads + re-pushes
    // from the start — already-accepted rows are ignored by the API.
    if (!ok) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Entry point — fire-and-forget from a plugin's /monitoring
// ---------------------------------------------------------------------------

/** Minimal exec primitive — any plugin can pass its own runner. */
export interface FileTailExecResult {
  stdout?: string;
  stderr?: string;
}
export type FileTailExec = (command: string, timeoutMs?: number) => Promise<FileTailExecResult | null>;

/** Per-host throttle + read-cap options for collectAndPushFileTailLines. */
export interface FileTailCollectOptions {
  /** This process's effective plugin uuid — sent as `pluginId` on push. */
  pluginId: string;
  /** The logSources option text (line grammar, see parseLogSources). Empty = disabled. */
  sourcesText: string;
  /** Minimum ms between reads per host (throttle window). Default 300_000. */
  intervalMs?: number;
  /** Lines kept from a baseline read of an unseen/rotated file. Default 200. */
  baselineLines?: number;
  maxBytesPerFile?: number;
  maxFilesPerBeat?: number;
}

/** Shape of the persisted state row: `{ cursors: {path: {inode, offset}}, lastReadAt }`. */
interface FileTailHostState {
  cursors?: Record<string, unknown>;
  lastReadAt?: number;
}

function readFileTailState(stored: unknown): { cursors: Map<string, FileTailCursor>; lastReadAt?: number } {
  const out: { cursors: Map<string, FileTailCursor>; lastReadAt?: number } = { cursors: new Map() };
  if (!stored || typeof stored !== 'object') return out;
  const o = stored as Record<string, unknown>;
  if (typeof o['lastReadAt'] === 'number' && Number.isFinite(o['lastReadAt'])) out.lastReadAt = o['lastReadAt'];
  const c = o['cursors'];
  if (c && typeof c === 'object') {
    for (const [p, v] of Object.entries(c as Record<string, unknown>)) {
      if (!v || typeof v !== 'object') continue;
      const cv = v as Record<string, unknown>;
      const offset = Number(cv['offset']);
      if (!Number.isFinite(offset) || offset < 0) continue;
      out.cursors.set(p, {
        inode: typeof cv['inode'] === 'string' && cv['inode'] !== '' ? cv['inode'] : null,
        offset: Math.trunc(offset),
      });
    }
  }
  return out;
}

/**
 * Reads new lines from the configured log files of one host and pushes them to
 * the API's security-events pipeline. Never throws: a dead host, missing tools
 * or an unreachable API must never break the poll. Cursors + last-read stamp
 * live in the caller's (instance-scoped) state store under namespace 'file-tail',
 * keyed by management address — they survive container restarts.
 *
 * THROTTLING: when `intervalMs` > 0 and a read happened less than that long ago,
 * this call returns WITHOUT touching the host. The cursor already sits at (or
 * just behind) every file's tail, so skipping beats only delays new lines by up
 * to one interval — while keeping busy hosts free of per-poll stat/tail churn.
 */
export async function collectAndPushFileTailLines(
  host: string,
  deviceId: string | null,
  exec: FileTailExec,
  state: PluginStateStore,
  opts: FileTailCollectOptions,
): Promise<void> {
  if (!deviceId) return; // no device scope → nothing to attribute rows to

  const sources = parseLogSources(opts.sourcesText);
  if (sources.length === 0) return; // feature disabled for this instance

  const intervalMs = Math.max(0, Number(opts.intervalMs ?? FILE_TAIL_DEFAULT_INTERVAL_MS));
  const baselineLines = Math.max(1, Math.trunc(Number(opts.baselineLines ?? FILE_TAIL_DEFAULT_BASELINE_LINES)));

  let cursors = new Map<string, FileTailCursor>();
  let lastReadAt: number | undefined;
  try {
    const st = readFileTailState(await state.get(FILE_TAIL_STATE_NAMESPACE, host));
    cursors = st.cursors;
    lastReadAt = st.lastReadAt;
  } catch { /* best-effort — no cursor means a fresh baseline */ }

  // Throttle: a recent read already consumed this window (see module docs).
  if (intervalMs > 0 && typeof lastReadAt === 'number' && Date.now() - lastReadAt < intervalMs) {
    return;
  }

  const r = await exec(
    buildFileTailReadScript(sources, cursors, { maxBytesPerFile: opts.maxBytesPerFile, maxFilesPerBeat: opts.maxFilesPerBeat }),
    30_000,
  ).catch(() => null);

  // Stamp the throttle window EVEN WHEN THE READ FAILED (same orphan-process
  // rationale as firewall events): a persistently failing host costs at most
  // one bounded attempt per interval. A failed push keeps the OLD cursors so
  // the next beat re-reads the same rows — the API dedupes by vendorEventId.
  const persist = async (value: Map<string, FileTailCursor>): Promise<void> => {
    try {
      await state.put([{
        namespace: FILE_TAIL_STATE_NAMESPACE,
        key: host,
        value: { cursors: Object.fromEntries(value), lastReadAt: Date.now() },
        deviceId,
      }]);
    } catch { /* best-effort — worst case the next beat re-sends and dedupe absorbs it */ }
  };

  if (!r || (r.stdout ?? '').trim() === '') {
    await persist(cursors); // exec failed — keep cursors, throttle until next interval
    return;
  }

  const parsed = parseFileTailOutput(r.stdout ?? '');
  const decision = decideFileTailActions(cursors, [...parsed.stats.values()], baselineLines);

  const readTimeMs = Date.now();
  const rows: FileTailEventRow[] = [];
  const newCursors = new Map(cursors);

  for (const plan of decision.plans) {
    if (plan.kind === 'skip') continue;
    const stat = parsed.stats.get(plan.path);
    if (!stat) continue;
    const section = parsed.sections.get(plan.path);
    if (!section) {
      // Planned a read but the host emitted nothing (file shrank/vanished
      // mid-beat). First sight of an empty file → park the cursor at 0 so we
      // don't re-baseline every beat; otherwise keep the old cursor — the next
      // beat re-decides from a fresh stat.
      if (plan.kind === 'baseline' && !newCursors.has(plan.path)) {
        newCursors.set(plan.path, { inode: stat.inode, offset: 0 });
      }
      continue;
    }

    const spec = matchLogSource(plan.path, sources);
    const appname = (spec?.label || plan.path.split('/').pop() || '').slice(0, 128) || null;
    const built = buildFileTailRows({
      host,
      path: plan.path,
      identity: stat.inode ?? 'noid',
      startOffset: section.startOffset,
      data: section.data,
      appname,
      levelOverride: spec?.level,
      offsetMinutes: parsed.offsetMinutes,
      readTimeMs,
      maxLines: plan.kind === 'baseline' ? baselineLines : 0,
    });
    rows.push(...built.rows);
    newCursors.set(plan.path, { inode: stat.inode, offset: section.startOffset + built.consumedBytes });
  }

  for (const p of decision.droppedPaths) newCursors.delete(p);

  if (rows.length === 0) {
    await persist(newCursors); // nothing new — still advance/drop cursors
    return;
  }

  const ok = await pushFileTailBatch(opts.pluginId, String(deviceId), rows);
  if (!ok) {
    await persist(cursors); // NOT advanced — re-read next beat, API dedupes
    return;
  }
  await persist(newCursors); // advance the cursors only after a successful push
}
