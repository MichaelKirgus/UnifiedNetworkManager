/**
 * Syslog line parsing — RFC 5424 (modern) + BSD syslog (legacy).
 *
 * Both formats share the `<PRI>` header: PRI = facility*8 + severity. We map
 * the 8-level syslog severity scale onto UNM's four log levels:
 *   emergency/alert/critical/error (0-3) → 'error'
 *   warning (4)                        → 'warn'
 *   notice/info (5-6)                  → 'info'
 *   debug (7)                          → 'debug'
 *
 * RFC 5424: `<PRI>VERSION TIMESTAMP HOSTNAME APPNAME PROCID MSGID [SD] MSG`
 * BSD:      `<PRI>Mmm dd hh:mm:ss hostname tag[pid]: message`
 *
 * Lines without a PRI header are accepted with the default PRI 13
 * (user.notice → 'info') — several home-grown senders omit it. Unparseable
 * lines return null and are counted as parse errors by the caller.
 */

export type SecurityLevel = 'debug' | 'info' | 'warn' | 'error';

export interface ParsedSyslog {
  /** Epoch milliseconds (BSD timestamps carry no year — inferred, see below). */
  tsMs: number;
  level: SecurityLevel;
  /** Canonical syslog severity name ('emergency' … 'debug'). */
  severity: string;
  /** Canonical facility name ('kern', 'auth', 'local0', …). */
  facility: string;
  hostname: string;
  /** BSD tag or RFC5424 APP-NAME. */
  appname: string;
  procid: string | null;
  msgid: string | null;
  message: string;
}

const FACILITIES = [
  'kern', 'user', 'mail', 'daemon', 'auth', 'su', 'lpr', 'news', 'uucp', 'cron',
  'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock', 'time', 'confsign',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7',
];

const SEVERITIES = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'];

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

export function levelOfSeverity(severity: number): SecurityLevel {
  if (severity <= 3) return 'error';
  if (severity === 4) return 'warn';
  if (severity <= 6) return 'info';
  return 'debug';
}

function facilityName(facility: number): string {
  return FACILITIES[facility] ?? `fac${facility}`;
}

/** BSD timestamps carry no year — assume the current one, stepping back a year
 *  when that would put the timestamp more than two days in the future (clock
 *  skew / New-Year rollover). */
function bsdTimestampToMs(month: string, day: number, hh: number, mm: number, ss: number): number {
  const now = new Date();
  let year = now.getFullYear();
  const d = new Date(year, MONTHS[month] ?? 0, day, hh, mm, ss);
  if (d.getTime() > now.getTime() + 2 * 86_400_000) {
    d.setFullYear(year - 1);
  }
  return d.getTime();
}

const PRI_RE = /^<(\d{1,3})>(.*)$/s;
const BSD_RE = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+([^\s]+)\s+([\w./-]+?)(?:\[(\d+)\])?\s*:\s?(.*)$/;

/**
 * Parse one syslog line (RFC 5424 or BSD). Returns null when the line matches
 * neither format. `fallbackTsMs` is used for RFC5424 NILVALUE timestamps and
 * unparseable instants.
 */
export function parseSyslogLine(line: string, fallbackTsMs?: number): ParsedSyslog | null {
  const trimmed = line.trim();
  if (trimmed === '') return null;

  let pri = 13; // user.notice default when the header is absent
  let rest = trimmed;
  const priMatch = PRI_RE.exec(trimmed);
  if (priMatch) {
    pri = Math.min(191, Number(priMatch[1]));
    rest = priMatch[2];
  }

  const facility = Math.floor(pri / 8);
  const severity = pri % 8;
  const base: Pick<ParsedSyslog, 'tsMs' | 'level' | 'severity' | 'facility'> = {
    tsMs: fallbackTsMs ?? Date.now(),
    level: levelOfSeverity(severity),
    severity: SEVERITIES[severity] ?? 'info',
    facility: facilityName(facility),
  };

  // RFC 5424 starts with a version digit; BSD starts with a month name.
  if (/^\d/.test(rest)) return parseRfc5424(rest, base);
  const bsd = BSD_RE.exec(rest);
  if (bsd) {
    const [, mon, dayStr, hhStr, mmStr, ssStr, hostname, tag, pid] = bsd;
    return {
      ...base,
      tsMs: bsdTimestampToMs(mon, Number(dayStr), Number(hhStr), Number(mmStr), Number(ssStr)),
      hostname: hostname === '-' ? '' : hostname,
      appname: tag,
      procid: pid ?? null,
      msgid: null,
      // Group 9 — group 8 is the optional [pid].
      message: (bsd[9] ?? '').trim(),
    };
  }
  return null;
}

function parseRfc5424(rest: string, base: Pick<ParsedSyslog, 'tsMs' | 'level' | 'severity' | 'facility'>): ParsedSyslog | null {
  // rest = "VERSION TIMESTAMP HOSTNAME APPNAME PROCID MSGID [SD] MSG"
  const versionMatch = /^(\d+)\s+/.exec(rest);
  if (!versionMatch) return null;

  let cursor = rest.slice(versionMatch[0].length);
  const takeField = (): string => {
    const i = cursor.indexOf(' ');
    let v: string;
    if (i === -1) {
      v = cursor;
      cursor = '';
    } else {
      v = cursor.slice(0, i);
      cursor = cursor.slice(i + 1);
    }
    return v;
  };

  const timestamp = takeField();
  const hostname = takeField();
  const appname = takeField();
  const procid = takeField();
  const msgid = takeField();

  // Remainder: [STRUCTURED-DATA] MSG, or NILVALUE '-' + MSG, or bare MSG.
  let message = cursor;
  if (cursor.startsWith('[')) {
    // Find the closing bracket of the last SD element ('\' escapes inside).
    let depth = 0;
    let end = -1;
    for (let i = 0; i < cursor.length; i++) {
      const c = cursor[i];
      if (c === '\\') {
        i++;
        continue;
      }
      if (c === '[') depth++;
      else if (c === ']') {
        depth--;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    if (end !== -1) message = cursor.slice(end + 1).replace(/^ /, '');
  } else if (cursor.startsWith('-')) {
    const sp = cursor.indexOf(' ');
    message = sp === -1 ? '' : cursor.slice(sp + 1);
  }

  let tsMs = base.tsMs;
  if (timestamp !== '-' && timestamp !== '') {
    const parsed = Date.parse(timestamp);
    if (Number.isFinite(parsed)) tsMs = parsed;
  }

  return {
    ...base,
    tsMs,
    hostname: hostname === '-' ? '' : hostname,
    appname: appname === '-' ? '' : appname,
    procid: procid && procid !== '-' ? procid : null,
    msgid: msgid && msgid !== '-' ? msgid : null,
    message: message.trim(),
  };
}
