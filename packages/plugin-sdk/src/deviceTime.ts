/**
 * Device clock / timezone helpers — shared contract for the "Time" page.
 *
 * Every plugin that CAN read a device's wall-clock time emits ONE metric key,
 * `system.deviceTime`, whose value is a {@link DeviceTimeInfo} object:
 *
 *   { localIso, timezone?, utcOffsetMinutes?, epochMs? }
 *
 * The central API stores it verbatim in the telemetry metrics blob and computes
 * drift (device clock vs. UNM's own clock) from `epochMs` — or re-derives it via
 * {@link parseDeviceTimeToEpochMs} when a plugin only supplied `localIso`.
 *
 * WHY THIS SHAPE (the "smart way" to avoid forcing UTC):
 *   - Devices keep their OWN timezone. We never rewrite a device's clock to UTC;
 *     we only NORMALIZE for comparison. `epochMs` is the single absolute instant
 *     both sides agree on, so drift = |deviceEpoch − unmNow| regardless of what
 *     local zone each box displays in.
 *   - `localIso` + `timezone` are for HUMAN display (the page shows "14:32 CET"
 *     next to the device name), not for math.
 *
 * Plugins that CANNOT read a wall clock (SNMP-only, ICMP, identity providers)
 * simply OMIT the key — an absent key means "not available", which is the same
 * contract as every other optional metric in this codebase.
 */

/** One device's reported clock + timezone (the value of `system.deviceTime`). */
export interface DeviceTimeInfo {
  /**
   * The device's local wall-clock time as an ISO-8601 string, e.g.
   * "2026-09-13T14:32:07" (no zone) or "2026-09-13T14:32:07+02:00". When the
   * string carries NO explicit offset, `timezone` is required to resolve it.
   */
  localIso: string;
  /** IANA timezone identifier (e.g. "Europe/Berlin") when known. Optional. */
  timezone?: string | null;
  /** Fixed UTC offset in minutes baked into the reading (e.g. +120 for CET). Optional. */
  utcOffsetMinutes?: number | null;
  /**
   * Absolute instant as epoch milliseconds, pre-computed by the plugin when it
   * already knows it (cheapest path). When absent, consumers derive it from
   * `localIso` + `timezone` via {@link parseDeviceTimeToEpochMs}.
   */
  epochMs?: number | null;
}

/**
 * Resolves a device's reported local time to an absolute instant in epoch ms.
 *
 * Resolution order:
 *   1. If `info.epochMs` is present and finite → return it (plugin pre-computed).
 *   2. Parse `localIso`. If the string carries an explicit offset ("Z" or ±HH:MM)
 *      → that instant is unambiguous; use it directly.
 *   3. Otherwise interpret the wall-clock in `info.timezone` (IANA name) using
 *      Node's built-in timezone-aware parsing (`Temporal` on Node ≥20, with a
 *      manual offset fallback for older runtimes). A missing/unknown zone makes
 *      the instant unresolvable → returns null.
 *
 * Returns null when no absolute instant can be determined — callers treat that
 * as "drift not computable" and render only the local time, never a fake drift.
 */
export function parseDeviceTimeToEpochMs(info: Pick<DeviceTimeInfo, 'localIso' | 'timezone' | 'utcOffsetMinutes' | 'epochMs'>): number | null {
  if (typeof info.epochMs === 'number' && Number.isFinite(info.epochMs)) return info.epochMs;

  const iso = typeof info.localIso === 'string' ? info.localIso.trim() : '';
  if (!iso) return null;

  // Fast path: the string already pins an absolute instant.
  const explicitOffset = /Z$/i.test(iso) || /[+-]\d{2}:?\d{2}$/.test(iso);
  if (explicitOffset) {
    const t = Date.parse(iso);
    return Number.isNaN(t) ? null : t;
  }

  // No explicit offset → we MUST know the zone to place it on the timeline.
  const tz = typeof info.timezone === 'string' && info.timezone.trim() !== '' ? info.timezone.trim() : null;
  if (!tz) {
    // Last resort: a fixed offset was supplied (e.g. an SNMP timezone enum in
    // minutes). The naive wall clock sits at that constant distance from UTC, so
    // epoch = parseAsUtc(naive) − offset. Append 'Z' to force UTC parsing — a bare
    // ISO datetime without a zone is otherwise parsed as the CONTAINER's local time.
    if (typeof info.utcOffsetMinutes === 'number' && Number.isFinite(info.utcOffsetMinutes)) {
      const t = Date.parse(iso.endsWith('Z') || /[+-]\d{2}:?\d{2}$/.test(iso) ? iso : `${iso}Z`);
      return Number.isNaN(t) ? null : t - info.utcOffsetMinutes * 60_000;
    }
    return null;
  }

  return wallClockInZoneToEpochMs(iso, tz);
}

/**
 * Resolves an IANA zone to its UTC offset in MINUTES at the given instant
 * (positive east of Greenwich), using Intl's `longOffset` name (e.g. "GMT+02:00").
 *
 * Exported for plugins whose WRITE API only accepts a fixed offset instead of an
 * IANA zone (SNMP timezone enums, whole-hour offsets) — they pass the user-chosen
 * zone and set the resolved minutes. Returns null for an unknown/invalid IANA name
 * (detected via constructor throw + format check, not runtime-specific behavior).
 */
export function ianaZoneToOffsetMinutes(timeZone: string, atMs: number = Date.now()): number | null {
  let fmt: Intl.DateTimeFormat;
  try {
    fmt = new Intl.DateTimeFormat('en-US', { timeZone, timeZoneName: 'longOffset' });
  } catch {
    return null; // unknown/invalid IANA zone
  }
  const part = fmt.formatToParts(new Date(atMs)).find((p) => p.type === 'timeZoneName');
  if (!part || !/^GMT([+-]\d{2}:?\d{2})?$/.test(part.value)) return null; // "GMT" (no offset) or unexpected
  const m = part.value.match(/^GMT([+-])(\d{2}):?(\d{2})$/);
  if (!m) return 0; // plain "GMT" → zero offset
  const sign = m[1] === '-' ? -1 : 1;
  return sign * (parseInt(m[2], 10) * 60 + parseInt(m[3], 10));
}

/** Reads the zone's UTC offset in ms at a given instant (internal — see ianaZoneToOffsetMinutes). */
function zoneOffsetMsAt(epochMs: number, timeZone: string): number | null {
  const minutes = ianaZoneToOffsetMinutes(timeZone, epochMs);
  return minutes === null ? null : minutes * 60_000;
}

/**
 * Interprets a naive ISO wall-clock string (no offset) in the given IANA zone and
 * returns its epoch ms. Let W be the wall clock read "as if it were UTC". The true
 * instant E satisfies E + offset(E) = W, i.e. E = W − offset(E). We solve this by
 * fixed-point iteration: start from E = W (offset 0), then refine with the zone's
 * actual offset at E. Real zones change offset only at DST boundaries, so two
 * iterations always converge; during a ~1h ambiguous transition we return the
 * earlier (standard-time) instant — deterministic and fine for drift detection.
 */
function wallClockInZoneToEpochMs(naiveIso: string, timeZone: string): number | null {
  const asUtc = Date.parse(`${naiveIso}Z`); // treat the wall clock as a UTC reference
  if (Number.isNaN(asUtc)) return null;

  let epoch = asUtc;
  for (let i = 0; i < 3; i++) {
    const off = zoneOffsetMsAt(epoch, timeZone);
    if (off === null) return null; // invalid timezone name
    const next = asUtc - off;
    if (next === epoch) break;
    epoch = next;
  }
  return epoch;
}

/**
 * Convenience builder for plugins: assembles a {@link DeviceTimeInfo} from the
 * pieces they most often have — an ISO local time and an IANA zone — and pre-computes
 * `epochMs` so downstream consumers never need to re-parse. Returns null when no
 * absolute instant can be resolved (caller should then omit the metric key).
 */
export function buildDeviceTimeInfo(localIso: string, timezone?: string | null, utcOffsetMinutes?: number | null): DeviceTimeInfo | null {
  const base: DeviceTimeInfo = { localIso };
  if (timezone) base.timezone = timezone;
  if (typeof utcOffsetMinutes === 'number' && Number.isFinite(utcOffsetMinutes)) base.utcOffsetMinutes = utcOffsetMinutes;
  const epochMs = parseDeviceTimeToEpochMs(base);
  if (epochMs === null) return null; // unresolvable → caller omits the key
  base.epochMs = epochMs;
  return base;
}

// --- Loose device-datetime parsing ----------------------------------------------------
//
// Vendor APIs report wall clocks in a handful of loose formats. Plugins used to
// each carry their own parser (OPNsense's asctime, LANCOM-LCOS's dotted/US dates);
// this is the shared superset so every plugin gets drift support for free.

/** Month abbreviations for asctime(3) parsing ("Jan".."Dec"). */
const MONTH_ABBR_TO_NUM: Record<string, number> = {
  Jan: 1, Feb: 2, Mar: 3, Apr: 4, May: 5, Jun: 6,
  Jul: 7, Aug: 8, Sep: 9, Oct: 10, Nov: 11, Dec: 12,
};

/** Result of {@link parseLooseDeviceDatetime}. */
export interface LooseDeviceDatetime {
  /** Naive ISO-8601 wall clock (no offset), e.g. "2026-09-13T23:06:02". */
  localIso: string;
  /** POSIX tzname abbreviation when the source carried one (e.g. "CEST"), else null. */
  tzAbbr?: string | null;
}

/**
 * Normalizes a vendor-reported wall-clock string to a naive ISO-8601 datetime.
 *
 * Accepted forms, tried in order:
 *   1. ISO-ish:        "YYYY-MM-DD HH:MM[:SS]" (or with 'T')
 *   2. asctime(3):     "Sun Sep 13 23:06:02 CEST 2026" — day may be space-padded
 *                      ("Sep  5"); the optional timezone abbreviation is surfaced
 *                      in `tzAbbr` so callers can map it via {@link tzAbbrToOffsetMinutes}
 *   3. EU dotted:      "DD.MM.YYYY HH:MM[:SS]"
 *   4. Slash:          "M/D/YYYY HH:MM[:SS]" — a component >12 forces its position
 *                      (first>12 → DD/MM); otherwise MM/DD is assumed (the observed
 *                      firmware default)
 *
 * Returns null when unparseable so the caller omits the metric key rather than
 * emitting a fake reading. Combine with {@link buildDeviceTimeInfo} to get an
 * absolute instant for drift computation.
 */
export function parseLooseDeviceDatetime(raw: string): LooseDeviceDatetime | null {
  const s = String(raw ?? '').trim();
  if (!s) return null;

  // 1. ISO-ish: "2026-09-13 14:32:07" or with 'T'.
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (m) return { localIso: `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] ?? '00'}`, tzAbbr: null };

  // 2. asctime(3): "Sun Sep 13 23:06:02 CEST 2026" (day may be space-padded).
  m = s.match(/^([A-Z][a-z]{2}) ([A-Z][a-z]{2}) +?(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\s+([A-Za-z]+))?\s+(\d{4})$/);
  if (m) {
    const month = MONTH_ABBR_TO_NUM[m[2]];
    if (!month) return null;
    const day = parseInt(m[3], 10);
    if (day < 1 || day > 31) return null;
    return {
      localIso: `${m[8]}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}T${m[4]}:${m[5]}:${m[6]}`,
      tzAbbr: m[7] ?? null,
    };
  }

  // 3. EU dotted: "13.09.2026 23:06:22" (DD.MM.YYYY).
  m = s.match(/^(\d{1,2})\.(\d{1,2})\.(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (m) {
    const day = parseInt(m[1], 10), month = parseInt(m[2], 10);
    if (month < 1 || month > 12 || day < 1 || day > 31) return null;
    return { localIso: `${m[3]}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}T${m[4]}:${m[5]}:${m[6] ?? '00'}`, tzAbbr: null };
  }

  // 4. Slash: "09/13/2026 23:06:22" — disambiguate day/month (>12 forces position,
  //    otherwise assume MM/DD, the firmware's observed default).
  m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (m) {
    const a = parseInt(m[1], 10), b = parseInt(m[2], 10);
    let month: number, day: number;
    if (a > 12 && b <= 12) { day = a; month = b; } // DD/MM forced by first>12
    else { month = a; day = b; }                   // MM/DD (default + second>12 case)
    const year = m[3];
    if (month < 1 || month > 12 || day < 1 || day > 31) return null;
    return { localIso: `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}T${m[4]}:${m[5]}:${m[6] ?? '00'}`, tzAbbr: null };
  }

  return null;
}

/**
 * Common POSIX tzname abbreviations → fixed UTC offset in minutes. Used to place
 * an asctime(3) reading on the timeline when the appliance exposes no IANA zone.
 * (DST-aware zones are approximated by their STANDARD+DAYLIGHT pair — good enough
 * for drift detection, which only needs a stable offset.)
 */
export const TZ_ABBR_OFFSET_MINUTES: Record<string, number> = {
  UTC: 0, GMT: 0, Z: 0,
  WET: 0, WEST: 60,
  CET: 60, CEST: 120, MET: 60, MEST: 120, BST: 60,
  EET: 120, EEST: 180, FET: 180, FEET: 240,
  EST: -300, EDT: -240, CST: -360, CDT: -300,
  MST: -420, MDT: -360, PST: -480, PDT: -420, HST: -600, AKST: -540, AKDT: -480,
};

/** Maps a tzname abbreviation (e.g. "CEST") to its fixed UTC offset in minutes; null when unknown. */
export function tzAbbrToOffsetMinutes(abbr: string | null | undefined): number | null {
  if (typeof abbr !== 'string') return null;
  const a = abbr.trim().toUpperCase();
  if (!a) return null;
  return Object.prototype.hasOwnProperty.call(TZ_ABBR_OFFSET_MINUTES, a) ? TZ_ABBR_OFFSET_MINUTES[a] : null;
}
