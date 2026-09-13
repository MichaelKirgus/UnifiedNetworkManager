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
 * Reads the zone's UTC offset (ms, positive east of Greenwich) at a given instant
 * using Intl's `longOffset` name (e.g. "GMT+02:00"). Returns null for an unknown
 * timezone — that is how we detect invalid IANA names without relying on throw
 * behavior differing across runtimes.
 */
function zoneOffsetMsAt(epochMs: number, timeZone: string): number | null {
  let fmt: Intl.DateTimeFormat;
  try {
    fmt = new Intl.DateTimeFormat('en-US', { timeZone, timeZoneName: 'longOffset' });
  } catch {
    return null; // unknown/invalid IANA zone
  }
  const part = fmt.formatToParts(new Date(epochMs)).find((p) => p.type === 'timeZoneName');
  if (!part || !/^GMT([+-]\d{2}:?\d{2})?$/.test(part.value)) return null; // "GMT" (no offset) or unexpected
  const m = part.value.match(/^GMT([+-])(\d{2}):?(\d{2})$/);
  if (!m) return 0; // plain "GMT" → zero offset
  const sign = m[1] === '-' ? -1 : 1;
  return sign * (parseInt(m[2], 10) * 60 + parseInt(m[3], 10)) * 60_000;
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
